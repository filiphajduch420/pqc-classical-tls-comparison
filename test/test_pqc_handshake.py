# test/test_pqc_handshake.py
import time
import tracemalloc
from typing import Dict, Any, Optional, Tuple, List

from tls import tls
from test.test_utils import _time_call, _memory_call, _stats, _print_table

ROUNDS = 10
VARIANTS_TO_TEST = [0, 1, 2]


def run_pqc_handshake_profiled(mldsa_id: int, mlkem_id: int) -> Optional[Dict[str, Any]]:
    """Run one PQC handshake for given variants and collect per-step timing and memory."""
    timings: Dict[str, float] = {}
    memory: Dict[str, float] = {}

    # Step 0: Server ML-DSA keygen
    server_keys_data, t = _time_call(tls.setup_server_keys, mldsa_id)
    if server_keys_data is None:
        return None
    timings["1_Server_DSA_KeyGen"] = t
    _, m = _memory_call(tls.setup_server_keys, mldsa_id)
    memory["1_Server_DSA_KeyGen"] = m

    client_known_pkS = server_keys_data["pkS"]
    mldsa_params = server_keys_data["mldsa_params"]

    # Step 1: Client Hello
    _, t = _time_call(tls.client_hello)
    timings["2_Client_Hello"] = t
    _, m = _memory_call(tls.client_hello)
    memory["2_Client_Hello"] = m

    # Step 2: Server Hello & KEM KeyGen & Sign
    server_data, t = _time_call(
        tls.server_hello_and_key_exchange,
        server_keys_data["skS"],
        mlkem_id,
        mldsa_params
    )
    if server_data is None:
        return None
    timings["3_Server_Hello_KEM_Sign"] = t
    _, m = _memory_call(
        tls.server_hello_and_key_exchange,
        server_keys_data["skS"],
        mlkem_id,
        mldsa_params
    )
    memory["3_Server_Hello_KEM_Sign"] = m

    # Step 3: Client Verify & Encaps
    client_data, t = _time_call(
        tls.client_verify_and_key_exchange,
        client_known_pkS,
        server_data["pkE"],
        server_data["signature"],
        server_data["data_to_sign"],
        mldsa_params,
        mlkem_id
    )
    if client_data is None:
        return None
    timings["4_Client_Verify_Encaps"] = t
    _, m = _memory_call(
        tls.client_verify_and_key_exchange,
        client_known_pkS,
        server_data["pkE"],
        server_data["signature"],
        server_data["data_to_sign"],
        mldsa_params,
        mlkem_id
    )
    memory["4_Client_Verify_Encaps"] = m

    # Step 4: Server Decapsulate
    server_final, t = _time_call(
        tls.server_decapsulate,
        server_data["skE"],
        client_data["ct"],
        mlkem_id
    )
    if server_final is None:
        return None
    timings["5_Server_Decaps"] = t
    _, m = _memory_call(
        tls.server_decapsulate,
        server_data["skE"],
        client_data["ct"],
        mlkem_id
    )
    memory["5_Server_Decaps"] = m

    # Check secrets
    if client_data["ss_client"] != server_final["ss_server"]:
        return None

    return {"timings": timings, "memory": memory}


def main():
    print("=== Running PQC Handshake Benchmark (ML-DSA v_i + ML-KEM v_i for i in {0,1,2}) ===")
    print(f"Rounds per combo: {ROUNDS}\n")

    headers_time = ("Combo", "Total [ms]", "1_KeyGen [ms]", "3_Srv_KEM+Sign [ms]", "4_Clnt_Verify+Enc [ms]",
                    "5_Srv_Decaps [ms]")
    headers_mem = ("Combo", "Total [KiB]", "1_KeyGen [KiB]", "3_Srv_KEM+Sign [KiB]", "4_Clnt_Verify+Enc [KiB]",
                   "5_Srv_Decaps [KiB]")

    time_rows: List[Tuple[str, ...]] = []
    mem_rows: List[Tuple[str, ...]] = []

    for variant_id in VARIANTS_TO_TEST:
        combo = f"ML-DSA v{variant_id} + ML-KEM v{variant_id}"
        print(f"--- Testing {combo} ---")

        timings_per_step = {
            "1_Server_DSA_KeyGen": [],
            "2_Client_Hello": [],
            "3_Server_Hello_KEM_Sign": [],
            "4_Client_Verify_Encaps": [],
            "5_Server_Decaps": [],
            "TOTAL_HANDSHAKE": []
        }
        memory_per_step = {k: [] for k in timings_per_step}

        ok = 0
        tracemalloc.start()
        for i in range(ROUNDS):
            print(f"  Round {i + 1}/{ROUNDS}...", end="\r")

            start_total = time.perf_counter()
            tracemalloc.clear_traces()

            result = run_pqc_handshake_profiled(variant_id, variant_id)

            total_ms = (time.perf_counter() - start_total) * 1000.0
            _, total_peak_kib = tracemalloc.get_traced_memory()

            if result is None:
                print(f"\n  Error in round {i + 1}, skipping.")
                continue

            ok += 1
            timings_per_step["TOTAL_HANDSHAKE"].append(total_ms)
            memory_per_step["TOTAL_HANDSHAKE"].append(total_peak_kib)

            for key, t_val in result["timings"].items():
                timings_per_step[key].append(t_val)
            for key, m_val in result["memory"].items():
                memory_per_step[key].append(m_val)

        tracemalloc.stop()
        print(f"\n  Done. Successful rounds: {ok}/{ROUNDS}")

        if ok > 0:
            _, t_avg_total, _ = _stats(timings_per_step["TOTAL_HANDSHAKE"])
            _, t_avg_kgen, _ = _stats(timings_per_step["1_Server_DSA_KeyGen"])
            _, t_avg_srv, _ = _stats(timings_per_step["3_Server_Hello_KEM_Sign"])
            _, t_avg_cli, _ = _stats(timings_per_step["4_Client_Verify_Encaps"])
            _, t_avg_dec, _ = _stats(timings_per_step["5_Server_Decaps"])

            time_rows.append((
                combo,
                f"{t_avg_total:.3f}",
                f"{t_avg_kgen:.3f}",
                f"{t_avg_srv:.3f}",
                f"{t_avg_cli:.3f}",
                f"{t_avg_dec:.3f}",
            ))

            _, m_avg_total, _ = _stats(memory_per_step["TOTAL_HANDSHAKE"])
            _, m_avg_kgen, _ = _stats(memory_per_step["1_Server_DSA_KeyGen"])
            _, m_avg_srv, _ = _stats(memory_per_step["3_Server_Hello_KEM_Sign"])
            _, m_avg_cli, _ = _stats(memory_per_step["4_Client_Verify_Encaps"])
            _, m_avg_dec, _ = _stats(memory_per_step["5_Server_Decaps"])

            mem_rows.append((
                combo,
                f"{m_avg_total:.2f}",
                f"{m_avg_kgen:.2f}",
                f"{m_avg_srv:.2f}",
                f"{m_avg_cli:.2f}",
                f"{m_avg_dec:.2f}",
            ))

    print("\n--- Average Time (PQC) ---")
    _print_table(time_rows, headers_time)

    print("\n--- Average Peak Memory (PQC) ---")
    _print_table(mem_rows, headers_mem)


if __name__ == "__main__":
    main()
