# test/test_oqs_tls.py
"""
Benchmark pro PQC implementaci pomocí knihovny LIBOQS (tls/tls_oqs_pqc_c.py).
"""
import time
import tracemalloc
import os
import matplotlib.pyplot as plt
from typing import Any, Dict, Optional, Tuple

# Import OQS wrapperu
from tls import tls_oqs_pqc_c as tls_module
from .test_utils import _stats, _print_table

# Nastavení benchmarku
ROUNDS = 100
VARIANTS = [0, 1, 2]
VARIANT_LABELS = [
    "OQS L2 (512/44)",
    "OQS L3 (768/65)",
    "OQS L5 (1024/87)"
]


def _profile_call(func, *args, **kwargs) -> Tuple[Any, float, float]:
    """Změří čas (ms) a paměť (KiB)."""
    tracemalloc.clear_traces()
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    _, peak_bytes = tracemalloc.get_traced_memory()
    return result, (end - start) * 1000.0, peak_bytes / 1024.0


def run_handshake(dsa_id: int, kem_id: int) -> Optional[Dict[str, Any]]:
    """Provede jeden handshake a vrátí metriky."""
    metrics = {"t": {}, "m": {}}
    try:
        # 1. Server Identity
        res, t, m = _profile_call(tls_module.setup_server_identity, dsa_id)
        if res is None: return None
        pk_s, sk_s, params = res
        metrics["t"]["1"], metrics["m"]["1"] = t, m

        # 2. Client Hello
        res, t, m = _profile_call(tls_module.client_hello, kem_id)
        pk_c, sk_c, info = res
        metrics["t"]["2"], metrics["m"]["2"] = t, m

        # 3. Server Response
        res, t, m = _profile_call(tls_module.server_response, pk_c, info, sk_s, params, kem_id)
        ct, sig, ss_s = res
        metrics["t"]["3"], metrics["m"]["3"] = t, m

        # 4. Client Finish
        ss_c, t, m = _profile_call(tls_module.client_finish, ct, sig, pk_s, sk_c, pk_c, params, kem_id)
        if ss_c is None: return None
        metrics["t"]["4"], metrics["m"]["4"] = t, m

        if ss_s != ss_c: return None
        return metrics
    except Exception:
        return None


def main():
    print(f"=== TEST: OQS (C KNIHOVNA) ({ROUNDS} kol) ===")
    results_time = []
    results_mem = []
    table_rows = []

    tracemalloc.start()

    for i, var_id in enumerate(VARIANTS):
        name = VARIANT_LABELS[i]
        print(f"Testuji: {name} ...")

        times = []
        mems = []

        for r in range(ROUNDS):
            m = run_handshake(var_id, var_id)
            if m:
                times.append(sum(m["t"].values()))
                # Pro paměť bereme maximum z dílčích kroků
                mems.append(max(m["m"].values()))

        if times:
            _, avg_t, _ = _stats(times)
            _, avg_m, _ = _stats(mems)
            results_time.append(avg_t)
            results_mem.append(avg_m)
            table_rows.append((name, f"{avg_t:.3f}", f"{avg_m:.2f}"))
        else:
            results_time.append(0)
            results_mem.append(0)
            table_rows.append((name, "FAIL", "FAIL"))

    tracemalloc.stop()

    print("\n--- VÝSLEDKY MĚŘENÍ ---")
    _print_table(table_rows, ("Varianta", "Průměr Čas [ms]", "Paměť [KiB]"))

    os.makedirs("graphs", exist_ok=True)

    # Graf času
    if any(results_time):
        plt.figure(figsize=(8, 5))
        plt.bar(VARIANT_LABELS, results_time, color="#FFB347")
        plt.title("PQC (OQS C) - Průměrný čas handshake")
        plt.ylabel("Čas [ms]")
        plt.tight_layout()
        plt.savefig("graphs/pqc_oqs_c_time.png")
        print("\nGraf času uložen: graphs/pqc_oqs_c_time.png")

    # Graf paměti
    if any(results_mem):
        plt.figure(figsize=(8, 5))
        plt.bar(VARIANT_LABELS, results_mem, color="#FFB347")
        plt.title("PQC (OQS C) - Průměrná špičková paměť")
        plt.ylabel("Paměť [KiB]")
        plt.tight_layout()
        plt.savefig("graphs/pqc_oqs_c_mem.png")
        print("Graf paměti uložen: graphs/pqc_oqs_c_mem.png")


if __name__ == "__main__":
    main()