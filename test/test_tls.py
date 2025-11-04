# test_tls.py
"""
Finální srovnávací benchmark pro tři různé implementace TLS handshake:
1. PQC (Čistý Python): Vaše implementace z `tls.py`.
2. PQC (OQS C Knihovna): Wrapper `tls_oqs_pqc_c.py`.
3. Klasika (Crypto C Knihovna): Wrapper `tls_classic_c.py`.
"""

import time
import tracemalloc
import statistics
from typing import Dict, Any, Optional, Tuple, List

# --- Import pomocných funkcí ---
# Předpokládá se, že tento skript je ve složce `test/`
from .test_utils import _stats, _print_table

# --- Import testovaných implementací ---
# Přejmenujeme původní tls.py pro přehlednost
from tls import tls as tls_pqc_python
from tls import tls_oqs_pqc_c
from tls import tls_classic_c

import os
import matplotlib.pyplot as plt

# --- Konfigurace benchmarku ---
# ZMĚNA: Nastavení počtu kol pro jednotlivé implementace
ROUNDS_PYTHON = 10
ROUNDS_C = 100  # Pro OQS a Klasiku
VARIANTS_TO_TEST = [0, 1, 2]  # ID variant (0, 1, 2)

# Mapování ID na názvy pro tabulky
COMBO_NAMES = {
    "PQC (Python)": [
        "ML-DSA v0 + ML-KEM v0 (Python)",
        "ML-DSA v1 + ML-KEM v1 (Python)",
        "ML-DSA v2 + ML-KEM v2 (Python)",
    ],
    "PQC (OQS C)": [
        "ML-DSA-44 + ML-KEM-512 (OQS-C)",
        "ML-DSA-65 + ML-KEM-768 (OQS-C)",
        "ML-DSA-87 + ML-KEM-1024 (OQS-C)",
    ],
    "Klasika (C)": [
        "ECDSA-P256 + ECDHE-X25519 (Crypto-C)",
        "ECDSA-P384 + ECDHE-X25519 (Crypto-C)",
        "Ed25519 + ECDHE-X25519 (Crypto-C)",
    ]
}

# --- ZMĚNA: Popisky pro osy X v grafech ---
# Použijeme kratší názvy, aby se vešly na osu grafu
VARIANT_LABELS_MAP = {
    "PQC (Python)": [
        "ML-DSA-44 (v0)\n+ ML-KEM-512 (v0)",
        "ML-DSA-65 (v1)\n+ ML-KEM-768 (v1)",
        "ML-DSA-87 (v2)\n+ ML-KEM-1024 (v2)"
    ],
    "PQC (OQS C)": [
        "OQS L2\n(512/44)",
        "OQS L3\n(768/65)",
        "OQS L5\n(1024/87)"
    ],
    "Klasika (C)": [
        "ECDSA-P256\n+X25519",
        "ECDSA-P384\n+X25519",
        "Ed25519\n+X25519"
    ],
}


# --- KONEC ZMĚN ---


# --- Pomocná funkce pro profilování ---
def _profile_call(func, *args, **kwargs) -> Tuple[Any, float, float]:
    """
    Spustí funkci a měří čas (ms) i špičkovou paměť (KiB).
    Volá se POUZE JEDNOU.
    """
    tracemalloc.clear_traces()
    start = time.perf_counter()

    result = func(*args, **kwargs)

    end = time.perf_counter()
    _, peak_bytes = tracemalloc.get_traced_memory()

    time_ms = (end - start) * 1000.0
    mem_kib = peak_bytes / 1024.0
    return result, time_ms, mem_kib


# --- Univerzální benchmarkovací funkce ---
def run_handshake_profiled(
        tls_module: Any,
        mldsa_id: int,
        mlkem_id: int
) -> Optional[Dict[str, Any]]:
    """
    Spustí jeden PQC handshake pro daný 'tls_module' a změří výkon.
    """
    timings: Dict[str, float] = {}
    memory: Dict[str, float] = {}

    try:
        # Krok 0: Server ML-DSA keygen
        server_keys_data, t, m = _profile_call(tls_module.setup_server_keys, mldsa_id)
        if server_keys_data is None: return None
        timings["1_Server_DSA_KeyGen"] = t
        memory["1_Server_DSA_KeyGen"] = m

        client_known_pkS = server_keys_data["pkS"]
        mldsa_params = server_keys_data["mldsa_params"]
        skS = server_keys_data["skS"]

        # Krok 1: Client Hello
        _, t, m = _profile_call(tls_module.client_hello)
        timings["2_Client_Hello"] = t
        memory["2_Client_Hello"] = m

        # Krok 2: Server Hello & KEM KeyGen & Sign
        server_data, t, m = _profile_call(
            tls_module.server_hello_and_key_exchange, skS, mlkem_id, mldsa_params
        )
        if server_data is None: return None
        timings["3_Server_Hello_KEM_Sign"] = t
        memory["3_Server_Hello_KEM_Sign"] = m
        skE = server_data["skE"]

        # Argumenty pro client_verify_and_key_exchange
        args = [
            client_known_pkS,
            server_data["pkE"],
            server_data["signature"],
            server_data["data_to_sign"],
        ]
        if tls_module is tls_oqs_pqc_c:
            args.append(mldsa_id)
        else:
            args.append(mldsa_params)
        args.append(mlkem_id)

        # Krok 3: Client Verify & Encaps
        client_data, t, m = _profile_call(
            tls_module.client_verify_and_key_exchange, *args
        )
        if client_data is None: return None
        timings["4_Client_Verify_Encaps"] = t
        memory["4_Client_Verify_Encaps"] = m

        # Krok 4: Server Decapsulate
        server_final, t, m = _profile_call(
            tls_module.server_decapsulate, skE, client_data["ct"], mlkem_id
        )
        if server_final is None: return None
        timings["5_Server_Decaps"] = t
        memory["5_Server_Decaps"] = m

        # Kontrola tajemství
        if client_data["ss_client"] != server_final["ss_server"]:
            print("\n  CHYBA: Tajemství se neshodují!")
            return None

        return {"timings": timings, "memory": memory}

    except Exception as e:
        print(f"\n  Neočekávaná chyba benchmarku: {e}")
        import traceback
        traceback.print_exc()
        return None


# --- Hlavní spouštěcí funkce ---
def main():
    benchmarks_to_run = [
        ("PQC (Python)", tls_pqc_python, ROUNDS_PYTHON),
        ("PQC (OQS C)", tls_oqs_pqc_c, ROUNDS_C),
        ("Klasika (C)", tls_classic_c, ROUNDS_C),
    ]

    all_time_rows: List[Tuple[str, ...]] = []
    all_mem_rows: List[Tuple[str, ...]] = []

    headers_time = ("Varianta", "Total [ms]", "1_KeyGen [ms]", "3_Srv_KEM+Sign [ms]", "4_Clnt_Verify+Enc [ms]",
                    "5_Srv_Decaps [ms]")
    headers_mem = ("Varianta", "Total [KiB]", "1_KeyGen [KiB]", "3_Srv_KEM+Sign [KiB]", "4_Clnt_Verify+Enc [KiB]",
                   "5_Srv_Decaps [KiB]")

    # --- ZMĚNA: Slovníky pro ukládání dat pro grafy ---
    grouped_time_results = {"PQC (Python)": [], "PQC (OQS C)": [], "Klasika (C)": []}
    grouped_mem_results = {"PQC (Python)": [], "PQC (OQS C)": [], "Klasika (C)": []}
    # --- KONEC ZMĚNY ---

    for name, tls_module, current_rounds in benchmarks_to_run:
        print(f"\n{'=' * 20} BĚŽÍ: {name} {'=' * 20}")
        print(f"Rounds per combo: {current_rounds}\n")

        for variant_id in VARIANTS_TO_TEST:
            combo_name = COMBO_NAMES[name][variant_id]
            print(f"--- Testuji: {combo_name} ---")

            timings_per_step = {
                "1_Server_DSA_KeyGen": [], "2_Client_Hello": [],
                "3_Server_Hello_KEM_Sign": [], "4_Client_Verify_Encaps": [],
                "5_Server_Decaps": [], "TOTAL_HANDSHAKE": []
            }
            memory_per_step = {k: [] for k in timings_per_step}

            ok = 0
            tracemalloc.start()
            for i in range(current_rounds):
                print(f"  Kolo {i + 1}/{current_rounds}...", end="\r")

                start_total = time.perf_counter()
                tracemalloc.clear_traces()
                result = run_handshake_profiled(tls_module, variant_id, variant_id)
                total_ms = (time.perf_counter() - start_total) * 1000.0
                _, total_peak_bytes = tracemalloc.get_traced_memory()

                if result is None:
                    print(f"\n  Chyba v kole {i + 1}, přeskakuji.")
                    continue

                ok += 1
                timings_per_step["TOTAL_HANDSHAKE"].append(total_ms)
                memory_per_step["TOTAL_HANDSHAKE"].append(total_peak_bytes / 1024.0)

                for key, t_val in result["timings"].items(): timings_per_step[key].append(t_val)
                for key, m_val in result["memory"].items(): memory_per_step[key].append(m_val)

            tracemalloc.stop()
            print(f"\n  Hotovo. Úspěšná kola: {ok}/{current_rounds}")

            if ok > 0:
                # Vypočítáme průměry
                _, t_avg_total, _ = _stats(timings_per_step["TOTAL_HANDSHAKE"])
                _, t_avg_kgen, _ = _stats(timings_per_step["1_Server_DSA_KeyGen"])
                _, t_avg_srv, _ = _stats(timings_per_step["3_Server_Hello_KEM_Sign"])
                _, t_avg_cli, _ = _stats(timings_per_step["4_Client_Verify_Encaps"])
                _, t_avg_dec, _ = _stats(timings_per_step["5_Server_Decaps"])

                all_time_rows.append((
                    combo_name, f"{t_avg_total:.3f}", f"{t_avg_kgen:.3f}",
                    f"{t_avg_srv:.3f}", f"{t_avg_cli:.3f}", f"{t_avg_dec:.3f}",
                ))

                # Ukládání dat pro grafy
                grouped_time_results[name].append(t_avg_total)

                _, m_avg_total, _ = _stats(memory_per_step["TOTAL_HANDSHAKE"])
                _, m_avg_kgen, _ = _stats(memory_per_step["1_Server_DSA_KeyGen"])
                _, m_avg_srv, _ = _stats(memory_per_step["3_Server_Hello_KEM_Sign"])
                _, m_avg_cli, _ = _stats(memory_per_step["4_Client_Verify_Encaps"])
                _, m_avg_dec, _ = _stats(memory_per_step["5_Server_Decaps"])

                all_mem_rows.append((
                    combo_name, f"{m_avg_total:.2f}", f"{m_avg_kgen:.2f}",
                    f"{m_avg_srv:.2f}", f"{m_avg_cli:.2f}", f"{m_avg_dec:.2f}",
                ))

                # Ukládání dat pro grafy
                grouped_mem_results[name].append(m_avg_total)
            else:
                all_time_rows.append((combo_name, "FAIL", "FAIL", "FAIL", "FAIL", "FAIL"))
                all_mem_rows.append((combo_name, "FAIL", "FAIL", "FAIL", "FAIL", "FAIL"))
                # Přidání None pro neúspěšné grafy
                grouped_time_results[name].append(None)
                grouped_mem_results[name].append(None)

    print("\n\n" + "=" * 30 + " SOUHRNNÉ VÝSLEDKY " + "=" * 30)
    print("\n--- SOUHRN: Průměrný Čas (ms) ---")
    _print_table(all_time_rows, headers_time)

    print("\n--- SOUHRN: Průměrná Špičková Paměť (KiB) ---")
    _print_table(all_mem_rows, headers_mem)

    # === 📊  Vykreslení a uložení sloupcových grafů ===

    output_dir = "graphs"
    os.makedirs(output_dir, exist_ok=True)
    print(f"\nUkládám grafy do složky: {output_dir}/")

    # --- ZMĚNA: Funkce pro vykreslení času ---
    def plot_and_save_time_group(title: str, data: list, labels: list, filename: str):
        if not data or all(v is None for v in data):
            print(f"⚠️ Graf '{filename}' byl přeskočen, žádná platná data.")
            return

        plt.figure(figsize=(8, 5))  # Mírně širší pro delší popisky
        bars = plt.bar(labels, data, color=["#4B9CD3", "#3CB371", "#FFB347"])
        plt.title(f"{title} – Průměrný čas handshake (ms)")
        plt.ylabel("Čas [ms]")
        plt.xticks(fontsize=8)  # Menší písmo pro popisky osy X
        plt.grid(axis="y", linestyle="--", alpha=0.5)

        valid_data = [d for d in data if d is not None and d > 0]
        if valid_data:
            max_val = max(valid_data)
            # Logaritmická osa pro Python, lineární pro C
            if "Python" in title:
                plt.yscale("log")
                plt.ylabel("Čas [ms] (Logaritmická osa)")
                # Odsazení pro log osu (multiplikativní)
                y_offset = 1.2
                for bar, val in zip(bars, data):
                    if val is not None:
                        plt.text(bar.get_x() + bar.get_width() / 2, val * y_offset,
                                 f"{val:.2f}", ha="center", va="bottom", fontsize=8)
            else:
                # Odsazení pro lineární osu (aditivní)
                y_offset = max_val * 0.05
                for bar, val in zip(bars, data):
                    if val is not None:
                        plt.text(bar.get_x() + bar.get_width() / 2, val + y_offset,
                                 f"{val:.3f}", ha="center", va="bottom", fontsize=8)

        plt.tight_layout()
        save_path = os.path.join(output_dir, filename)
        plt.savefig(save_path, dpi=200)
        plt.close()
        print(f"✅ Graf času uložen: {save_path}")

    # --- NOVÁ FUNKCE: Vykreslení paměti ---
    def plot_and_save_memory_group(title: str, data: list, labels: list, filename: str):
        if not data or all(v is None for v in data):
            print(f"⚠️ Graf '{filename}' byl přeskočen, žádná platná data.")
            return

        plt.figure(figsize=(8, 5))
        bars = plt.bar(labels, data, color=["#4B9CD3", "#3CB371", "#FFB347"])
        plt.title(f"{title} – Průměrná špičková paměť (KiB)")
        plt.ylabel("Paměť [KiB]")
        plt.xticks(fontsize=8)
        plt.grid(axis="y", linestyle="--", alpha=0.5)

        valid_data = [d for d in data if d is not None and d > 0]
        if valid_data:
            max_val = max(valid_data)
            # Logaritmická osa pro Python, lineární pro C
            if "Python" in title:
                plt.yscale("log")
                plt.ylabel("Paměť [KiB] (Logaritmická osa)")
                y_offset = 1.2
                for bar, val in zip(bars, data):
                    if val is not None:
                        plt.text(bar.get_x() + bar.get_width() / 2, val * y_offset,
                                 f"{val:.2f}", ha="center", va="bottom", fontsize=8)
            else:
                y_offset = max_val * 0.05
                for bar, val in zip(bars, data):
                    if val is not None:
                        plt.text(bar.get_x() + bar.get_width() / 2, val + y_offset,
                                 f"{val:.2f}", ha="center", va="bottom", fontsize=8)

        plt.tight_layout()
        save_path = os.path.join(output_dir, filename)
        plt.savefig(save_path, dpi=200)
        plt.close()
        print(f"✅ Graf paměti uložen: {save_path}")

    # --- KONEC NOVÉ FUNKCE ---

    # --- ZMĚNA: Volání vykreslovacích funkcí ---

    # Vykresli 3 grafy pro čas
    plot_and_save_time_group(
        "PQC (Python)",
        grouped_time_results["PQC (Python)"],
        VARIANT_LABELS_MAP["PQC (Python)"],
        "pqc_python_time.png"
    )
    plot_and_save_time_group(
        "PQC (OQS C)",
        grouped_time_results["PQC (OQS C)"],
        VARIANT_LABELS_MAP["PQC (OQS C)"],
        "pqc_oqs_c_time.png"
    )
    plot_and_save_time_group(
        "Klasika (C)",
        grouped_time_results["Klasika (C)"],
        VARIANT_LABELS_MAP["Klasika (C)"],
        "classical_c_time.png"
    )

    # Vykresli 3 grafy pro paměť
    plot_and_save_memory_group(
        "PQC (Python)",
        grouped_mem_results["PQC (Python)"],
        VARIANT_LABELS_MAP["PQC (Python)"],
        "pqc_python_mem.png"
    )
    plot_and_save_memory_group(
        "PQC (OQS C)",
        grouped_mem_results["PQC (OQS C)"],
        VARIANT_LABELS_MAP["PQC (OQS C)"],
        "pqc_oqs_c_mem.png"
    )
    plot_and_save_memory_group(
        "Klasika (C)",
        grouped_mem_results["Klasika (C)"],
        VARIANT_LABELS_MAP["Klasika (C)"],
        "classical_c_mem.png"
    )
    # --- KONEC ZMĚN ---


if __name__ == "__main__":
    main()