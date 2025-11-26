# test/test_my_tls.py
"""
Benchmark pro TVOU vlastní implementaci v čistém Pythonu (tls/tls.py).
Čistá verze bez debug výpisů.
"""
import time
import tracemalloc
import os
import matplotlib.pyplot as plt
from typing import Any, Dict, Optional, Tuple

# Import mé implementace
from tls import tls as tls_module
# Import pomocných funkcí
from .test_utils import _stats, _print_table

# Nastavení benchmarku
ROUNDS = 10  # Standardní počet kol pro Python
VARIANTS = [0, 1, 2]
VARIANT_LABELS = [
    "ML-DSA-44 + ML-KEM-512 (v0)",
    "ML-DSA-65 + ML-KEM-768 (v1)",
    "ML-DSA-87 + ML-KEM-1024 (v2)"
]


def _profile_call(func, *args, **kwargs) -> Tuple[Any, float, float]:
    """Změří čas (ms) a paměť (KiB) volání jedné funkce."""
    tracemalloc.clear_traces()
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    _, peak_bytes = tracemalloc.get_traced_memory()
    return result, (end - start) * 1000.0, peak_bytes / 1024.0


def run_handshake(dsa_id: int, kem_id: int) -> Optional[Dict[str, Any]]:
    """Provede jeden kompletní handshake a vrátí naměřené metriky."""
    metrics = {"t": {}, "m": {}}

    try:
        # 1. Server Identity (Generování klíčů serveru)
        res, t, m = _profile_call(tls_module.setup_server_identity, dsa_id)
        if res is None: return None
        pk_s, sk_s, params = res
        metrics["t"]["1_ServerIdent"], metrics["m"]["1_ServerIdent"] = t, m

        # 2. Client Hello (Generování klíčů klienta)
        res, t, m = _profile_call(tls_module.client_hello, kem_id)
        if res is None: return None
        pk_c, sk_c, info = res
        metrics["t"]["2_ClientHello"], metrics["m"]["2_ClientHello"] = t, m

        # 3. Server Response (Encapsulation + Podpis)
        res, t, m = _profile_call(tls_module.server_response, pk_c, info, sk_s, params, kem_id)
        if res is None: return None
        ct, sig, ss_s = res
        metrics["t"]["3_ServerResp"], metrics["m"]["3_ServerResp"] = t, m

        # 4. Client Finish (Ověření podpisu + Decapsulation)
        ss_c, t, m = _profile_call(tls_module.client_finish, ct, sig, pk_s, sk_c, pk_c, params, kem_id)
        if ss_c is None: return None
        metrics["t"]["4_ClientFinish"], metrics["m"]["4_ClientFinish"] = t, m

        # Kontrola shody sdíleného tajemství
        if ss_s != ss_c:
            print("! CHYBA: Neshoda sdílených tajemství!")
            return None

        return metrics

    except Exception as e:
        print(f"! Chyba při běhu handshake: {e}")
        return None


def main():
    print(f"=== TEST: MOJE PYTHON IMPLEMENTACE ({ROUNDS} kol) ===")
    results_time = []
    table_rows = []

    tracemalloc.start()

    for i, var_id in enumerate(VARIANTS):
        name = VARIANT_LABELS[i]
        print(f"Testuji variantu: {name} ...")

        times = []
        mems = []

        for r in range(ROUNDS):
            m = run_handshake(var_id, var_id)
            if m:
                # Celkový čas handshake (součet jednotlivých kroků)
                total_t = sum(m["t"].values())
                # Odhad paměti (max peak z kroků)
                max_m = max(m["m"].values())
                times.append(total_t)
                mems.append(max_m)

        if times:
            _, avg_t, _ = _stats(times)
            _, avg_m, _ = _stats(mems)
            results_time.append(avg_t)
            table_rows.append((name, f"{avg_t:.2f}", f"{avg_m:.2f}"))
        else:
            results_time.append(0)
            table_rows.append((name, "FAIL", "FAIL"))

    tracemalloc.stop()

    print("\n--- VÝSLEDKY MĚŘENÍ ---")
    _print_table(table_rows, ("Varianta", "Průměr Čas [ms]", "Paměť [KiB]"))

    # Uložení grafu
    if any(results_time):
        os.makedirs("graphs", exist_ok=True)
        plt.figure(figsize=(8, 5))
        plt.bar(VARIANT_LABELS, results_time, color="#4B9CD3")
        plt.title("PQC (Python) - Průměrný čas handshake")
        plt.ylabel("Čas [ms]")
        plt.yscale("log")  # Logaritmická osa pro lepší čitelnost u Pythonu
        plt.tight_layout()
        plt.savefig("graphs/pqc_python_time.png")
        print("\nGraf uložen: graphs/pqc_python_time.png")


if __name__ == "__main__":
    main()