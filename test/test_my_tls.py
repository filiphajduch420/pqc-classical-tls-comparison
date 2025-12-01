# test/test_my_tls.py
"""
Benchmark pro TVOU vlastní implementaci v čistém Pythonu (tls/tls.py).
"""
import time
import tracemalloc
import os
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, Optional, Tuple, Any

from tls import tls as tls_module
from .test_utils import _stats

ROUNDS = 100
VARIANTS = [
    {"id": 0, "name": "ML-DSA-44 + ML-KEM-512"},
    {"id": 1, "name": "ML-DSA-65 + ML-KEM-768"},
    {"id": 2, "name": "ML-DSA-87 + ML-KEM-1024"}
]


def _profile_call(func, *args, **kwargs) -> Tuple[Any, float, float]:
    """Změří čas (ms) a paměť (KiB) volání funkce."""
    tracemalloc.clear_traces()
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    _, peak_bytes = tracemalloc.get_traced_memory()
    return result, (end - start) * 1000.0, peak_bytes / 1024.0


def run_handshake(var_id: int) -> Optional[Dict[str, float]]:
    """Provede jeden kompletní handshake a vrátí detailní metriky."""
    try:
        step_times = {}
        step_mems = {}

        # 1. Server Identity
        res, t, m = _profile_call(tls_module.setup_server_identity, var_id)
        if res is None: return None
        pk_s, sk_s, params = res
        step_times["Server Identity"] = t
        step_mems["Server Identity"] = m

        # 2. Client Hello
        res, t, m = _profile_call(tls_module.client_hello, var_id)
        if res is None: return None
        pk_c, sk_c, info = res
        step_times["Client Hello"] = t
        step_mems["Client Hello"] = m

        # 3. Server Response
        res, t, m = _profile_call(tls_module.server_response, pk_c, info, sk_s, params, var_id)
        if res is None: return None
        ct, sig, ss_s = res
        step_times["Server Response"] = t
        step_mems["Server Response"] = m

        # 4. Client Finish
        ss_c, t, m = _profile_call(tls_module.client_finish, ct, sig, pk_s, sk_c, pk_c, params, var_id)
        if ss_c is None: return None
        step_times["Client Finish"] = t
        step_mems["Client Finish"] = m

        if ss_s != ss_c:
            return None

        return {
            "time": sum(step_times.values()),
            "memory": max(step_mems.values()),
            "steps_time": step_times,
            "steps_mem": step_mems
        }

    except Exception:
        return None


def plot_results(results):
    """Vykreslí grafy pro čas a paměť."""
    variant_names = [v["name"] for v in VARIANTS]
    os.makedirs("graphs", exist_ok=True)

    # Graf času
    times = [results[v["name"]]["time"] for v in VARIANTS]

    plt.figure(figsize=(10, 6))
    bars = plt.bar(variant_names, times, color='#4B9CD3')
    plt.title('PQC Python - Celkový čas handshake')
    plt.ylabel('Čas [ms]')
    plt.yscale('log')
    plt.grid(axis='y', linestyle='--', alpha=0.5)
    plt.bar_label(bars, padding=3, fmt='%.2f', fontsize=9)
    plt.tight_layout()
    plt.savefig("graphs/tls_python_time.png", dpi=150)
    plt.close()
    print("Graf času uložen: graphs/tls_python_time.png")

    # Graf paměti
    mems = [results[v["name"]]["memory"] for v in VARIANTS]

    plt.figure(figsize=(10, 6))
    bars = plt.bar(variant_names, mems, color='#4B9CD3')
    plt.title('PQC Python - Špičková paměť handshake')
    plt.ylabel('Paměť [KiB]')
    plt.grid(axis='y', linestyle='--', alpha=0.5)
    plt.bar_label(bars, padding=3, fmt='%.2f', fontsize=9)
    plt.tight_layout()
    plt.savefig("graphs/tls_python_memory.png", dpi=150)
    plt.close()
    print("Graf paměti uložen: graphs/tls_python_memory.png")


def main():
    print(f"=== BENCHMARK TLS: Python implementace ({ROUNDS} kol) ===")
    all_results = {}

    tracemalloc.start()

    for var in VARIANTS:
        v_name = var["name"]
        v_id = var["id"]
        print(f"\nTestuji variantu: {v_name}")

        times = []
        mems = []
        step_times_list = {step: [] for step in ["Server Identity", "Client Hello", "Server Response", "Client Finish"]}
        step_mems_list = {step: [] for step in ["Server Identity", "Client Hello", "Server Response", "Client Finish"]}

        for _ in range(ROUNDS):
            result = run_handshake(v_id)
            if result:
                times.append(result["time"])
                mems.append(result["memory"])
                for step, t in result["steps_time"].items():
                    step_times_list[step].append(t)
                for step, m in result["steps_mem"].items():
                    step_mems_list[step].append(m)

        if times:
            _, avg_time, _ = _stats(times)
            _, avg_mem, _ = _stats(mems)

            avg_step_times = {step: sum(vals)/len(vals) for step, vals in step_times_list.items()}
            avg_step_mems = {step: sum(vals)/len(vals) for step, vals in step_mems_list.items()}

            all_results[v_name] = {
                "time": avg_time,
                "memory": avg_mem
            }

            # Tabulka s rozpisem
            print(f"{'Krok':<20} | {'Čas [ms]':<15} | {'Paměť [KiB]':<15}")
            print("-" * 55)
            for step in ["Server Identity", "Client Hello", "Server Response", "Client Finish"]:
                print(f"{step:<20} | {avg_step_times[step]:<15.2f} | {avg_step_mems[step]:<15.2f}")
            print("-" * 55)
            print(f"{'CELKEM':<20} | {avg_time:<15.2f} | {avg_mem:<15.2f}")
        else:
            print(f"  SELHALO")

    tracemalloc.stop()

    if all_results:
        plot_results(all_results)


if __name__ == "__main__":
    main()
