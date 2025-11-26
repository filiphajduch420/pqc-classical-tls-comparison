import time
import tracemalloc
import os
import matplotlib.pyplot as plt
import numpy as np
import oqs
from typing import List, Tuple

# Import mé implementace
from tls import mlkem
from tls.mlkem_files.constants import get_params_by_id

# Nastavení počtu opakování
ROUNDS_PYTHON = 10  # Python je pomalý
ROUNDS_OQS = 1000  # C je rychlé, potřebujeme více vzorků pro přesnost

# Definice variant k testování
VARIANTS = [
    {"id": 0, "name": "ML-KEM-512", "oqs_name": "ML-KEM-512"},
    {"id": 1, "name": "ML-KEM-768", "oqs_name": "ML-KEM-768"},
    {"id": 2, "name": "ML-KEM-1024", "oqs_name": "ML-KEM-1024"},
]


def measure_python_kem(variant_id, rounds):
    """Změří průměrné časy pro mou Python implementaci."""
    times = {"KeyGen": [], "Encaps": [], "Decaps": []}

    print(f"  -> Měřím Python (ID {variant_id}, {rounds} kol)...")

    for _ in range(rounds):
        # 1. KeyGen
        t0 = time.perf_counter()
        pk, sk = mlkem.MLKEM_KeyGen(variant_id)
        times["KeyGen"].append((time.perf_counter() - t0) * 1000)

        # 2. Encaps
        t0 = time.perf_counter()
        ss_c, ct = mlkem.MLKEM_Encaps(pk, variant_id)
        times["Encaps"].append((time.perf_counter() - t0) * 1000)

        # 3. Decaps
        t0 = time.perf_counter()
        ss_s = mlkem.MLKEM_Decaps(sk, ct, variant_id)
        times["Decaps"].append((time.perf_counter() - t0) * 1000)

    return {k: sum(v) / len(v) for k, v in times.items()}


def measure_oqs_kem(oqs_name, rounds):
    """Změří průměrné časy pro OQS (C) implementaci."""
    times = {"KeyGen": [], "Encaps": [], "Decaps": []}

    print(f"  -> Měřím OQS ({oqs_name}, {rounds} kol)...")

    # Vytvoření objektu pro testování
    kem = oqs.KeyEncapsulation(oqs_name)

    for _ in range(rounds):
        # 1. KeyGen
        t0 = time.perf_counter()
        pk = kem.generate_keypair()
        times["KeyGen"].append((time.perf_counter() - t0) * 1000)

        # 2. Encaps
        t0 = time.perf_counter()
        ct, ss_c = kem.encap_secret(pk)
        times["Encaps"].append((time.perf_counter() - t0) * 1000)

        # 3. Decaps
        t0 = time.perf_counter()
        ss_s = kem.decap_secret(ct)
        times["Decaps"].append((time.perf_counter() - t0) * 1000)

    return {k: sum(v) / len(v) for k, v in times.items()}


def plot_comparison(results):
    """Vykreslí a uloží SAMOSTATNÝ graf pro každou operaci."""
    ops = ["KeyGen", "Encaps", "Decaps"]
    variant_names = [v["name"] for v in VARIANTS]

    os.makedirs("graphs", exist_ok=True)

    # Projdeme každou operaci a uděláme jí vlastní graf
    for op in ops:
        py_vals = []
        oqs_vals = []

        # Sběr dat pro danou operaci napříč variantami
        for v in VARIANTS:
            name = v["name"]
            py_vals.append(results[name]["Python"][op])
            oqs_vals.append(results[name]["OQS"][op])

        # Vytvoření grafu
        plt.figure(figsize=(10, 6))

        x = np.arange(len(variant_names))
        width = 0.35

        bars1 = plt.bar(x - width / 2, py_vals, width, label='Python (Moje)', color='#4B9CD3')
        bars2 = plt.bar(x + width / 2, oqs_vals, width, label='OQS (C)', color='#FFB347')

        plt.title(f'ML-KEM: {op} - Porovnání času (Logaritmická osa)')
        plt.ylabel('Čas [ms]')
        plt.xticks(x, variant_names)
        plt.yscale('log')  # Logaritmická osa je nutná kvůli rozdílu řádů
        plt.legend()
        plt.grid(axis='y', linestyle='--', alpha=0.5)

        # Popisky hodnot nad sloupci
        plt.bar_label(bars1, padding=3, fmt='%.2f', fontsize=9)
        plt.bar_label(bars2, padding=3, fmt='%.3f', fontsize=9)

        plt.tight_layout()

        # Uložení
        filename = f"graphs/kem_{op.lower()}.png"
        plt.savefig(filename, dpi=150)
        plt.close()  # Zavřít figuru, aby se uvolnila paměť
        print(f"Graf uložen: {filename}")


def main():
    print("=== BENCHMARK ML-KEM: Python vs OQS ===")
    all_results = {}

    for var in VARIANTS:
        v_name = var["name"]
        print(f"\nTestuji variantu: {v_name}")

        res_py = measure_python_kem(var["id"], ROUNDS_PYTHON)
        res_oqs = measure_oqs_kem(var["oqs_name"], ROUNDS_OQS)

        all_results[v_name] = {
            "Python": res_py,
            "OQS": res_oqs
        }

        # Textový výpis pro kontrolu
        print(f"{'Operace':<10} | {'Python [ms]':<15} | {'OQS [ms]':<15} | {'Zrychlení (x)':<10}")
        print("-" * 60)
        for op in ["KeyGen", "Encaps", "Decaps"]:
            t_py = res_py[op]
            t_oqs = res_oqs[op]
            speedup = t_py / t_oqs if t_oqs > 0 else 0
            print(f"{op:<10} | {t_py:<15.3f} | {t_oqs:<15.4f} | {speedup:<10.1f}")

    plot_comparison(all_results)


if __name__ == "__main__":
    main()