# test/test_oqs_pqc_handshake.py
import os
import time
import tracemalloc
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass

try:
    # Importujeme OQS knihovnu
    import oqs
    # Důležitý import podmodulu!
    from oqs import oqs as oqs_main
except ImportError:
    print("Chyba: Knihovna 'oqs' (liboqs-python) není nainstalována.")
    print("Spusťte: pip install oqs")
    raise SystemExit(1)

# Importujeme pomocné testovací funkce
from .test_utils import _time_call, _memory_call, _stats, _print_table

ROUNDS = 100  # Můžeš snížit/zvýšit počet kol
CONTEXT = b"TLS Handshake Signature Context"


# --- Definice variant OQS ---

@dataclass(frozen=True)
class OQSVariant:
    name: str
    kem_alg: str
    sig_alg: str
    kem: oqs_main.KeyEncapsulation  # Opraveno: oqs.oqs.KeyEncapsulation
    sig: oqs_main.Signature  # Opraveno: oqs.oqs.Signature


def get_oqs_variants() -> List[OQSVariant]:
    """Sestaví seznam podporovaných variant OQS pro testování."""
    # Mapování tvých ID na OQS jména
    # ML-KEM-512 (ID 0) -> Kyber512
    # ML-KEM-768 (ID 1) -> Kyber768
    # ML-KEM-1024 (ID 2) -> Kyber1024
    # ML-DSA-44 (ID 0, Cat 2) -> Dilithium2
    # ML-DSA-65 (ID 1, Cat 3) -> Dilithium3
    # ML-DSA-87 (ID 2, Cat 5) -> Dilithium5
    variants = [
        ("OQS (Kyber512 + Dilithium2)", "Kyber512", "Dilithium2"),
        ("OQS (Kyber768 + Dilithium3)", "Kyber768", "Dilithium3"),
        ("OQS (Kyber1024 + Dilithium5)", "Kyber1024", "Dilithium5"),
    ]

    supported_variants = []
    for name, kem_alg, sig_alg in variants:
        # Opravená cesta ke statickým metodám
        if oqs_main.KeyEncapsulation.is_kem_enabled(kem_alg) and oqs_main.Signature.is_sig_enabled(sig_alg):
            supported_variants.append(OQSVariant(
                name=name,
                kem_alg=kem_alg,
                sig_alg=sig_alg,
                kem=oqs_main.KeyEncapsulation(kem_alg),  # Opraveno
                sig=oqs_main.Signature(sig_alg)  # Opraveno
            ))
        else:
            print(f"Varování: Varianta {name} není podporována touto buildou liboqs. Přeskakuji.")

    return supported_variants


# --- Základní funkce handshake (používající OQS) ---

def gen_server_keys_oqs(sig: oqs_main.Signature) -> Dict[str, Any]:
    """Generuje dlouhodobý ML-DSA klíčový pár pomocí OQS."""
    pk_sig, sk_sig = sig.generate_keypair()
    return {"pk_sig": pk_sig, "sk_sig": sk_sig}


def server_hello_and_key_exchange_oqs(sk_sig: bytes, sig: oqs_main.Signature, kem: oqs_main.KeyEncapsulation) -> Dict[
    str, Any]:
    """Generuje efemérní ML-KEM klíče a podepíše je pomocí OQS."""
    pk_e, sk_e = kem.generate_keypair()

    data_to_sign = CONTEXT + pk_e
    signature = sig.sign(data_to_sign, sk_sig)

    return {"sk_e": sk_e, "pk_e_bytes": pk_e, "signature": signature, "data_to_sign": data_to_sign}


def client_verify_and_key_exchange_oqs(pk_sig: bytes, pk_e_bytes: bytes, signature: bytes, data_to_verify: bytes,
                                       sig: oqs_main.Signature, kem: oqs_main.KeyEncapsulation) -> Optional[
    Dict[str, Any]]:
    """Ověří podpis a zapouzdří tajemství pomocí OQS."""
    try:
        is_valid = sig.verify(data_to_verify, signature, pk_sig)
        if not is_valid:
            print(f"\nCHYBA: Ověření OQS podpisu selhalo!")
            return None
    except oqs.MechanismNotEnabledError:
        print(f"\nCHYBA: OQS algoritmus není povolen.")
        return None
    except Exception as e:
        print(f"\nCHYBA: OQS ověření selhalo: {e}")
        return None

    # Zapouzdření (Encaps)
    ct, ss_client = kem.encap_secret(pk_e_bytes)

    return {"ss_client": ss_client, "ct": ct}


def server_decapsulate_oqs(sk_e: bytes, ct: bytes, kem: oqs_main.KeyEncapsulation) -> bytes:
    """Dekapsuluje tajemství pomocí OQS."""
    return kem.decap_secret(sk_e, ct)


# --- Funkce pro profilování (upravená) ---

def run_oqs_handshake_profiled(variant: OQSVariant) -> Optional[Dict[str, Any]]:
    """
    Provede jeden OQS handshake a změří čas a paměť každé fáze.
    """
    timings = {}
    memory = {}

    sig = variant.sig
    kem = variant.kem

    # Krok 0: Setup
    server_keys_data, t = _time_call(gen_server_keys_oqs, sig)
    if server_keys_data is None: return None
    timings["1_Server_Sig_KeyGen"] = t
    _, m = _memory_call(gen_server_keys_oqs, sig)
    memory["1_Server_Sig_KeyGen"] = m

    client_known_pkS = server_keys_data["pk_sig"]

    # Krok 1: Client Hello
    _, t = _time_call(lambda: True)
    timings["2_Client_Hello"] = t
    _, m = _memory_call(lambda: True)
    memory["2_Client_Hello"] = m

    # Krok 2: Server Hello & KEM KeyGen & Sign
    server_data, t = _time_call(server_hello_and_key_exchange_oqs, server_keys_data["sk_sig"], sig, kem)
    if server_data is None: return None
    timings["3_Server_Hello_KEM_Sign"] = t
    _, m = _memory_call(server_hello_and_key_exchange_oqs, server_keys_data["sk_sig"], sig, kem)
    memory["3_Server_Hello_KEM_Sign"] = m

    # Krok 3: Client Sig Verify & KEM Encaps
    client_data, t = _time_call(
        client_verify_and_key_exchange_oqs,
        client_known_pkS,
        server_data["pk_e_bytes"],
        server_data["signature"],
        server_data["data_to_sign"],
        sig, kem
    )
    if client_data is None: return None
    timings["4_Client_Verify_KEM_Encaps"] = t
    _, m = _memory_call(
        client_verify_and_key_exchange_oqs,
        client_known_pkS,
        server_data["pk_e_bytes"],
        server_data["signature"],
        server_data["data_to_sign"],
        sig, kem
    )
    memory["4_Client_Verify_KEM_Encaps"] = m

    # Krok 4: Server KEM Decaps (Finish)
    server_final_data_ss, t = _time_call(
        server_decapsulate_oqs,
        server_data["sk_e"],
        client_data["ct"],
        kem
    )
    if server_final_data_ss is None: return None
    timings["5_Server_KEM_Decaps"] = t
    _, m = _memory_call(
        server_decapsulate_oqs,
        server_data["sk_e"],
        client_data["ct"],
        kem
    )
    memory["5_Server_KEM_Decaps"] = m

    # Kontrola
    if client_data["ss_client"] != server_final_data_ss:
        raise RuntimeError(f"OQS Handshake selhal pro {variant.name}: Tajemství se neshodují!")

    return {"timings": timings, "memory": memory}


# --- Hlavní funkce (main) ---

def main():
    print(f"=== Spouštím OQS Handshake Benchmark ===")
    try:
        # Opravená cesta k verzi
        print(f"OQS Verze: {oqs_main.OQS_VERSION}")
    except Exception:
        print("OQS Verze: Není k dispozici")
    print(f"Počet kol pro každou variantu: {ROUNDS}\n")

    variants_to_test = get_oqs_variants()
    if not variants_to_test:
        print("Žádné z definovaných OQS variant nejsou v této buildě liboqs povoleny. Test končí.")
        return

    all_timings_stats = []
    all_memory_stats = []

    headers_time = ("Varianta", "Celkem [ms]", "1_KeyGen [ms]", "3_Srv_KEX+Sign [ms]", "4_Clnt_Vrfy+KEX [ms]",
                    "5_Srv_Decaps [ms]")
    headers_mem = ("Varianta", "Celkem [KiB]", "1_KeyGen [KiB]", "3_Srv_KEX+Sign [KiB]", "4_Clnt_Vrfy+KEX [KiB]",
                   "5_Srv_Decaps [KiB]")

    for variant in variants_to_test:
        print(f"--- Testuji variantu: {variant.name} ---")

        timings_per_step = {
            "1_Server_Sig_KeyGen": [],
            "2_Client_Hello": [],
            "3_Server_Hello_KEM_Sign": [],
            "4_Client_Verify_KEM_Encaps": [],
            "5_Server_KEM_Decaps": [],
            "TOTAL_HANDSHAKE": []
        }
        memory_per_step = {k: [] for k in timings_per_step}

        ok = 0
        tracemalloc.start()
        for i in range(ROUNDS):
            print(f"  Spouštím kolo {i + 1}/{ROUNDS}...", end="\r")

            start_total_time = time.perf_counter()
            tracemalloc.clear_traces()

            result = run_oqs_handshake_profiled(variant)

            total_time_ms = (time.perf_counter() - start_total_time) * 1000.0
            _, total_peak_mem_kib = tracemalloc.get_traced_memory()

            if result is None:
                print(f"\n  Chyba v kole {i + 1}, přeskakuji.")
                continue

            ok += 1
            timings_per_step["TOTAL_HANDSHAKE"].append(total_time_ms)
            memory_per_step["TOTAL_HANDSHAKE"].append(total_peak_mem_kib)

            for key, t_val in result["timings"].items():
                timings_per_step[key].append(t_val)
            for key, m_val in result["memory"].items():
                memory_per_step[key].append(m_val)

        tracemalloc.stop()
        print(f"\n  Dokončeno. Úspěšných kol: {ok}/{ROUNDS}")

        if ok > 0:
            # Zpracování statistik pro tabulky
            t_min, t_avg_total, t_max = _stats(timings_per_step["TOTAL_HANDSHAKE"])
            _, t_avg_kgen, _ = _stats(timings_per_step["1_Server_Sig_KeyGen"])
            _, t_avg_srv_kex, _ = _stats(timings_per_step["3_Server_Hello_KEM_Sign"])
            _, t_avg_clnt_kex, _ = _stats(timings_per_step["4_Client_Verify_KEM_Encaps"])
            _, t_avg_srv_fin, _ = _stats(timings_per_step["5_Server_KEM_Decaps"])

            all_timings_stats.append((
                variant.name,
                f"{t_avg_total:.3f}",
                f"{t_avg_kgen:.3f}",
                f"{t_avg_srv_kex:.3f}",
                f"{t_avg_clnt_kex:.3f}",
                f"{t_avg_srv_fin:.3f}"
            ))

            m_min, m_avg_total, m_max = _stats(memory_per_step["TOTAL_HANDSHAKE"])
            _, m_avg_kgen, _ = _stats(memory_per_step["1_Server_Sig_KeyGen"])
            _, m_avg_srv_kex, _ = _stats(memory_per_step["3_Server_Hello_KEM_Sign"])
            _, m_avg_clnt_kex, _ = _stats(memory_per_step["4_Client_Verify_KEM_Encaps"])
            _, m_avg_srv_fin, _ = _stats(memory_per_step["5_Server_KEM_Decaps"])

            all_memory_stats.append((
                variant.name,
                f"{m_avg_total:.2f}",
                f"{m_avg_kgen:.2f}",
                f"{m_avg_srv_kex:.2f}",
                f"{m_avg_clnt_kex:.2f}",
                f"{m_avg_srv_fin:.2f}"
            ))

    # Finální výpis tabulek
    print("\n--- Měření Průměrného Času (OQS) ---")
    _print_table(all_timings_stats, headers_time)

    print("\n--- Měření Průměrné Špičkové Paměti (OQS) ---")
    _print_table(all_memory_stats, headers_mem)


if __name__ == "__main__":
    main()