# tls_oqs_pqc_c.py
"""
Parametrizovaný TLS-like PQC handshake (verze s C knihovnou OQS).

Tento soubor replikuje API souboru `tls.py`, ale pro kryptografické
operace používá C-optimalizovanou knihovnu `oqs` místo
čisté Python implementace.
"""

import oqs
import sys
from typing import Optional, Dict, Any

# Importujeme parametry z ML-DSA pro zachování kompatibility API
# I když je OQS přímo nepoužívá, funkce je musí přijímat a vracet.
try:
    # Standardní import pro použití v rámci balíčku
    from .mldsa_files.constants import get_params_by_id as get_mldsa_params
except ImportError:
    # Záložní import pro přímé spuštění souboru
    try:
        from mldsa_files.constants import get_params_by_id as get_mldsa_params
    except ImportError:
        print("VAROVÁNÍ: Nelze importovat mldsa_files.constants. Používám placeholder.")
        get_mldsa_params = lambda x: {"name": f"ML-DSA-v{x}", "id": x}


# --- Názvy algoritmů v knihovně OQS ---
# Mapování ID variant (0, 1, 2) na názvy v OQS
ML_DSA_ALGS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
ML_KEM_ALGS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]

# Kontext je stejný jako v původním tls.py
CONTEXT_DSA = b"TLS Handshake Signature Context"

__all__ = [
    "setup_server_keys",
    "client_hello",
    "server_hello_and_key_exchange",
    "client_verify_and_key_exchange",
    "server_decapsulate",
    "run_handshake_simulation",
]


def setup_server_keys(mldsa_variant_id: int) -> Optional[Dict[str, Any]]:
    """
    Krok 0: Server generuje ML-DSA klíče pomocí OQS.
    Vrací slovník s klíči. 'skS' je objekt oqs.Signature.
    """
    try:
        # Načteme parametry jen pro zachování API
        mldsa_params = get_mldsa_params(mldsa_variant_id)
        alg_name = ML_DSA_ALGS[mldsa_variant_id]
    except (ValueError, IndexError):
        return None

    try:
        # Vytvoříme 'signer' objekt
        signer = oqs.Signature(alg_name)

        # Vygenerujeme klíče. pkS jsou bajty, skS zůstává uvnitř objektu.
        pkS = signer.generate_keypair()

        # Vrátíme objekt 'signer' pod klíčem 'skS' pro další použití
        return {"pkS": pkS, "skS": signer, "mldsa_params": mldsa_params}

    except (oqs.MechanismNotSupportedError, oqs.MechanismNotEnabledError, Exception):
        return None


def client_hello() -> bool:
    """Krok 1: Klient zahajuje komunikaci."""
    return True


def server_hello_and_key_exchange(
        skS: oqs.Signature,  # Přijímá objekt z kroku 0
        mlkem_variant_id: int,
        mldsa_params: Any
) -> Optional[Dict[str, Any]]:
    """
    Krok 2: Server generuje efemérní KEM klíče (OQS) a podepisuje je (OQS).
    Vrací 'skE' jako objekt oqs.KeyEncapsulation.
    """
    try:
        # Získáme název KEM algoritmu
        kem_alg = ML_KEM_ALGS[mlkem_variant_id]

        # Vytvoříme 'kem' objekt
        kem = oqs.KeyEncapsulation(kem_alg)

        # Vygenerujeme KEM klíče. pkE jsou bajty.
        pkE = kem.generate_keypair()

    except (oqs.MechanismNotSupportedError, oqs.MechanismNotEnabledError, Exception):
        return None

    # Připravíme data k podepsání (stejně jako v tls.py)
    # OQS 'sign' nemá parametr pro kontext, musíme ho přidat ručně
    data_to_sign_with_context = CONTEXT_DSA + pkE

    try:
        # Použijeme 'signer' objekt (skS) k podepsání
        signature = skS.sign(data_to_sign_with_context)
        if signature is None:
            return None
    except Exception:
        return None

    return {
        "skE": kem,  # Vracíme KEM objekt
        "pkE": pkE,
        "signature": signature,
        "data_to_sign": pkE  # Vracíme původní data (bez kontextu), stejně jako tls.py
    }


def client_verify_and_key_exchange(
        pkS: bytes,
        pkE: bytes,
        signature: bytes,
        data_to_verify: bytes,  # Toto je původní pkE
        mldsa_variant_id: int,
        mlkem_variant_id: int
) -> Optional[Dict[str, bytes]]:
    """
    Krok 3: Klient ověří podpis (OQS) a zapouzdří tajemství (OQS).
    """
    try:
        # Získáme názvy algoritmů z ID
        mldsa_alg = ML_DSA_ALGS[mldsa_variant_id]
        kem_alg = ML_KEM_ALGS[mlkem_variant_id]
    except IndexError:
        return None

    # Ověření podpisu
    try:
        # Vytvoříme nový 'verifier' objekt
        verifier = oqs.Signature(mldsa_alg)

        # Připravíme stejná data, jaká byla podepsána
        data_to_verify_with_context = CONTEXT_DSA + data_to_verify

        ok = verifier.verify(data_to_verify_with_context, signature, pkS)
        if not ok:
            print("CHYBA: Ověření podpisu selhalo!")
            return None
    except (oqs.MechanismNotSupportedError, oqs.MechanismNotEnabledError, Exception) as e:
        print(f"CHYBA při ověřování: {e}")
        return None

    # Zapouzdření
    try:
        # Vytvoříme nový 'kem' objekt
        kem = oqs.KeyEncapsulation(kem_alg)

        # OPRAVA: Správné pořadí návratových hodnot je (ciphertext, shared_secret)
        ct, ss_client = kem.encap_secret(pkE)
    except (oqs.MechanismNotSupportedError, oqs.MechanismNotEnabledError, Exception):
        return None

    return {"ss_client": ss_client, "ct": ct}


def server_decapsulate(skE: oqs.KeyEncapsulation, ct: bytes, mlkem_variant_id: int) -> Optional[Dict[str, bytes]]:
    """
    Krok 4: Server dekapsuluje tajemství pomocí OQS.
    """
    try:
        # Přímo použijeme 'kem' objekt (skE) z kroku 2
        ss_server = skE.decap_secret(ct)
    except Exception:
        return None

    return {"ss_server": ss_server}


def run_handshake_simulation(mldsa_variant_id: int, mlkem_variant_id: int) -> bool:
    """
    Spustí kompletní simulaci handshake s OQS.
    """
    server_keys = setup_server_keys(mldsa_variant_id)
    if not server_keys:
        return False
    client_known_pkS = server_keys["pkS"]
    mldsa_params = server_keys["mldsa_params"]

    if not client_hello():
        return False

    server_data = server_hello_and_key_exchange(server_keys["skS"], mlkem_variant_id, mldsa_params)
    if not server_data:
        return False

    client_data = client_verify_and_key_exchange(
        client_known_pkS,
        server_data["pkE"],
        server_data["signature"],
        server_data["data_to_sign"],
        mldsa_variant_id,
        mlkem_variant_id
    )
    if not client_data:
        return False

    server_final = server_decapsulate(server_data["skE"], client_data["ct"], mlkem_variant_id)
    if not server_final:
        return False

    return client_data["ss_client"] == server_final["ss_server"]

# --- DEBUG TESTOVACÍ SKRIPT ---
# Následující kód se spustí, pouze pokud je tento soubor spuštěn přímo.

def run_step_by_step_test(mldsa_variant_id: int, mlkem_variant_id: int):
    """Spustí detailní test jednotlivých kroků handshake."""
    print(f"\n--- Zahajuji podrobný test pro {ML_DSA_ALGS[mldsa_variant_id]} + {ML_KEM_ALGS[mlkem_variant_id]} ---")

    # --- Krok 0: Generování klíčů serveru ---
    print("Krok 0: setup_server_keys...")
    server_keys = setup_server_keys(mldsa_variant_id)
    if not server_keys:
        print("   -> SELHALO: Nepodařilo se vygenerovat klíče serveru.")
        return False
    print(f"   -> ÚSPĚCH. Vygenerován pkS (délka: {len(server_keys['pkS'])} B).")
    print(f"   -> Použité parametry: {server_keys['mldsa_params']}")

    # --- Krok 1: Client Hello ---
    print("Krok 1: client_hello...")
    if not client_hello():
        print("   -> SELHALO: Client hello selhalo.")
        return False
    print("   -> ÚSPĚCH.")

    # --- Krok 2: Server Hello a výměna klíčů ---
    print("Krok 2: server_hello_and_key_exchange...")
    server_data = server_hello_and_key_exchange(
        server_keys["skS"],
        mlkem_variant_id,
        server_keys["mldsa_params"]
    )
    if not server_data:
        print("   -> SELHALO: Server nedokázal vygenerovat a podepsat KEM klíče.")
        return False
    print(f"   -> ÚSPĚCH. Vygenerován pkE (délka: {len(server_data['pkE'])} B) a podpis (délka: {len(server_data['signature'])} B).")

    # --- Krok 3: Ověření a výměna klíčů na straně klienta ---
    print("Krok 3: client_verify_and_key_exchange...")
    client_data = client_verify_and_key_exchange(
        server_keys["pkS"],
        server_data["pkE"],
        server_data["signature"],
        server_data["data_to_sign"],
        mldsa_variant_id,
        mlkem_variant_id
    )
    if not client_data:
        print("   -> SELHALO: Klient nedokázal ověřit podpis nebo zapouzdřit tajemství.")
        return False
    print(f"   -> ÚSPĚCH. Ověření podpisu v pořádku. Vygenerován ciphertext (délka: {len(client_data['ct'])} B).")

    # --- Krok 4: Dekapsulace na straně serveru ---
    print("Krok 4: server_decapsulate...")
    server_final = server_decapsulate(
        server_data["skE"],
        client_data["ct"],
        mlkem_variant_id
    )
    if not server_final:
        print("   -> SELHALO: Server nedokázal dekapsulovat tajemství.")
        return False
    print("   -> ÚSPĚCH. Tajemství dekapsulováno.")

    # --- Finální kontrola ---
    print("Finální kontrola: Porovnání sdílených tajemství...")
    if client_data["ss_client"] == server_final["ss_server"]:
        print("   -> ÚSPĚCH! Tajemství se shodují.")
        return True
    else:
        print("   -> SELHALO! Tajemství se neshodují.")
        return False
