"""
Simulace zjednodušeného TLS-like handshake pomocí
ML-KEM (Kyber) pro výměnu klíčů a ML-DSA (Dilithium) pro autentizaci.
"""

import os
from typing import Optional, Tuple

# Importujeme relativně v rámci balíčku 'tls'
from . import mldsa
from . import mlkem
from .mldsa_files.constants import get_params_by_id as get_mldsa_params

# --- Konfigurace ---
MLDSA_VARIANT_ID = 1  # ML-DSA-65 (pro podpis serveru)
MLKEM_VARIANT_ID = 1  # ML-KEM-768 (pro výměnu klíčů)

try:
    mldsa_params = get_mldsa_params(MLDSA_VARIANT_ID)
except ValueError as e:
    print(f"Chyba: Nepodařilo se načíst ML-DSA parametry: {e}")
    exit(1)

# --- Simulace ---
def simulate_pqc_handshake():
    # --- Setup (probíhá na pozadí, nevypisuje se jako krok handshake) ---
    server_keypair_dsa = mldsa.ML_DSA_KeyGen(mldsa_params)
    if server_keypair_dsa is None: return False # Chyba při generování klíčů
    pkS, skS = server_keypair_dsa
    # Předpokládáme, že klient zná pkS

    # --- Handshake ---

    # 1. Client Hello
    print("[Klient -> Server] Client Hello")

    # 2. Server Hello + Key Exchange + Certificate Verify
    print("[Server -> Klient] Server Hello")
    try:
        pkE, skE = mlkem.MLKEM_KeyGen(MLKEM_VARIANT_ID)
        data_to_sign = pkE
        context_dsa = b"TLS Handshake Signature Context"
        server_signature = mldsa.ML_DSA_Sign(skS, data_to_sign, context_dsa, mldsa_params)
        if server_signature is None: return False # Chyba podpisu
    except Exception:
        return False # Obecná chyba na straně serveru
    print("[Server -> Klient] Server Key Exchange (posílá pkE a podpis)")

    # 3. Client Key Exchange + Certificate Verify
    print("[Klient] Ověřuji podpis serveru...")
    try:
        is_signature_valid = mldsa.ML_DSA_Verify(pkS, data_to_sign, server_signature, context_dsa, mldsa_params)
        if not is_signature_valid:
            print("[Klient] Chyba: Podpis serveru je neplatný!")
            return False
        print("[Klient] Server ověřen.")
    except Exception:
         return False # Chyba ověření

    print("[Klient] Generuji sdílené tajemství a posílám ciphertext...")
    try:
        ss_client, ct = mlkem.MLKEM_Encaps(pkE, MLKEM_VARIANT_ID)
    except Exception:
        return False # Chyba zapouzdření

    print("[Klient -> Server] Client Key Exchange (posílá ct)")

    # 4. Server Decapsulation & Finished (Implicitní)
    print("[Server] Dekapsuluji sdílené tajemství...")
    try:
        ss_server = mlkem.MLKEM_Decaps(skE, ct, MLKEM_VARIANT_ID)
    except Exception:
        return False # Chyba dekapsulace

    # 5. Ověření shody tajemství (Výsledek handshake)
    if ss_client == ss_server:
        print("\n[Status] ÚSPĚCH: Sdílená tajemství se shodují!")
        return True
    else:
        print("\n[Status] CHYBA: Sdílená tajemství se neshodují!")
        return False


if __name__ == "__main__":
    success = simulate_pqc_handshake()
    if success:
        print("=== Handshake dokončen ===")
    else:
        print("=== Handshake selhal ===")