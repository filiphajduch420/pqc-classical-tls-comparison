# tls/tls.py
"""
Parametrizovaný TLS-like PQC handshake využívající
ML-KEM (Kyber) pro výměnu klíčů a ML-DSA (Dilithium) pro autentizaci.
"""

from typing import Optional, Dict, Any

from . import mldsa
from . import mlkem
from .mldsa_files.constants import get_params_by_id as get_mldsa_params

# Kontext pro podpis (bezpečnostní konstanta)
CONTEXT = b"TLS 1.3 Handshake"


# --- KROK 0: PŘÍPRAVA SERVERU ---
def setup_server_identity(dsa_variant):
    """
    Krok 0: Server si generuje dlouhodobý pár klíčů (ML-DSA).
    """
    params = get_mldsa_params(dsa_variant)
    pk_server, sk_server = mldsa.ML_DSA_KeyGen(params)
    return pk_server, sk_server, params


# --- KROK 1: KLIENT (Client Hello) ---
def client_hello(kem_variant):
    """
    Krok 1: Klient začíná. Posílá svůj klíč (Key Share) a info o šifře.
    """
    pk_client, sk_client = mlkem.MLKEM_KeyGen(kem_variant)

    client_info = {
        "verze": "TLS 1.3 (PQC)",
        "sifra": "AES-256-GCM"
    }

    return pk_client, sk_client, client_info


# --- KROK 2: SERVER (Server Hello) ---
def server_response(pk_client, client_info, sk_server_dsa, dsa_params, kem_variant):
    """
    Krok 2: Server zapouzdří tajemství (KEM) a podepíše transkript (DSA).
    """
    # 1. Encaps: Server použije klientův klíč a vyrobí sdílené tajemství + ciphertext
    ss_server, ct = mlkem.MLKEM_Encaps(pk_client, kem_variant)

    # 2. Sign: Server podepíše data (klientův klíč + ciphertext)
    # Tím svazuje identitu serveru s touto konkrétní výměnou klíčů.
    data_to_sign = pk_client + ct
    signature = mldsa.ML_DSA_Sign(sk_server_dsa, data_to_sign, CONTEXT, dsa_params)

    return ct, signature, ss_server


# --- KROK 3: KLIENT (Finish) ---
def client_finish(ct, signature, pk_server_dsa, sk_client_kem, pk_client_original, dsa_params, kem_variant):
    """
    Krok 3: Klient ověří podpis serveru a pokud je OK, rozbalí si tajemství.
    """
    # 1. Příprava dat pro ověření (musí být shodná s daty, co server podepsal)
    data_to_verify = pk_client_original + ct

    # 2. Ověření podpisu (Verify)
    is_valid = mldsa.ML_DSA_Verify(pk_server_dsa, data_to_verify, signature, CONTEXT, dsa_params)

    if not is_valid:
        print(f"!!! CHYBA v client_finish: Podpis serveru je neplatný (Variant {dsa_params.name}) !!!")

        # --- DEBUG INTROSPEKCE ---
        # Pokud ověření selže, zavoláme introspekci, abychom zjistili proč.
        try:
            debug_info = mldsa.ML_DSA_Verify_Introspect(pk_server_dsa, data_to_verify, signature, CONTEXT, dsa_params)
            print("    DEBUG INFO z Verify:")
            print(f"    - Shoda hashe (c_tilde): {debug_info.get('c_match')}")
            print(f"    - Max norma vektoru z:   {debug_info.get('z_norm_max')} (Limit: {debug_info.get('z_bound')})")
            print(f"    - Očekávaná délka Sig:   {debug_info.get('sig_len_expected')}")
            print(f"    - Skutečná délka Sig:    {debug_info.get('sig_len_actual')}")
        except Exception as e:
            print(f"    (Nepodařilo se získat debug info: {e})")

        return None

    # 3. Decaps: Rozbalíme si tajemství
    try:
        ss_client = mlkem.MLKEM_Decaps(sk_client_kem, ct, kem_variant)
    except ValueError as e:
        print(f"!!! CHYBA v client_finish: Selhalo KEM Decapsulation: {e}")
        return None

    return ss_client