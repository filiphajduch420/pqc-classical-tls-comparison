# tls_oqs_pqc_c.py
"""
Simulace TLS 1.3 handshake s PQC knihovnou OQS (liboqs).
Struktura kódu je identická s pure-Python implementací.
"""

import oqs
import os

# Kontext pro podpis (bezpečnostní konstanta)
CONTEXT = b"TLS 1.3 Handshake"

# --- MAPOVÁNÍ VARIANT NA ALGORITMY OQS ---
OQS_DSA_ALGS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
OQS_KEM_ALGS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]


def get_oqs_alg_name(variant_id, is_sig=True):
    try:
        return OQS_DSA_ALGS[variant_id] if is_sig else OQS_KEM_ALGS[variant_id]
    except IndexError:
        return OQS_DSA_ALGS[0] if is_sig else OQS_KEM_ALGS[0]


# --- KROK 0: PŘÍPRAVA SERVERU ---
def setup_server_identity(dsa_variant):
    """
    Server si generuje dlouhodobý pár klíčů (ML-DSA z liboqs).
    """
    alg_name = get_oqs_alg_name(dsa_variant, is_sig=True)

    # OQS Signer objekt
    signer = oqs.Signature(alg_name)
    pk_server = signer.generate_keypair()

    # U OQS si musíme nechat 'signer' objekt jako privátní klíč
    return pk_server, signer, alg_name


# --- KROK 1: KLIENT (Client Hello) ---
def client_hello(kem_variant):
    """
    Klient začíná. Generuje ML-KEM klíče.
    """
    alg_name = get_oqs_alg_name(kem_variant, is_sig=False)

    # 1. Vygenerujeme dočasný pár klíčů pro ML-KEM
    # OQS KEM objekt - client side
    client_kem = oqs.KeyEncapsulation(alg_name)
    pk_client = client_kem.generate_keypair()

    # 2. Nastavíme parametry
    client_info = {
        "verze": "TLS 1.3 (OQS C)",
        "sifra": "AES-256-GCM"
    }

    # Jako sk_client vracíme celý objekt, který drží stav
    return pk_client, client_kem, client_info


# --- KROK 2: SERVER (Server Hello) ---
def server_response(pk_client, client_info, sk_server_dsa, dsa_params, kem_variant):
    """
    Server přijme klíč klienta, zapouzdří a podepíše.
    """
    alg_name = get_oqs_alg_name(kem_variant, is_sig=False)

    # 1. Encaps: Server použije klientův klíč
    server_kem = oqs.KeyEncapsulation(alg_name)

    # OQS vrací (ciphertext, shared_secret)
    ct, ss_server = server_kem.encap_secret(pk_client)

    # 2. Sign: Server podepíše data
    data_to_sign = pk_client + ct

    # sk_server_dsa je instance oqs.Signature
    # OQS sign nebere kontext přímo v API pro ML-DSA, spojíme ho ručně
    signature = sk_server_dsa.sign(CONTEXT + data_to_sign)

    return ct, signature, ss_server


# --- KROK 3: KLIENT (Finish) ---
def client_finish(ct, signature, pk_server_dsa, sk_client_kem, pk_client_original, dsa_params, kem_variant):
    """
    Klient ověří podpis serveru a rozbalí tajemství.
    """
    # 1. Ověření podpisu (Verify)
    data_to_verify = pk_client_original + ct

    # Pro ověření musíme vytvořit novou instanci signeru (nebo použít statickou metodu, pokud by byla)
    verifier = oqs.Signature(dsa_params)  # dsa_params zde drží jméno algoritmu

    is_signature_valid = verifier.verify(CONTEXT + data_to_verify, signature, pk_server_dsa)

    if not is_signature_valid:
        # print("CHYBA: Podpis serveru je neplatný! Někdo se za něj vydává.")
        return None

    # 2. Decaps: Rozbalíme tajemství
    # sk_client_kem je instance oqs.KeyEncapsulation s privátním klíčem uvnitř
    ss_client = sk_client_kem.decap_secret(ct)

    return ss_client