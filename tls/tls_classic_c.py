# tls_classic_c.py
"""
Simulace TLS 1.3 handshake s klasickou kryptografií (ECDH + ECDSA/Ed25519).
Struktura kódu je identická s PQC variantami pro možnost přímého srovnání.
"""

import os
from typing import Any, Dict, Optional, Tuple

# Pokus o import klasické knihovny
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
except ImportError:
    print("CHYBA: Knihovna `cryptography` není nainstalována (pip install cryptography).")
    exit(1)

# Kontext pro podpis (bezpečnostní konstanta)
CONTEXT = b"TLS 1.3 Handshake"


# --- MAPOVÁNÍ VARIANT NA ALGORITMY ---
class ClassicParams:
    def __init__(self, name, sig_alg_builder, hash_alg):
        self.name = name
        self.sig_alg_builder = sig_alg_builder
        self.hash_alg = hash_alg


CLASSIC_VARIANTS = {
    0: ClassicParams("ECDSA-P256", lambda: ec.generate_private_key(ec.SECP256R1()), hashes.SHA256()),
    1: ClassicParams("ECDSA-P384", lambda: ec.generate_private_key(ec.SECP384R1()), hashes.SHA384()),
    2: ClassicParams("Ed25519", lambda: ed25519.Ed25519PrivateKey.generate(), None)
}


def get_classic_params(variant_id):
    return CLASSIC_VARIANTS.get(variant_id, CLASSIC_VARIANTS[0])


# --- KROK 0: PŘÍPRAVA SERVERU ---
def setup_server_identity(dsa_variant):
    """
    Server si generuje dlouhodobý pár klíčů (ECDSA/Ed25519).
    """
    params = get_classic_params(dsa_variant)

    # Generování klíče
    sk_server = params.sig_alg_builder()
    pk_server = sk_server.public_key()

    # Serializace veřejného klíče na bytes (aby byl kompatibilní s API)
    if params.name == "Ed25519":
        pk_bytes = pk_server.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    else:
        pk_bytes = pk_server.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    return pk_bytes, sk_server, params


# --- KROK 1: KLIENT (Client Hello) ---
def client_hello(kem_variant):
    """
    Klient začíná. Generuje efemérní klíče (X25519) pro ECDH.
    """
    # 1. Vygenerujeme dočasný pár klíčů pro X25519 (ECDH)
    sk_client = x25519.X25519PrivateKey.generate()
    pk_client = sk_client.public_key()

    # Serializace na bytes
    pk_client_bytes = pk_client.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    # 2. Nastavíme parametry
    client_info = {
        "verze": "TLS 1.3 (Classic)",
        "sifra": "AES-256-GCM"
    }

    return pk_client_bytes, sk_client, client_info


# --- KROK 2: SERVER (Server Hello) ---
def server_response(pk_client_bytes, client_info, sk_server_dsa, dsa_params, kem_variant):
    """
    Server provede ECDH (Encapsulation analogie) a podepíše to.
    """
    # 1. Encaps (ECDH): Server vygeneruje svůj efemérní klíč a dopočítá tajemství
    sk_server_ephemeral = x25519.X25519PrivateKey.generate()
    pk_server_ephemeral = sk_server_ephemeral.public_key()

    # Rekonstrukce klientova veřejného klíče z bytes
    pk_client_obj = x25519.X25519PublicKey.from_public_bytes(pk_client_bytes)

    # Výpočet sdíleného tajemství (Shared Secret)
    ss_server = sk_server_ephemeral.exchange(pk_client_obj)

    # "Ciphertext" je v ECDH veřejný klíč serveru
    ct = pk_server_ephemeral.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    # 2. Sign: Server podepíše (klientův klíč + svůj klíč/ct)
    data_to_sign = pk_client_bytes + ct

    # Podpisová logika podle typu klíče
    if dsa_params.name == "Ed25519":
        # Ed25519 nemá hash algoritmus (je zabudovaný) a používá kontext jen v některých verzích (zde zjednodušeno připojíme)
        signature = sk_server_dsa.sign(CONTEXT + data_to_sign)
    else:
        # ECDSA
        signature = sk_server_dsa.sign(
            CONTEXT + data_to_sign,
            ec.ECDSA(dsa_params.hash_alg)
        )

    return ct, signature, ss_server


# --- KROK 3: KLIENT (Finish) ---
def client_finish(ct, signature, pk_server_dsa_bytes, sk_client_kem, pk_client_original_bytes, dsa_params, kem_variant):
    """
    Klient ověří podpis a dokončí ECDH.
    """
    # 1. Ověření podpisu
    data_to_verify = pk_client_original_bytes + ct

    # Deserializace serverova identitního klíče
    if dsa_params.name == "Ed25519":
        pk_server_obj = ed25519.Ed25519PublicKey.from_public_bytes(pk_server_dsa_bytes)
        try:
            pk_server_obj.verify(signature, CONTEXT + data_to_verify)
            is_valid = True
        except Exception:
            is_valid = False
    else:
        try:
            pk_server_obj = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1() if "P256" in dsa_params.name else ec.SECP384R1(),
                pk_server_dsa_bytes
            )
            pk_server_obj.verify(signature, CONTEXT + data_to_verify, ec.ECDSA(dsa_params.hash_alg))
            is_valid = True
        except Exception:
            is_valid = False

    if not is_valid:
        # print("CHYBA: Podpis serveru je neplatný! Někdo se za něj vydává.")
        return None

    # 2. Decaps (ECDH): Klient použije serverův veřejný klíč (ct) k dopočtu tajemství
    pk_server_ephemeral_obj = x25519.X25519PublicKey.from_public_bytes(ct)
    ss_client = sk_client_kem.exchange(pk_server_ephemeral_obj)

    return ss_client