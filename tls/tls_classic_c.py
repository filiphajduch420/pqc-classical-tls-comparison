# tls_classic_c.py
"""
Parametrizovaný TLS-like handshake (klasická krypto, OpenSSL přes `cryptography`).

Tato verze replikuje API souboru `tls.py`, ale místo RSA-KEM používá
TLS 1.3 styl: ECDHE-X25519 (Forward Secrecy) pro dohodu klíče
a ECDSA/Ed25519 pro autentizaci serveru.

Pozn.: Aby zůstalo API stejné jako u KEM variant, pole `ct` nese
klientův ECDHE veřejný klíč (raw 32 B), který server použije
k dopočtu sdíleného tajemství.
"""

import os
from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, x25519
except ImportError:
    print("CHYBA: Knihovna `cryptography` není nainstalována.")
    print("Nainstalujte ji pomocí: pip install cryptography")
    raise SystemExit(1)

# Importujeme "dummy" funkci, abychom zachovali API kompatibilitu s testy
try:
    from .mldsa_files.constants import get_params_by_id as _get_dummy_pqc_params
except ImportError:
    _get_dummy_pqc_params = lambda x: {"id": x, "name": "dummy"}

CONTEXT_DSA = b"TLS Handshake Signature Context"


# --- Definice klasických podpisových algoritmů ---

@dataclass(frozen=True)
class ClassicSigParams:
    """Datová třída pro uložení parametrů klasického podpisu."""
    id: int
    name: str
    key_gen_func: Callable
    # Následující pole jsou specifická pro `cryptography` API
    hash_alg: Optional[hashes.HashAlgorithm]
    padding_alg: Optional[Any]
    sign_hash_alg: Optional[hashes.HashAlgorithm]  # Pro RSA-PSS (pokud bys doplnil)


# Mapování ID variant (0, 1, 2) na klasické podpisy
CLASSICAL_SIG_PARAMS = [
    # Varianta 0 -> ECDSA-P256
    ClassicSigParams(
        id=0, name="ECDSA-P256",
        key_gen_func=lambda: ec.generate_private_key(ec.SECP256R1()),
        hash_alg=hashes.SHA256(),
        padding_alg=ec.ECDSA(hashes.SHA256()),
        sign_hash_alg=None
    ),
    # Varianta 1 -> ECDSA-P384
    ClassicSigParams(
        id=1, name="ECDSA-P384",
        key_gen_func=lambda: ec.generate_private_key(ec.SECP384R1()),
        hash_alg=hashes.SHA384(),
        padding_alg=ec.ECDSA(hashes.SHA384()),
        sign_hash_alg=None
    ),
    # Varianta 2 -> Ed25519
    ClassicSigParams(
        id=2, name="Ed25519",
        key_gen_func=lambda: ed25519.Ed25519PrivateKey.generate(),
        hash_alg=None,
        padding_alg=None,
        sign_hash_alg=None
    )
]

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
    Krok 0: Server generuje dlouhodobé podpisové klíče (ECDSA/Ed25519).
    Vrací slovník s 'pkS' (bytes), 'skS' (privátní klíč objekt) a 'mldsa_params'.
    """
    try:
        sig_params = CLASSICAL_SIG_PARAMS[mldsa_variant_id]
    except IndexError:
        return None

    try:
        skS = sig_params.key_gen_func()
        pkS = skS.public_key()

        # Serializujeme pkS na bajty pro přenos
        if sig_params.name.startswith("ECDSA"):
            pkS_bytes = pkS.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint
            )
        elif sig_params.name == "Ed25519":
            pkS_bytes = pkS.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw
            )
        else:  # pro případ, že bys doplnil např. RSA-PSS
            pkS_bytes = pkS.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )

        return {"pkS": pkS_bytes, "skS": skS, "mldsa_params": sig_params}

    except Exception:
        return None


def client_hello() -> bool:
    """Krok 1: Klient zahajuje komunikaci."""
    return True


def server_hello_and_key_exchange(
        skS: Any,  # podpisový privátní klíč z kroku 0
        mlkem_variant_id: int,  # ignorováno; ECDHE-X25519 nemá varianty
        mldsa_params: ClassicSigParams
) -> Optional[Dict[str, Any]]:
    """
    Krok 2: Server vygeneruje EFEMÉRNÍ ECDHE-X25519 klíče a podepíše public key.
    Vrací:
      - 'skE': objekt x25519.X25519PrivateKey (serverův ephemeral privátní klíč)
      - 'pkE': raw 32B serverova veřejného klíče (bytes)
      - 'signature': podpis nad CONTEXT_DSA || pkE
      - 'data_to_sign': pkE (kvůli kompatibilitě s původním API)
    """
    try:
        # ECDHE server ephemeral
        skE = x25519.X25519PrivateKey.generate()
        pkE = skE.public_key()
        pkE_bytes = pkE.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    except Exception:
        return None

    # Podepsání serverova ephemeral public key s kontextem
    data_to_sign_with_context = CONTEXT_DSA + pkE_bytes

    try:
        sig_params = mldsa_params
        if sig_params.name == "Ed25519":
            signature = skS.sign(data_to_sign_with_context)
        elif sig_params.sign_hash_alg is not None:  # (pokud bys měl RSA-PSS)
            signature = skS.sign(
                data_to_sign_with_context,
                sig_params.padding_alg,
                sig_params.sign_hash_alg
            )
        else:  # ECDSA
            signature = skS.sign(
                data_to_sign_with_context,
                sig_params.padding_alg
            )
        if signature is None:
            return None
    except Exception:
        return None

    return {
        "skE": skE,
        "pkE": pkE_bytes,
        "signature": signature,
        "data_to_sign": pkE_bytes
    }


def client_verify_and_key_exchange(
        pkS: bytes,
        pkE: bytes,  # raw 32B serverova X25519 public key
        signature: bytes,
        data_to_verify: bytes,  # původní pkE (raw 32B)
        mldsa_params: ClassicSigParams,
        mlkem_variant_id: int  # ignorováno
) -> Optional[Dict[str, bytes]]:
    """
    Krok 3: Klient ověří podpis serverova ECDHE public key a provede ECDHE.
    Vrací:
      - 'ss_client': sdílené tajemství (bytes)
      - 'ct': klientův ECDHE public key (raw 32B), které server použije pro výpočet
    """
    sig_params = mldsa_params

    # 3a) Ověření podpisu serverova pkE
    try:
        # načtení podpisového pkS
        if sig_params.name.startswith("ECDSA"):
            curve = ec.SECP256R1() if sig_params.name.endswith("P256") else ec.SECP384R1()
            pkS_obj = ec.EllipticCurvePublicKey.from_encoded_point(curve, pkS)
        elif sig_params.name == "Ed25519":
            pkS_obj = ed25519.Ed25519PublicKey.from_public_bytes(pkS)
        else:
            pkS_obj = serialization.load_pem_public_key(pkS)

        data_to_verify_with_context = CONTEXT_DSA + data_to_verify

        if sig_params.name == "Ed25519":
            pkS_obj.verify(signature, data_to_verify_with_context)
        elif sig_params.sign_hash_alg is not None:
            pkS_obj.verify(
                signature,
                data_to_verify_with_context,
                sig_params.padding_alg,
                sig_params.sign_hash_alg
            )
        else:
            pkS_obj.verify(
                signature,
                data_to_verify_with_context,
                sig_params.padding_alg
            )
    except Exception:
        return None

    # 3b) ECDHE: klient vytvoří svůj ephemeral klíč a spočítá sdílené tajemství
    try:
        server_pkE_obj = x25519.X25519PublicKey.from_public_bytes(pkE)

        sk_client = x25519.X25519PrivateKey.generate()
        client_pk_bytes = sk_client.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        ss_client = sk_client.exchange(server_pkE_obj)

        # ct = klientův public key (aby server mohl spočítat stejné tajemství)
        ct = client_pk_bytes
    except Exception:
        return None

    return {"ss_client": ss_client, "ct": ct}


def server_decapsulate(skE: x25519.X25519PrivateKey, ct: bytes, mlkem_variant_id: int) -> Optional[Dict[str, bytes]]:
    """
    Krok 4: Server dopočítá sdílené tajemství z vlastního ECDHE skE a klientova pk (ct).
    V této ECDHE verzi 'ct' = klientův X25519 veřejný klíč (raw 32 B).
    """
    try:
        client_pk_obj = x25519.X25519PublicKey.from_public_bytes(ct)
        ss_server = skE.exchange(client_pk_obj)
    except Exception:
        return None

    return {"ss_server": ss_server}


def run_handshake_simulation(mldsa_variant_id: int, mlkem_variant_id: int) -> bool:
    """
    Spustí kompletní simulaci handshake s klasickou kryptografií (ECDHE-X25519 + ECDSA/Ed25519).
    API i tok je identický s ostatními implementacemi.
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
        mldsa_params,
        mlkem_variant_id
    )
    if not client_data:
        return False

    server_final = server_decapsulate(server_data["skE"], client_data["ct"], mlkem_variant_id)
    if not server_final:
        return False

    # (volitelné) konstantní porovnání by bylo lepší; držíme kompatibilitu s tvým testem
    return client_data["ss_client"] == server_final["ss_server"]