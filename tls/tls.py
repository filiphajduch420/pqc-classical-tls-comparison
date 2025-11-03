# tls/tls.py
"""
Parametrized TLS-like PQC handshake using
ML-KEM (Kyber) for key exchange and ML-DSA (Dilithium) for authentication.
"""

from typing import Optional, Dict, Any

from . import mldsa
from . import mlkem
from .mldsa_files.constants import get_params_by_id as get_mldsa_params

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
    Step 0: Server generates long-term ML-DSA key pair for given variant.
    Returns dict with keys or None on error.
    """
    try:
        mldsa_params = get_mldsa_params(mldsa_variant_id)
    except ValueError:
        return None

    keypair = mldsa.ML_DSA_KeyGen(mldsa_params)
    if keypair is None:
        return None

    pkS, skS = keypair
    return {"pkS": pkS, "skS": skS, "mldsa_params": mldsa_params}


def client_hello() -> bool:
    """Step 1: Client starts communication."""
    return True


def server_hello_and_key_exchange(
    skS: bytes,
    mlkem_variant_id: int,
    mldsa_params: Any
) -> Optional[Dict[str, Any]]:
    """
    Step 2: Server responds, generates ephemeral KEM keys and signs them.
    Returns dict with data for client and server's secret key, or None on error.
    """
    try:
        pkE, skE = mlkem.MLKEM_KeyGen(mlkem_variant_id)
    except Exception:
        return None

    data_to_sign = pkE
    try:
        signature = mldsa.ML_DSA_Sign(skS, data_to_sign, CONTEXT_DSA, mldsa_params)
        if signature is None:
            return None
    except Exception:
        return None

    return {
        "skE": skE,
        "pkE": pkE,
        "signature": signature,
        "data_to_sign": data_to_sign
    }


def client_verify_and_key_exchange(
    pkS: bytes,
    pkE: bytes,
    signature: bytes,
    data_to_verify: bytes,
    mldsa_params: Any,
    mlkem_variant_id: int
) -> Optional[Dict[str, bytes]]:
    """
    Step 3: Client verifies server and encapsulates the secret.
    Returns dict with ciphertext for server and client's shared secret, or None on error.
    """
    try:
        ok = mldsa.ML_DSA_Verify(pkS, data_to_verify, signature, CONTEXT_DSA, mldsa_params)
        if not ok:
            return None
    except Exception:
        return None

    try:
        ss_client, ct = mlkem.MLKEM_Encaps(pkE, mlkem_variant_id)
    except Exception:
        return None

    return {"ss_client": ss_client, "ct": ct}


def server_decapsulate(skE: bytes, ct: bytes, mlkem_variant_id: int) -> Optional[Dict[str, bytes]]:
    """
    Step 4: Server decapsulates ciphertext and obtains the secret.
    Returns dict with server's shared secret, or None on error.
    """
    try:
        ss_server = mlkem.MLKEM_Decaps(skE, ct, mlkem_variant_id)
    except Exception:
        return None
    return {"ss_server": ss_server}


def run_handshake_simulation(mldsa_variant_id: int, mlkem_variant_id: int) -> bool:
    """
    Runs a single PQC handshake for given ML-DSA and ML-KEM variants.
    Returns True on success, False otherwise.
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

    return client_data["ss_client"] == server_final["ss_server"]
