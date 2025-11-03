# test/test_classical_handshake.py
import os
import time
import tracemalloc
from typing import Optional, Dict, Any, List, Tuple, Callable
from dataclasses import dataclass

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, ed25519, x25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    print("Error: Python package `cryptography` is not installed.")
    print("Install with: pip install cryptography")
    raise SystemExit(1)

# Import helpers
from .test_utils import _time_call, _memory_call, _stats, _print_table

ROUNDS = 10
CONTEXT = b"TLS Handshake Signature Context"


# --- Variant definitions ---

@dataclass(frozen=True)
class KexParams:
    name: str
    key_gen_func: Callable
    serialize_func: Callable
    deserialize_func: Callable
    exchange_func: Callable


@dataclass(frozen=True)
class SigParams:
    name: str
    key_gen_func: Callable
    hash_alg: Any
    padding_alg: Any
    sign_hash_alg: Any


@dataclass(frozen=True)
class ClassicalVariant:
    name: str
    kex: KexParams
    sig: SigParams


# --- KEX methods ---

KEX_ECDH_P256 = KexParams(
    name="ECDH-P256",
    key_gen_func=lambda: ec.generate_private_key(ec.SECP256R1()),
    serialize_func=lambda pk: pk.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    ),
    deserialize_func=lambda b: ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b),
    exchange_func=lambda sk, pk: sk.exchange(ec.ECDH(), pk)
)

KEX_ECDH_P384 = KexParams(
    name="ECDH-P384",
    key_gen_func=lambda: ec.generate_private_key(ec.SECP384R1()),
    serialize_func=lambda pk: pk.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    ),
    deserialize_func=lambda b: ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), b),
    exchange_func=lambda sk, pk: sk.exchange(ec.ECDH(), pk)
)

KEX_X25519 = KexParams(
    name="X25519",
    key_gen_func=lambda: x25519.X25519PrivateKey.generate(),
    serialize_func=lambda pk: pk.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ),
    deserialize_func=lambda b: x25519.X25519PublicKey.from_public_bytes(b),
    exchange_func=lambda sk, pk: sk.exchange(pk)
)

# --- SIG methods ---

SIG_RSA_3072_PSS = SigParams(
    name="RSA-3072-PSS",
    key_gen_func=lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072),
    hash_alg=hashes.SHA384(),
    padding_alg=padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=padding.PSS.MAX_LENGTH),
    sign_hash_alg=hashes.SHA384()
)

SIG_ECDSA_P256 = SigParams(
    name="ECDSA-P256",
    key_gen_func=lambda: ec.generate_private_key(ec.SECP256R1()),
    hash_alg=hashes.SHA256(),
    padding_alg=ec.ECDSA(hashes.SHA256()),  # FIX: use ec.ECDSA(...)
    sign_hash_alg=None
)

SIG_ECDSA_P384 = SigParams(
    name="ECDSA-P384",
    key_gen_func=lambda: ec.generate_private_key(ec.SECP384R1()),
    hash_alg=hashes.SHA384(),
    padding_alg=ec.ECDSA(hashes.SHA384()),  # FIX: use ec.ECDSA(...)
    sign_hash_alg=None
)

SIG_ED25519 = SigParams(
    name="Ed25519",
    key_gen_func=lambda: ed25519.Ed25519PrivateKey.generate(),
    hash_alg=None,
    padding_alg=None,
    sign_hash_alg=None
)

# --- Variants to test ---

VARIANTS_TO_TEST = [
    ClassicalVariant(
        name="RSA-3072 + ECDH-P384",
        kex=KEX_ECDH_P384,
        sig=SIG_RSA_3072_PSS
    ),
    ClassicalVariant(
        name="ECDSA-P256 + ECDH-P256",
        kex=KEX_ECDH_P256,
        sig=SIG_ECDSA_P256
    ),
    ClassicalVariant(
        name="ECDSA-P384 + ECDH-P384",
        kex=KEX_ECDH_P384,
        sig=SIG_ECDSA_P384
    ),
    ClassicalVariant(
        name="Ed25519 + X25519",
        kex=KEX_X25519,
        sig=SIG_ED25519
    ),
]


# --- Handshake functions ---

def gen_server_keys(sig: SigParams) -> Dict[str, Any]:
    sk_sig = sig.key_gen_func()
    return {"sk_sig": sk_sig, "pk_sig": sk_sig.public_key()}


def server_hello_and_key_exchange(sk_sig, sig: SigParams, kex: KexParams) -> Dict[str, Any]:
    sk_e = kex.key_gen_func()
    pk_e = sk_e.public_key()
    pk_e_bytes = kex.serialize_func(pk_e)

    to_sign = CONTEXT + pk_e_bytes

    if sig.name == "Ed25519":
        signature = sk_sig.sign(to_sign)
    elif sig.sign_hash_alg is not None:
        hasher = hashes.Hash(sig.hash_alg)
        hasher.update(to_sign)
        data_hash = hasher.finalize()
        signature = sk_sig.sign(data_hash, sig.padding_alg, sig.hash_alg)
    else:
        signature = sk_sig.sign(to_sign, sig.padding_alg)

    return {"sk_e": sk_e, "pk_e_bytes": pk_e_bytes, "signature": signature, "data_to_sign": to_sign}


def client_verify_and_key_exchange(pk_sig, pk_e_bytes: bytes, signature: bytes, data_to_verify: bytes,
                                   sig: SigParams, kex: KexParams) -> Optional[Dict[str, Any]]:
    try:
        if sig.name == "Ed25519":
            pk_sig.verify(signature, data_to_verify)
        elif sig.sign_hash_alg is not None:
            hasher = hashes.Hash(sig.hash_alg)
            hasher.update(data_to_verify)
            data_hash = hasher.finalize()
            pk_sig.verify(signature, data_hash, sig.padding_alg, sig.hash_alg)
        else:
            pk_sig.verify(signature, data_to_verify, sig.padding_alg)
    except Exception:
        print(f"\nERROR: Signature verification failed for {sig.name}!")
        return None

    sk_c = kex.key_gen_func()
    pk_c = sk_c.public_key()
    pk_c_bytes = kex.serialize_func(pk_c)

    pk_e = kex.deserialize_func(pk_e_bytes)
    ss_client = kex.exchange_func(sk_c, pk_e)

    return {"ss_client": ss_client, "pk_c_bytes": pk_c_bytes}


def server_finish(sk_e, pk_c_bytes: bytes, kex: KexParams) -> bytes:
    pk_c = kex.deserialize_func(pk_c_bytes)
    return kex.exchange_func(sk_e, pk_c)


# --- Profiling ---

def run_classical_handshake_profiled(variant: ClassicalVariant) -> Optional[Dict[str, Any]]:
    timings = {}
    memory = {}

    sig = variant.sig
    kex = variant.kex

    server_keys_data, t = _time_call(gen_server_keys, sig)
    if server_keys_data is None:
        return None
    timings["1_Server_Sig_KeyGen"] = t
    _, m = _memory_call(gen_server_keys, sig)
    memory["1_Server_Sig_KeyGen"] = m

    client_known_pkS = server_keys_data["pk_sig"]

    _, t = _time_call(lambda: True)
    timings["2_Client_Hello"] = t
    _, m = _memory_call(lambda: True)
    memory["2_Client_Hello"] = m

    server_data, t = _time_call(server_hello_and_key_exchange, server_keys_data["sk_sig"], sig, kex)
    if server_data is None:
        return None
    timings["3_Server_Hello_KEX_Sign"] = t
    _, m = _memory_call(server_hello_and_key_exchange, server_keys_data["sk_sig"], sig, kex)
    memory["3_Server_Hello_KEX_Sign"] = m

    client_data, t = _time_call(
        client_verify_and_key_exchange,
        client_known_pkS,
        server_data["pk_e_bytes"],
        server_data["signature"],
        server_data["data_to_sign"],
        sig, kex
    )
    if client_data is None:
        return None
    timings["4_Client_Verify_KEX_Exchange"] = t
    _, m = _memory_call(
        client_verify_and_key_exchange,
        client_known_pkS,
        server_data["pk_e_bytes"],
        server_data["signature"],
        server_data["data_to_sign"],
        sig, kex
    )
    memory["4_Client_Verify_KEX_Exchange"] = m

    server_final_data_ss, t = _time_call(
        server_finish,
        server_data["sk_e"],
        client_data["pk_c_bytes"],
        kex
    )
    if server_final_data_ss is None:
        return None
    timings["5_Server_KEX_Exchange"] = t
    _, m = _memory_call(
        server_finish,
        server_data["sk_e"],
        client_data["pk_c_bytes"],
        kex
    )
    memory["5_Server_KEX_Exchange"] = m

    if client_data["ss_client"] != server_final_data_ss:
        raise RuntimeError(f"Classical Handshake failed for {variant.name}: Secrets do not match!")

    return {"timings": timings, "memory": memory}


# --- Main ---

def main():
    print(f"=== Running Classical Handshake Benchmark ===")
    print(f"Rounds per variant: {ROUNDS}\n")

    all_timings_stats = []
    all_memory_stats = []

    headers_time = ("Variant", "Total [ms]", "1_KeyGen [ms]", "3_Srv_KEX+Sign [ms]", "4_Clnt_Vrfy+KEX [ms]",
                    "5_Srv_KEX [ms]")
    headers_mem = ("Variant", "Total [KiB]", "1_KeyGen [KiB]", "3_Srv_KEX+Sign [KiB]", "4_Clnt_Vrfy+KEX [KiB]",
                   "5_Srv_KEX [KiB]")

    for variant in VARIANTS_TO_TEST:
        print(f"--- Testing variant: {variant.name} ---")

        timings_per_step = {
            "1_Server_Sig_KeyGen": [],
            "2_Client_Hello": [],
            "3_Server_Hello_KEX_Sign": [],
            "4_Client_Verify_KEX_Exchange": [],
            "5_Server_KEX_Exchange": [],
            "TOTAL_HANDSHAKE": []
        }
        memory_per_step = {k: [] for k in timings_per_step}

        ok = 0
        tracemalloc.start()
        for i in range(ROUNDS):
            print(f"  Round {i + 1}/{ROUNDS}...", end="\r")

            start_total_time = time.perf_counter()
            tracemalloc.clear_traces()

            result = run_classical_handshake_profiled(variant)

            total_time_ms = (time.perf_counter() - start_total_time) * 1000.0
            _, total_peak_mem_kib = tracemalloc.get_traced_memory()

            if result is None:
                print(f"\n  Error in round {i + 1}, skipping.")
                continue

            ok += 1
            timings_per_step["TOTAL_HANDSHAKE"].append(total_time_ms)
            memory_per_step["TOTAL_HANDSHAKE"].append(total_peak_mem_kib)

            for key, t_val in result["timings"].items():
                timings_per_step[key].append(t_val)
            for key, m_val in result["memory"].items():
                memory_per_step[key].append(m_val)

        tracemalloc.stop()
        print(f"\n  Done. Successful rounds: {ok}/{ROUNDS}")

        if ok > 0:
            t_min, t_avg_total, t_max = _stats(timings_per_step["TOTAL_HANDSHAKE"])
            _, t_avg_kgen, _ = _stats(timings_per_step["1_Server_Sig_KeyGen"])
            _, t_avg_srv_kex, _ = _stats(timings_per_step["3_Server_Hello_KEX_Sign"])
            _, t_avg_clnt_kex, _ = _stats(timings_per_step["4_Client_Verify_KEX_Exchange"])
            _, t_avg_srv_fin, _ = _stats(timings_per_step["5_Server_KEX_Exchange"])

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
            _, m_avg_srv_kex, _ = _stats(memory_per_step["3_Server_Hello_KEX_Sign"])
            _, m_avg_clnt_kex, _ = _stats(memory_per_step["4_Client_Verify_KEX_Exchange"])
            _, m_avg_srv_fin, _ = _stats(memory_per_step["5_Server_KEX_Exchange"])

            all_memory_stats.append((
                variant.name,
                f"{m_avg_total:.2f}",
                f"{m_avg_kgen:.2f}",
                f"{m_avg_srv_kex:.2f}",
                f"{m_avg_clnt_kex:.2f}",
                f"{m_avg_srv_fin:.2f}"
            ))

    print("\n--- Average Time (Classical) ---")
    _print_table(all_timings_stats, headers_time)

    print("\n--- Average Peak Memory (Classical) ---")
    _print_table(all_memory_stats, headers_mem)


if __name__ == "__main__":
    main()
