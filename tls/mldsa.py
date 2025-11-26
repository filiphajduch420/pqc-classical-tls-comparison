import os
from typing import Optional, Tuple

from .mldsa_files.constants import MLDSAParams, get_params_by_id
from .mldsa_files.dsa_internal import ML_DSA_KeyGen_internal, ML_DSA_Sign_internal, ML_DSA_Verify_internal
from .mldsa_files.conversions import IntegerToBytes, BytesToBits
from .mldsa_files.crypto_primitives import PREHASH_FUNCTIONS

# Sentinel hodnota pro ⊥ (error/NULL)
ERROR_VALUE = None


def ML_DSA_KeyGen(params: MLDSAParams) -> Optional[Tuple[bytes, bytes]]:
    """
    Generuje veřejný a soukromý klíč ML-DSA.
    Implementuje Algorithm 1: ML-DSA.KeyGen.


    Vstup:
        params: Objekt MLDSAParams definující parametry sady.

    Výstup:
        Dvojice (pk, sk) jako byte stringy, nebo None při chybě.
    """
    # 1: xi <- B^32
    try:
        xi = os.urandom(32)  # [cite: 470]
    except NotImplementedError:
        # 2: if xi = NULL then return ⊥
        return ERROR_VALUE  # [cite: 474-476]

    # 5: return ML-DSA.KeyGen_internal(xi)
    try:
        return ML_DSA_KeyGen_internal(xi, params)  # [cite: 477]
    except Exception as e:
        print(f"Chyba v ML_DSA_KeyGen_internal: {e}")
        import traceback
        traceback.print_exc()
        return ERROR_VALUE


def ML_DSA_Sign(
        sk: bytes,
        M: bytes,
        ctx: bytes,
        params: MLDSAParams,
        deterministic: bool = False
) -> Optional[bytes]:
    """
    Generuje ML-DSA podpis.
    Implementuje Algorithm 2: ML-DSA.Sign.


    Vstupy:
        sk: Bajtový řetězec soukromého klíče.
        M: Zpráva k podepsání (bajtový řetězec).
        ctx: Kontextový řetězec (max 255 bajtů).
        params: Objekt MLDSAParams.
        deterministic: Pokud True, použije se deterministická varianta (rnd = 0).

    Výstup:
        Bajtový řetězec podpisu, nebo None při chybě.
    """
    # 1: if |ctx| > 255 then return ⊥
    if len(ctx) > 255:  # [cite: 491]
        return ERROR_VALUE  # [cite: 492-494]
    # 3: end if

    # 5: rnd <- B^32 (nebo {0}^32 pro deterministickou)
    if deterministic:
        rnd = bytes(32)  # [cite: 496, 505]
    else:
        try:
            rnd = os.urandom(32)  # [cite: 496]
        except NotImplementedError:
            # 6: if rnd = NULL then return ⊥
            return ERROR_VALUE  # [cite: 497-500]
    # 8: end if

    # 10: M' <- BytesToBits(IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx) || M
    # Poznámka: Alg 2 má chybu v popisu M'. Správně má být || M na konci,
    # ale M je byte string, ne bit string. Musíme ho převést.
    # Použijeme BytesToBits(M) na základě textu a Alg 7 (kde M' je bitstring).
    try:
        prefix_bytes = IntegerToBytes(0, 1) + IntegerToBytes(len(ctx), 1) + ctx  # [cite: 507]
        prefix_bits = BytesToBits(prefix_bytes)
        message_bits = BytesToBits(M)  # Převod M na bity
        M_prime = prefix_bits + message_bits  # [cite: 507]
    except Exception as e:
        print(f"Chyba při formátování M na M_prime: {e}")
        import traceback
        traceback.print_exc()
        return ERROR_VALUE

    # 11: sigma <- ML-DSA.Sign_internal(sk, M', rnd)
    try:
        sigma = ML_DSA_Sign_internal(sk, M_prime, rnd, params)  # [cite: 508]
        # 12: return sigma
        return sigma  # [cite: 508]
    except RuntimeError as e:  # Sign může selhat po limitu iterací
        print(f"Chyba v ML_DSA_Sign_internal: {e}")
        return ERROR_VALUE
    except Exception as e:
        print(f"Chyba v ML_DSA_Sign_internal: {e}")
        import traceback
        traceback.print_exc()
        return ERROR_VALUE


def ML_DSA_Verify(
        pk: bytes,
        M: bytes,
        sigma: bytes,
        ctx: bytes,
        params: MLDSAParams
) -> bool:
    """
    Ověří ML-DSA podpis.
    Implementuje Algorithm 3: ML-DSA.Verify.


    Vstupy:
        pk: Bajtový řetězec veřejného klíče.
        M: Původní zpráva (bajtový řetězec).
        sigma: Bajtový řetězec podpisu.
        ctx: Kontextový řetězec (max 255 bajtů).
        params: Objekt MLDSAParams.

    Výstup:
        True, pokud je podpis platný, jinak False.
    """
    # 1: if |ctx| > 255 then return ⊥ (vracíme False místo ⊥)
    if len(ctx) > 255:  # [cite: 520]
        return False  # [cite: 521-524]
    # 3: end if

    # 5: M' <- BytesToBits(IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx) || M
    # Opět převádíme M na bity
    try:
        prefix_bytes = IntegerToBytes(0, 1) + IntegerToBytes(len(ctx), 1) + ctx  # [cite: 526]
        prefix_bits = BytesToBits(prefix_bytes)
        message_bits = BytesToBits(M)  # Převod M na bity
        M_prime = prefix_bits + message_bits  # [cite: 526-527]
    except Exception as e:
        print(f"Chyba při formátování M na M_prime ve Verify: {e}")
        import traceback
        traceback.print_exc()
        return False  # Chyba při přípravě vstupu

    # 6: return ML-DSA.Verify_internal(pk, M', sigma)
    # Verify_internal již obsahuje kontroly délek pk a sigma
    try:
        return ML_DSA_Verify_internal(pk, M_prime, sigma, params)  # [cite: 527]
    except Exception as e:
        # Neočekávaná chyba ve Verify_internal -> považujeme za neplatný podpis
        print(f"Chyba v ML_DSA_Verify_internal: {e}")
        import traceback
        traceback.print_exc()
        return False

def HashML_DSA_Sign(
        sk: bytes,
        M: bytes,
        ctx: bytes,
        ph_name: str,
        params: MLDSAParams,
        deterministic: bool = False
) -> Optional[bytes]:
    """
    Generuje "pre-hash" ML-DSA podpis.
    Implementuje Algorithm 4: HashML-DSA.Sign.


    Vstupy:
        sk: Bajtový řetězec soukromého klíče.
        M: Zpráva k podepsání (bajtový řetězec).
        ctx: Kontextový řetězec (max 255 bajtů).
        ph_name: Název pre-hash funkce ("SHA-256", "SHA-512", "SHAKE128").
        params: Objekt MLDSAParams.
        deterministic: Pokud True, použije se deterministická varianta (rnd = 0).

    Výstup:
        Bajtový řetězec podpisu, nebo None při chybě.
    """
    # 1: if |ctx| > 255 then return ⊥
    if len(ctx) > 255:  # [cite: 567]
        # Vracíme None místo ⊥ pro indikaci chyby
        return None  # [cite: 567]
    # 3: end if

    # 5: rnd <- B^32 (nebo {0}^32 pro deterministickou)
    if deterministic:
        rnd = bytes(32)  # [cite: 567]
    else:
        try:
            rnd = os.urandom(32)  # [cite: 545]
        except NotImplementedError:
            # os.urandom selhalo
            return None  # [cite: 567] (indikace chyby generování náhodnosti)
    # 6: if rnd = NULL then return ⊥ (ošetřeno výjimkou výše)

    # 10: switch PH do ...
    if ph_name not in PREHASH_FUNCTIONS:  # [cite: 567]
        raise ValueError(f"Nepodporovaná pre-hash funkce: {ph_name}")

    OID, hash_func = PREHASH_FUNCTIONS[ph_name]  # [cite: 567]

    # Vypočet PH_M
    PH_M = hash_func(M)  # [cite: 567]

    # 23: M' <- BytesToBits(IntegerToBytes(1, 1) || IntegerToBytes(|ctx|, 1) || ctx || OID || PH_M)
    # Domain separator = 1 for pre-hash [cite: 556]
    prefix = (
            IntegerToBytes(1, 1) +  # [cite: 556]
            IntegerToBytes(len(ctx), 1) +  # [cite: 555]
            ctx +  # [cite: 555]
            OID +  # [cite: 555]
            PH_M  # [cite: 555]
    )
    M_prime = BytesToBits(prefix)  # [cite: 567]

    # 24: sigma <- ML-DSA.Sign_internal(sk, M', rnd)
    try:
        sigma = ML_DSA_Sign_internal(sk, M_prime, rnd, params)  # [cite: 567]
    except RuntimeError:
        # Sign_internal mohl selhat (např. limit iterací)
        return None
    except Exception:
        # Jiná neočekávaná chyba
        import traceback
        traceback.print_exc()
        return None

    # 25: return sigma
    return sigma  # [cite: 567]

def HashML_DSA_Verify(
        pk: bytes,
        M: bytes,
        sigma: bytes,
        ctx: bytes,
        ph_name: str,
        params: MLDSAParams
) -> bool:
    """
    Ověří "pre-hash" ML-DSA podpis.
    Implementuje Algorithm 5: HashML-DSA.Verify.


    Vstupy:
        pk: Bajtový řetězec veřejného klíče.
        M: Původní zpráva (bajtový řetězec).
        sigma: Bajtový řetězec podpisu.
        ctx: Kontextový řetězec (max 255 bajtů).
        ph_name: Název pre-hash funkce ("SHA-256", "SHA-512", "SHAKE128").
        params: Objekt MLDSAParams.

    Výstup:
        True, pokud je podpis platný, jinak False.
    """
    # 1: if |ctx| > 255 then return false
    if len(ctx) > 255:  #
        return False  #
    # 3: end if

    # 5: switch PH do ...
    if ph_name not in PREHASH_FUNCTIONS:  #
        # Nepodporovaná funkce -> neplatný podpis
        return False

    OID, hash_func = PREHASH_FUNCTIONS[ph_name]  #

    # Vypočet PH_M
    try:
        PH_M = hash_func(M)  #
    except Exception:
        # Chyba při hashování -> neplatný podpis
        return False

    # 18: M' <- BytesToBits(IntegerToBytes(1, 1) || IntegerToBytes(|ctx|, 1) || ctx || OID || PH_M)
    prefix = (
            IntegerToBytes(1, 1) +  # [cite: 556]
            IntegerToBytes(len(ctx), 1) +  # [cite: 555]
            ctx +  # [cite: 555]
            OID +  # [cite: 555]
            PH_M  # [cite: 555]
    )
    M_prime = BytesToBits(prefix)  #

    # 19: return ML-DSA.Verify_internal(pk, M', sigma)
    # Verify_internal již obsahuje kontroly délek pk a sigma
    try:
        return ML_DSA_Verify_internal(pk, M_prime, sigma, params)  #
    except Exception:
        # Neočekávaná chyba ve Verify_internal -> považujeme za neplatný podpis
        import traceback
        traceback.print_exc()
        return False

from .mldsa_files.dsa_internal import ML_DSA_Verify_debug as _ML_DSA_Verify_debug

def ML_DSA_Verify_Introspect(
        pk: bytes,
        M: bytes,
        sigma: bytes,
        ctx: bytes,
        params: MLDSAParams
) -> dict:
    """
    Public wrapper that mirrors ML_DSA_Verify, but returns debug info from verification:
    includes c_tilde, c'_tilde, match flag, and z-norm bound info.
    """
    if len(ctx) > 255:
        return {"ok": False, "error": "ctx too long"}
    try:
        prefix_bytes = IntegerToBytes(0, 1) + IntegerToBytes(len(ctx), 1) + ctx
        prefix_bits = BytesToBits(prefix_bytes)
        message_bits = BytesToBits(M)
        M_prime = prefix_bits + message_bits
    except Exception as e:
        return {"ok": False, "error": f"prep failed: {e}"}

    try:
        return _ML_DSA_Verify_debug(pk, M_prime, sigma, params)
    except Exception as e:
        return {"ok": False, "error": f"verify_debug failed: {e}"}

def main():
    """
    Hlavní funkce pro testování výkonu podepisovacích operací.
    Porovnává rychlost standardního a pre-hash podepisování pro
    malé a velké zprávy pro všechny varianty ML-DSA.
    """
    import time

    variant_ids = [0, 1, 2]
    small_message = b"Toto je kratka testovaci zprava."
    large_message = b'\x41' * (10 * 1024 * 1024)  # 10 MB
    ctx = b""
    iterations = 3
    ph_name = "SHA-512"

    for variant_id in variant_ids:
        params = get_params_by_id(variant_id)
        if not params:
            print(f"Chyba: Nepodařilo se načíst parametry pro ID {variant_id}.")
            continue

        pk, sk = ML_DSA_KeyGen(params)
        if not pk or not sk:
            print(f"Chyba: Generování klíčů pro {params.name} selhalo.")
            continue

        results = {
            "small": {"std_time": 0, "hash_time": 0},
            "large": {"std_time": 0, "hash_time": 0}
        }

        # --- Měření ---

        # Standardní podpis (malá zpráva)
        start_time = time.perf_counter()
        for _ in range(iterations):
            ML_DSA_Sign(sk, small_message, ctx, params, deterministic=True)
        end_time = time.perf_counter()
        results["small"]["std_time"] = (end_time - start_time) / iterations

        # Standardní podpis (velká zpráva)
        start_time = time.perf_counter()
        for _ in range(iterations):
            ML_DSA_Sign(sk, large_message, ctx, params, deterministic=True)
        end_time = time.perf_counter()
        results["large"]["std_time"] = (end_time - start_time) / iterations

        # Pre-hash podpis (malá zpráva)
        start_time = time.perf_counter()
        for _ in range(iterations):
            HashML_DSA_Sign(sk, small_message, ctx, ph_name, params, deterministic=True)
        end_time = time.perf_counter()
        results["small"]["hash_time"] = (end_time - start_time) / iterations

        # Pre-hash podpis (velká zpráva)
        start_time = time.perf_counter()
        for _ in range(iterations):
            HashML_DSA_Sign(sk, large_message, ctx, ph_name, params, deterministic=True)
        end_time = time.perf_counter()
        results["large"]["hash_time"] = (end_time - start_time) / iterations

        # --- Výpis výsledků v tabulce ---
        print(f"\n--- Výsledky pro: {params.name} ---")
        header = f"| {'Zpráva':<10} | {'Standardní čas (s)':>20} | {'Pre-hash čas (s)':>20} | {'Poměr (Std / Pre-hash)':>25} |"
        separator = f"|{'-'*12}|{'-'*22}|{'-'*22}|{'-'*27}|"
        print(header)
        print(separator)

        # Malá zpráva
        t_std_s = results["small"]["std_time"]
        t_hash_s = results["small"]["hash_time"]
        ratio_s = t_std_s / t_hash_s if t_hash_s > 0 else float('inf')
        print(f"| {'Malá':<10} | {t_std_s:>20.6f} | {t_hash_s:>20.6f} | {f'{ratio_s:.2f}x':>25} |")

        # Velká zpráva
        t_std_l = results["large"]["std_time"]
        t_hash_l = results["large"]["hash_time"]
        ratio_l = t_std_l / t_hash_l if t_hash_l > 0 else float('inf')
        print(f"| {'Velká':<10} | {t_std_l:>20.6f} | {t_hash_l:>20.6f} | {f'{ratio_l:.2f}x':>25} |")
        print("-" * len(header))


if __name__ == "__main__":
    main()

