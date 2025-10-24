"""
Hlavní soubor pro ML-DSA (FIPS 204).
Obsahuje externí (API) funkce:
- ML_DSA_KeyGen (Alg 1)
- ML_DSA_Sign (Alg 2)
- ML_DSA_Verify (Alg 3)
"""
import os
from typing import Optional, Tuple

# Importujeme z našeho podbalíčku 'mldsa_files'
from mldsa_files.constants import MLDSAParams, get_params_by_id
from mldsa_files.dsa_internal import ML_DSA_KeyGen_internal, ML_DSA_Sign_internal, ML_DSA_Verify_internal
from mldsa_files.conversions import IntegerToBytes, BytesToBits
from mldsa_files.crypto_primitives import PREHASH_FUNCTIONS

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



# --- Testovací Blok ---
if __name__ == "__main__":

    # Test pro standardní ML-DSA (Alg 1, 2, 3)
    def run_mldsa_test(variant_id: int):
        print(f"\n--- Spouštím ML-DSA test pro variantu ID: {variant_id} ---")
        try:
            params = get_params_by_id(variant_id)
            print(f"Parametry: {params.name}")
        except ValueError as e:
            print(f"Chyba: {e}")
            return False

        keypair = ML_DSA_KeyGen(params)
        if keypair is None: print("Selhalo generování klíčů."); return False
        pk, sk = keypair
        print("Klíče vygenerovány.")

        message = b"Toto je zprava pro ML-DSA test."
        context = b"MLDSA_Context"
        print(f"Podepisuji zprávu: {message!r} s kontextem: {context!r}")
        signature = ML_DSA_Sign(sk, message, context, params)
        if signature is None: print("Selhalo podepisování."); return False
        print("Podpis vygenerován.")

        print("Ověřuji platný podpis...")
        is_valid = ML_DSA_Verify(pk, message, signature, context, params)
        print(f"Výsledek (platný podpis): {is_valid}")
        if not is_valid: return False

        print("Ověřuji neplatný podpis (jiná zpráva)...")
        is_invalid_msg = ML_DSA_Verify(pk, b"Jina zprava", signature, context, params)
        print(f"Výsledek (jiná zpráva): {not is_invalid_msg}")
        if is_invalid_msg: return False

        print("Ověřuji neplatný podpis (jiný kontext)...")
        is_invalid_ctx = ML_DSA_Verify(pk, message, signature, b"JinyKontext", params)
        print(f"Výsledek (jiný kontext): {not is_invalid_ctx}")
        if is_invalid_ctx: return False

        print("--- ML-DSA test dokončen úspěšně ---")
        return True


    # Test pro HashML-DSA (Alg 4, 5)
    def run_hashml_test(variant_id: int):
        print(f"\n--- Spouštím HashML-DSA test pro variantu ID: {variant_id} ---")
        try:
            params = get_params_by_id(variant_id)
            print(f"Parametry: {params.name}")
        except ValueError as e:
            print(f"Chyba: {e}")
            return False

        keypair = ML_DSA_KeyGen(params)
        if keypair is None: print("Selhalo generování klíčů."); return False
        pk, sk = keypair
        print("Klíče vygenerovány.")

        message = b"Toto je zprava pro HashML-DSA test, muze byt i delsi..." * 10
        context = b"HashML_Context"
        all_hash_tests_passed = True

        for ph_name in PREHASH_FUNCTIONS.keys():
            print(f"\n  Testuji s pre-hash funkcí: {ph_name}")
            print(f"  Podepisuji zprávu (délka {len(message)}) s kontextem: {context!r}")
            signature = HashML_DSA_Sign(sk, message, context, ph_name, params)
            if signature is None:
                print(f"  Selhalo podepisování s {ph_name}.")
                all_hash_tests_passed = False
                continue
            print("  Podpis vygenerován.")

            print("  Ověřuji platný podpis...")
            is_valid = HashML_DSA_Verify(pk, message, signature, context, ph_name, params)
            print(f"  Výsledek (platný podpis, {ph_name}): {is_valid}")
            if not is_valid: all_hash_tests_passed = False; continue

            print("  Ověřuji neplatný podpis (jiná zpráva)...")
            is_invalid_msg = HashML_DSA_Verify(pk, b"Jina zprava", signature, context, ph_name, params)
            print(f"  Výsledek (jiná zpráva, {ph_name}): {not is_invalid_msg}")
            if is_invalid_msg: all_hash_tests_passed = False; continue

            print("  Ověřuji neplatný podpis (jiný kontext)...")
            is_invalid_ctx = HashML_DSA_Verify(pk, message, signature, b"JinyKontext", ph_name, params)
            print(f"  Výsledek (jiný kontext, {ph_name}): {not is_invalid_ctx}")
            if is_invalid_ctx: all_hash_tests_passed = False; continue

            # Zkusíme ověřit se špatně specifikovanou hash funkcí
            other_ph_name = "SHA-512" if ph_name == "SHA-256" else "SHA-256"
            print(f"  Ověřuji neplatný podpis (nesprávná PH funkce '{other_ph_name}')...")
            is_invalid_ph = HashML_DSA_Verify(pk, message, signature, context, other_ph_name, params)
            print(f"  Výsledek (nesprávná PH funkce, {ph_name}): {not is_invalid_ph}")
            if is_invalid_ph: all_hash_tests_passed = False; continue

        if all_hash_tests_passed:
            print("--- HashML-DSA test dokončen úspěšně ---")
            return True
        else:
            print("--- HashML-DSA test selhal pro některé hash funkce ---")
            return False


    # Spuštění obou sad testů
    mldsa_results = {}
    hashml_results = {}
    for i in range(3):
        mldsa_results[i] = run_mldsa_test(i)
        hashml_results[i] = run_hashml_test(i)

    print("\n--- Souhrn VŠECH testů ---")
    all_passed = True
    for i in range(3):
        mldsa_status = "PASS" if mldsa_results[i] else "FAIL"
        hashml_status = "PASS" if hashml_results[i] else "FAIL"
        print(f"Varianta {i}: ML-DSA={mldsa_status}, HashML-DSA={hashml_status}")
        if not mldsa_results[i] or not hashml_results[i]:
            all_passed = False

    if all_passed:
        print("\n=> Všechny testy (ML-DSA i HashML-DSA) prošly!")
    else:
        print("\n=> Některé testy selhaly!")
