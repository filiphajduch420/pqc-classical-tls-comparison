"""
Implementace externích (external) ověřovacích funkcí ML-DSA.
- ML-DSA.Verify (Alg 3)
- HashML-DSA.Verify (Alg 5)
"""
from typing import Optional  # <-- PŘIDÁN IMPORT
from .constants import MLDSAParams  # <-- PŘIDÁN IMPORT
from .dsa_internal import ML_DSA_Verify_internal
from .conversions import IntegerToBytes, BytesToBits  # <-- PŘIDÁN IMPORT
from .crypto_primitives import PREHASH_FUNCTIONS  # <-- PŘIDÁN IMPORT


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