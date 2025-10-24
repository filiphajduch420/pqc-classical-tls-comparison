"""
Implementace externích (external) podepisovacích funkcí ML-DSA.
- ML-DSA.Sign (Alg 2)
- HashML-DSA.Sign (Alg 4)
"""
import os
from typing import Optional
from .constants import MLDSAParams
from .dsa_internal import ML_DSA_Sign_internal
from .conversions import IntegerToBytes, BytesToBits
from .crypto_primitives import PREHASH_FUNCTIONS


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