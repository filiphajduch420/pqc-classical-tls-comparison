# mldsa_files/__init__.py

# Z konstant exportujeme základní parametry a způsob jejich získání
from .constants import (
    N, Q, ZETA, D,         # Základní konstanty
    MLDSAParams,           # Datová třída pro parametry
    get_params_by_id,      # Funkce pro získání parametrů podle ID
)

# Z interních funkcí exportujeme hlavní algoritmy
from .dsa_internal import (
    ML_DSA_KeyGen_internal,
    ML_DSA_Sign_internal,
    ML_DSA_Verify_internal,
)

# Případně můžeš exportovat i další užitečné funkce nebo typy,
# pokud je budeš potřebovat přímo importovat z `mldsa_files`
# Například:
# from .utils import Poly, Vector
# from .encode import pkEncode, pkDecode, sigEncode, sigDecode

# __all__ definuje, co se má importovat při 'from mldsa_files import *'
# Je dobrým zvykem ho definovat.
__all__ = [
    # Konstanty a parametry
    "N", "Q", "ZETA", "D",
    "MLDSAParams", "get_params_by_id",

    # Interní algoritmy
    "ML_DSA_KeyGen_internal",
    "ML_DSA_Sign_internal",
    "ML_DSA_Verify_internal",

    # Případně další exportované symboly
    # "Poly", "Vector",
    # "pkEncode", "pkDecode", "sigEncode", "sigDecode",
]