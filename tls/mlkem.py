import os
from .mlkem_files.constants import get_params_by_id, MLKEMParams
from .mlkem_files.kem_internal import (
    MLKEM_KeyGen_internal,
    MLKEM_Encaps_internal,
    MLKEM_Decaps_internal,
)
from .mlkem_files.crypto_primitives import H
from .mlkem_files.utils import ByteDecode, ByteEncode

def MLKEM_KeyGen(variant_id: int = 1) -> tuple[bytes, bytes]:
    params = get_params_by_id(variant_id)
    d = os.urandom(32)
    z = os.urandom(32)
    return MLKEM_KeyGen_internal(d, z, params)

def MLKEM_Encaps(ek: bytes, variant_id: int = 1) -> tuple[bytes, bytes]:
    params = get_params_by_id(variant_id)
    if not _validate_encapsulation_key(ek, params):
        raise ValueError("Invalid ek")
    m = os.urandom(32)
    return MLKEM_Encaps_internal(ek, m, params)

def MLKEM_Decaps(dk: bytes, c: bytes, variant_id: int = 1) -> bytes:
    params = get_params_by_id(variant_id)
    if not _validate_decaps_inputs(dk, c, params):
        raise ValueError("Invalid inputs")
    return MLKEM_Decaps_internal(dk, c, params)

# Backward wrappers\
def MLKEM768_KeyGen(): return MLKEM_KeyGen(1)
def MLKEM768_Encaps(ek: bytes): return MLKEM_Encaps(ek, 1)
def MLKEM768_Decaps(dk: bytes, c: bytes): return MLKEM_Decaps(dk, c, 1)

def _validate_encapsulation_key(ek: bytes, params: MLKEMParams) -> bool:
    if not isinstance(ek, bytes):
        return False
    expected = 384 * params.K + 32
    if len(ek) != expected:
        return False
    try:
        for i in range(params.K):
            seg = ek[i*384:(i+1)*384]
            coeffs = ByteDecode(seg, 12)
            if ByteEncode(coeffs, 12) != seg:
                return False
    except Exception:
        return False
    return True


def _validate_decaps_inputs(dk: bytes, c: bytes, params: MLKEMParams) -> bool:
    off_dkPKE = 384 * params.K
    off_ekPKE = 768 * params.K + 32
    off_h = 768 * params.K + 64
    ekPKE_part = dk[off_dkPKE:off_ekPKE]
    h_expected = dk[off_ekPKE:off_h]  # Přejmenováno z 'h'
    h_calculated = H(ekPKE_part)  # Použijeme H z crypto_primitives


    match = (h_calculated == h_expected)
    if not match:
        return False

    return match