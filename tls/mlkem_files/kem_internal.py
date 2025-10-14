from tls.mlkem_files.crypto_primitives import H, J, G
from tls.mlkem_files.pke import K_PKE_KeyGen, K_PKE_Encrypt, K_PKE_Decrypt
from tls.mlkem_files.constants import MLKEMParams

def MLKEM_KeyGen_internal(d: bytes, z: bytes, params: MLKEMParams) -> tuple[bytes, bytes]:
    if len(d) != 32 or len(z) != 32:
        raise ValueError("d and z must be 32 bytes")
    ekPKE, dkPKE = K_PKE_KeyGen(d, params)
    h_ek = H(ekPKE)
    dk = dkPKE + ekPKE + h_ek + z
    return ekPKE, dk

def MLKEM_Encaps_internal(ek: bytes, m: bytes, params: MLKEMParams) -> tuple[bytes, bytes]:
    if len(m) != 32:
        raise ValueError("m must be 32 bytes")
    h_ek = H(ek)
    K_shared, r = G(m + h_ek)
    c = K_PKE_Encrypt(ek, m, r, params)
    return K_shared, c

def MLKEM_Decaps_internal(dk: bytes, c: bytes, params: MLKEMParams) -> bytes:
    K = params.K
    off_dkPKE = 384 * K
    off_ekPKE = 768 * K + 32
    off_h = 768 * K + 64
    off_z = 768 * K + 96
    dkPKE = dk[0:off_dkPKE]
    ekPKE = dk[off_dkPKE:off_ekPKE]
    h = dk[off_ekPKE:off_h]
    z = dk[off_h:off_z]

    m_prime = K_PKE_Decrypt(dkPKE, c, params)
    K_prime, r_prime = G(m_prime + h)
    K_bar = J(z + c)
    c_prime = K_PKE_Encrypt(ekPKE, m_prime, r_prime, params)
    if c != c_prime:
        K_prime = K_bar
    return K_prime