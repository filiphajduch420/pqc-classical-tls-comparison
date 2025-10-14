from tls.mlkem_files.constants import N, Q
from tls.mlkem_files.crypto_primitives import G, PRF
from tls.mlkem_files.sampling import SamplePolyCBD, SampleNTT
from tls.mlkem_files.ntt import NTT, MultiplyNTTs, InvNTT
from tls.mlkem_files.utils import ByteEncode, ByteDecode, Decompress, Compress
from tls.mlkem_files.constants import MLKEMParams

def K_PKE_KeyGen(d: bytes, params: MLKEMParams) -> tuple[bytes, bytes]:
    if len(d) != 32:
        raise ValueError("d must be 32 bytes")
    rho, sigma = G(d)
    A_hat = _generate_matrix(rho, params, transpose=False)

    s = []
    nonce = 0
    for _ in range(params.K):
        prf_out = PRF(params.ETA1, sigma, nonce)
        s.append(SamplePolyCBD(prf_out, params.ETA1))
        nonce += 1
    e = []
    for _ in range(params.K):
        prf_out = PRF(params.ETA1, sigma, nonce)
        e.append(SamplePolyCBD(prf_out, params.ETA1))
        nonce += 1

    s_hat = [NTT(poly) for poly in s]
    e_hat = [NTT(poly) for poly in e]

    t_hat = []
    for i in range(params.K):
        acc = [0] * N
        for j in range(params.K):
            acc = _poly_add(acc, MultiplyNTTs(A_hat[i][j], s_hat[j]))
        t_hat.append(_poly_add(acc, e_hat[i]))

    t_bytes = b"".join(ByteEncode(poly, 12) for poly in t_hat)
    ekPKE = t_bytes + rho
    dkPKE = b"".join(ByteEncode(poly, 12) for poly in s_hat)
    return ekPKE, dkPKE

def K_PKE_Encrypt(ekPKE: bytes, m: bytes, r: bytes, params: MLKEMParams) -> bytes:
    if len(ekPKE) != 384 * params.K + 32:
        raise ValueError("ekPKE length mismatch")
    if len(m) != 32 or len(r) != 32:
        raise ValueError("m and r must be 32 bytes")
    t_hat = [ByteDecode(ekPKE[i*384:(i+1)*384], 12) for i in range(params.K)]
    rho = ekPKE[384 * params.K: 384 * params.K + 32]
    A_hat_T = _generate_matrix(rho, params, transpose=True)

    y = [SamplePolyCBD(PRF(params.ETA1, r, i), params.ETA1) for i in range(params.K)]
    e1 = [SamplePolyCBD(PRF(params.ETA2, r, params.K + i), params.ETA2) for i in range(params.K)]
    e2 = SamplePolyCBD(PRF(params.ETA2, r, 2 * params.K), params.ETA2)

    y_hat = [NTT(poly) for poly in y]

    u = []
    for i in range(params.K):
        acc = [0] * N
        for j in range(params.K):
            acc = _poly_add(acc, MultiplyNTTs(A_hat_T[i][j], y_hat[j]))
        u.append(_poly_add(InvNTT(acc), e1[i]))

    mu = [Decompress(bit, 1) for bit in ByteDecode(m, 1)]

    acc = [0] * N
    for i in range(params.K):
        acc = _poly_add(acc, MultiplyNTTs(t_hat[i], y_hat[i]))
    v = _poly_add(_poly_add(InvNTT(acc), e2), mu)

    c1 = b"".join(ByteEncode([Compress(c, params.DU) for c in poly], params.DU) for poly in u)
    c2 = ByteEncode([Compress(c, params.DV) for c in v], params.DV)
    return c1 + c2

def K_PKE_Decrypt(dkPKE: bytes, c: bytes, params: MLKEMParams) -> bytes:
    if len(dkPKE) != 384 * params.K:
        raise ValueError("dkPKE length mismatch")
    if len(c) != 32 * (params.DU * params.K + params.DV):
        raise ValueError("ciphertext length mismatch")

    split = 32 * params.DU * params.K
    c1, c2 = c[:split], c[split:]

    u_prime = []
    for i in range(params.K):
        seg = c1[i * 32 * params.DU:(i + 1) * 32 * params.DU]
        dec = ByteDecode(seg, params.DU)
        u_prime.append([Decompress(x, params.DU) for x in dec])
    v_prime = [Decompress(x, params.DV) for x in ByteDecode(c2, params.DV)]

    s_hat = [ByteDecode(dkPKE[i*384:(i+1)*384], 12) for i in range(params.K)]

    u_prime_hat = [NTT(poly) for poly in u_prime]
    acc = [0] * N
    for i in range(params.K):
        acc = _poly_add(acc, MultiplyNTTs(s_hat[i], u_prime_hat[i]))
    w = _poly_sub(v_prime, InvNTT(acc))

    compressed = [Compress(x, 1) for x in w]
    return ByteEncode(compressed, 1)

def _generate_matrix(rho: bytes, params: MLKEMParams, transpose: bool) -> list[list[list[int]]]:
    A_hat = [[None for _ in range(params.K)] for _ in range(params.K)]
    for i in range(params.K):
        for j in range(params.K):
            ii, jj = (j, i) if transpose else (i, j)
            standard = SampleNTT(rho, ii, jj)
            A_hat[i][j] = NTT(standard)
    return A_hat

def _poly_add(a, b): return [(x + y) % Q for x, y in zip(a, b)]
def _poly_sub(a, b): return [(x - y) % Q for x, y in zip(a, b)]