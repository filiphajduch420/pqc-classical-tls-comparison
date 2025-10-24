"""
Implementace pro kódování a dekódování klíčů a podpisů
(FIPS 204, Sekce 7.2).

Tyto funkce závisí na pomocných funkcích v:
- bitpacking.py (SimpleBitPack, SimpleBitUnpack, BitPack, BitUnpack)
- hints.py (HintBitPack, HintBitUnpack)
"""
from .constants import Q, D, N
from .utils import Vector, Poly, bitlen
from .constants import MLDSAParams  # Potřebujeme k, l, eta, atd.
from .bitpacking import SimpleBitPack, SimpleBitUnpack, BitPack, BitUnpack
from .hints import HintBitPack, HintBitUnpack

# Sentinel hodnota pro ⊥ (rejection)
REJECT = None


def pkEncode(rho: bytes, t1: Vector, params: MLDSAParams) -> bytes:
    """
    Kóduje veřejný klíč.
    Implementuje Algorithm 22: pkEncode.
    [cite: 1040-1048]
    """
    # Parametr 'b' pro SimpleBitPack
    b = (1 << (bitlen(Q - 1) - D)) - 1  # b = 2**(bitlen(q-1)-d) - 1

    pk = bytearray(rho)  # 1: pk <- rho

    # 2: for i from 0 to k-1 do
    for i in range(params.k):  #
        # 3: pk <- pk || SimpleBitPack(t1[i], b)
        pk.extend(SimpleBitPack(t1[i], b))  #
    # 4: end for

    # 5: return pk
    return bytes(pk)  #


def pkDecode(pk: bytes, params: MLDSAParams) -> tuple[bytes, Vector]:
    """
    Dekóduje veřejný klíč.
    Implementuje Algorithm 23: pkDecode.
    [cite: 1049-1057]
    """
    k = params.k

    # Vypočítáme délku 'b'
    len_q_minus_1_d = bitlen(Q - 1) - D
    b = (1 << len_q_minus_1_d) - 1

    # Vypočítáme délku jednoho packed polynomu z_i
    # (viz Alg 23, řádek 1: 32 * (bitlen(q-1)-d))
    len_z_i = 32 * len_q_minus_1_d

    # 1: (rho, z_0, ..., z_k-1) <- pk
    rho = pk[0:32]
    if len(rho) != 32:
        raise ValueError("Neplatná délka pk (část rho)")

    t1: Vector = []
    ptr = 32

    # 2: for i from 0 to k-1 do
    for i in range(k):  #
        # 3: t1[i] <- SimpleBitUnpack(z_i, b)
        z_i = pk[ptr: ptr + len_z_i]
        if len(z_i) != len_z_i:
            raise ValueError(f"Neplatná délka pk (část z_{i})")

        t1.append(SimpleBitUnpack(z_i, b))  #
        ptr += len_z_i

    if ptr != len(pk):
        raise ValueError("Neplatná celková délka pk")

    # 5: return (rho, t1)
    return (rho, t1)  #


def skEncode(rho: bytes, K: bytes, tr: bytes, s1: Vector, s2: Vector, t0: Vector, params: MLDSAParams) -> bytes:
    """
    Kóduje soukromý klíč.
    Implementuje Algorithm 24: skEncode.
    [cite: 1064-1081]
    """
    eta = params.eta
    k = params.k
    l = params.l

    # 1: sk <- rho || K || tr
    sk = bytearray(rho)  #
    sk.extend(K)
    sk.extend(tr)

    # 2: for i from 0 to l-1 do
    for i in range(l):  #
        # 3: sk <- sk || BitPack(s1[i], eta, eta)
        sk.extend(BitPack(s1[i], eta, eta))  #
    # 4: end for

    # 5: for i from 0 to k-1 do
    for i in range(k):  #
        # 6: sk <- sk || BitPack(s2[i], eta, eta)
        sk.extend(BitPack(s2[i], eta, eta))  #
    # 7: end for

    # 8: for i from 0 to k-1 do
    t0_a = (1 << (D - 1)) - 1  # 2**(d-1) - 1
    t0_b = (1 << (D - 1))  # 2**(d-1)
    for i in range(k):  #
        # 9: sk <- sk || BitPack(t0[i], 2**(d-1)-1, 2**(d-1))
        sk.extend(BitPack(t0[i], t0_a, t0_b))  #
    # 10: end for

    # 11: return sk
    return bytes(sk)  #


def skDecode(sk: bytes, params: MLDSAParams) -> tuple[bytes, bytes, bytes, Vector, Vector, Vector]:
    """
    Dekóduje soukromý klíč.
    Implementuje Algorithm 25: skDecode.
    [cite: 1082-1104]
    """
    k = params.k
    l = params.l
    eta = params.eta

    # Vypočítáme délky jednotlivých komponent
    len_rho = 32
    len_K = 32
    len_tr = 64

    # bitlen(a+b) = bitlen(eta+eta) = bitlen(2*eta)
    len_s_i = 32 * bitlen(2 * eta)
    # bitlen(a+b) = bitlen((2**(d-1)-1) + 2**(d-1)) = bitlen(2**d - 1) = d
    len_t0_i = 32 * D

    # 1: (rho, K, tr, y_0...y_l-1, z_0...z_k-1, w_0...w_k-1) <- sk
    s1: Vector = []
    s2: Vector = []
    t0: Vector = []

    ptr = 0
    rho = sk[ptr: ptr + len_rho]
    ptr += len_rho

    K = sk[ptr: ptr + len_K]
    ptr += len_K

    tr = sk[ptr: ptr + len_tr]
    ptr += len_tr

    # 2: for i from 0 to l-1 do
    for i in range(l):  #
        y_i = sk[ptr: ptr + len_s_i]
        # 3: s1[i] <- BitUnpack(y_i, eta, eta)
        s1.append(BitUnpack(y_i, eta, eta))  #
        ptr += len_s_i
    # 4: end for

    # 5: for i from 0 to k-1 do
    for i in range(k):  #
        z_i = sk[ptr: ptr + len_s_i]
        # 6: s2[i] <- BitUnpack(z_i, eta, eta)
        s2.append(BitUnpack(z_i, eta, eta))  #
        ptr += len_s_i
    # 7: end for

    # 8: for i from 0 to k-1 do
    t0_a = (1 << (D - 1)) - 1  # 2**(d-1) - 1
    t0_b = (1 << (D - 1))  # 2**(d-1)
    for i in range(k):  #
        w_i = sk[ptr: ptr + len_t0_i]
        # 9: t0[i] <- BitUnpack(w_i, 2**(d-1)-1, 2**(d-1))
        t0.append(BitUnpack(w_i, t0_a, t0_b))  #
        ptr += len_t0_i
    # 10: end for

    if ptr != len(sk) or len(rho) != 32 or len(K) != 32 or len(tr) != 64:
        raise ValueError("Neplatná délka sk při dekódování")

    # 11: return (rho, K, tr, s1, s2, t0)
    return (rho, K, tr, s1, s2, t0)  #


def sigEncode(c_tilde: bytes, z: Vector, h: Vector, params: MLDSAParams) -> bytes:
    """
    Kóduje podpis.
    Implementuje Algorithm 26: sigEncode.
    [cite: 1111-1122]
    """
    l = params.l
    gamma1 = params.gamma1

    # 1: sigma <- c_tilde
    sigma = bytearray(c_tilde)  #

    # 2: for i from 0 to l-1 do
    for i in range(l):  #
        # 3: sigma <- sigma || BitPack(z[i], gamma1 - 1, gamma1)
        sigma.extend(BitPack(z[i], gamma1 - 1, gamma1))  #
    # 4: end for

    # 5: sigma <- sigma || HintBitPack(h)
    # HintBitPack (Alg 20) bude potřebovat omega a k z params
    sigma.extend(HintBitPack(h, params))  #

    # 6: return sigma
    return bytes(sigma)  #


def sigDecode(sigma: bytes, params: MLDSAParams) -> tuple[bytes, Vector, Vector | None]:
    """
    Dekóduje podpis.
    Implementuje Algorithm 27: sigDecode.
    [cite: 1123-1133]
    """
    l = params.l
    k = params.k
    gamma1 = params.gamma1
    lam_bytes = params.lam // 4  # lambda/4
    omega = params.omega

    # Vypočítáme délky komponent
    len_c_tilde = lam_bytes
    # bitlen(a+b) = bitlen((gamma1-1) + gamma1) = bitlen(2*gamma1 - 1)
    # Protože gamma1 je mocnina 2, bitlen(2*gamma1 - 1) = 1 + bitlen(gamma1 - 1)
    len_z_i = 32 * (1 + bitlen(gamma1 - 1))
    len_h = omega + k

    # 1: (c_tilde, x_0...x_l-1, y) <- sigma
    z: Vector = []

    ptr = 0
    c_tilde = sigma[ptr: ptr + len_c_tilde]
    ptr += len_c_tilde

    # 2: for i from 0 to l-1 do
    for i in range(l):  #
        x_i = sigma[ptr: ptr + len_z_i]
        # 3: z[i] <- BitUnpack(x_i, gamma1 - 1, gamma1)
        z.append(BitUnpack(x_i, gamma1 - 1, gamma1))  #
        ptr += len_z_i
    # 4: end for

    y = sigma[ptr: ptr + len_h]
    ptr += len_h

    if ptr != len(sigma) or len(c_tilde) != len_c_tilde or len(y) != len_h:
        raise ValueError("Neplatná délka podpisu při dekódování")

    # 5: h <- HintBitUnpack(y)
    # HintBitUnpack (Alg 21) vrací ⊥ (None) při chybě
    h = HintBitUnpack(y, params)  #

    # 6: return (c_tilde, z, h)
    return (c_tilde, z, h)  #


def w1Encode(w1: Vector, params: MLDSAParams) -> bytes:
    """
    Kóduje w1.
    Implementuje Algorithm 28: w1Encode.
    [cite: 1136-1143]
    """
    k = params.k
    gamma2 = params.gamma2

    # Vypočítáme parametr 'b' pro SimpleBitPack
    b = (Q - 1) // (2 * gamma2) - 1

    # 1: w1_tilde <- ()
    w1_tilde = bytearray()  #

    # 2: for i from 0 to k-1 do
    for i in range(k):  #
        # 3: w1_tilde <- w1_tilde || SimpleBitPack(w1[i], b)
        w1_tilde.extend(SimpleBitPack(w1[i], b))  #
    # 4: end for

    # 5: return w1_tilde
    return bytes(w1_tilde)  #