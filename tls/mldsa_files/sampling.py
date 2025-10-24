"""
Implementace algoritmů pro pseudonáhodné vzorkování
(FIPS 204, Sekce 7.3).
"""
from .constants import N
from .utils import Poly, PolyNTT, Vector, VectorNTT, MatrixNTT, bitlen
from .crypto_primitives import H, H_Functions, G_Functions
from .conversions import (
    BytesToBits,
    CoeffFromThreeBytes,
    CoeffFromHalfByte,
    IntegerToBytes,
)
from .bitpacking import BitUnpack

# Sentinel hodnota pro ⊥ (rejection)
REJECT = None


def SampleInBall(rho: bytes, tau: int) -> Poly:
    """
    Vzorkuje polynom c ∈ R s koeficienty {-1, 0, 1} a Hammingovou vahou tau.
    Implementuje Algorithm 29: SampleInBall.
    [cite: 1154-1182]

    Vstupy:
        rho: Seed (bajtový řetězec)
        tau: Cílový počet nenulových koeficientů (parametr 𝜏)
    """
    # 1: c <- 0
    c: Poly = [0] * N  # [cite: 1158]

    # 2: ctx <- H.Init()
    ctx = H_Functions.Init()  # [cite: 1159]
    # 3: ctx <- H.Absorb(ctx, rho)
    H_Functions.Absorb(ctx, rho)  # [cite: 1160]

    # 4: (ctx, s) <- H.Squeeze(ctx, 8)
    ctx, s = H_Functions.Squeeze(ctx, 8)  # [cite: 1161]

    # 5: h <- BytesToBits(s)
    h = BytesToBits(s)  # [cite: 1163]
    if len(h) != 64:
        raise RuntimeError(f"BytesToBits(8 bytes) vrátil {len(h)} bitů, očekáváno 64")

    # 6: for i from 256 - tau to 255 do
    for i in range(N - tau, N):  # [cite: 1164]
        # 7: (ctx, j_bytes) <- H.Squeeze(ctx, 1)
        ctx, j_bytes = H_Functions.Squeeze(ctx, 1)  # [cite: 1168]
        j = j_bytes[0]  # Převedeme bajt na integer

        # 8: while j > i do
        while j > i:  # [cite: 1171]
            # 9: (ctx, j_bytes) <- H.Squeeze(ctx, 1)
            ctx, j_bytes = H_Functions.Squeeze(ctx, 1)  # [cite: 1173]
            j = j_bytes[0]
        # 10: end while

        # 11: c_i <- c_j
        c[i] = c[j]  # [cite: 1178]

        # 12: c_j <- (-1)^h[i + tau - 256]
        # Výpočet indexu pro pole h (viz myšlenkový pochod nahoře)
        sign_bit_index = i + tau - N
        sign_bit = h[sign_bit_index]  # [cite: 1180]
        c[j] = (-1) ** sign_bit

    # 13: end for
    return c  # [cite: 1182]


def RejNTTPoly(rho: bytes) -> PolyNTT:
    """
    Vzorkuje polynom â ∈ T_q pomocí rejection samplingu.
    Implementuje Algorithm 30: RejNTTPoly.
    [cite: 1192-1213]

    Vstup:
        rho: Seed (34 bajtů)
    """
    if len(rho) != 34:
        raise ValueError("Seed pro RejNTTPoly musí být 34 bajtů")

    a_hat: PolyNTT = [0] * N
    j = 0  # [cite: 1196]

    # 2: ctx <- G.Init()
    ctx = G_Functions.Init()  # [cite: 1197]
    # 3: ctx <- G.Absorb(ctx, rho)
    G_Functions.Absorb(ctx, rho)  # [cite: 1199]

    # 4: while j < 256 do
    while j < N:  # [cite: 1206]
        # 5: (ctx, s) <- G.Squeeze(ctx, 3)
        ctx, s = G_Functions.Squeeze(ctx, 3)  # [cite: 1202]

        # 6: a_hat[j] <- CoeffFromThreeBytes(s[0], s[1], s[2])
        coeff = CoeffFromThreeBytes(s[0], s[1], s[2])  # [cite: 1207]

        # 7: if a_hat[j] != ⊥ then
        if coeff is not REJECT:  # [cite: 1208]
            a_hat[j] = coeff
            # 8: j <- j + 1
            j += 1  # [cite: 1209]
        # 9: end if
    # 10: end while
    return a_hat  # [cite: 1213]


def RejBoundedPoly(rho: bytes, eta: int) -> Poly:
    """
    Vzorkuje polynom a ∈ R s koeficienty v [-eta, eta].
    Implementuje Algorithm 31: RejBoundedPoly.
    [cite: 1214-1246]

    Vstupy:
        rho: Seed (66 bajtů)
        eta: Rozsah koeficientů (parametr 𝜂)
    """
    if len(rho) != 66:
        raise ValueError("Seed pro RejBoundedPoly musí být 66 bajtů")

    a: Poly = [0] * N
    j = 0  # [cite: 1218]

    # 2: ctx <- H.Init()
    ctx = H_Functions.Init()  # [cite: 1219]
    # 3: ctx <- H.Absorb(ctx, rho)
    H_Functions.Absorb(ctx, rho)  # [cite: 1220]

    # 4: while j < 256 do
    while j < N:  # [cite: 1222]
        # 5: z_bytes <- H.Squeeze(ctx, 1)
        ctx, z_bytes = H_Functions.Squeeze(ctx, 1)  # [cite: 1232]
        z = z_bytes[0]  # Převedeme bajt na integer

        # 6: z0 <- CoeffFromHalfByte(z mod 16)
        z0 = CoeffFromHalfByte(z % 16, eta)  # [cite: 1233]

        # 7: z1 <- CoeffFromHalfByte(floor(z / 16))
        z1 = CoeffFromHalfByte(z // 16, eta)  # [cite: 1234]

        # 8: if z0 != ⊥ then
        if z0 is not REJECT:  # [cite: 1235]
            # 9: a_j <- z0
            a[j] = z0  # [cite: 1236]
            # 10: j <- j + 1
            j += 1  # [cite: 1237]
        # 11: end if

        # 12: if z1 != ⊥ and j < 256 then
        if z1 is not REJECT and j < N:  # [cite: 1239]
            # 13: a_j <- z1
            a[j] = z1  # [cite: 1240]
            # 14: j <- j + 1
            j += 1  # [cite: 1242]
        # 15: end if
    # 16: end while
    return a  # [cite: 1246]


def ExpandA(rho: bytes, k: int, l: int) -> MatrixNTT:
    """
    Vzorkuje matici Â (k x l) polynomů v NTT doméně.
    Implementuje Algorithm 32: ExpandA.
    [cite: 1250-1263]

    Vstupy:
        rho: Seed (32 bajtů)
        k, l: Rozměry matice (z MLDSAParams)
    """
    if len(rho) != 32:
        raise ValueError("Seed pro ExpandA musí být 32 bajtů")

    A_hat: MatrixNTT = []
    # 1: for r from 0 to k-1 do
    for r in range(k):  # [cite: 1254]
        row: VectorNTT = []
        # 2: for s from 0 to l-1 do
        for s in range(l):  # [cite: 1255]
            # 3: rho' <- rho || IntegerToBytes(s, 1) || IntegerToBytes(r, 1)
            s_bytes = IntegerToBytes(s, 1)
            r_bytes = IntegerToBytes(r, 1)
            rho_prime = rho + s_bytes + r_bytes  # [cite: 1256]

            # 4: A_hat[r, s] <- RejNTTPoly(rho')
            row.append(RejNTTPoly(rho_prime))  # [cite: 1257]
        # 5: end for
        A_hat.append(row)
    # 6: end for
    return A_hat  # [cite: 1263]


def ExpandS(rho: bytes, k: int, l: int, eta: int) -> tuple[Vector, Vector]:
    """
    Vzorkuje vektory s1 (délka l) a s2 (délka k) s koeficienty v [-eta, eta].
    Implementuje Algorithm 33: ExpandS.
    [cite: 1265-1281]

    Vstupy:
        rho: Seed (64 bajtů)
        k, l, eta: Parametry z MLDSAParams
    """
    if len(rho) != 64:
        raise ValueError("Seed pro ExpandS musí být 64 bajtů")

    s1: Vector = []
    s2: Vector = []

    # 1: for r from 0 to l-1 do
    for r in range(l):  # [cite: 1270]
        # 2: s1[r] <- RejBoundedPoly(rho || IntegerToBytes(r, 2))
        r_bytes = IntegerToBytes(r, 2)
        rho_prime_s1 = rho + r_bytes  # [cite: 1272]
        s1.append(RejBoundedPoly(rho_prime_s1, eta))  # [cite: 1272]
    # 3: end for

    # 4: for r from 0 to k-1 do
    for r in range(k):  # [cite: 1276]
        # 5: s2[r] <- RejBoundedPoly(rho || IntegerToBytes(r + l, 2))
        rl_bytes = IntegerToBytes(r + l, 2)
        rho_prime_s2 = rho + rl_bytes  # [cite: 1278]
        s2.append(RejBoundedPoly(rho_prime_s2, eta))  # [cite: 1278]
    # 6: end for

    return (s1, s2)  # [cite: 1281]


def ExpandMask(rho: bytes, mu: int, l: int, gamma1: int) -> Vector:
    """
    Vzorkuje maskovací vektor y (délka l) s koeficienty v [-gamma1+1, gamma1].
    Implementuje Algorithm 34: ExpandMask.
    [cite: 1282-1296]

    Vstupy:
        rho: Seed (64 bajtů)
        mu: Nonce (kappa, 𝜅)
        l, gamma1: Parametry z MLDSAParams
    """
    if len(rho) != 64:
        raise ValueError("Seed pro ExpandMask musí být 64 bajtů")

    # 1: c <- 1 + bitlen(gamma1 - 1)
    # Poznámka: FIPS říká, že gamma1 je mocnina 2[cite: 1297].
    # bitlen(2^n - 1) je n.
    # bitlen(a+b) pro BitUnpack je bitlen(gamma1-1 + gamma1) = bitlen(2*gamma1 - 1)
    # Pokud gamma1 = 2^17, pak 2*gamma1 - 1 = 2^18 - 1. bitlen = 18.
    # Alg 34, ř. 1: c = 1 + bitlen(2^17 - 1) = 1 + 17 = 18. Shoduje se.
    c = bitlen((gamma1 - 1) + gamma1)  # [cite: 1287, 943]

    y: Vector = []

    # 2: for r from 0 to l-1 do
    for r in range(l):  # [cite: 1288]
        # 3: rho' <- rho || IntegerToBytes(mu + r, 2)
        mur_bytes = IntegerToBytes(mu + r, 2)
        rho_prime = rho + mur_bytes  # [cite: 1292]

        # 4: v <- H(rho', 32 * c)
        v = H(rho_prime, 32 * c)  # [cite: 1293]

        # 5: y[r] <- BitUnpack(v, gamma1 - 1, gamma1)
        y.append(BitUnpack(v, gamma1 - 1, gamma1))  # [cite: 1294]
    # 6: end for

    return y  # [cite: 1296]