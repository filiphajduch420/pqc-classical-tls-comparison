"""
Implementace pro Number Theoretic Transform (NTT) a
aritmetiku v NTT doméně (T_q) podle FIPS 204, Sekce 7.5 a 7.6.
"""
from .constants import N, Q, ZETAS
from .utils import Poly, PolyNTT, VectorNTT, mod
from .conversions import IntegerToBits, BitsToInteger

# Konstanty z FIPS 204, Alg 42, řádek 21
# f = 256^(-1) mod q
F_INV_256 = 8347681  # [cite: 1490, 1496]


def NTT(w: Poly) -> PolyNTT:
    """
    Počítá Number Theoretic Transform (NTT).
    Implementuje Algorithm 41: NTT.
    [cite: 1411-1447]
    """
    if len(w) != N:
        raise ValueError(f"Vstupní polynom pro NTT musí mít délku {N}")

    # 1: for j from 0 to 255 do
    # 2:   w_hat[j] <- w_j
    # 3: end for
    w_hat = list(w)  # [cite: 1415-1418]

    m = 0  # [cite: 1419]
    length = 128  # [cite: 1420]

    while length >= 1:  # [cite: 1421]
        start = 0  # [cite: 1422]
        while start < N:  # [cite: 1423]
            m += 1  # [cite: 1424]
            z = ZETAS[m]  # [cite: 1425]

            for j in range(start, start + length):  # [cite: 1426]
                # t <- (z * w_hat[j + length]) mod q
                t = mod(z * w_hat[j + length], Q)  # [cite: 1427]

                # w_hat[j + length] <- (w_hat[j] - t) mod q
                w_hat[j + length] = mod(w_hat[j] - t, Q)  # [cite: 1443]

                # w_hat[j] <- (w_hat[j] + t) mod q
                w_hat[j] = mod(w_hat[j] + t, Q)  # [cite: 1444]

            start = start + 2 * length  # [cite: 1446]

        length = length // 2  # [cite: 1441]

    return w_hat  # [cite: 1447]


def NTT_inv(w_hat: PolyNTT) -> Poly:
    """
    Počítá inverzní NTT.
    Implementuje Algorithm 42: NTT_inv.
    [cite: 1452-1494]
    """
    if len(w_hat) != N:
        raise ValueError(f"Vstupní NTT polynom musí mít délku {N}")

    # 1: for j from 0 to 255 do
    # 2:   w_j <- w_hat[j]
    # 3: end for
    w = list(w_hat)  # [cite: 1456-1459]

    m = N  # [cite: 1460]
    length = 1  # [cite: 1461]

    while length < N:  # [cite: 1462]
        start = 0  # [cite: 1463]
        while start < N:  # [cite: 1464]
            m -= 1  # [cite: 1478]
            z = -ZETAS[m]  # [cite: 1479]

            for j in range(start, start + length):  # [cite: 1480]
                t = w[j]  # [cite: 1481]

                # w_j <- (t + w[j + length]) mod q
                w[j] = mod(t + w[j + length], Q)  # [cite: 1482]

                # w[j + length] <- (t - w[j + length]) mod q
                w[j + length] = mod(t - w[j + length], Q)  # [cite: 1483]

                # w[j + length] <- (z * w[j + length]) mod q
                w[j + length] = mod(z * w[j + length], Q)  # [cite: 1484]

            start = start + 2 * length  # [cite: 1486]

        length = 2 * length  # [cite: 1488]

    # Závěrečné škálování
    # f <- 8347681 [cite: 1490]
    for j in range(N):  # [cite: 1491]
        w[j] = mod(F_INV_256 * w[j], Q)  # [cite: 1492]

    return w  # [cite: 1494]


def BitRev8(m: int) -> int:
    """
    Obrátí pořadí bitů v 8-bitovém integeru (bajtu).
    Implementuje Algorithm 43: BitRev8.
    [cite: 1497-1509]

    Poznámka: Ačkoliv je tato funkce definována, Algoritmy 41 a 42
    ji přímo NEVOLAJÍ. Místo toho používají předpočítanou
    tabulku 'ZETAS', která již bit-reverzi zohledňuje[cite: 1681].
    Tato funkce je zde pro kompletnost (a možná pro jiné účely).
    """
    if not (0 <= m <= 255):
        raise ValueError("Vstup pro BitRev8 musí být v rozsahu [0, 255]")

    # b <- IntegerToBits(m, 8)
    b = IntegerToBits(m, 8)  # [cite: 1501]

    # b_rev <- (0, ..., 0)
    b_rev = [0] * 8  # [cite: 1502]

    # for i from 0 to 7 do
    #   b_rev[i] <- b[7 - i]
    # end for
    for i in range(8):  # [cite: 1503]
        b_rev[i] = b[7 - i]  # [cite: 1505]

    # r <- BitsToInteger(b_rev, 8)
    r = BitsToInteger(b_rev, 8)  # [cite: 1508]

    return r  # [cite: 1509]


# --- Aritmetika v T_q (NTT doméně) ---
# FIPS 204, Sekce 7.6
# (Implementováno v předchozím kroku)

def AddNTT(a_hat: PolyNTT, b_hat: PolyNTT) -> PolyNTT:
    """
    Sčítá dva polynomy v NTT doméně (T_q) po složkách.
    Implementuje Algorithm 44: AddNTT.
    [cite: 1518-1526]
    """
    if len(a_hat) != N or len(b_hat) != N:
        raise ValueError(f"Vstupy AddNTT musí mít délku {N}")

    c_hat: PolyNTT = [0] * N
    for i in range(N):  # [cite: 1522]
        # ĉ[i] ← â[i] + b̂[i]
        c_hat[i] = mod(a_hat[i] + b_hat[i], Q)  # [cite: 1524]
    return c_hat  # [cite: 1526]


def MultiplyNTT(a_hat: PolyNTT, b_hat: PolyNTT) -> PolyNTT:
    """
    Násobí (po složkách) dva polynomy v NTT doméně (T_q).
    Implementuje Algorithm 45: MultiplyNTT.
    [cite: 1527-1535]
    """
    if len(a_hat) != N or len(b_hat) != N:
        raise ValueError(f"Vstupy MultiplyNTT musí mít délku {N}")

    c_hat: PolyNTT = [0] * N
    for i in range(N):  # [cite: 1531]
        # ĉ[i] ← â[i] ⋅ b̂[i]
        c_hat[i] = mod(a_hat[i] * b_hat[i], Q)  # [cite: 1533]
    return c_hat  # [cite: 1535]


def AddVectorNTT(v_hat: VectorNTT, w_hat: VectorNTT) -> VectorNTT:
    """
    Sčítá dva vektory polynomů v NTT doméně (T_q).
    Implementuje Algorithm 46: AddVectorNTT.
    [cite: 1536-1544]
    """
    if len(v_hat) != len(w_hat):
        raise ValueError("Vektory v AddVectorNTT musí mít stejnou délku")

    l = len(v_hat)
    u_hat: VectorNTT = []

    for i in range(l):  # [cite: 1540]
        # û[i] ← AddNTT(v̂[i], ŵ[i])
        u_hat.append(AddNTT(v_hat[i], w_hat[i]))  # [cite: 1542]

    return u_hat  # [cite: 1544]