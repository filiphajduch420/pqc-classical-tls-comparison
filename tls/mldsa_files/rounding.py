"""
Implementace pomocných funkcí pro zaokrouhlování, dekompozici
a zpracování "hints" (FIPS 204, Sekce 7.4).
"""
from .constants import Q, D
from .utils import mod, mod_pm


def Power2Round(r: int, d: int = D) -> tuple[int, int]:
    """
    Dekomponuje r na (r1, r0) tak, že r = r1 * 2^d + r0 (mod q).
    Implementuje Algorithm 35: Power2Round.
    [cite: 1334-1341]
    """
    r_plus = mod(r, Q)  # [cite: 1338]
    modulus_2d = 1 << d

    # r0 <- r+ mod± 2^d
    r0 = mod_pm(r_plus, modulus_2d)  # [cite: 1339]

    # r1 <- (r+ - r0) / 2^d
    r1 = (r_plus - r0) // modulus_2d  # [cite: 1341]

    return (r1, r0)  # [cite: 1341]


def Decompose(r: int, gamma2: int) -> tuple[int, int]:
    """
    Dekomponuje r na (r1, r0) tak, že r = r1 * (2*gamma2) + r0 (mod q).
    Zahrnuje speciální opravu pro (q-1).
    Implementuje Algorithm 36: Decompose.
    [cite: 1342-1357]
    """
    r_plus = mod(r, Q)  # [cite: 1346, 1348]
    alpha = 2 * gamma2

    # r0 <- r+ mod± (2*gamma2)
    r0 = mod_pm(r_plus, alpha)  # [cite: 1349]

    if (r_plus - r0) == (Q - 1):  # [cite: 1350]
        r1 = 0  # [cite: 1353]
        r0 = r0 - 1  # [cite: 1354]
    else:
        r1 = (r_plus - r0) // alpha  # [cite: 1356]

    return (r1, r0)  # [cite: 1357]


def HighBits(r: int, gamma2: int) -> int:
    """
    Vrátí r1 (high bits) z Decompose(r).
    Implementuje Algorithm 37: HighBits.
    [cite: 1358-1363]
    """
    (r1, r0) = Decompose(r, gamma2)  # [cite: 1362]
    return r1  # [cite: 1363]


def LowBits(r: int, gamma2: int) -> int:
    """
    Vrátí r0 (low bits) z Decompose(r).
    Implementuje Algorithm 38: LowBits.
    [cite: 1366-1371]
    """
    (r1, r0) = Decompose(r, gamma2)  # [cite: 1370]
    return r0  # [cite: 1371]


def MakeHint(z: int, r: int, gamma2: int) -> bool:
    """
    Vypočítá "hint bit".
    Vrátí True, pokud se HighBits(r) a HighBits(r+z) liší.
    Implementuje Algorithm 39: MakeHint.
    [cite: 1373-1381]
    """
    r1 = HighBits(r, gamma2)  # [cite: 1377, 1379]

    # Vstup do HighBits musí být v Z_q
    v1 = HighBits(mod(r + z, Q), gamma2)  # [cite: 1378, 1380]

    # [[r1 != v1]] znamená boolean
    return r1 != v1  # [cite: 1381]


def UseHint(h: bool, r: int, gamma2: int) -> int:
    """
    Upraví HighBits(r) na základě "hint bitu" h.
    Implementuje Algorithm 40: UseHint.
    [cite: 1382-1390]
    """
    m = (Q - 1) // (2 * gamma2)  # [cite: 1386]
    (r1, r0) = Decompose(r, gamma2)  # [cite: 1387]

    if h and r0 > 0:  # [cite: 1388]
        return mod(r1 + 1, m)

    if h and r0 <= 0:  # [cite: 1389]
        return mod(r1 - 1, m)

    return r1  # [cite: 1390]