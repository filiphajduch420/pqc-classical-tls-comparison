"""
Implementace funkcí pro konverzi datových typů
(FIPS 204, Sekce 7.1).
"""
import math
from typing import List
from .constants import Q


def IntegerToBits(x: int, a: int) -> List[int]:
    """
    Vypočítá base-2 reprezentaci x mod 2^a v little-endian pořadí bitů.
    Implementuje Algorithm 9: IntegerToBits.
    [cite_start][cite: 799-809]
    """
    x_prime = x  # 1: x' <- x
    y = [0] * a
    for i in range(a):  # 2
        y[i] = x_prime % 2  # 3
        x_prime = x_prime // 2  # 4
    return y  # 6


def BitsToInteger(y: List[int], a: int) -> int:
    """
    Vypočítá celočíselnou hodnotu z bitového řetězce 'y' o délce 'a'.
    Pseudokód interpretuje pole 'y' v big-endian pořadí.
    Implementuje Algorithm 10: BitsToInteger.
    [cite_start][cite: 810-819]
    """
    if len(y) < a:
        raise ValueError(f"Délka bitového řetězce {len(y)} je menší než 'a' {a}")
    x = 0  # 1
    for i in range(1, a + 1):  # 2
        x = 2 * x + y[a - i]  # 3
    return x  # 5


def IntegerToBytes(x: int, a: int) -> bytes:
    """
    Vypočítá base-256 reprezentaci x mod 256^a (little-endian).
    Implementuje Algorithm 11: IntegerToBytes.
    [cite_start][cite: 820-830]
    """
    x_prime = x  # 1
    y = bytearray(a)
    for i in range(a):  # 2
        y[i] = x_prime % 256  # 3
        x_prime = x_prime // 256  # 4
    return bytes(y)  # 6


def BitsToBytes(y: List[int]) -> bytes:
    """
    Konvertuje bit string (list) na byte string (little-endian).
    Implementuje Algorithm 12: BitsToBytes.
    [cite_start][cite: 834-843]
    """
    a = len(y)
    len_z = math.ceil(a / 8)
    z = bytearray(len_z)  # 1
    for i in range(a):  # 2
        z[i // 8] = z[i // 8] + (y[i] << (i % 8))  # 3
    return bytes(z)  # 5


def BytesToBits(z: bytes) -> List[int]:
    """
    Konvertuje byte string na bit string (list integerů) v little-endian pořadí.
    Implementuje Algorithm 13: BytesToBits.
    [cite_start][cite: 844-858]
    """
    a = len(z)
    y = [0] * (8 * a)
    z_prime = list(z)  # 1
    for i in range(a):  # 2
        for j in range(8):  # 3
            y[8 * i + j] = z_prime[i] % 2  # 4
            z_prime[i] = z_prime[i] // 2  # 5
    return y  # 8


def CoeffFromThreeBytes(b0: int, b1: int, b2: int) -> int | None:
    """
    Generuje prvek z {0, ..., q-1} nebo None (⊥).
    Implementuje Algorithm 14: CoeffFromThreeBytes.
    [cite_start][cite: 862-877]
    """
    b2_prime = b2 & 0x7F  # 1-4
    z = (b2_prime << 16) + (b1 << 8) + b0  # 5
    if z < Q:  # 6
        return z
    else:
        return None  # 7


def CoeffFromHalfByte(b: int, eta: int) -> int | None:
    """
    Generuje prvek z {-eta, ..., eta} nebo None (⊥).
    Implementuje Algorithm 15: CoeffFromHalfByte.
    [cite_start][cite: 881-895]
    """
    if not (0 <= b <= 15):
        raise ValueError("Vstup 'b' musí být v rozsahu [0, 15]")

    if eta == 2:
        # 1: if eta = 2 and b < 15 then return 2 - (b mod 5)
        if b < 15:
            return 2 - (b % 5)
        # 4: else return ⊥
        else:

            return None

    elif eta == 4:
        # 3: if eta = 4 and b < 9 then return 4 - b
        if b < 9:
            return 4 - b
        # 4: else return ⊥
        else:
            return None

    else:
        raise ValueError(f"Nepodporovaná hodnota eta: {eta}")