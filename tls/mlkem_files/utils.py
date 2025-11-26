from tls.mlkem_files.constants import N, Q


def BitsToBytes(b: list[int]) -> bytes:
    """
    Převádí seznam bitů (0 a 1) na pole bajtů.

    Args:
        b (list[int]): Vstupní seznam bitů, kde délka je násobkem 8.

    Returns:
        bytes: Výstupní pole bajtů.

    Raises:
        ValueError: Pokud délka seznamu není násobkem 8.
    """
    if len(b) % 8 != 0:
        raise ValueError("Délka vstupního seznamu bitů musí být násobkem 8.")

    B = bytearray(len(b) // 8)
    for i in range(len(b)):
        if b[i] == 1:
            B[i // 8] |= (1 << (i % 8))
    return bytes(B)


def BytesToBits(B: bytes) -> list[int]:
    """
    Převádí pole bajtů na seznam bitů.

    Args:
        B (bytes): Vstupní pole bajtů.

    Returns:
        list[int]: Výstupní seznam bitů.
    """
    b = [0] * (8 * len(B))
    for i in range(len(B)):
        for j in range(8):
            b[8 * i + j] = (B[i] >> j) & 1
    return b


def Compress(x: int, d: int) -> int:
    """
    Komprimuje celé číslo z rozsahu Z_q na Z_{2^d}.

    Args:
        x (int): Vstupní číslo.
        d (int): Cílová bitová hloubka.

    Returns:
        int: Komprimované číslo.
    """
    if not (0 < d < 12):
        raise ValueError(f"Bitová hloubka d={d} musí být mezi 1 a 11.")

    scale = 1 << d  # Equivalent to 2^d
    rounded = (scale * x + Q // 2) // Q
    return rounded % scale


def Decompress(y: int, d: int) -> int:
    """
    Dekomprimuje celé číslo z rozsahu Z_{2^d} na Z_q.

    Args:
        y (int): Vstupní číslo.
        d (int): Bitová hloubka.

    Returns:
        int: Dekomprimované číslo.
    """
    if not (0 < d < 12):
        raise ValueError(f"Bitová hloubka d={d} musí být mezi 1 a 11.")

    scale = 1 << d  # Equivalent to 2^d
    offset = 1 << (d - 1)  # Half of the scale
    result = (Q * y + offset) // scale
    return result


def ByteEncode(F: list[int], d: int) -> bytes:
    """
    Kóduje seznam celých čísel do pole bajtů.

    Args:
        F (list[int]): Vstupní seznam čísel.
        d (int): Bitová hloubka.

    Returns:
        bytes: Kódované pole bajtů.
    """
    if len(F) != N:
        raise ValueError(f"Vstupní seznam musí mít délku {N}.")
    b = []
    for a in F:
        for _ in range(d):
            b.append(a % 2)
            a = a // 2
    return BitsToBytes(b)


def ByteDecode(B: bytes, d: int) -> list[int]:
    """
    Dekóduje pole bajtů na seznam celých čísel.

    Args:
        B (bytes): Vstupní pole bajtů.
        d (int): Bitová hloubka.

    Returns:
        list[int]: Dekódovaný seznam čísel.
    """
    b = BytesToBits(B)
    F = [0] * N

    for i in range(N):
        bit_offset = i * d
        for j in range(d):
            F[i] += b[bit_offset + j] * (1 << j)

    return F