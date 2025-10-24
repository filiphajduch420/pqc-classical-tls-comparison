"""
Implementace algoritmů pro efektivní (bitové) balení a rozbalení
polynomů s koeficienty v omezeném rozsahu (FIPS 204, Sekce 7.1).
"""
from .constants import N
from .utils import Poly, bitlen
from .conversions import IntegerToBits, BitsToInteger, BitsToBytes, BytesToBits


def SimpleBitPack(w: Poly, b: int) -> bytes:
    """
    Kóduje polynom w (s koeficienty v [0, b]) do byte stringu.
    Implementuje Algorithm 16: SimpleBitPack.
    [cite_start][cite: 900-908]
    """
    # 1: z <- ()
    z: list[int] = []  #
    c = bitlen(b)  # bitlen b

    # 2: for i from 0 to 255 do
    for i in range(N):
        # 3: z <- z || IntegerToBits(w_i, bitlen b)
        z.extend(IntegerToBits(w[i], c))  #
    # 4: end for

    # 5: return BitsToBytes(z)
    return BitsToBytes(z)  #


def BitPack(w: Poly, a: int, b: int) -> bytes:
    """
    Kóduje polynom w (s koeficienty v [-a, b]) do byte stringu.
    Implementuje Algorithm 17: BitPack.
    [cite_start][cite: 909-917]
    """
    # 1: z <- ()
    z: list[int] = []  #
    c = bitlen(a + b)  # bitlen(a + b)

    # 2: for i from 0 to 255 do
    for i in range(N):
        # 3: z <- z || IntegerToBits(b - w_i, bitlen(a + b))
        z.extend(IntegerToBits(b - w[i], c))  #
    # 4: end for

    # 5: return BitsToBytes(z)
    return BitsToBytes(z)  #


def SimpleBitUnpack(v: bytes, b: int) -> Poly:
    """
    Dekóduje byte string v na polynom w (s koeficienty v [0, b]).
    Implementuje Algorithm 18: SimpleBitUnpack.
    [cite_start][cite: 925-936]
    """
    # 1: c <- bitlen b
    c = bitlen(b)  #

    # 2: z <- BytesToBits(v)
    z = BytesToBits(v)  #
    w: Poly = [0] * N

    # 3: for i from 0 to 255 do
    for i in range(N):
        # 4: w_i <- BitsToInteger((z[ic], ... z[ic+c-1]), c)
        bit_slice = z[i * c: (i + 1) * c]
        if len(bit_slice) != c:
            raise ValueError(f"Nedostatek bitů v SimpleBitUnpack pro index {i}")
        w[i] = BitsToInteger(bit_slice, c)  #
    # 5: end for

    # 6: return w
    return w  #


def BitUnpack(v: bytes, a: int, b: int) -> Poly:
    """
    Dekóduje byte string v na polynom w (s koeficienty v [-a, b]).
    Implementuje Algorithm 19: BitUnpack.
    [cite_start][cite: 937-949]
    """
    # 1: c <- bitlen(a + b)
    c = bitlen(a + b)  #

    # 2: z <- BytesToBits(v)
    z = BytesToBits(v)  #
    w: Poly = [0] * N

    # 3: for i from 0 to 255 do
    for i in range(N):
        # 4: w_i <- b - BitsToInteger((z[ic], ... z[ic+c-1]), c)
        bit_slice = z[i * c: (i + 1) * c]
        if len(bit_slice) != c:
            raise ValueError(f"Nedostatek bitů v BitUnpack pro index {i}")
        int_val = BitsToInteger(bit_slice, c)  #
        w[i] = b - int_val
    # 5: end for

    # 6: return w
    return w  #