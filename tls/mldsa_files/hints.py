"""
Implementace algoritmů pro balení a rozbalení "hint" vektorů
(FIPS 204, Sekce 7.1).
"""
from typing import Optional
from .constants import N
from .utils import Vector, Poly
from .constants import MLDSAParams  # Potřebujeme k a omega

# Sentinel hodnota pro ⊥ (rejection)
REJECT = None


def HintBitPack(h: Vector, params: MLDSAParams) -> bytes:
    """
    Kóduje "hint" vektor h (s binárními koeficienty) do byte stringu.
    Implementuje Algorithm 20: HintBitPack.
    [cite: 958-984]

    Vstupy:
        h: Vektor (délky k) polynomů (délky N)
        params: Parametry (pro k a omega)
    """
    k = params.k
    omega = params.omega

    # 1: y <- 0^{omega+k}
    y = bytearray(omega + k)  #

    # 2: Index <- 0
    Index = 0  #

    # 3: for i from 0 to k-1 do
    for i in range(k):  #
        # 4: for j from 0 to 255 do
        for j in range(N):  #
            # 5: if h[i][j] != 0 then
            if h[i][j] != 0:  #
                # 6: y[Index] <- j
                y[Index] = j  #
                # 7: Index <- Index + 1
                Index += 1  #
            # 8: end if
        # 9: end for

        # 10: y[omega + i] <- Index
        y[omega + i] = Index  #
    # 11: end for

    # 12: return y
    return bytes(y)  #


def HintBitUnpack(y: bytes, params: MLDSAParams) -> Optional[Vector]:
    """
    Dekóduje byte string y zpět na "hint" vektor h.
    Vrací None (⊥) při selhání (malformed input).
    Implementuje Algorithm 21: HintBitUnpack.
    [cite: 985-1031]

    Vstupy:
        y: Byte string (délky omega + k)
        params: Parametry (pro k a omega)
    """
    k = params.k
    omega = params.omega

    if len(y) != (omega + k):
        raise ValueError(f"Neplatná délka vstupu y pro HintBitUnpack: {len(y)}")

    # 1: h <- 0^k
    # Vytvoříme vektor 'k' nulových polynomů
    h: Vector = [[0] * N for _ in range(k)]  #

    # 2: Index <- 0
    Index = 0  #

    # 3: for i from 0 to k-1 do
    for i in range(k):  #
        # 4: if y[omega + i] < Index or y[omega + i] > omega then return ⊥
        if y[omega + i] < Index or y[omega + i] > omega:  #
            return REJECT  #
        # 5: end if

        # 6: First <- Index
        First = Index  #

        # 7: while Index < y[omega + i] do
        while Index < y[omega + i]:  #
            # 8: if Index > First then
            if Index > First:  #
                # 9: if y[Index - 1] >= y[Index] then return ⊥
                if y[Index - 1] >= y[Index]:  #
                    return REJECT  #
                # 10: end if
            # 11: end if

            # 12: h[i][y[Index]] <- 1
            # y[Index] obsahuje j (index koeficientu), který má být 1
            coeff_index = y[Index]
            if coeff_index >= N:  # Další kontrola (není v pseudokódu, ale logická)
                return REJECT
            h[i][coeff_index] = 1  #

            # 13: Index <- Index + 1
            Index += 1  #
        # 14: end while
    # 15: end for

    # 16: for i from Index to omega - 1 do
    # Kontrola zbývajících (padding) bajtů v první omega části
    for i in range(Index, omega):  #
        # 17: if y[i] != 0 then return ⊥
        if y[i] != 0:  #
            return REJECT  #
        # 18: end if
    # 19: end for

    # 20: return h
    return h  #