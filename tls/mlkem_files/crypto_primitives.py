# Cryptographic primitives for ML-KEM768

from hashlib import sha3_256, shake_256, sha3_512


def PRF(eta: int, s: bytes, b: int) -> bytes:
    """
    Implementuje pseudonáhodnou funkci - PRF
    FIPS 203 Algoritmus 4.3.

    Args:
        eta (int): Parametr určující délku výstupu.
        s (bytes): Vstupní seed pro PRF.
        b (int): Jednobajtový vstup připojený k seedu.

    Returns:
        bytes: Výstup PRF o délce 64 * eta bajtů.
    """
    input_data = s + bytes([b])
    output_length = 64 * eta  # Správná délka výstupu v bajtech
    return shake_256(input_data).digest(output_length)


def H(s: bytes) -> bytes:
    """
    Implementuje hashovací funkci H pomocí SHA3-256.
    FIPS 203 Algoritmus 4.4

    Args:
        s (bytes): Vstupní data pro hashování.

    Returns:
        bytes: 32bajtový hash vstupních dat.
    """
    return sha3_256(s).digest()


def J(s: bytes) -> bytes:
    """
    Implementuje hashovací funkci J pomocí SHAKE-256.
    FIPS 203 Algoritmus 4.4

    Args:
        s (bytes): Vstupní data pro hashování.

    Returns:
        bytes: 32bajtový hash vstupních dat.
    """
    return shake_256(s).digest(32)


def G(c: bytes) -> tuple[bytes, bytes]:
    """
    Implementuje hashovací funkci G pomocí SHA3-512.
    FIPS 203 Algoritmus 4.5

    Args:
        c (bytes): Vstupní data pro hashování.

    Returns:
        tuple[bytes, bytes]: Dvojice obsahující dvě 32bajtové hodnoty odvozené z hashe:
            - Prvních 32 bajtů hashe.
            - Druhých 32 bajtů hashe.
    """
    h = sha3_512(c).digest()
    return h[:32], h[32:]