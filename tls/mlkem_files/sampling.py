# Sampling algorithms for ML-KEM768

from tls.mlkem_files.constants import N, Q
from tls.mlkem_files.utils import BytesToBits
from hashlib import shake_128


def SampleNTT(rho: bytes, i: int, j: int) -> list[int]:
    """
    Generuje pseudonáhodný prvek z T_q (256 koeficientů v NTT doméně)
    na základě seedu rho a indexů i, j.

    Args:
        rho (bytes): Seed o délce 32 bajtů.
        i (int): První index (0-255).
        j (int): Druhý index (0-255).

    Returns:
        list[int]: Pole 256 koeficientů v NTT reprezentaci.

    Raises:
        ValueError: Pokud `rho` nemá délku 32 bajtů nebo indexy nejsou v rozsahu 0-255.
        RuntimeError: Pokud není dostatek bajtů v SHAKE streamu.
    """
    if len(rho) != 32:
        raise ValueError("Seed rho musí mít délku 32 bajtů.")
    if not (0 <= i < 256 and 0 <= j < 256):
        raise ValueError("Indexy i, j musí být v rozsahu 0-255.")

    input_bytes = rho + bytes([i]) + bytes([j])
    xof = shake_128()
    xof.update(input_bytes)

    required_bytes = 1024  # Dostatečně velká konstanta
    byte_stream = xof.digest(required_bytes)

    a_hat = [0] * N
    k = 0
    stream_idx = 0

    while k < N:
        if stream_idx + 3 > len(byte_stream):
            raise RuntimeError("Nedostatek bajtů v SHAKE streamu. Zvětši required_bytes.")

        # Získání 3 bajtů z byte_stream
        C = byte_stream[stream_idx:stream_idx + 3]
        stream_idx += 3

        d1 = C[0] + 256 * (C[1] % 16)
        d2 = (C[1] // 16) + 16 * C[2]

        if d1 < Q:
            a_hat[k] = d1
            k += 1

        if d2 < Q and k < N:
            a_hat[k] = d2
            k += 1

    return a_hat


def SamplePolyCBD(B: bytes, eta: int) -> list[int]:
    """
    Generuje pole 256 koeficientů polynomu ze středované binomické distribuce D_eta(R_q).

    Args:
        B (bytes): Vstupní bajtové pole délky 64 * eta.
        eta (int): Parametr distribuce (ETA1 nebo ETA2).

    Returns:
        list[int]: Pole 256 koeficientů modulo Q.

    Raises:
        ValueError: Pokud `B` nemá správnou délku nebo `eta` není kladné celé číslo.
        RuntimeError: Pokud převod bajtů na bity vrátí nesprávnou délku.
    """
    if eta <= 0:
        raise ValueError("Parametr eta musí být kladné celé číslo.")
    expected_len_bytes = 64 * eta
    if len(B) != expected_len_bytes:
        raise ValueError(f"Délka vstupu B ({len(B)}) neodpovídá {expected_len_bytes} pro eta={eta}")

    b = BytesToBits(B)
    expected_len_bits = expected_len_bytes * 8
    if len(b) != expected_len_bits:
        raise RuntimeError(f"Interní chyba: BytesToBits vrátilo {len(b)} bitů, očekáváno {expected_len_bits}")

    f = [0] * N
    for i in range(N):
        start_index_x = 2 * i * eta
        start_index_y = 2 * i * eta + eta
        x = sum(b[start_index_x + j] for j in range(eta))
        y = sum(b[start_index_y + j] for j in range(eta))
        f[i] = (x - y) % Q
    return f