# The Number-Theoretic Transform pro ML-KEM768

from tls.mlkem_files.constants import ZETAS_BITREV, GAMMAS, N, Q, N_inv


def NTT(f: list[int]) -> list[int]:
    """
    Funkce provádí číselnou teoretickou transformaci (NTT) na poli koeficientů f
    FIPS 203 Algoritmus 9
    Výstup v bitově převráceném pořadí

    Args:
        f (list[int]): Vstupní pole 256 koeficientů

    Returns:
        list[int]: Výstupní pole 256 koeficientů po NTT v bitově převráceném pořadí.
    """
    k = 1  # Index pro ZETAS_BITREV
    l = 128  # Délka pod-transformace (n/2)
    coeffs_copy = f[:]  # Kopie vstupního pole

    # Iterace přes NTT vrstvy
    while l >= 2:
        start = 0  # Začátek bloku
        # Iterace přes bloky v aktuální vrstvě
        while start < 256:  # n=256
            zeta = ZETAS_BITREV[k]
            k += 1
            for j in range(start, start + l):
                t = zeta * coeffs_copy[j + l] % Q
                coeffs_copy[j + l] = (coeffs_copy[j] - t) % Q
                coeffs_copy[j] = (coeffs_copy[j] + t) % Q
            start += 2 * l
        l = l // 2

    return coeffs_copy


def InvNTT(f_hat: list[int]) -> list[int]:
    """
    Funkce provádí inverzní číselnou teoretickou transformaci
    FIPS 203 Algoritmus 10
    Vstupní koeficienty jsou v bitově převráceném pořadí
    Výstupní koeficienty jsou ve standardním pořadí

    Args:
        f_hat (list[int]): Vstupní pole 256 koeficientů v bitově převráceném pořadí

    Returns:
        list[int]: Výstupní pole 256 koeficientů ve standardním pořadí
    """
    k = 127  # Index pro ZETAS_BITREV, začínáme od konce a klesáme
    l = 2  # Počáteční délka pod-transformace
    coeffs_copy = f_hat[:]  # Kopie vstupního pole

    # Iterace přes vrstvy InvNTT
    while l <= 128:
        start = 0  # Začátek bloku
        while start < 256:  # Iterace přes bloky
            zeta = ZETAS_BITREV[k]  # Twiddle faktor
            k -= 1
            for j in range(start, start + l):
                t = coeffs_copy[j]  # Levá hodnota
                coeffs_copy[j] = (t + coeffs_copy[j + l]) % Q  # Aktualizace levé hodnoty
                temp = (coeffs_copy[j + l] - t) % Q  # Rozdíl
                coeffs_copy[j + l] = zeta * temp % Q  # Aktualizace pravé hodnoty
            start += 2 * l  # Další blok
        l *= 2  # Další vrstva

    # Finální škálování: násobení N_inv
    for j in range(256):
        coeffs_copy[j] = coeffs_copy[j] * N_inv % Q

    return coeffs_copy


def MultiplyNTTs(f_hat: list[int], g_hat: list[int]) -> list[int]:
    """
    Vypočítá součin dvou polynomů v jejich NTT reprezentacích.
    FIPS 203 Algoritmus 11.

    Args:
        f_hat (list[int]): NTT reprezentace prvního polynomu (256 koeficientů).
        g_hat (list[int]): NTT reprezentace druhého polynomu (256 koeficientů).

    Returns:
        list[int]: NTT reprezentace výsledného polynomu (256 koeficientů).

    Raises:
        ValueError: Pokud vstupní pole nemají délku 256.
    """
    if len(f_hat) != N or len(g_hat) != N:
        raise ValueError(f"Vstupní pole f_hat a g_hat musí mít délku {N}")

    h_hat = [0] * N  # Inicializace výsledného pole

    # Iterace přes koeficienty
    for i in range(N // 2):  # N/2 = 128
        a0 = f_hat[2 * i]
        a1 = f_hat[2 * i + 1]
        b0 = g_hat[2 * i]
        b1 = g_hat[2 * i + 1]
        gamma = GAMMAS[i]  # Twiddle faktor

        # Výpočet součinu pomocí BaseCaseMultiply
        c0, c1 = BaseCaseMultiply(a0, a1, b0, b1, gamma)

        # Uložení výsledku
        h_hat[2 * i] = c0
        h_hat[2 * i + 1] = c1

    return h_hat


def BaseCaseMultiply(a0: int, a1: int, b0: int, b1: int, gamma: int) -> tuple[int, int]:
    """
    Vypočítá součin dvou polynomů stupně 1 modulo (X^2 - gamma).
    FIPS 203 Algoritmus 12.

    Args:
        a0 (int): Koeficient X^0 prvního polynomu.
        a1 (int): Koeficient X^1 prvního polynomu.
        b0 (int): Koeficient X^0 druhého polynomu.
        b1 (int): Koeficient X^1 druhého polynomu.
        gamma (int): Hodnota definující modul (X^2 - gamma).

    Returns:
        tuple[int, int]: Koeficienty výsledného polynomu (c0, c1).
    """
    # Výpočet koeficientu c0
    c0 = (a0 * b0 + a1 * b1 * gamma) % Q

    # Výpočet koeficientu c1
    c1 = (a0 * b1 + a1 * b0) % Q

    return c0, c1
