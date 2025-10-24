"""
Pomocné funkce, konstanty a definice datových typů pro FIPS 204 (ML-DSA).
"""
from typing import List
from .constants import Q, N

# --- Definice vlastních typů ---
# Pro lepší čitelnost kódu

# Polynomial v koeficientové reprezentaci (R nebo R_q)
# list[int] o délce N
Poly = List[int]

# Polynomial v NTT (bodové) reprezentaci (T_q)
# list[int] o délce N [cite: 1517]
PolyNTT = List[int]

# Vektor polynomialů v koeficientové reprezentaci
Vector = List[Poly]

# Vektor polynomialů v NTT reprezentaci (T_q^l)
VectorNTT = List[PolyNTT]

# Matice polynomialů v koeficientové reprezentaci
Matrix = List[Vector]

# Matice polynomialů v NTT reprezentaci (T_q^{k x l})
MatrixNTT = List[VectorNTT]


# --- Aritmetické pomocné funkce ---

def mod(a: int, q: int = Q) -> int:
    """
    Vrátí 'a mod q' ve standardním rozsahu [0, q-1].
    Zpracovává správně i záporná čísla 'a'.
    """
    # Pythoní operátor % se chová jako 'mod' (např. -1 % 8380417 == 8380416)
    return a % q


def mod_pm(a: int, modulus: int) -> int:
    """
    Implementuje operátor mod± (centrovaný modulus).
    Vrátí jedinečný prvek m' v rozsahu (-modulus/2, modulus/2].

    Tato implementace je založena na definici v FIPS 204, Sekce 2.3.

    """
    # 1. Získání 'a' v rozsahu [0, modulus-1]
    a_prime = mod(a, modulus)

    # 2. Posunutí do rozsahu (-modulus/2, modulus/2]
    # (modulus // 2) je floor(modulus/2)
    if a_prime > (modulus // 2):
        a_prime -= modulus

    return a_prime


def bitlen(a: int) -> int:
    """
    Vrátí bitovou délku pozitivního integeru 'a'.
    Definice FIPS 204, Sekce 2.3.

    Poznámka: FIPS 204 uvádí, že bitlen 32 = 6 a bitlen 31 = 5.
    Funkce int.bit_length() v Pythonu dělá přesně toto.
    """
    if a < 0:
        raise ValueError("bitlen je definován pouze pro pozitivní celá čísla")
    # int.bit_length() vrací 0 pro vstup 0, ale FIPS 204 jej volá
    # jen na hodnotách jako (gamma1 - 1), které jsou > 0.
    return a.bit_length()


def poly_add(p1: Poly, p2: Poly) -> Poly:
    """Sčítání polynomů po koeficientech (mod q)."""
    return [mod(c1 + c2, Q) for c1, c2 in zip(p1, p2)]


def poly_sub(p1: Poly, p2: Poly) -> Poly:
    """Odčítání polynomů po koeficientech (mod q)."""
    return [mod(c1 - c2, Q) for c1, c2 in zip(p1, p2)]


def poly_neg(p: Poly) -> Poly:
    """Negace polynomu po koeficientech (mod q)."""
    return [mod(-c, Q) for c in p]


# --- Aritmetika vektorů (po polynomech) ---

def vec_add(v1: Vector, v2: Vector) -> Vector:
    """Sčítání vektorů po složkách."""
    if len(v1) != len(v2):
        raise ValueError("Vektory musí mít stejnou délku pro sčítání.")
    return [poly_add(p1, p2) for p1, p2 in zip(v1, v2)]


def vec_sub(v1: Vector, v2: Vector) -> Vector:
    """Odčítání vektorů po složkách."""
    if len(v1) != len(v2):
        raise ValueError("Vektory musí mít stejnou délku pro odčítání.")
    return [poly_sub(p1, p2) for p1, p2 in zip(v1, v2)]


# --- Normy a další operace ---

def poly_inf_norm(p: Poly) -> int:
    """
    Počítá ||p||_inf (infinity normu polynomu).
    Najde maximální absolutní hodnotu centrovaného koeficientu.
    [cite: 215]
    """
    # mod_pm(c, Q) centruje koeficient v (-(q-1)/2, (q-1)/2]
    return max(abs(mod_pm(c, Q)) for c in p)


def vec_inf_norm(v: Vector) -> int:
    """Počítá ||v||_inf (infinity normu vektoru)."""
    return max(poly_inf_norm(p) for p in v)


def vec_centered_mod(v: Vector) -> Vector:
    """Aplikuje mod±q na každý koeficient každého polynomu ve vektoru."""
    new_v = []
    for p in v:
        new_v.append([mod_pm(c, Q) for c in p])
    return new_v


def vec_total_weight(h: Vector) -> int:
    """Spočítá celkový počet nenulových koeficientů ve vektoru h."""
    total_weight = 0
    for poly in h:
        for coeff in poly:
            if coeff != 0:
                total_weight += 1
    return total_weight