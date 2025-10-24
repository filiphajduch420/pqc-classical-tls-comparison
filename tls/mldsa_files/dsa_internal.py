"""
Implementace interních (internal) funkcí pro ML-DSA:
- KeyGen_internal (Alg 6)
- Sign_internal (Alg 7)
- Verify_internal (Alg 8)

Tyto funkce jsou deterministické a přijímají veškerou
potřebnou náhodnost jako vstupní parametry.
(FIPS 204, Sekce 6).
"""
import os
from typing import List, Optional
from .constants import Q, D, N, MLDSAParams, get_params_by_id
from .utils import (
    Vector, Poly, mod, mod_pm, bitlen,
    poly_neg, vec_add, vec_sub, vec_inf_norm,
    vec_centered_mod, vec_total_weight
)
from .conversions import BytesToBits, BitsToBytes, IntegerToBytes
from .crypto_primitives import H
from .encode import (
    pkDecode, sigDecode, w1Encode, skDecode, sigEncode,
    pkEncode, skEncode
)
from .sampling import ExpandA, SampleInBall, ExpandMask, ExpandS
from .ntt import NTT, NTT_inv, AddNTT, MultiplyNTT
from .rounding import UseHint, HighBits, LowBits, MakeHint, Power2Round

# Sentinel hodnota pro ⊥ (rejection)
REJECT = None


def ML_DSA_KeyGen_internal(
        xi: bytes,
        params: MLDSAParams
) -> tuple[bytes, bytes]:
    """
    Interní funkce pro generování klíčového páru ze seedu.
    Implementuje Algorithm 6: ML-DSA.KeyGen_internal.
    [cite_start][cite: 608-628]
    """
    # ... (stávající kód Alg 6)
    if len(xi) != 32:
        raise ValueError("Vstupní seed (xi) musí být 32 bajtů")

    k = params.k
    l = params.l

    # 1: (rho, rho_prime, K) <- H(xi || IntegerToBytes(k, 1) || IntegerToBytes(l, 1), 128)
    k_bytes = IntegerToBytes(k, 1)
    l_bytes = IntegerToBytes(l, 1)
    expanded_seed = H(xi + k_bytes + l_bytes, 128)  #

    rho = expanded_seed[0:32]
    rho_prime = expanded_seed[32:96]  # 64 bajtů
    K = expanded_seed[96:128]  # 32 bajtů

    # 3: A_hat <- ExpandA(rho)
    A_hat = ExpandA(rho, k, l)  #

    # 4: (s1, s2) <- ExpandS(rho_prime)
    (s1, s2) = ExpandS(rho_prime, k, l, params.eta)  #

    # 5: t <- NTT_inv(A_hat ∘ NTT(s1)) + s2
    s1_hat = [NTT(poly) for poly in s1]

    t_hat_part1 = []
    for i in range(k):
        sum_poly_ntt = [0] * N
        for j in range(l):
            product = MultiplyNTT(A_hat[i][j], s1_hat[j])
            sum_poly_ntt = AddNTT(sum_poly_ntt, product)
        t_hat_part1.append(sum_poly_ntt)

    t_part1_vec = [NTT_inv(poly) for poly in t_hat_part1]

    t_vec = vec_add(t_part1_vec, s2)  #

    # 6: (t1, t0) <- Power2Round(t)
    t1_vec: Vector = []
    t0_vec: Vector = []
    for poly in t_vec:
        t1_poly: Poly = [0] * N
        t0_poly: Poly = [0] * N
        for j in range(N):
            (r1, r0) = Power2Round(poly[j], D)  #
            t1_poly[j] = r1
            t0_poly[j] = r0
        t1_vec.append(t1_poly)
        t0_vec.append(t0_poly)

    # 8: pk <- pkEncode(rho, t1)
    pk = pkEncode(rho, t1_vec, params)  #

    # 9: tr <- H(pk, 64)
    tr = H(pk, 64)  #

    # 10: sk <- skEncode(rho, K, tr, s1, s2, t0)
    sk = skEncode(rho, K, tr, s1, s2, t0_vec, params)  #

    # 11: return (pk, sk)
    return (pk, sk)  #


def ML_DSA_Sign_internal(
        sk: bytes,
        M_prime: List[int],
        rnd: bytes,
        params: MLDSAParams
) -> bytes:
    """
    Interní funkce pro generování podpisu.
    Implementuje Algorithm 7: ML-DSA.Sign_internal.
    [cite_start][cite: 672-743]
    """
    # ... (stávající kód Alg 7)
    (rho, K, tr, s1, s2, t0) = skDecode(sk, params)
    s1_hat = [NTT(poly) for poly in s1]
    s2_hat = [NTT(poly) for poly in s2]
    t0_hat = [NTT(poly) for poly in t0]
    A_hat = ExpandA(rho, params.k, params.l)

    tr_bits = BytesToBits(tr)
    mu_data_bits = tr_bits + M_prime
    mu_data_bytes = BitsToBytes(mu_data_bits)
    mu = H(mu_data_bytes, 64)

    rho_prime_prime_data = K + rnd + mu
    rho_prime_prime = H(rho_prime_prime_data, 64)

    kappa = 0
    z_vec: Optional[Vector] = REJECT
    h_vec: Optional[Vector] = REJECT

    # Nastavení limitu pro smyčku (viz Appendix C, Table 3)
    max_iterations = 814
    iterations = 0

    while (z_vec is REJECT or h_vec is REJECT) and iterations < max_iterations:
        iterations += 1

        y_vec = ExpandMask(rho_prime_prime, kappa, params.l, params.gamma1)

        y_hat = [NTT(poly) for poly in y_vec]
        w_hat = []
        for i in range(params.k):
            sum_poly_ntt = [0] * N
            for j in range(params.l):
                product = MultiplyNTT(A_hat[i][j], y_hat[j])
                sum_poly_ntt = AddNTT(sum_poly_ntt, product)
            w_hat.append(sum_poly_ntt)
        w_vec = [NTT_inv(poly) for poly in w_hat]

        w1_vec = []
        gamma2 = params.gamma2
        for poly in w_vec:
            w1_poly = [HighBits(c, gamma2) for c in poly]
            w1_vec.append(w1_poly)

        w1_bytes = w1Encode(w1_vec, params)
        c_tilde_data = mu + w1_bytes
        c_tilde = H(c_tilde_data, params.lam // 4)

        c_poly = SampleInBall(c_tilde, params.tau)
        c_hat = NTT(c_poly)

        cs1_hat = [MultiplyNTT(c_hat, s1_hat_poly) for s1_hat_poly in s1_hat]
        cs1_vec = [NTT_inv(poly) for poly in cs1_hat]

        cs2_hat = [MultiplyNTT(c_hat, s2_hat_poly) for s2_hat_poly in s2_hat]
        cs2_vec = [NTT_inv(poly) for poly in cs2_hat]

        z_vec = vec_add(y_vec, cs1_vec)

        w_minus_cs2 = vec_sub(w_vec, cs2_vec)
        r0_vec = []
        for poly in w_minus_cs2:
            r0_poly = [LowBits(c, gamma2) for c in poly]
            r0_vec.append(r0_poly)

        if (vec_inf_norm(z_vec) >= (params.gamma1 - params.beta) or
                vec_inf_norm(r0_vec) >= (params.gamma2 - params.beta)):
            z_vec = REJECT
            h_vec = REJECT

        else:
            ct0_hat = [MultiplyNTT(c_hat, t0_hat_poly) for t0_hat_poly in t0_hat]
            ct0_vec = [NTT_inv(poly) for poly in ct0_hat]

            neg_ct0_vec = [poly_neg(p) for p in ct0_vec]
            tmp_vec = vec_add(w_minus_cs2, ct0_vec)

            h_vec = []
            for i in range(params.k):
                poly_neg_ct0 = neg_ct0_vec[i]
                poly_tmp = tmp_vec[i]
                h_poly = [0] * N
                for j in range(N):
                    h_poly[j] = int(MakeHint(poly_neg_ct0[j], poly_tmp[j], gamma2))
                h_vec.append(h_poly)

            if (vec_inf_norm(ct0_vec) >= gamma2 or
                    vec_total_weight(h_vec) > params.omega):
                z_vec = REJECT
                h_vec = REJECT

        kappa += params.l

    # Pokud smyčka doběhla bez úspěchu
    if z_vec is REJECT or h_vec is REJECT:
        raise RuntimeError(f"Generování podpisu selhalo po {iterations} iteracích (limit: {max_iterations})")

    z_centered = vec_centered_mod(z_vec)
    sigma = sigEncode(c_tilde, z_centered, h_vec, params)

    return sigma


def ML_DSA_Verify_internal(
        pk: bytes,
        M_prime: List[int],
        sigma: bytes,
        params: MLDSAParams
) -> bool:
    """
    Interní funkce pro ověření podpisu.
    Implementuje Algorithm 8: ML-DSA.Verify_internal.
    [cite_start][cite: 769-790]
    """
    # ... (stávající kód Alg 8)

    # Kontrola délky pk (FIPS 204, Sekce 6.3 a 3.6.2)
    # Počítáme bitlen(Q-1) - D přímo
    try:
        bitlen_q_minus_1 = bitlen(Q - 1)
    except ValueError:  # Pokud Q=1, což by nemělo nastat
        raise ValueError("Q musí být > 1")
    len_q_minus_1_d = bitlen_q_minus_1 - D
    expected_pk_len = 32 + params.k * (32 * len_q_minus_1_d)
    if len(pk) != expected_pk_len:
        print(f"Verify Error: Nesprávná délka pk. Očekáváno {expected_pk_len}, dostáno {len(pk)}")
        return False

    # Kontrola délky sigma (FIPS 204, Sekce 6.3 a 3.6.2)
    # Počítáme bitlen(gamma1-1) přímo
    try:
        bitlen_g1_minus_1 = bitlen(params.gamma1 - 1)
    except ValueError:  # Pokud gamma1=1
        bitlen_g1_minus_1 = 0
    len_z_i = 32 * (1 + bitlen_g1_minus_1)
    expected_sigma_len = (params.lam // 4) + (params.l * len_z_i) + params.omega + params.k
    if len(sigma) != expected_sigma_len:
        print(f"Verify Error: Nesprávná délka sigma. Očekáváno {expected_sigma_len}, dostáno {len(sigma)}")
        return False

    # 1: (rho, t1) <- pkDecode(pk)
    try:
        (rho, t1) = pkDecode(pk, params)
    except (ValueError, IndexError) as e:
        print(f"Verify Error: Selhalo pkDecode: {e}")
        return False  # Selhání dekódování pk

    # 2: (c_tilde, z, h) <- sigDecode(sigma)
    try:
        (c_tilde, z, h) = sigDecode(sigma, params)
    except (ValueError, IndexError) as e:
        print(f"Verify Error: Selhalo sigDecode: {e}")
        return False  # Selhání dekódování podpisu

    # 3: if h = ⊥ then return false
    if h is REJECT:
        print("Verify Error: Hint byl REJECT (⊥)")
        return False
    # 4: end if

    # 5: A_hat <- ExpandA(rho)
    A_hat = ExpandA(rho, params.k, params.l)

    # 6: tr <- H(pk, 64)
    tr = H(pk, 64)

    # 7: mu <- (H(BytesToBits(tr)||M', 64))
    tr_bits = BytesToBits(tr)
    mu_data_bits = tr_bits + M_prime
    mu_data_bytes = BitsToBytes(mu_data_bits)
    mu = H(mu_data_bytes, 64)

    # 8: c <- SampleInBall(c_tilde)
    c_poly = SampleInBall(c_tilde, params.tau)

    # 9: w'_approx <- NTT_inv(A_hat ∘ NTT(z) - NTT(c) ∘ NTT(t1 * 2^d))
    ntt_z = [NTT(poly) for poly in z]
    ntt_c = NTT(c_poly)

    scalar = 1 << D
    t1_scaled = []
    for poly in t1:
        scaled_poly = [mod(coeff * scalar, Q) for coeff in poly]
        t1_scaled.append(scaled_poly)

    ntt_t1_scaled = [NTT(poly) for poly in t1_scaled]

    w_approx_part1 = []
    for i in range(params.k):
        sum_poly_ntt = [0] * N
        for j in range(params.l):
            product = MultiplyNTT(A_hat[i][j], ntt_z[j])
            sum_poly_ntt = AddNTT(sum_poly_ntt, product)
        w_approx_part1.append(sum_poly_ntt)

    w_approx_part2 = []
    for i in range(params.k):
        product = MultiplyNTT(ntt_c, ntt_t1_scaled[i])
        w_approx_part2.append(product)

    w_approx_ntt_vec = []
    for i in range(params.k):
        diff_poly = [0] * N
        for j in range(N):
            diff_poly[j] = mod(w_approx_part1[i][j] - w_approx_part2[i][j], Q)
        w_approx_ntt_vec.append(diff_poly)

    w_prime_approx = [NTT_inv(poly) for poly in w_approx_ntt_vec]

    # 10: w1' <- UseHint(h, w'_approx)
    w1_prime = []
    gamma2 = params.gamma2
    for i in range(params.k):
        poly_h = h[i]
        poly_r = w_prime_approx[i]
        new_poly = [0] * N
        for j in range(N):
            new_poly[j] = UseHint(poly_h[j] == 1, poly_r[j], gamma2)
        w1_prime.append(new_poly)

    # 12: c'_tilde <- H(mu || w1Encode(w1'), lambda/4)
    w1_bytes = w1Encode(w1_prime, params)
    c_prime_data = mu + w1_bytes
    c_prime_tilde = H(c_prime_data, params.lam // 4)

    # 13: return [[ ||z||_inf < gamma1 - beta ]] and [[ c_tilde = c'_tilde ]]
    check_hash = (c_tilde == c_prime_tilde)
    if not check_hash:
        print("Verify Error: Hash c_tilde se neshoduje")

    check_norm = True
    bound = params.gamma1 - params.beta
    max_norm_found = 0
    for poly_idx, poly in enumerate(z):
        for coeff_idx, coeff in enumerate(poly):
            abs_coeff = abs(coeff)
            max_norm_found = max(max_norm_found, abs_coeff)
            if abs_coeff >= bound:
                print(
                    f"Verify Error: Norma z je příliš velká ({abs_coeff} >= {bound}) v poly {poly_idx}, coeff {coeff_idx}")
                check_norm = False
                break
        if not check_norm:
            break

    return check_norm and check_hash


# --- TESTOVACÍ FUNKCE ---

def test_sign_verify_internal(variant_id: int):
    """
    Otestuje cyklus KeyGen_internal -> Sign_internal -> Verify_internal.
    """
    print(f"\n--- Spouštím test pro variantu ID: {variant_id} ---")

    # Získání parametrů
    try:
        params = get_params_by_id(variant_id)
        print(f"Parametry načteny: {params.name}")
    except ValueError as e:
        print(f"Chyba: Nepodařilo se načíst parametry: {e}")
        return False

    # 1. KeyGen
    xi = os.urandom(32)
    print("Generuji klíčový pár...")
    try:
        pk, sk = ML_DSA_KeyGen_internal(xi, params)
        print("Klíčový pár vygenerován.")
        # print(f"  pk délka: {len(pk)}")
        # print(f"  sk délka: {len(sk)}")
    except Exception as e:
        print(f"Chyba při KeyGen_internal: {e}")
        return False

    # 2. Příprava zprávy M_prime
    M = b"Toto je testovaci zprava pro ML-DSA."
    ctx = b""  # Prázdný kontext

    # Formátování M' podle Alg 2/3 (prefix || M)
    try:
        prefix = IntegerToBytes(0, 1) + IntegerToBytes(len(ctx), 1) + ctx
        prefix_bits = BytesToBits(prefix)
        M_bits = BytesToBits(M)
        M_prime = prefix_bits + M_bits
        # print(f"Zpráva M naformátována na M_prime (délka bitů: {len(M_prime)})")
    except Exception as e:
        print(f"Chyba při formátování M na M_prime: {e}")
        return False

    # 3. Sign
    rnd = os.urandom(32)  # Hedged varianta
    # rnd = bytes(32) # Deterministická varianta
    print("Generuji podpis (hedged)...")
    try:
        sigma = ML_DSA_Sign_internal(sk, M_prime, rnd, params)
        print("Podpis vygenerován.")
        # print(f"  sigma délka: {len(sigma)}")
    except RuntimeError as e:  # Sign může selhat po limitu iterací
        print(f"Chyba při Sign_internal: {e}")
        return False
    except Exception as e:
        print(f"Chyba při Sign_internal: {e}")
        return False

    # 4. Verify
    print("Ověřuji podpis...")
    try:
        is_valid = ML_DSA_Verify_internal(pk, M_prime, sigma, params)
        print(f"Výsledek ověření: {is_valid}")
        return is_valid
    except Exception as e:
        print(f"Chyba při Verify_internal: {e}")
        return False


if __name__ == "__main__":
    results = {}
    for i in range(3):  # Otestujeme všechny varianty 0, 1, 2
        results[i] = test_sign_verify_internal(i)

    print("\n--- Souhrn testů ---")
    all_passed = True
    for i in range(3):
        status = "PASS" if results[i] else "FAIL"
        print(f"Varianta {i}: {status}")
        if not results[i]:
            all_passed = False

    if all_passed:
        print("\n=> Všechny základní testy prošly!")
    else:
        print("\n=> Některé testy selhaly!")