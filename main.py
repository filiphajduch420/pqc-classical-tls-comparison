
from tls.mlkem import MLKEM_KeyGen, MLKEM_Encaps, MLKEM_Decaps
from tls.mlkem_files.constants import get_params_by_id

def sizes_for(params):
    ek_len_expected = 384 * params.K + 32
    dk_len_expected = 768 * params.K + 96
    ct_len_expected = 32 * (params.DU * params.K + params.DV)
    shared_len_expected = 32
    return ek_len_expected, dk_len_expected, ct_len_expected, shared_len_expected

def main():
    variant_id = 0  # 0->512, 1->768, 2->1024
    params = get_params_by_id(variant_id)

    ek, dk = MLKEM_KeyGen(variant_id)
    K_shared, c = MLKEM_Encaps(ek, variant_id)
    K_recv = MLKEM_Decaps(dk, c, variant_id)

    ek_exp, dk_exp, ct_exp, sk_exp = sizes_for(params)

    print(f"Variant {variant_id} ({params.name}) parameters: K={params.K}, ETA1={params.ETA1}, ETA2={params.ETA2}, DU={params.DU}, DV={params.DV}")
    print(f"Public key len:   {len(ek)} bytes (expected {ek_exp})  OK={len(ek)==ek_exp}")
    print(f"Secret key len:   {len(dk)} bytes (expected {dk_exp})  OK={len(dk)==dk_exp}")
    print(f"Ciphertext len:   {len(c)} bytes (expected {ct_exp})  OK={len(c)==ct_exp}")
    print(f"Shared key len:   {len(K_shared)} bytes (expected {sk_exp})  OK={len(K_shared)==sk_exp}")
    print(f"Key match:        {K_shared == K_recv}")

if __name__ == "__main__":
    main()