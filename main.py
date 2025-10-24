from tls.mlkem import MLKEM_KeyGen, MLKEM_Encaps, MLKEM_Decaps
from tls.mlkem_files.constants import get_params_by_id

def main():
    for variant_id in range(3):  # 0->512, 1->768, 2->1024
        params = get_params_by_id(variant_id)
        ek, dk = MLKEM_KeyGen(variant_id)

        r1, r2 = MLKEM_Encaps(ek, variant_id)
        expected_ct_len = 32 * (params.DU * params.K + params.DV)
        expected_ss_len = 32

        if len(r1) == expected_ct_len and len(r2) == expected_ss_len:
            ct, ss_enc = r1, r2
        elif len(r2) == expected_ct_len and len(r1) == expected_ss_len:
            ct, ss_enc = r2, r1
        else:
            raise RuntimeError(f"Unexpected MLKEM_Encaps return lengths: {len(r1)} and {len(r2)} for variant {variant_id}")

        ss_dec = MLKEM_Decaps(dk, ct, variant_id)

        print(f"Variant {variant_id} ({params.name}):")
        print(f"  Public key (EK) len: {len(ek)}  | EK: {ek.hex()}")
        print(f"  Secret key (DK) len: {len(dk)}  | DK: {dk.hex()}")
        print(f"  Ciphertext (CT) len: {len(ct)} | CT: {ct.hex()}")
        print(f"  Shared secret (encaps) len: {len(ss_enc)} | {ss_enc.hex()}")
        print(f"  Shared secret (decaps) len: {len(ss_dec)} | {ss_dec.hex()}")
        print(f"  Shared secrets match: {ss_enc == ss_dec}\n")

if __name__ == "__main__":
    main()
