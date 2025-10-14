from dataclasses import dataclass

# Shared constants (identical across variants)
N = 256
Q = 3329
N_INV = 3303  # keep original name if used elsewhere (or alias N_inv)
N_inv = N_INV

def bitrev7(x: int) -> int:
    return int(f"{x:07b}"[::-1], 2)

ZETAS_BITREV = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974,
    821, 289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320,
    1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110,
    1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156,
    3015, 3050, 1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733,
    2337, 268, 641, 1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757,
    2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874,
    1029, 2110, 2935, 885, 2154
]

GAMMAS = [pow(17, 2 * bitrev7(i) + 1, Q) for i in range(128)]

@dataclass(frozen=True)
class MLKEMParams:
    id: int
    name: str
    K: int
    ETA1: int
    ETA2: int
    DU: int
    DV: int

PARAMS_BY_ID = [
    MLKEMParams(0, "512",  2, 3, 2, 10, 4),
    MLKEMParams(1, "768",  3, 2, 2, 10, 4),
    MLKEMParams(2, "1024", 4, 2, 2, 11, 5),
]

def get_params_by_id(variant_id: int) -> MLKEMParams:
    if not isinstance(variant_id, int):
        raise ValueError("variant_id must be int 0,1,2")
    if 0 <= variant_id < len(PARAMS_BY_ID):
        return PARAMS_BY_ID[variant_id]
    raise ValueError("Unsupported variant_id (use 0,1,2)")