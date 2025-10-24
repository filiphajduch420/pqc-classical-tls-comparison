# Tento soubor vyžaduje knihovnu pycryptodome:
# pip install pycryptodomex
# nebo
# pip install pycryptodome
import hashlib # <-- PŘIDÁN IMPORT
from Crypto.Hash import SHAKE128, SHAKE256
from typing import Union

# --- Definice typů pro kontext (stavové hashovací objekty) ---
Shake128Context = type(SHAKE128.new())
Shake256Context = type(SHAKE256.new())
XOFContext = Union[Shake128Context, Shake256Context]


# --- Jednorázové (stateless) funkce H a G ---

def H(data: bytes, length_bytes: int) -> bytes:
    """ Wrapper H (SHAKE256). [cite: 411] """
    return SHAKE256.new(data=data).read(length=length_bytes)

def G(data: bytes, length_bytes: int) -> bytes:
    """ Wrapper G (SHAKE128). [cite: 413] """
    return SHAKE128.new(data=data).read(length=length_bytes)

# --- Standardní hashovací funkce ---

def SHA256(data: bytes) -> bytes:
    """ Wrapper pro SHA-256. """
    return hashlib.sha256(data).digest()

def SHA512(data: bytes) -> bytes:
    """ Wrapper pro SHA-512. """
    return hashlib.sha512(data).digest()

# --- Inkrementální (stavové) API ---

class H_Functions:
    """ Wrapper pro inkrementální API H (SHAKE256). [cite: 414, 416, 418] """
    @staticmethod
    def Init() -> Shake256Context:
        return SHAKE256.new() # [cite: 414]

    @staticmethod
    def Absorb(ctx: Shake256Context, data: bytes) -> Shake256Context:
        ctx.update(data) # [cite: 416]
        return ctx

    @staticmethod
    def Squeeze(ctx: Shake256Context, length_bytes: int) -> tuple[Shake256Context, bytes]:
        out = ctx.read(length=length_bytes) # [cite: 418]
        return ctx, out

class G_Functions:
    """ Wrapper pro inkrementální API G (SHAKE128). [cite: 415, 417, 419] """
    @staticmethod
    def Init() -> Shake128Context:
        return SHAKE128.new() # [cite: 415]

    @staticmethod
    def Absorb(ctx: Shake128Context, data: bytes) -> Shake128Context:
        ctx.update(data) # [cite: 417]
        return ctx

    @staticmethod
    def Squeeze(ctx: Shake128Context, length_bytes: int) -> tuple[Shake128Context, bytes]:
        out = ctx.read(length=length_bytes) # [cite: 419]
        return ctx, out

# --- OID konstanty pro HashML-DSA ---
# DER encoding without tag and length, just the value bytes
OID_SHA256 = bytes.fromhex("608648016503040201") # [cite: 567]
OID_SHA512 = bytes.fromhex("608648016503040203") # [cite: 567]
OID_SHAKE128 = bytes.fromhex("60864801650304020B") # [cite: 567]

# Slovník pro mapování názvu funkce na OID a hashovací funkci
PREHASH_FUNCTIONS = {
    "SHA-256": (OID_SHA256, SHA256),
    "SHA-512": (OID_SHA512, SHA512),
    # SHAKE128 requires length, Alg 4 specifies 256 bits (32 bytes)
    "SHAKE128": (OID_SHAKE128, lambda data: G(data, 32)),
}