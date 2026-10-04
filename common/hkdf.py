# hkdf.py - Derivar las claves de sesion con HKDF (apuntes §3.8, RFC 5869)
# Extract:  PRK = HMAC(NA || NB, Z || PSK)
# Expand:   K_enc = HMAC(PRK, "enc" || 0x01),  K_mac = HMAC(PRK, "mac" || 0x01)
#           SID   = trunc4( HMAC(PRK, "sid" || 0x01) )
# Z no sirve directo como clave (256 B, bits no uniformes) y cada uso lleva su propia clave.

from tag import hmac_sha256

HASH_LEN = 32
KEY_LEN = 32
SID_LEN = 4


def hkdf_extract(salt, ikm):
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk, info, length):
    # T(i) = HMAC(PRK, T(i-1) || info || i), con T(0) vacio
    if length > 255 * HASH_LEN:
        raise ValueError("HKDF no puede sacar tantos bytes")
    okm = b""
    t = b""
    i = 1
    while len(okm) < length:
        t = hmac_sha256(prk, t + info + bytes([i]))
        okm += t
        i += 1
    return okm[:length]


def derive_keys(na, nb, z, psk):
    # z ya en bytes (256 B, big-endian), lo convierte dh.py
    prk = hkdf_extract(na + nb, z + psk)
    k_enc = hkdf_expand(prk, b"enc", KEY_LEN)
    k_mac = hkdf_expand(prk, b"mac", KEY_LEN)
    sid = hkdf_expand(prk, b"sid", SID_LEN)
    return k_enc, k_mac, sid


if __name__ == "__main__":
    import os
    from binascii import hexlify, unhexlify

    # 1) Vector oficial RFC 5869, caso 1: demuestra que es HKDF-SHA256 estandar
    ikm = b"\x0b" * 22
    salt = bytes(range(0x00, 0x0d))
    info = bytes(range(0xf0, 0xfa))
    prk_rfc = unhexlify("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    okm_rfc = unhexlify("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        "34007208d5b887185865")
    prk = hkdf_extract(salt, ikm)
    print("1) RFC 5869 PRK:", "OK" if prk == prk_rfc else "FALLA")
    print("   RFC 5869 OKM:", "OK" if hkdf_expand(prk, info, 42) == okm_rfc else "FALLA")

    # 2) A y B con los mismos datos sacan las mismas claves
    na = os.urandom(16)
    nb = os.urandom(16)
    z = os.urandom(256)                 # aqui iria Z de DH
    psk = os.urandom(32)
    claves_a = derive_keys(na, nb, z, psk)
    claves_b = derive_keys(na, nb, z, psk)
    k_enc, k_mac, sid = claves_a
    print("2) A y B iguales:", claves_a == claves_b)
    print("   K_enc:", hexlify(k_enc).decode())
    print("   K_mac:", hexlify(k_mac).decode())
    print("   SID:  ", hexlify(sid).decode())
    print("   K_enc != K_mac (separacion de claves):", k_enc != k_mac)

    # 3) Sin la PSK correcta las claves salen otras (segunda barrera)
    otra = derive_keys(na, nb, z, os.urandom(32))
    print("3) Otra PSK -> K_enc distinta:", otra[0] != k_enc, "| K_mac distinta:", otra[1] != k_mac)

    # 4) Otros nonces -> otra sesion (otro SID)
    nueva = derive_keys(os.urandom(16), os.urandom(16), z, psk)
    print("4) Otros nonces -> SID:", hexlify(nueva[2]).decode(), "| distinto:", nueva[2] != sid)
