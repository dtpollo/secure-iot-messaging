# hkdf.py - Derive the session keys with HKDF (notes §3.8, RFC 5869)
# Extract:  PRK = HMAC(NA || NB, Z || PSK)
# Expand:   K_enc = HMAC(PRK, "enc" || 0x01),  K_mac = HMAC(PRK, "mac" || 0x01)
#           SID   = trunc4( HMAC(PRK, "sid" || 0x01) )
# Z can not be used directly as a key (256 B, bits not uniform) and each use gets its own key.

from tag import hmac_sha256

HASH_LEN = 32
KEY_LEN = 32
SID_LEN = 4


def hkdf_extract(salt, ikm):
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk, info, length):
    # T(i) = HMAC(PRK, T(i-1) || info || i), with T(0) empty
    if length > 255 * HASH_LEN:
        raise ValueError("HKDF can not output that many bytes")
    okm = b""
    t = b""
    i = 1
    while len(okm) < length:
        t = hmac_sha256(prk, t + info + bytes([i]))
        okm += t
        i += 1
    return okm[:length]


def derive_keys(na, nb, z, psk):
    # z already in bytes (256 B, big-endian), dh.py converts it
    prk = hkdf_extract(na + nb, z + psk)
    k_enc = hkdf_expand(prk, b"enc", KEY_LEN)
    k_mac = hkdf_expand(prk, b"mac", KEY_LEN)
    sid = hkdf_expand(prk, b"sid", SID_LEN)
    return k_enc, k_mac, sid


if __name__ == "__main__":
    import os
    from binascii import hexlify, unhexlify

    # 1) Official RFC 5869 vector, case 1: shows it is standard HKDF-SHA256
    ikm = b"\x0b" * 22
    salt = bytes(range(0x00, 0x0d))
    info = bytes(range(0xf0, 0xfa))
    prk_rfc = unhexlify("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    okm_rfc = unhexlify("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        "34007208d5b887185865")
    prk = hkdf_extract(salt, ikm)
    print("1) RFC 5869 PRK:", "OK" if prk == prk_rfc else "FAIL")
    print("   RFC 5869 OKM:", "OK" if hkdf_expand(prk, info, 42) == okm_rfc else "FAIL")

    # 2) A and B with the same inputs get the same keys
    na = os.urandom(16)
    nb = os.urandom(16)
    z = os.urandom(256)                 # Z from DH would go here
    psk = os.urandom(32)
    claves_a = derive_keys(na, nb, z, psk)
    claves_b = derive_keys(na, nb, z, psk)
    k_enc, k_mac, sid = claves_a
    print("2) A and B equal:", claves_a == claves_b)
    print("   K_enc:", hexlify(k_enc).decode())
    print("   K_mac:", hexlify(k_mac).decode())
    print("   SID:  ", hexlify(sid).decode())
    print("   K_enc != K_mac (key separation):", k_enc != k_mac)

    # 3) Without the right PSK the keys come out different (second barrier)
    otra = derive_keys(na, nb, z, os.urandom(32))
    print("3) Other PSK -> K_enc different:", otra[0] != k_enc, "| K_mac different:", otra[1] != k_mac)

    # 4) Other nonces -> other session (other SID)
    nueva = derive_keys(os.urandom(16), os.urandom(16), z, psk)
    print("4) Other nonces -> SID:", hexlify(nueva[2]).decode(), "| different:", nueva[2] != sid)
