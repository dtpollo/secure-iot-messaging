# tag.py - TAG with HMAC-SHA256 (notes §3.13 and §3.15)
# TAG = trunc16( HMAC(K_mac, TYPE || IDS || SID || SEQ || IV || C) )
# Encrypt-then-MAC: the TAG is computed over C (already encrypted) and checked BEFORE decrypting.
# NOTE: this file can NOT be called hmac.py (it would hide the hmac library).

import hashlib
import hmac

TAG_LEN = 16


def hmac_sha256(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()


def make_tag(k_mac, data):
    return hmac_sha256(k_mac, data)[:TAG_LEN]


def ct_equal(a, b):
    # Constant time: it does not stop at the first different byte
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0


if __name__ == "__main__":
    import os
    from binascii import unhexlify, hexlify

    # 1) Official vectors RFC 4231: show expected vs obtained
    casos = [
        (b"\x0b" * 20, b"Hi There",
         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (b"Jefe", b"what do ya want for nothing?",
         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    ]
    for i, (k, m, esperado) in enumerate(casos, 1):
        obtenido = hmac_sha256(k, m)
        print("1) RFC 4231 case", i)
        print("   key:      ", hexlify(k).decode())
        print("   message:  ", m)
        print("   expected: ", esperado)
        print("   obtained: ", hexlify(obtenido).decode())
        print("   result:   ", "OK" if obtenido == unhexlify(esperado) else "FAIL")

    # 2) ct_equal: show the values being compared
    a = os.urandom(16)
    b = bytearray(a)
    b[15] ^= 0x01
    print("2) ct_equal")
    print("   a     :", hexlify(a).decode())
    print("   b     :", hexlify(bytes(b)).decode(), "(last bit flipped)")
    print("   a[:15]:", hexlify(a[:15]).decode(), "(15 bytes)")
    print("   equal:", ct_equal(a, a),
          "| 1 byte different:", ct_equal(a, bytes(b)),
          "| different length:", ct_equal(a, a[:15]))

    # 3) Encrypt-then-MAC: the same bit-flip as in aes_cbc.py, but now with the TAG
    from padding import pkcs7_pad, pkcs7_unpad
    from aes_cbc import aes_cbc_encrypt, aes_cbc_decrypt

    k_enc = os.urandom(32)
    k_mac = os.urandom(32)
    print("3) Keys")
    print("   K_enc:", hexlify(k_enc).decode())
    print("   K_mac:", hexlify(k_mac).decode())

    # Sender: header = TYPE || IDS || SID || SEQ
    header = bytes([0x10, 0x01]) + b"\x3a\x7f\x00\xc2" + (5).to_bytes(4, "big")
    iv = os.urandom(16)
    texto = b"order from app: LIGHT=0"
    relleno = pkcs7_pad(texto)
    c = aes_cbc_encrypt(k_enc, iv, relleno)
    tag = make_tag(k_mac, header + iv + c)
    paquete = header + iv + c + tag

    print("   SENDER")
    print("   text   (%2d B):" % len(texto), texto)
    print("   padded (%2d B):" % len(relleno), hexlify(relleno).decode())
    print("   header (%2d B):" % len(header), hexlify(header).decode())
    print("   IV     (%2d B):" % len(iv), hexlify(iv).decode())
    print("   C      (%2d B):" % len(c), hexlify(c).decode())
    print("   TAG    (%2d B):" % len(tag), hexlify(tag).decode())
    print("   packet (%2d B):" % len(paquete), hexlify(paquete).decode())

    # Receiver: first the TAG, then decrypt
    def recibir(p):
        tag_rx = p[-TAG_LEN:]
        tag_calc = make_tag(k_mac, p[:-TAG_LEN])
        print("      TAG received :", hexlify(tag_rx).decode())
        print("      TAG computed :", hexlify(tag_calc).decode())
        if not ct_equal(tag_calc, tag_rx):
            return "REJECTED: TAG (not decrypted)"
        descifrado = aes_cbc_decrypt(k_enc, p[10:26], p[26:-TAG_LEN])
        print("      decrypted    :", hexlify(descifrado).decode())
        return pkcs7_unpad(descifrado)

    # Attacker: flips the last bit of byte i
    def flip(p, i):
        p = bytearray(p)
        print("      ATTACKER: byte", i, format(p[i], "08b"), "->", format(p[i] ^ 0x01, "08b"))
        p[i] ^= 0x01
        return bytes(p)

    print("3) Packet of", len(paquete), "bytes")
    print("   Legitimate:")
    print("   =>", recibir(paquete))
    print("   C modified (flip):")
    print("   =>", recibir(flip(paquete, 26 + 6)))
    print("   TAG modified:")
    print("   =>", recibir(flip(paquete, -1)))
    print("   SEQ modified:")
    print("   =>", recibir(flip(paquete, 9)))