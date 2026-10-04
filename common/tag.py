# tag.py - TAG con HMAC-SHA256 (apuntes §3.13 y §3.15)
# TAG = trunc16( HMAC(K_mac, TYPE || IDS || SID || SEQ || IV || C) )
# Encrypt-then-MAC: el TAG se calcula sobre C (ya cifrado) y se verifica ANTES de descifrar.
# OJO: este archivo NO se puede llamar hmac.py (taparia la libreria hmac).

import hashlib
import hmac

TAG_LEN = 16


def hmac_sha256(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()


def make_tag(k_mac, data):
    return hmac_sha256(k_mac, data)[:TAG_LEN]


def ct_equal(a, b):
    # Es constante, no depende del inicio
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
        print("1) RFC 4231 caso", i)
        print("   clave:    ", hexlify(k).decode())
        print("   mensaje:  ", m)
        print("   esperado: ", esperado)
        print("   obtenido: ", hexlify(obtenido).decode())
        print("   resultado:", "OK" if obtenido == unhexlify(esperado) else "FALLA")

    # 2) ct_equal: show the values being compared
    a = os.urandom(16)
    b = bytearray(a)
    b[15] ^= 0x01
    print("2) ct_equal")
    print("   a     :", hexlify(a).decode())
    print("   b     :", hexlify(bytes(b)).decode(), "(ultimo bit invertido)")
    print("   a[:15]:", hexlify(a[:15]).decode(), "(15 bytes)")
    print("   iguales:", ct_equal(a, a),
          "| 1 byte distinto:", ct_equal(a, bytes(b)),
          "| largo distinto:", ct_equal(a, a[:15]))

    # 3) Encrypt-then-MAC: el mismo bit-flip de aes_cbc.py, pero ahora con TAG
    from padding import pkcs7_pad, pkcs7_unpad
    from aes_cbc import aes_cbc_encrypt, aes_cbc_decrypt

    k_enc = os.urandom(32)
    k_mac = os.urandom(32)
    print("3) Claves")
    print("   K_enc:", hexlify(k_enc).decode())
    print("   K_mac:", hexlify(k_mac).decode())

    # Sender: header = TYPE || IDS || SID || SEQ
    header = bytes([0x10, 0x01]) + b"\x3a\x7f\x00\xc2" + (5).to_bytes(4, "big")
    iv = os.urandom(16)
    texto = b"orden de la app:ABRIR=0"
    relleno = pkcs7_pad(texto)
    c = aes_cbc_encrypt(k_enc, iv, relleno)
    tag = make_tag(k_mac, header + iv + c)
    paquete = header + iv + c + tag

    print("   EMISOR")
    print("   texto  (%2d B):" % len(texto), texto)
    print("   con pad(%2d B):" % len(relleno), hexlify(relleno).decode())
    print("   header (%2d B):" % len(header), hexlify(header).decode())
    print("   IV     (%2d B):" % len(iv), hexlify(iv).decode())
    print("   C      (%2d B):" % len(c), hexlify(c).decode())
    print("   TAG    (%2d B):" % len(tag), hexlify(tag).decode())
    print("   paquete(%2d B):" % len(paquete), hexlify(paquete).decode())

    # Receiver: first the TAG, then decrypt
    def recibir(p):
        tag_rx = p[-TAG_LEN:]
        tag_calc = make_tag(k_mac, p[:-TAG_LEN])
        print("      TAG recibido :", hexlify(tag_rx).decode())
        print("      TAG calculado:", hexlify(tag_calc).decode())
        if not ct_equal(tag_calc, tag_rx):
            return "RECHAZADO: TAG (no se descifra)"
        descifrado = aes_cbc_decrypt(k_enc, p[10:26], p[26:-TAG_LEN])
        print("      descifrado   :", hexlify(descifrado).decode())
        return pkcs7_unpad(descifrado)

    # Attacker: flips the last bit of byte i
    def flip(p, i):
        p = bytearray(p)
        print("      ATACANTE: byte", i, format(p[i], "08b"), "->", format(p[i] ^ 0x01, "08b"))
        p[i] ^= 0x01
        return bytes(p)

    print("3) Paquete de", len(paquete), "bytes")
    print("   Legitimo:")
    print("   =>", recibir(paquete))
    print("   C alterado (flip):")
    print("   =>", recibir(flip(paquete, 26 + 6)))
    print("   TAG alterado:")
    print("   =>", recibir(flip(paquete, -1)))
    print("   SEQ alterado:")
    print("   =>", recibir(flip(paquete, 9)))