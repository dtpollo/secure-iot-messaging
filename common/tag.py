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
    # Compara mirando TODOS los bytes, aunque el primero ya sea distinto
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0


if __name__ == "__main__":
    import os
    from binascii import unhexlify

    # 1) Vectores oficiales RFC 4231: demuestran que es HMAC-SHA256 estandar
    casos = [
        (b"\x0b" * 20, b"Hi There",
         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (b"Jefe", b"what do ya want for nothing?",
         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    ]
    for i, (k, m, esperado) in enumerate(casos, 1):
        print("1) RFC 4231 caso", i, ":", "OK" if hmac_sha256(k, m) == unhexlify(esperado) else "FALLA")

    # 2) ct_equal
    a = os.urandom(16)
    b = bytearray(a)
    b[15] ^= 0x01
    print("2) ct_equal iguales:", ct_equal(a, a),
          "| 1 byte distinto:", ct_equal(a, bytes(b)),
          "| largo distinto:", ct_equal(a, a[:15]))

    # 3) Encrypt-then-MAC: el mismo bit-flip de aes_cbc.py, pero ahora con TAG
    from padding import pkcs7_pad, pkcs7_unpad
    from aes_cbc import aes_cbc_encrypt, aes_cbc_decrypt

    k_enc = os.urandom(32)
    k_mac = os.urandom(32)

    # Emisor: header = TYPE || IDS || SID || SEQ
    header = bytes([0x10, 0x01]) + b"\x3a\x7f\x00\xc2" + (5).to_bytes(4, "big")
    iv = os.urandom(16)
    c = aes_cbc_encrypt(k_enc, iv, pkcs7_pad(b"orden de la app:ABRIR=0"))
    paquete = header + iv + c + make_tag(k_mac, header + iv + c)

    # Receptor: primero el TAG, despues descifrar
    def recibir(p):
        if not ct_equal(make_tag(k_mac, p[:-TAG_LEN]), p[-TAG_LEN:]):
            return "RECHAZADO: TAG (no se descifra)"
        return pkcs7_unpad(aes_cbc_decrypt(k_enc, p[10:26], p[26:-TAG_LEN]))

    def flip(p, i):
        p = bytearray(p)
        p[i] ^= 0x01
        return bytes(p)

    print("3) Paquete de", len(paquete), "bytes")
    print("   Legitimo:          ", recibir(paquete))
    print("   C alterado (flip): ", recibir(flip(paquete, 26 + 6)))
    print("   TAG alterado:      ", recibir(flip(paquete, -1)))
    print("   SEQ alterado:      ", recibir(flip(paquete, 9)))
