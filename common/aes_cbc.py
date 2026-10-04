# aes_cbc.py - Cifrado AES-256-CBC (apuntes §3.10 y §3.11)
# Cifrar:     C_i = AES_K(P_i xor C_{i-1}),       con C_0 = IV
# Descifrar:  P_i = AES^-1_K(C_i) xor C_{i-1}
# Entra el mensaje YA con padding (multiplo de 16). Sale C del mismo tamano.
# OJO: descifrar NO detecta si C fue modificado. Eso lo hace el TAG.

import sys

MICROPYTHON = sys.implementation.name == "micropython"

if MICROPYTHON:
    import cryptolib                    # ESP32
else:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes   # PC

KEY_LEN = 32                            # AES-256
IV_LEN = 16
BLOCK = 16
MODE_CBC = 2                            # en cryptolib: 1 = ECB, 2 = CBC


def _check(key, iv, data):
    if len(key) != KEY_LEN:
        raise ValueError("la clave debe medir 32 bytes")
    if len(iv) != IV_LEN:
        raise ValueError("el IV debe medir 16 bytes")
    if len(data) == 0 or len(data) % BLOCK != 0:
        raise ValueError("los datos deben ser multiplo de 16 (falta el padding?)")


def aes_cbc_encrypt(key, iv, data):
    _check(key, iv, data)
    if MICROPYTHON:
        return cryptolib.aes(key, MODE_CBC, iv).encrypt(data)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def aes_cbc_decrypt(key, iv, cipher_data):
    _check(key, iv, cipher_data)
    if MICROPYTHON:
        # en cryptolib un objeto sirve para cifrar O para descifrar: se crea uno nuevo
        return cryptolib.aes(key, MODE_CBC, iv).decrypt(cipher_data)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(cipher_data) + dec.finalize()


if __name__ == "__main__":
    import os
    from binascii import hexlify, unhexlify
    from padding import pkcs7_pad, pkcs7_unpad

    print("Corriendo en:", "ESP32 (cryptolib)" if MICROPYTHON else "PC (cryptography)")

    # 1) Vector oficial NIST SP 800-38A, F.2.5 (CBC-AES256): demuestra que es AES estandar
    key = unhexlify("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv = unhexlify("000102030405060708090a0b0c0d0e0f")
    p = unhexlify("6bc1bee22e409f96e93d7e117393172a"
                  "ae2d8a571e03ac9c9eb76fac45af8e51"
                  "30c81c46a35ce411e5fbc1191a0a52ef"
                  "f69f2445df4f9b17ad2b417be66c3710")
    c_nist = unhexlify("f58c4c04d6e5f1ba779eabfb5f7bfbd6"
                       "9cfc4e967edb808d679f777bc6702c7d"
                       "39f23369a9d9bacfa530e26304231461"
                       "b2eb05e2c39be9fcda6c19078c6a9d1b")
    c = aes_cbc_encrypt(key, iv, p)
    print("NIST cifrar:   ", "OK" if c == c_nist else "FALLA")
    print("NIST descifrar:", "OK" if aes_cbc_decrypt(key, iv, c_nist) == p else "FALLA")

    # 2) Ida y vuelta con clave e IV aleatorios: pad -> cifrar -> descifrar -> unpad
    k_enc = os.urandom(32)
    iv = os.urandom(16)
    msg = b"Hola ESP32"
    c = aes_cbc_encrypt(k_enc, iv, pkcs7_pad(msg))
    print("Mensaje:", msg, "->", len(c), "bytes cifrados:", hexlify(c).decode())
    print("Descifrado:", pkcs7_unpad(aes_cbc_decrypt(k_enc, iv, c)))

    # 3) Bit-flipping (apuntes §5.5): cambiar 1 bit de C_1 cambia ESE bit en P_2
    msg = b"orden de la app:" + b"ABRIR=0"         # bloque 1 (16 B) + bloque 2
    c = bytearray(aes_cbc_encrypt(k_enc, iv, pkcs7_pad(msg)))
    c[6] ^= 0x01                                   # Delta en la posicion del '0' de "ABRIR=0"
    p_mal = aes_cbc_decrypt(k_enc, iv, bytes(c))
    print("3) Original: ", msg)
    print("   Bloque 1:  ", p_mal[:16], "<- basura")
    print("   Bloque 2:  ", pkcs7_unpad(p_mal)[16:], "<- '0' se volvio '1' sin conocer la clave")
    print("   AES no dio ningun error: por eso hace falta el TAG")
