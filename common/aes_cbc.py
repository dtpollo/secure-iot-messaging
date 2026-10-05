# aes_cbc.py - AES-256-CBC encryption (notes §3.10 and §3.11)
# Encrypt:    C_i = AES_K(P_i xor C_{i-1}),       with C_0 = IV
# Decrypt:    P_i = AES^-1_K(C_i) xor C_{i-1}
# Input is the message ALREADY padded (multiple of 16). Output C has the same size.
# Decrypt does NOT detect if C was modified. The TAG does that. !

import sys

MICROPYTHON = sys.implementation.name == "micropython"

if MICROPYTHON:
    import cryptolib                    # ESP32
else:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes   # PC

KEY_LEN = 32                            # AES-256
IV_LEN = 16
BLOCK = 16
MODE_CBC = 2                            # in cryptolib: 1 = ECB, 2 = CBC


def _check(key, iv, data):
    if len(key) != KEY_LEN:
        raise ValueError("key must be 32 bytes")
    if len(iv) != IV_LEN:
        raise ValueError("IV must be 16 bytes")
    if len(data) == 0 or len(data) % BLOCK != 0:
        raise ValueError("data must be a multiple of 16 (missing padding?)")


def aes_cbc_encrypt(key, iv, data):
    _check(key, iv, data)
    if MICROPYTHON:
        return cryptolib.aes(key, MODE_CBC, iv).encrypt(data)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def aes_cbc_decrypt(key, iv, cipher_data):
    _check(key, iv, cipher_data)
    if MICROPYTHON:
        return cryptolib.aes(key, MODE_CBC, iv).decrypt(cipher_data)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(cipher_data) + dec.finalize()


if __name__ == "__main__":
    import os
    from binascii import hexlify, unhexlify
    from padding import pkcs7_pad, pkcs7_unpad

    print("Running on:", "ESP32 (cryptolib)" if MICROPYTHON else "PC (cryptography)")

    # 1) Official NIST SP 800-38A vector, F.2.5 (CBC-AES256): shows it is standard AES
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
    print("NIST encrypt:", "OK" if c == c_nist else "FAIL")
    print("NIST decrypt:", "OK" if aes_cbc_decrypt(key, iv, c_nist) == p else "FAIL")

    # 2) Round trip with random key and IV: pad -> encrypt -> decrypt -> unpad
    k_enc = os.urandom(32)
    iv = os.urandom(16)
    msg = b"Hello ESP32"
    c = aes_cbc_encrypt(k_enc, iv, pkcs7_pad(msg))
    print("Message:", msg, "->", len(c), "encrypted bytes:", hexlify(c).decode())
    print("Decrypted:", pkcs7_unpad(aes_cbc_decrypt(k_enc, iv, c)))

    # 3) Bit-flipping (notes §5.5): changing 1 bit of C_1 changes THAT bit in P_2
    msg = b"order from app: " + b"LIGHT=0"         # block 1 (16 B) + block 2
    c = bytearray(aes_cbc_encrypt(k_enc, iv, pkcs7_pad(msg)))
    c[6] ^= 0x01                                   # Delta at the position of the '0' in "LIGHT=0"
    p_mal = aes_cbc_decrypt(k_enc, iv, bytes(c))
    print("3) Original:", msg)
    print("   Block 1: ", p_mal[:16], "<- garbage")
    print("   Block 2: ", pkcs7_unpad(p_mal)[16:], "<- '0' became '1' without knowing the key")
    print("   AES gave no error: that is why we need the TAG")
