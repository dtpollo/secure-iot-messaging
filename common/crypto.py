# crypto.py - Funciones criptograficas (el mismo archivo corre en el PC y en la ESP32)
# Responsable: Integrante A
#
# Por hacer:
#   [ ] Usar cryptolib en la ESP32 y la libreria cryptography en el PC
#   [ ] Copiar el primo p de ffdhe2048 (RFC 7919, Apendice A.1)
#   [ ] Implementar cada funcion sin cambiarle el nombre

import sys

MICROPYTHON = sys.implementation.name == "micropython"

if MICROPYTHON:
    import cryptolib            # ESP32

DH_P = None                     # TODO: primo de 2048 bits del RFC 7919
DH_G = 2


def pkcs7_pad(data):
    raise NotImplementedError


def pkcs7_unpad(data):
    raise NotImplementedError


def aes_cbc_encrypt(key, iv, data):
    raise NotImplementedError


def aes_cbc_decrypt(key, iv, c):
    raise NotImplementedError


def hmac_sha256(key, msg):
    raise NotImplementedError


def hkdf(salt, ikm, info):
    # PRK = HMAC(salt, ikm) ; clave = HMAC(PRK, info + b"\x01")
    raise NotImplementedError


def dh_keygen():
    # devolver (a, YA) con a de 32 bytes aleatorios y YA = g^a mod p
    raise NotImplementedError


def dh_shared(a, y):
    # validar 1 < y < p-1 y devolver Z = y^a mod p
    raise NotImplementedError


def ct_equal(a, b):
    # comparar en tiempo constante
    raise NotImplementedError
