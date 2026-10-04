# dh.py - Diffie-Hellman efimero con el grupo ffdhe2048 (apuntes §3.4, §3.5 y §3.6)
# A:  a = rand(32),  YA = g^a mod p   -> YA va en el HELLO (publico)
#     Z = YB^a mod p                  -> Z va al HKDF y NUNCA viaja por la red
# Antes de usar YB se valida 1 < YB < p-1 (RFC 7919).
# Borrar a y Z despues de usarlos (a = None) para que la sesion sea efimera (DHE).

import os

# ffdhe2048, RFC 7919 apendice A.1. Primo seguro de 2048 bits (p = 2q + 1). No es inventado.
P = int(
    "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"
    "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"
    "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
    "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"
    "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"
    "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
    "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"
    "C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF", 16)
G = 2
P_LEN = 256                             # bytes de YA, YB y Z
EXP_LEN = 32                            # a de 256 bits (RFC 7919 pide >= 224)


def dh_keygen():
    # devuelve (a, YA): a es secreto (int), YA va en el paquete (256 B)
    a = int.from_bytes(os.urandom(EXP_LEN), "big")
    y = pow(G, a, P)
    return a, y.to_bytes(P_LEN, "big")


def dh_shared(a, y_peer):
    # valida el YB recibido y devuelve Z (256 B)
    if len(y_peer) != P_LEN:
        raise ValueError("Y debe medir 256 bytes")
    y = int.from_bytes(y_peer, "big")
    if not 1 < y < P - 1:
        raise ValueError("Y fuera de rango (1 < Y < p-1)")
    z = pow(y, a, P)
    return z.to_bytes(P_LEN, "big")


if __name__ == "__main__":
    import sys
    import time
    from binascii import hexlify

    MICROPYTHON = sys.implementation.name == "micropython"

    def ms():
        if MICROPYTHON:
            return time.ticks_ms()
        return time.perf_counter() * 1000

    print("Corriendo en:", "ESP32" if MICROPYTHON else "PC")

    # 1) p es primo seguro (Fermat). Solo en el PC: en la ESP32 tardaria ~16 s
    if MICROPYTHON:
        print("1) Primo seguro: se prueba en el PC")
    else:
        q = (P - 1) // 2
        ok = P.bit_length() == 2048 and pow(2, P - 1, P) == 1 and pow(2, q - 1, q) == 1
        print("1) p de 2048 bits, p y q=(p-1)/2 primos:", "OK" if ok else "FALLA")

    # 2) A y B llegan al mismo Z sin mandarlo
    t0 = ms()
    a, ya = dh_keygen()
    t1 = ms()
    b, yb = dh_keygen()
    z_a = dh_shared(a, yb)
    t2 = ms()
    z_b = dh_shared(b, ya)
    print("2) YA (lo que viaja):", hexlify(ya[:8]).decode(), "...", len(ya), "bytes")
    print("   Z de A == Z de B:", z_a == z_b, "->", hexlify(z_a[:8]).decode(), "...")
    print("   Tiempo keygen:", int(t1 - t0), "ms | tiempo Z:", int(ms() - t2), "ms")

    # 3) Validacion de YB: con estos valores cualquiera conoceria Z
    malos = [("0", 0), ("1", 1), ("p-1", P - 1), ("p", P)]
    for nombre, y in malos:
        try:
            dh_shared(a, y.to_bytes(P_LEN, "big"))
            print("3) YB =", nombre, ": ACEPTADO (mal)")
        except ValueError:
            print("3) YB =", nombre, ": rechazado")

    # 4) Z va al HKDF: los dos sacan las mismas claves
    from hkdf import derive_keys
    na = os.urandom(16)
    nb = os.urandom(16)
    psk = os.urandom(32)
    print("4) Claves de A == claves de B:", derive_keys(na, nb, z_a, psk) == derive_keys(na, nb, z_b, psk))

    # Borrar los secretos (DHE)
    a = b = z_a = z_b = None
