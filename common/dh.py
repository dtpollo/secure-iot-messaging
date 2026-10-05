# dh.py - Ephemeral Diffie-Hellman with the ffdhe2048 group (notes §3.4, §3.5 and §3.6)
# A:  a = rand(32),  YA = g^a mod p   -> YA goes in the HELLO (public)
#     Z = YB^a mod p                  -> Z goes to HKDF and NEVER travels over the network
# Before using YB we check 1 < YB < p-1 (RFC 7919).
# Delete a and Z after using them (a = None) so the session is ephemeral (DHE).

import os

# ffdhe2048, RFC 7919 appendix A.1. Safe prime of 2048 bits (p = 2q + 1). Not made up.
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
P_LEN = 256                             # bytes of YA, YB and Z
EXP_LEN = 32                            # a of 256 bits (RFC 7919 asks for >= 224)


def dh_keygen():
    # returns (a, YA): a is secret (int), YA goes in the packet (256 B)
    a = int.from_bytes(os.urandom(EXP_LEN), "big")
    y = pow(G, a, P)
    return a, y.to_bytes(P_LEN, "big")


def dh_shared(a, y_peer):
    # checks the received YB and returns Z (256 B)
    if len(y_peer) != P_LEN:
        raise ValueError("Y must be 256 bytes")
    y = int.from_bytes(y_peer, "big")
    if not 1 < y < P - 1:
        raise ValueError("Y out of range (1 < Y < p-1)")
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

    print("Running on:", "ESP32" if MICROPYTHON else "PC")

    # 1) p is a safe prime (Fermat). Only on the PC: on the ESP32 it would take ~16 s
    if MICROPYTHON:
        print("1) Safe prime: tested on the PC")
    else:
        q = (P - 1) // 2
        ok = P.bit_length() == 2048 and pow(2, P - 1, P) == 1 and pow(2, q - 1, q) == 1
        print("1) p of 2048 bits, p and q=(p-1)/2 prime:", "OK" if ok else "FAIL")

    # 2) A and B get the same Z without sending it
    t0 = ms()
    a, ya = dh_keygen()
    t1 = ms()
    b, yb = dh_keygen()
    z_a = dh_shared(a, yb)
    t2 = ms()
    z_b = dh_shared(b, ya)
    print("2) YA (what travels):", hexlify(ya[:8]).decode(), "...", len(ya), "bytes")
    print("   Z of A == Z of B:", z_a == z_b, "->", hexlify(z_a[:8]).decode(), "...")
    print("   keygen time:", int(t1 - t0), "ms | Z time:", int(ms() - t2), "ms")

    # 3) YB check: with these values anyone would know Z
    malos = [("0", 0), ("1", 1), ("p-1", P - 1), ("p", P)]
    for nombre, y in malos:
        try:
            dh_shared(a, y.to_bytes(P_LEN, "big"))
            print("3) YB =", nombre, ": ACCEPTED (wrong)")
        except ValueError:
            print("3) YB =", nombre, ": rejected")

    # 4) Z goes to HKDF: both get the same keys
    from hkdf import derive_keys
    na = os.urandom(16)
    nb = os.urandom(16)
    psk = os.urandom(32)
    print("4) Keys of A == keys of B:", derive_keys(na, nb, z_a, psk) == derive_keys(na, nb, z_b, psk))

    # Delete the secrets (DHE)
    a = b = z_a = z_b = None
