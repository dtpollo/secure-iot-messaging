# protocol.py - Handshake (HELLO, RESPONSE, CONFIRM) y paquetes de datos (apuntes §3 y §4)
# Responsable: Integrante A
#
# Handshake DHE-PSK:
#   HELLO    A->B: 0x01 | IDA | NA | YA                          274 B
#   RESPONSE B->A: 0x02 | IDB | NB | YB | HMAC(PSK, "B" | t)     306 B
#   CONFIRM  A->B: 0x03 | IDA | HMAC(PSK, "A" | t)               34 B
#   con t = IDA | IDB | NA | NB | YA | YB
#   Despues: K_enc, K_mac, SID = HKDF(NA | NB, Z | PSK)
#
# En la ESP32 hay que copiar a la raiz: padding.py, aes_cbc.py, tag.py, hkdf.py, dh.py y este archivo.

import os

from padding import pkcs7_pad, pkcs7_unpad
from aes_cbc import aes_cbc_encrypt, aes_cbc_decrypt
from tag import hmac_sha256, make_tag, ct_equal, TAG_LEN
from hkdf import derive_keys
from dh import dh_keygen, dh_shared

HELLO = 0x01
RESPONSE = 0x02
CONFIRM = 0x03
DATA = 0x10

HELLO_LEN = 274
RESPONSE_LEN = 306
CONFIRM_LEN = 34
N_LEN = 16

# Paquete DATA:  TYPE[0] | IDS[1] | SID[2:6] | SEQ[6:10] | IV[10:26] | C[26:-16] | TAG[-16:]


class Rejected(Exception):
    # str(e) es el motivo: "formato", "handshake", "sesion/ID", "TAG" o "replay"
    pass


def packet_type(data):
    return data[0]


def _transcript(id_a, id_b, na, nb, ya, yb):
    return bytes([id_a, id_b]) + na + nb + ya + yb


class Initiator:
    # El que manda el HELLO (A)

    def __init__(self, my_id, psks):
        self.my_id = my_id
        self.psks = psks
        self.peer_id = None
        self.na = None
        self.a = None
        self.ya = None

    def hello(self, peer_id):
        if peer_id not in self.psks:
            raise Rejected("handshake")
        self.peer_id = peer_id
        self.na = os.urandom(N_LEN)
        self.a, self.ya = dh_keygen()
        return bytes([HELLO, self.my_id]) + self.na + self.ya

    def on_response(self, data):
        if len(data) != RESPONSE_LEN or data[0] != RESPONSE or data[1] != self.peer_id or self.a is None:
            raise Rejected("handshake")
        nb = data[2:18]
        yb = data[18:274]
        hmac_b = data[274:306]
        psk = self.psks[self.peer_id]
        t = _transcript(self.my_id, self.peer_id, self.na, nb, self.ya, yb)

        # B demuestra que tiene la PSK y que vio los mismos YA y YB (sin MITM)
        if not ct_equal(hmac_sha256(psk, b"B" + t), hmac_b):
            raise Rejected("handshake")
        try:
            z = dh_shared(self.a, yb)           # valida 1 < YB < p-1
        except ValueError:
            raise Rejected("handshake")
        self.a = None                           # borrar a (DHE)

        k_enc, k_mac, sid = derive_keys(self.na, nb, z, psk)
        z = None                                # borrar Z
        confirm = bytes([CONFIRM, self.my_id]) + hmac_sha256(psk, b"A" + t)
        return confirm, Session(self.my_id, self.peer_id, sid, k_enc, k_mac)


class Responder:
    # El que espera el HELLO (B)

    def __init__(self, my_id, psks):
        self.my_id = my_id
        self.psks = psks
        self.peer_id = None
        self.keys = None
        self.hmac_a = None

    def on_hello(self, data):
        # ID desconocido = dispositivo no autorizado
        if len(data) != HELLO_LEN or data[0] != HELLO or data[1] not in self.psks:
            raise Rejected("handshake")
        peer_id = data[1]
        na = data[2:18]
        ya = data[18:274]
        psk = self.psks[peer_id]

        b, yb = dh_keygen()
        try:
            z = dh_shared(b, ya)                # valida 1 < YA < p-1
        except ValueError:
            raise Rejected("handshake")
        b = None                                # borrar b (DHE)

        nb = os.urandom(N_LEN)
        t = _transcript(peer_id, self.my_id, na, nb, ya, yb)
        # Las claves quedan guardadas, pero la sesion se entrega solo si el CONFIRM es valido
        self.keys = derive_keys(na, nb, z, psk)
        z = None                                # borrar Z
        self.peer_id = peer_id
        self.hmac_a = hmac_sha256(psk, b"A" + t)
        return bytes([RESPONSE, self.my_id]) + nb + yb + hmac_sha256(psk, b"B" + t)

    def on_confirm(self, data):
        if len(data) != CONFIRM_LEN or data[0] != CONFIRM or data[1] != self.peer_id or self.keys is None:
            raise Rejected("handshake")
        # A demuestra que tiene la PSK y que vio el mismo transcript
        if not ct_equal(data[2:34], self.hmac_a):
            raise Rejected("handshake")
        k_enc, k_mac, sid = self.keys
        self.keys = None
        return Session(self.my_id, self.peer_id, sid, k_enc, k_mac)


class Session:

    def __init__(self, my_id, peer_id, sid, k_enc, k_mac):
        self.my_id = my_id
        self.peer_id = peer_id
        self.sid = sid
        self.k_enc = k_enc
        self.k_mac = k_mac
        self.seq = 0                    # el primer mensaje sale con SEQ = 1
        self.ultimo_seq = 0

    def seal(self, mensaje):
        self.seq += 1
        header = bytes([DATA, self.my_id]) + self.sid + self.seq.to_bytes(4, "big")
        iv = os.urandom(16)
        c = aes_cbc_encrypt(self.k_enc, iv, pkcs7_pad(mensaje))
        data = header + iv + c
        return data + make_tag(self.k_mac, data)        # Encrypt-then-MAC

    def open(self, packet):
        if len(packet) < 58 or (len(packet) - 42) % 16 != 0:
            raise Rejected("formato")
        # 1) SID e ID: descarte rapido, sin calcular HMAC
        if packet[0] != DATA or packet[1] != self.peer_id or packet[2:6] != self.sid:
            raise Rejected("sesion/ID")
        # 2) TAG antes que nada (sin esto: padding oracle y DoS del contador)
        if not ct_equal(make_tag(self.k_mac, packet[:-TAG_LEN]), packet[-TAG_LEN:]):
            raise Rejected("TAG")
        # 3) SEQ, ya autenticado por el TAG
        seq = int.from_bytes(packet[6:10], "big")
        if seq <= self.ultimo_seq:
            raise Rejected("replay")
        self.ultimo_seq = seq
        # 4) Descifrar y quitar padding
        try:
            return pkcs7_unpad(aes_cbc_decrypt(self.k_enc, packet[10:26], packet[26:-TAG_LEN]))
        except ValueError:
            raise Rejected("formato")


if __name__ == "__main__":
    import sys
    import time

    MICROPYTHON = sys.implementation.name == "micropython"

    def ms():
        if MICROPYTHON:
            return time.ticks_ms()
        return time.perf_counter() * 1000

    def intentar(nombre, funcion):
        try:
            funcion()
            print("  ", nombre, "-> ACEPTADO (mal)")
        except Rejected as e:
            print("  ", nombre, "-> Rechazado:", e)

    def flip(p, i):
        p = bytearray(p)
        p[i] ^= 0x01
        return bytes(p)

    ID_A = 0x01
    ID_B = 0x02
    psk = os.urandom(32)

    # 1) Handshake normal, sin red: los mensajes se pasan a mano
    t0 = ms()
    a = Initiator(ID_A, {ID_B: psk})
    b = Responder(ID_B, {ID_A: psk})
    hello = a.hello(ID_B)
    response = b.on_hello(hello)
    confirm, ses_a = a.on_response(response)
    ses_b = b.on_confirm(confirm)
    print("1) Handshake:", len(hello), "+", len(response), "+", len(confirm), "bytes,", int(ms() - t0), "ms")
    print("   Mismas claves y SID:", (ses_a.k_enc, ses_a.k_mac, ses_a.sid) == (ses_b.k_enc, ses_b.k_mac, ses_b.sid))

    # 2) Comunicacion normal en los dos sentidos
    msg = b"Hola ESP32"
    t0 = ms()
    p = ses_a.seal(msg)
    t1 = ms()
    print("2) A->B:", ses_b.open(p), "| mensaje", len(msg), "B, paquete", len(p), "B")
    print("   B->A:", ses_a.open(ses_b.seal(b"Hola A")))
    print("   Tiempo seal:", int(t1 - t0), "ms")

    # 3) Ataques a los paquetes de datos
    print("3) Ataques a los datos:")
    p = ses_a.seal(b"orden de la app:ABRIR=0")
    intentar("C alterado     ", lambda: ses_b.open(flip(p, 26 + 6)))
    intentar("TAG alterado   ", lambda: ses_b.open(flip(p, -1)))
    intentar("SEQ alterado   ", lambda: ses_b.open(flip(p, 9)))
    intentar("IDS alterado   ", lambda: ses_b.open(flip(p, 1)))
    print("   Legitimo:       ", ses_b.open(p))
    intentar("Replay         ", lambda: ses_b.open(p))
    falso = Session(ID_A, ID_B, ses_a.sid, os.urandom(32), os.urandom(32))
    falso.seq = 1000
    intentar("Paquete forjado", lambda: ses_b.open(falso.seal(b"ABRIR=1")))

    # 4) Ataques al handshake
    print("4) Ataques al handshake:")
    intruso = Initiator(0x99, {ID_B: os.urandom(32)})
    intentar("ID no autorizado 0x99", lambda: Responder(ID_B, {ID_A: psk}).on_hello(intruso.hello(ID_B)))

    a = Initiator(ID_A, {ID_B: psk})
    hello = a.hello(ID_B)
    otro = Initiator(ID_A, {ID_B: psk}).hello(ID_B)         # el atacante cambia YA por el suyo
    response = Responder(ID_B, {ID_A: psk}).on_hello(hello[:18] + otro[18:])
    intentar("MITM cambia YA       ", lambda: a.on_response(response))

    b = Responder(ID_B, {ID_A: psk})
    resp = b.on_hello(Initiator(ID_A, {ID_B: psk}).hello(ID_B))
    intentar("Reflexion (HMAC_B)   ", lambda: b.on_confirm(bytes([CONFIRM, ID_A]) + resp[274:306]))
