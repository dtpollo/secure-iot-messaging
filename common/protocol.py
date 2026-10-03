# protocol.py - Handshake (HELLO, RESPONSE, CONFIRM) y paquetes de datos
# Responsable: Integrante A
#
# OJO: por ahora es una VERSION DE PRUEBA (FALSO = True).
# Tiene las mismas funciones y el mismo formato de paquete que la version final,
# pero NO cifra ni verifica el TAG. Sirve para que el Integrante B pueda programar
# node.py, main.py y attacker.py desde ya. Cuando este lista la version real,
# el codigo de B no cambia.
#
# Por hacer (Integrante A):
#   [ ] Agregar DH + HMAC con la PSK en el handshake
#   [ ] Sacar K_enc, K_mac y SID con HKDF
#   [ ] Cifrar con AES-CBC y calcular el TAG en seal()
#   [ ] Verificar SID, TAG y SEQ (en ese orden) antes de descifrar en open()
#   [ ] Poner FALSO = False

import os

FALSO = True

HELLO = 0x01
RESPONSE = 0x02
CONFIRM = 0x03
DATA = 0x10

# Paquete DATA:  TYPE[0] | IDS[1] | SID[2:6] | SEQ[6:10] | IV[10:26] | C[26:-16] | TAG[-16:]


class Rejected(Exception):
    # str(e) es el motivo: "formato", "handshake", "sesion/ID", "TAG" o "replay"
    pass


def packet_type(data):
    return data[0]


class Initiator:
    # El que manda el HELLO

    def __init__(self, my_id, psks):
        self.my_id = my_id
        self.psks = psks
        self.peer_id = None
        self.na = None

    def hello(self, peer_id):
        self.peer_id = peer_id
        self.na = os.urandom(16)
        ya = bytes(256)                                 # FALSO
        return bytes([HELLO, self.my_id]) + self.na + ya

    def on_response(self, data):
        if len(data) != 306 or data[0] != RESPONSE or data[1] != self.peer_id:
            raise Rejected("handshake")
        nb = data[2:18]
        confirm = bytes([CONFIRM, self.my_id]) + bytes(32)   # FALSO
        return confirm, Session(self.my_id, self.peer_id, self.na[:2] + nb[:2])


class Responder:
    # El que espera el HELLO

    def __init__(self, my_id, psks):
        self.my_id = my_id
        self.psks = psks
        self.peer_id = None
        self.na = None
        self.nb = None

    def on_hello(self, data):
        if len(data) != 274 or data[0] != HELLO or data[1] not in self.psks:
            raise Rejected("handshake")
        self.peer_id = data[1]
        self.na = data[2:18]
        self.nb = os.urandom(16)
        yb = bytes(256)                                 # FALSO
        hmac_b = bytes(32)                              # FALSO
        return bytes([RESPONSE, self.my_id]) + self.nb + yb + hmac_b

    def on_confirm(self, data):
        if len(data) != 34 or data[0] != CONFIRM or data[1] != self.peer_id:
            raise Rejected("handshake")
        return Session(self.my_id, self.peer_id, self.na[:2] + self.nb[:2])


class Session:

    def __init__(self, my_id, peer_id, sid):
        self.my_id = my_id
        self.peer_id = peer_id
        self.sid = sid
        self.seq = 0
        self.ultimo_seq = 0

    def seal(self, mensaje):
        self.seq += 1
        header = bytes([DATA, self.my_id]) + self.sid + self.seq.to_bytes(4, "big")
        iv = os.urandom(16)
        n = 16 - len(mensaje) % 16
        c = mensaje + bytes([n]) * n                    # FALSO: sin cifrar
        tag = bytes(16)                                 # FALSO
        return header + iv + c + tag

    def open(self, packet):
        if len(packet) < 58 or (len(packet) - 42) % 16 != 0:
            raise Rejected("formato")
        if packet[0] != DATA or packet[1] != self.peer_id or packet[2:6] != self.sid:
            raise Rejected("sesion/ID")
        # FALSO: aqui va la verificacion del TAG
        seq = int.from_bytes(packet[6:10], "big")
        if seq <= self.ultimo_seq:
            raise Rejected("replay")
        self.ultimo_seq = seq
        c = packet[26:-16]                              # FALSO: sin descifrar
        return c[:-c[-1]]
