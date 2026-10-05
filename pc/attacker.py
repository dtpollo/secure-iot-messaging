# attacker.py - Man in the middle attacker for the security tests (PDF §4)
# Owner: Member B
#
# It sits between the two nodes and forwards the packets from one to the other.
# The boards are uploaded with  .\subir.ps1 ambas -Atacante  so they send everything to the attacker (port 6000).
# The attacker does NOT know the PSK (it does not use config.py).
#
# Usage:
#   python pc/attacker.py --mode MODE --a IP_ALICE --b IP_BOB [--port 5005]
#
#   sniff        show the packets: only public values and ciphertext go through
#   tamper_c     flip 1 bit of the ciphertext          -> Rejected: TAG
#   tamper_tag   flip 1 bit of the TAG                 -> Rejected: TAG
#   replay       resend a packet already accepted      -> Rejected: replay
#   forge        make up IV, C and TAG                 -> Rejected: TAG
#   mitm         replace YA in the HELLO with its own  -> Rejected: handshake (on the initiator)
#
#   python pc/attacker.py --test     test the attacks without network, against protocol.py
#
# Each attack is done only once; after that the packets go through normally.

import os
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))

from dh import dh_keygen    # noqa: E402

HELLO = 0x01
RESPONSE = 0x02
CONFIRM = 0x03
DATA = 0x10
NOMBRES = {HELLO: "HELLO", RESPONSE: "RESPONSE", CONFIRM: "CONFIRM", DATA: "DATA"}
MODOS = ["sniff", "tamper_c", "tamper_tag", "replay", "forge", "mitm"]
PORT_ATACANTE = 6000
PORT_NODOS = 5005

# Positions in the DATA packet
IDS = 1
SID = slice(2, 6)
SEQ = slice(6, 10)
IV = slice(10, 26)
C = slice(26, -16)
TAG = slice(-16, None)


def obtener_argumento(nombre):
    if nombre in sys.argv:
        posicion = sys.argv.index(nombre)
        if posicion + 1 < len(sys.argv):
            return sys.argv[posicion + 1]
    return None


def es_data(data):
    return len(data) >= 58 and data[0] == DATA and (len(data) - 42) % 16 == 0


def mostrar_paquete(data):
    # Show the fields of the DATA packet
    print("   TYPE:", hex(data[0]))
    print("   IDS: ", hex(data[IDS]))
    print("   SID: ", data[SID].hex())
    print("   SEQ: ", int.from_bytes(data[SEQ], "big"))
    print("   IV:  ", data[IV].hex())
    print("   C:   ", data[C].hex())
    print("   TAG: ", data[TAG].hex())


def mostrar_handshake(data):
    # In the handshake only IDs, nonces, public DH values and HMAC are sent
    print("  ", NOMBRES.get(data[0], "?"), len(data), "B | ID:", hex(data[1]) if len(data) > 1 else "-")
    if data[0] in (HELLO, RESPONSE) and len(data) >= 274:
        print("   N:", data[2:18].hex())
        print("   Y:", data[18:34].hex(), "...")


def modificar_ciphertext(data):
    # Flip one bit of the ciphertext
    paquete = bytearray(data)
    paquete[26] ^= 0x01
    return bytes(paquete)


def modificar_tag(data):
    # Flip one bit of the TAG
    paquete = bytearray(data)
    paquete[-1] ^= 0x01
    return bytes(paquete)


def crear_falso(data):
    # Copies the header (IDS, SID, SEQ) and makes up IV, C and TAG: without K_mac it cannot make a valid TAG
    paquete = bytearray(data)
    paquete[IV] = os.urandom(16)
    paquete[C] = os.urandom(len(paquete[C]))
    paquete[TAG] = os.urandom(16)
    return bytes(paquete)


def cambiar_ya(hello):
    # MITM: puts its own public value. Without the PSK it cannot fix HMAC_B
    _, y_atacante = dh_keygen()
    return hello[:18] + y_atacante


def procesar_paquete(sock, data, destino, mode, ataque_hecho):
    # Returns True once the attack is done
    if not ataque_hecho and mode == "mitm" and len(data) == 274 and data[0] == HELLO:
        sock.sendto(cambiar_ya(data), destino)
        print("   HELLO sent with YA replaced by the attacker's")
        return True
    if not es_data(data):
        if mode == "sniff" and data:
            mostrar_handshake(data)
        sock.sendto(data, destino)
        print("  ", NOMBRES.get(data[0], "?") if data else "empty", "forwarded")
        return ataque_hecho
    if mode == "sniff":
        mostrar_paquete(data)
        sock.sendto(data, destino)
    elif mode == "tamper_c" and not ataque_hecho:
        sock.sendto(modificar_ciphertext(data), destino)
        print("   Ciphertext modified (1 bit)")
        return True
    elif mode == "tamper_tag" and not ataque_hecho:
        sock.sendto(modificar_tag(data), destino)
        print("   TAG modified (1 bit)")
        return True
    elif mode == "replay" and not ataque_hecho:
        # First the normal packet goes through and then the same one is sent again
        sock.sendto(data, destino)
        time.sleep(0.2)
        sock.sendto(data, destino)
        print("   Packet sent twice (the second one is the replay)")
        return True
    elif mode == "forge" and not ataque_hecho:
        sock.sendto(crear_falso(data), destino)
        print("   Fake packet sent instead of the original")
        return True
    else:
        sock.sendto(data, destino)
    print("   DATA forwarded")
    return ataque_hecho


def prueba_sin_red():
    # Applies each attack to real packets and shows that protocol.py rejects them
    from protocol import Initiator, Responder, Rejected

    def intentar(nombre, funcion):
        try:
            funcion()
            print("  ", nombre, "-> ACCEPTED (wrong)")
        except Rejected as e:
            print("  ", nombre, "-> Rejected:", e)

    psk = os.urandom(32)
    a = Initiator(0x01, {0x02: psk})
    b = Responder(0x02, {0x01: psk})
    confirm, ses_a = a.on_response(b.on_hello(a.hello(0x02)))
    ses_b = b.on_confirm(confirm)

    p = ses_a.seal(b"Hello ESP32")
    print("Original packet (sniff):")
    mostrar_paquete(p)
    print("Attacks:")
    intentar("tamper_c  ", lambda: ses_b.open(modificar_ciphertext(p)))
    intentar("tamper_tag", lambda: ses_b.open(modificar_tag(p)))
    intentar("forge     ", lambda: ses_b.open(crear_falso(p)))
    print("   legitimate -> Accepted:", ses_b.open(p))
    intentar("replay    ", lambda: ses_b.open(p))

    a = Initiator(0x01, {0x02: psk})
    response = Responder(0x02, {0x01: psk}).on_hello(cambiar_ya(a.hello(0x02)))
    intentar("mitm      ", lambda: a.on_response(response))


def main():
    if "--test" in sys.argv:
        prueba_sin_red()
        return
    mode = obtener_argumento("--mode")
    ip_a = obtener_argumento("--a")
    ip_b = obtener_argumento("--b")
    port = int(obtener_argumento("--port") or PORT_NODOS)
    if mode not in MODOS:
        print("Invalid mode. Modes:", ", ".join(MODOS))
        return
    if ip_a is None or ip_b is None:
        print("Missing the IPs of the two nodes: --a IP_A --b IP_B")
        return
    nodo_a = (ip_a, port)
    nodo_b = (ip_b, port)
    if nodo_a == nodo_b:
        print("The nodes must have different addresses")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", PORT_ATACANTE))
    sock.settimeout(1)          # so Ctrl+C works on Windows
    print("Attacker listening on port", PORT_ATACANTE, "| mode:", mode)
    print("Node A:", nodo_a, "| Node B:", nodo_b)
    ataque_hecho = False
    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except ConnectionResetError:
                # Windows (WinError 10054): a forwarded packet reached a node that is not listening yet
                print("   (the other node is not listening yet)")
                continue
            if addr == nodo_a:
                destino = nodo_b
                print("A -> B")
            elif addr == nodo_b:
                destino = nodo_a
                print("B -> A")
            else:
                print("Packet from unknown source:", addr)
                continue
            ataque_hecho = procesar_paquete(sock, data, destino, mode, ataque_hecho)
    except KeyboardInterrupt:
        print("\nAttacker stopped")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
