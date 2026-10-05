# node.py - Node on the PC, mainly the intruder for the unauthorized device test
# (it can also act as a normal node)
# Owner: Member B
#
# Usage:
#   python pc/node.py                normal node
#   python pc/node.py --id 0x99      intruder with an ID that is not authorized (and without the PSK)
#   python pc/node.py --psk-falsa    intruder with a valid ID but without the PSK
#
# The intruder makes only one handshake attempt and shows why it was rejected.
# If it is the initiator and gets the RESPONSE, it still sends its CONFIRM (made with its fake PSK)
# to show that the legitimate node also rejects it.
# Each message shows its size and the seal / open time (PDF §5).

import os
import sys
import socket
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))

import config      # noqa: E402   (pc/config.py, in the same folder as node.py)
import protocol    # noqa: E402
from medir import ahora_us, ms_desde, resumen     # noqa: E402

PING = b"\x00BENCH_PING"
PONG = b"\x00BENCH_PONG"
ESPERA_HANDSHAKE = 10       # s waiting for RESPONSE or CONFIRM
ESPERA_MENSAJE = 60         # s waiting for the first message in "Receive"
ESPERA_COLA = 1             # s to read the next ones in the queue (so the replay is seen)
N_PING = 50                 # repetitions for the latency


def crear_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", config.PORT))
    print("UDP socket open on port", config.PORT)
    return sock


def leer_argumentos():
    # Returns (my_id, psks, intruso)
    my_id = config.MY_ID
    psks = config.PSKS
    intruso = False
    if "--id" in sys.argv:
        posicion = sys.argv.index("--id")
        if posicion + 1 < len(sys.argv):
            my_id = int(sys.argv[posicion + 1], 0)
        intruso = True
    if "--psk-falsa" in sys.argv:
        intruso = True
    if intruso:
        # The intruder does not know the PSK: it uses a made-up one
        psks = {peer: os.urandom(32) for peer in config.PEERS}
    return my_id, psks, intruso


def obtener_peer():
    # The project works with a single pair
    peer_id = list(config.PEERS.keys())[0]
    return peer_id, config.PEERS[peer_id]


def recibir(sock):
    # recvfrom that ignores WinError 10054: on Windows, if one of our packets reached
    # a closed port, the next recvfrom raises ConnectionResetError
    while True:
        try:
            return sock.recvfrom(4096)
        except ConnectionResetError:
            pass


def esperar_paquete(sock):
    # recvfrom with no limit, but every 1 s it lets Ctrl+C through (on Windows it does not stop a recvfrom)
    sock.settimeout(1)
    while True:
        try:
            return recibir(sock)
        except socket.timeout:
            pass


def confirm_sin_psk(hs, response, psk):
    # CONFIRM that the intruder would build with its fake PSK
    t = bytes([hs.my_id, hs.peer_id]) + hs.na + response[2:18] + hs.ya + response[18:274]
    return bytes([protocol.CONFIRM, hs.my_id]) + protocol.hmac_sha256(psk, b"A" + t)


def handshake_iniciador(sock, my_id, psks, intruso, peer_id, peer_addr):
    # Sends HELLO and waits for RESPONSE; the normal node retries, the intruder does not
    while True:
        hs = protocol.Initiator(my_id, psks)
        t0 = ahora_us()
        sock.sendto(hs.hello(peer_id), peer_addr)
        print("HELLO sent to", peer_addr)
        try:
            sock.settimeout(ESPERA_HANDSHAKE)
            response, addr = recibir(sock)
            print("RESPONSE received from", addr)
            confirm, session = hs.on_response(response)
        except protocol.Rejected as e:
            print("Rejected:", e)
            if intruso:
                sock.sendto(confirm_sin_psk(hs, response, psks[peer_id]), peer_addr)
                print("Fake CONFIRM sent: the other node must show 'Rejected: handshake'")
                return None
        except OSError:
            print("No RESPONSE in", ESPERA_HANDSHAKE, "s")
            if intruso:
                print("The other node rejected the HELLO")
                return None
        else:
            sock.sendto(confirm, peer_addr)
            print("CONFIRM sent")
            print("Handshake time (HELLO -> CONFIRM):", round(ms_desde(t0), 1), "ms")
            return session
        print("Retrying in 2 s...")
        time.sleep(2)


def handshake_responder(sock, my_id, psks, intruso):
    # Waits for HELLO; the normal node waits again if something fails, the intruder does not
    siguiente = None        # HELLO that arrived while waiting for the CONFIRM (the other one retried)
    while True:
        hs = protocol.Responder(my_id, psks)
        if siguiente is None:
            print("Waiting for HELLO...")
            hello, peer_addr = esperar_paquete(sock)
        else:
            hello, peer_addr = siguiente
            siguiente = None
        t0 = ahora_us()
        print("HELLO received from", peer_addr)
        try:
            response = hs.on_hello(hello)
            sock.sendto(response, peer_addr)
            print("RESPONSE sent")
            sock.settimeout(ESPERA_HANDSHAKE)
            confirm, addr = recibir(sock)
            if len(confirm) > 0 and confirm[0] == protocol.HELLO:
                if intruso:
                    print("The other node rejected the RESPONSE and sent HELLO again")
                    return None, None
                print("Got another HELLO instead of the CONFIRM: starting again")
                siguiente = (confirm, addr)
                continue
            print("CONFIRM received from", addr)
            session = hs.on_confirm(confirm)
        except protocol.Rejected as e:
            print("Rejected:", e)
        except OSError:
            print("No CONFIRM in", ESPERA_HANDSHAKE, "s")
            if intruso:
                print("The other node rejected the RESPONSE")
        else:
            print("Handshake time (HELLO -> CONFIRM):", round(ms_desde(t0), 1), "ms")
            return session, peer_addr
        if intruso:
            return None, None


def enviar_mensaje(sock, session, peer_addr):
    mensaje = input("Message: ").encode()
    t0 = ahora_us()
    paquete = session.seal(mensaje)
    t_seal = ms_desde(t0)
    sock.sendto(paquete, peer_addr)
    print("Sent | message", len(mensaje), "B, packet", len(paquete), "B, seal", round(t_seal, 3), "ms")


def procesar_paquete(sock, session, peer_addr, paquete):
    t0 = ahora_us()
    try:
        mensaje = session.open(paquete)
    except protocol.Rejected as e:
        print("Rejected:", e, "| packet", len(paquete), "B")
        return
    t_open = ms_desde(t0)
    if mensaje == PING:
        sock.sendto(session.seal(PONG), peer_addr)
        print("Latency PING answered")
        return
    print("Message received:", mensaje.decode("utf-8", "replace"))
    print("   message", len(mensaje), "B, packet", len(paquete), "B, open", round(t_open, 3), "ms")


def recibir_mensajes(sock, session, peer_addr):
    # Waits for the first packet and then reads the ones already in the queue
    print("Waiting for message...")
    espera = ESPERA_MENSAJE
    while True:
        sock.settimeout(espera)
        try:
            paquete, addr = recibir(sock)
        except OSError:
            if espera == ESPERA_MENSAJE:
                print("No message in", ESPERA_MENSAJE, "s")
            return
        procesar_paquete(sock, session, peer_addr, paquete)
        espera = ESPERA_COLA


def medir_latencia(sock, session, peer_addr):
    # RTT of a protected PING/PONG. The other node must be in "Receive"
    tiempos = []
    sock.settimeout(5)
    for i in range(N_PING):
        t0 = ahora_us()
        sock.sendto(session.seal(PING), peer_addr)
        try:
            paquete, addr = recibir(sock)
            if session.open(paquete) == PONG:
                tiempos.append(ms_desde(t0))
        except protocol.Rejected as e:
            print("Rejected:", e)
        except OSError:
            print("No answer to PING", i + 1, "(is the other node in Receive?)")
            break
    if tiempos:
        prom, desv = resumen(tiempos)
        print("RTT (n=%d): %.1f +- %.1f ms | latency ~ RTT/2 = %.1f ms" % (len(tiempos), prom, desv, prom / 2))


def chat(sock, session, peer_addr):
    while True:
        print()
        print("1. Send message")
        print("2. Receive messages")
        print("3. Measure latency (the other node must be in Receive)")
        print("4. Exit")
        opcion = input("> ")
        if opcion == "1":
            enviar_mensaje(sock, session, peer_addr)
        elif opcion == "2":
            recibir_mensajes(sock, session, peer_addr)
        elif opcion == "3":
            medir_latencia(sock, session, peer_addr)
        elif opcion == "4":
            return
        else:
            print("Invalid option")


def main():
    my_id, psks, intruso = leer_argumentos()
    peer_id, peer_addr = obtener_peer()
    print("ID:", hex(my_id), "| peer:", hex(peer_id), peer_addr, "| INTRUDER" if intruso else "")
    sock = crear_socket()
    try:
        if config.INITIATOR:
            session = handshake_iniciador(sock, my_id, psks, intruso, peer_id, peer_addr)
        else:
            session, peer_addr = handshake_responder(sock, my_id, psks, intruso)
        if session is None:
            print("The intruder could not create a session")
            return
        print("Handshake complete | SID:", session.sid.hex())
        chat(sock, session, peer_addr)
    except protocol.Rejected as e:
        print("Rejected:", e, "(check that PSKS has the peer ID in config.py)")
    except KeyboardInterrupt:
        print("\nProgram stopped")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
