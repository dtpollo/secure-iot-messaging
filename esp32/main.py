# main.py - ESP32 program (runs by itself when the board turns on)
# Owner: Member B
#
# Steps:
#   1. Connect to Wi-Fi and open the UDP socket on config.PORT
#   2. Handshake: Initiator or Responder depending on config.INITIATOR
#      - If something fails (packet rejected or no answer) it tries again,
#        so the board does not crash in the unauthorized device test
#   3. Menu: send, receive, measure latency
#
# Each message shows its size and the seal / open time (PDF §5).
# subir.ps1 copies to the board: this file, led.py, medir.py, the common/ modules
# and config_alice.py or config_bob.py with the name config.py.

import config
import led
import protocol
import network
import socket
import time
from binascii import hexlify
from medir import ahora_us, ms_desde, resumen, guardar_csv

PING = b"\x00BENCH_PING"
PONG = b"\x00BENCH_PONG"
ESPERA_HANDSHAKE = 10       # s waiting for RESPONSE or CONFIRM
ESPERA_MENSAJE = 60         # s waiting for the first message in "Receive"
ESPERA_COLA = 1             # s to read the ones still in the queue (so the replay shows up)
N_PING = 50                 # repetitions for the latency


def conectar_wifi():
    wifi = network.WLAN(network.STA_IF)
    # After a soft reboot the driver can be left in a bad state: reset it and retry
    for _ in range(3):
        try:
            wifi.active(False)
            time.sleep_ms(300)
            wifi.active(True)
            break
        except OSError:
            time.sleep_ms(500)
    else:
        raise OSError("Wi-Fi driver error: press the EN button")
    if not wifi.isconnected():
        wifi.connect(config.WIFI_SSID, config.WIFI_PASSWORD)
        inicio = time.ticks_ms()
        while not wifi.isconnected():
            if time.ticks_diff(time.ticks_ms(), inicio) >= 20000:
                raise OSError("Could not connect to Wi-Fi")
            time.sleep_ms(200)
    print("IP:", wifi.ifconfig()[0])
    return wifi


def crear_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", config.PORT))
    print("UDP socket open on port", config.PORT)
    return sock


def obtener_peer():
    # The project works with a single peer. With USAR_ATACANTE the packets go to the attacker PC,
    # which forwards them to the other node (subir.ps1 -Atacante)
    peer_id = list(config.PEERS.keys())[0]
    if getattr(config, "USAR_ATACANTE", False):
        print("Test mode: packets go through the attacker", config.ATACANTE)
        return peer_id, config.ATACANTE
    return peer_id, config.PEERS[peer_id]


def handshake_iniciador(sock, peer_id, peer_addr):
    # Sends HELLO and waits for RESPONSE; if it fails, it tries again
    while True:
        hs = protocol.Initiator(config.MY_ID, config.PSKS)
        t0 = ahora_us()
        sock.sendto(hs.hello(peer_id), peer_addr)
        print("HELLO sent to", peer_addr)
        try:
            sock.settimeout(ESPERA_HANDSHAKE)
            response, addr = sock.recvfrom(2048)
            print("RESPONSE received from", addr)
            confirm, session = hs.on_response(response)
        except protocol.Rejected as e:
            print("Rejected:", e)
            led.rechazado()
        except OSError:
            print("No RESPONSE arrived in", ESPERA_HANDSHAKE, "s")
        else:
            sock.sendto(confirm, peer_addr)
            print("CONFIRM sent")
            print("Handshake time (HELLO -> CONFIRM):", ms_desde(t0), "ms")
            return session
        print("Retrying in 2 s...")
        time.sleep(2)


def handshake_responder(sock):
    # Waits for HELLO; if it fails, it waits for another HELLO
    siguiente = None        # HELLO that arrived while waiting for the CONFIRM (the other node retried)
    while True:
        hs = protocol.Responder(config.MY_ID, config.PSKS)
        if siguiente is None:
            sock.settimeout(None)
            print("Waiting for HELLO...")
            hello, peer_addr = sock.recvfrom(2048)
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
            confirm, addr = sock.recvfrom(2048)
            if len(confirm) > 0 and confirm[0] == protocol.HELLO:
                print("Got another HELLO instead of the CONFIRM: starting again")
                siguiente = (confirm, addr)
                continue
            print("CONFIRM received from", addr)
            session = hs.on_confirm(confirm)
        except protocol.Rejected as e:
            print("Rejected:", e)
            led.rechazado()
        except OSError:
            print("No CONFIRM arrived in", ESPERA_HANDSHAKE, "s")
        else:
            print("Handshake time (HELLO -> CONFIRM):", ms_desde(t0), "ms")
            return session, peer_addr


def enviar_mensaje(sock, session, peer_addr):
    mensaje = input("Message: ").encode()
    t0 = ahora_us()
    paquete = session.seal(mensaje)
    t_seal = ms_desde(t0)
    sock.sendto(paquete, peer_addr)
    print("Sent | message", len(mensaje), "B, packet", len(paquete), "B, seal", t_seal, "ms")


def procesar_paquete(sock, session, peer_addr, paquete):
    t0 = ahora_us()
    try:
        mensaje = session.open(paquete)
    except protocol.Rejected as e:
        print("Rejected:", e, "| packet", len(paquete), "B")
        led.rechazado()
        return
    t_open = ms_desde(t0)
    if mensaje == PING:
        # No LED, so it does not add time to the latency
        sock.sendto(session.seal(PONG), peer_addr)
        print("Latency PING answered")
        return
    try:
        texto = mensaje.decode()
    except UnicodeError:
        texto = str(mensaje)
    print("Message received:", texto)
    print("   message", len(mensaje), "B, packet", len(paquete), "B, open", t_open, "ms")
    led.aceptado()


def recibir_mensajes(sock, session, peer_addr):
    # Waits for the first packet and then reads the ones already in the queue
    print("Waiting for message...")
    espera = ESPERA_MENSAJE
    while True:
        sock.settimeout(espera)
        try:
            paquete, addr = sock.recvfrom(4096)
        except OSError:
            if espera == ESPERA_MENSAJE:
                print("No message arrived in", ESPERA_MENSAJE, "s")
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
            paquete, addr = sock.recvfrom(4096)
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
        # Saved on the board: python -m mpremote connect COMx fs cp :latency_esp32.csv results/
        guardar_csv("latency_esp32.csv", "i,rtt_ms", [(i + 1, t) for i, t in enumerate(tiempos)])


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
    sock = None
    try:
        conectar_wifi()
        sock = crear_socket()
        peer_id, peer_addr = obtener_peer()
        print("ID:", hex(config.MY_ID), "| peer:", hex(peer_id), peer_addr)
        if config.INITIATOR:
            session = handshake_iniciador(sock, peer_id, peer_addr)
        else:
            session, peer_addr = handshake_responder(sock)
        print("Handshake complete | SID:", hexlify(session.sid).decode())
        led.handshake_ok()
        chat(sock, session, peer_addr)
    except protocol.Rejected as e:
        print("Rejected:", e, "(check that PSKS has the peer ID in config.py)")
    except OSError as e:
        print("Network error:", e)
    except KeyboardInterrupt:
        print("\nProgram stopped")
    finally:
        if sock is not None:
            sock.close()


if __name__ == "__main__":
    main()
