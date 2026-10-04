# main.py - Programa de la ESP32 (se ejecuta solo al prender la placa)
# Responsable: Integrante B
#
# Por hacer:
#   [x] Conectar al Wi-Fi e imprimir la IP
#   [x] Abrir un socket UDP en config.PORT
#   [x] Hacer el handshake (Initiator o Responder segun config.INITIATOR)
#   [x] Indicar handshake correcto y prender el LED 1 s
#   [x] Recibir paquetes, abrirlos con session.open() e imprimir el mensaje
#   [x] Si llega protocol.Rejected, imprimir el motivo y hacer led.rechazado()
#   [x] Enviar mensajes con session.seal()
#   [ ] Medir los tiempos con time.ticks_us() (para la evaluacion)

import config
import led
import protocol
import network
import socket
import time

PING = b"\x00BENCH_PING"
PONG = b"\x00BENCH_PONG"


def conectar_wifi():
    wifi = network.WLAN(network.STA_IF)
    wifi.active(True)
    if not wifi.isconnected():
        wifi.connect(config.WIFI_SSID, config.WIFI_PASSWORD)
        inicio = time.ticks_ms()
        while not wifi.isconnected():
            if time.ticks_diff(time.ticks_ms(), inicio) >= 20000:
                raise OSError("No se pudo conectar al Wi-Fi")
            time.sleep_ms(200)
    print("IP:", wifi.ifconfig()[0])
    return wifi


def crear_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", config.PORT))
    print("Socket UDP abierto en el puerto", config.PORT)
    return sock


def obtener_peer():
    peer_id = list(config.PEERS.keys())[0]
    return peer_id, config.PEERS[peer_id]


def handshake_iniciador(sock, peer_id, peer_addr):
    # El que manda el HELLO
    hs = protocol.Initiator(config.MY_ID, config.PSKS)
    sock.sendto(hs.hello(peer_id), peer_addr)
    print("HELLO enviado")
    response, addr = sock.recvfrom(2048)
    print("RESPONSE recibido de", addr)
    confirm, session = hs.on_response(response)
    sock.sendto(confirm, peer_addr)
    print("CONFIRM enviado")
    return session


def handshake_responder(sock):
    # El que espera el HELLO
    hs = protocol.Responder(config.MY_ID, config.PSKS)
    print("Esperando HELLO...")
    hello, peer_addr = sock.recvfrom(2048)
    response = hs.on_hello(hello)
    sock.sendto(response, peer_addr)
    print("RESPONSE enviado")
    confirm, addr = sock.recvfrom(2048)
    print("CONFIRM recibido de", addr)
    session = hs.on_confirm(confirm)
    return session, peer_addr


def enviar_mensaje(sock, session, peer_addr):
    texto = input("Mensaje: ")
    sock.sendto(session.seal(texto.encode()), peer_addr)
    print("Mensaje enviado:", texto)


def recibir_mensaje(sock, session):
    print("Esperando mensaje...")
    paquete, addr = sock.recvfrom(4096)
    try:
        mensaje = session.open(paquete)
    except protocol.Rejected as e:
        print("Rechazado:", e)
        led.rechazado()
        return
    if mensaje == PING:
        # Respuesta protegida para medir RTT desde el PC
        sock.sendto(session.seal(PONG), addr)
        print("Prueba de latencia respondida")
    else:
        try:
            print("Mensaje recibido:", mensaje.decode())
        except UnicodeError:
            print("Mensaje recibido (bytes):", mensaje)
    led.aceptado()


def chat(sock, session, peer_addr):
    # Menu simple para enviar o recibir
    while True:
        print("\n1. Enviar mensaje")
        print("2. Recibir mensaje")
        print("3. Salir")
        opcion = input("> ")
        if opcion == "1":
            enviar_mensaje(sock, session, peer_addr)
        elif opcion == "2":
            recibir_mensaje(sock, session)
        elif opcion == "3":
            return
        else:
            print("Opcion invalida")


def main():
    sock = None
    try:
        conectar_wifi()
        sock = crear_socket()
        peer_id, peer_addr = obtener_peer()
        if config.INITIATOR:
            session = handshake_iniciador(sock, peer_id, peer_addr)
        else:
            session, peer_addr = handshake_responder(sock)
        print("Handshake completado")
        print("SID:", session.sid.hex())
        led.handshake_ok()
        chat(sock, session, peer_addr)
    except protocol.Rejected as e:
        print("Rechazado:", e)
        led.rechazado()
    except OSError as e:
        print("Error de red:", e)
    except KeyboardInterrupt:
        print("\nPrograma detenido")
    finally:
        if sock is not None:
            sock.close()


if __name__ == "__main__":
    main()
