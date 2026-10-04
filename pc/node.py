# node.py - Nodo en el PC (hace de segundo dispositivo)
# Responsable: Integrante B
#
# Uso:
#   python pc/node.py               nodo normal
#   python pc/node.py --id 0x99     dispositivo NO autorizado
#   python pc/node.py --bench       medir tamanos, tiempos y latencia
#
# Por hacer:
#   [x] Abrir un socket UDP en config.PORT
#   [x] Hacer el handshake (Initiator o Responder segun config.INITIATOR)
#   [x] Leer mensajes del teclado, sellarlos con session.seal() y enviarlos
#   [x] Recibir paquetes, abrirlos con session.open() e imprimirlos
#   [x] Si llega protocol.Rejected, imprimir el motivo
#   [x] --id: usar otro ID para probar un dispositivo no autorizado
#   [x] --bench: medir tamano del mensaje y del paquete, tiempo de cifrado,
#       tiempo de descifrado + verificacion y latencia

import os
import sys
import socket
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))

import config      # noqa: E402
import protocol    # noqa: E402

def crear_socket():
    # Socket UDP del PC
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", config.PORT))
    print("Socket UDP abierto en el puerto", config.PORT)
    return sock

def obtener_id():
    # Usar el ID normal o el indicado con --id
    my_id = config.MY_ID
    if "--id" in sys.argv:
        posicion = sys.argv.index("--id")
        if posicion + 1 < len(sys.argv):
            my_id = int(sys.argv[posicion + 1], 0)
    return my_id

def obtener_peer():
    # El proyecto trabaja con un solo par 
    peer_id = list(config.PEERS.keys())[0]
    peer_addr = config.PEERS[peer_id]
    return peer_id, peer_addr

def handshake_iniciador(sock, my_id, peer_id, peer_addr):
    # El que manda el HELLO
    hs = protocol.Initiator(my_id, config.PSKS)
    hello = hs.hello(peer_id)
    sock.sendto(hello, peer_addr)
    print("HELLO enviado")
    response, addr = sock.recvfrom(2048)
    print("RESPONSE recibido de", addr)
    confirm, session = hs.on_response(response)
    sock.sendto(confirm, peer_addr)
    print("CONFIRM enviado")
    return session


def handshake_responder(sock, my_id):
    # El que espera el HELLO
    hs = protocol.Responder(my_id, config.PSKS)
    print("Esperando HELLO...")
    hello, peer_addr = sock.recvfrom(2048)
    print("HELLO recibido de", peer_addr)
    response = hs.on_hello(hello)
    sock.sendto(response, peer_addr)
    print("RESPONSE enviado")
    confirm, addr = sock.recvfrom(2048)
    print("CONFIRM recibido de", addr)
    session = hs.on_confirm(confirm)
    return session, peer_addr


def enviar_mensaje(sock, session, peer_addr, texto, bench):
    mensaje = texto.encode()
    inicio = time.perf_counter()
    paquete = session.seal(mensaje)
    fin = time.perf_counter()
    sock.sendto(paquete, peer_addr)
    print("Mensaje enviado:", texto)
    if bench:
        print("Tamano mensaje:", len(mensaje), "bytes")
        print("Tamano paquete:", len(paquete), "bytes")
        print("Tiempo seal:", round((fin - inicio) * 1000, 3), "ms")


def recibir_mensaje(sock, session, bench):
    print("Esperando mensaje...")
    paquete, addr = sock.recvfrom(4096)
    inicio = time.perf_counter()
    try:
        mensaje = session.open(paquete)
    except protocol.Rejected as e:
        print("Rechazado:", e)
        return
    fin = time.perf_counter()
    print("Mensaje recibido:", mensaje.decode())
    if bench:
        print("Tamano paquete:", len(paquete), "bytes")
        print("Tamano mensaje:", len(mensaje), "bytes")
        print("Tiempo open:", round((fin - inicio) * 1000, 3), "ms")

def chat(sock, session, peer_addr, bench):
    # Menu simple para enviar o recibir
    while True:
        print()
        print("1. Enviar mensaje")
        print("2. Recibir mensaje")
        print("3. Salir")
        opcion = input("> ")
        if opcion == "1":
            texto = input("Mensaje: ")
            enviar_mensaje(sock, session, peer_addr, texto, bench)
        elif opcion == "2":
            recibir_mensaje(sock, session, bench)
        elif opcion == "3":
            break
        else:
            print("Opcion invalida")


def main():
    my_id = obtener_id()
    bench = "--bench" in sys.argv
    print("ID:", hex(my_id))
    sock = crear_socket()
    peer_id, peer_addr = obtener_peer()
    try:
        if config.INITIATOR:
            session = handshake_iniciador(sock, my_id, peer_id, peer_addr)
        else:
            session, peer_addr = handshake_responder(sock, my_id)
        print("Handshake completado")
        print("SID:", session.sid.hex())
        chat(sock, session, peer_addr, bench)
    except protocol.Rejected as e:
        print("Rechazado:", e)
    except KeyboardInterrupt:
        print("\nPrograma detenido")
    finally:
        sock.close()


if __name__ == "__main__":
    main()