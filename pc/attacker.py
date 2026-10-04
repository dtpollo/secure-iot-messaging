# attacker.py - Atacante en medio (MITM) para las pruebas de seguridad
# Responsable: Integrante B
#
# Se pone entre los dos nodos: cada nodo le manda los paquetes al atacante
# En config.py, PEERS debe apuntar a la IP del atacante en el puerto 6000.
# El atacante funciona como relay y reenvia los paquetes al otro nodo.
#
# Uso:
#   python pc/attacker.py --mode sniff --a IP_A --b IP_B       ver los paquetes
#   python pc/attacker.py --mode tamper_c --a IP_A --b IP_B    cambiar 1 bit del ciphertext -> Rechazado: TAG
#   python pc/attacker.py --mode tamper_tag --a IP_A --b IP_B  cambiar 1 bit del TAG -> Rechazado: TAG
#   python pc/attacker.py --mode replay --a IP_A --b IP_B      reenviar un paquete viejo -> Rechazado: replay
#   python pc/attacker.py --mode forge --a IP_A --b IP_B       inventar un paquete -> Rechazado: TAG
#
# Por hacer:
#   [x] Recibir de un nodo y reenviar al otro
#   [x] Implementar los 5 modos (solo tocar paquetes DATA, TYPE = 0x10)
#   [x] Imprimir que se hizo con cada paquete

import os
import socket
import sys
import time
import config

DATA = 0x10
PORT_ATACANTE = 6000
# Posiciones en el paquete DATA
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

def mostrar_paquete(data):
    # Mostrar los campos del paquete DATA
    print("TYPE:", hex(data[0]))
    print("IDS:", hex(data[IDS]))
    print("SID:", data[SID].hex())
    print("SEQ:", int.from_bytes(data[SEQ], "big"))
    print("IV:", data[IV].hex())
    print("C:", data[C].hex())
    print("TAG:", data[TAG].hex())

def modificar_ciphertext(data):
    # Cambiar un bit del ciphertext
    paquete = bytearray(data)
    if len(paquete[C]) > 0:
        paquete[26] ^= 1
    return bytes(paquete)

def modificar_tag(data):
    # Cambiar un bit del TAG
    paquete = bytearray(data)
    paquete[-1] ^= 1
    return bytes(paquete)

def crear_falso(data):
    # Crear un paquete con datos inventados y un TAG invalido
    paquete = bytearray(data)
    paquete[IV] = os.urandom(16)
    paquete[C] = os.urandom(len(paquete[C]))
    paquete[TAG] = os.urandom(16)
    return bytes(paquete)

def procesar_paquete(sock, data, destino, mode, ataque_hecho):
    # Los paquetes del handshake se reenvian sin modificar
    if len(data) == 0 or data[0] != DATA:
        sock.sendto(data, destino)
        print("Handshake reenviado")
        return ataque_hecho
    if len(data) < 58 or (len(data) - 42) % 16 != 0:
        sock.sendto(data, destino)
        print("DATA con formato invalido reenviado")
        return ataque_hecho
    if mode == "sniff":
        print()
        print("Paquete DATA capturado")
        mostrar_paquete(data)
        sock.sendto(data, destino)
    elif mode == "tamper_c" and not ataque_hecho:
        paquete = modificar_ciphertext(data)
        sock.sendto(paquete, destino)
        print("Ciphertext modificado")
        ataque_hecho = True
    elif mode == "tamper_tag" and not ataque_hecho:
        paquete = modificar_tag(data)
        sock.sendto(paquete, destino)
        print("TAG modificado")
        ataque_hecho = True
    elif mode == "replay" and not ataque_hecho:
        # Primero llega el paquete normal
        sock.sendto(data, destino)
        time.sleep(0.2)
        # Luego se manda exactamente el mismo paquete
        sock.sendto(data, destino)
        print("Paquete reenviado dos veces")
        ataque_hecho = True
    elif mode == "forge" and not ataque_hecho:
        paquete = crear_falso(data)
        sock.sendto(paquete, destino)
        print("Paquete falso enviado")
        ataque_hecho = True
    else:
        # Despues del ataque los demas paquetes pasan normalmente
        sock.sendto(data, destino)
        print("DATA reenviado")
    return ataque_hecho

def main():
    mode = obtener_argumento("--mode")
    ip_a = obtener_argumento("--a")
    ip_b = obtener_argumento("--b")
    modos = [
        "sniff",
        "tamper_c",
        "tamper_tag",
        "replay",
        "forge"
    ]
    if mode not in modos:
        print("Modo invalido")
        return
    if ip_a is None or ip_b is None:
        print("Faltan las IP de los dos nodos")
        return
    nodo_a = (ip_a, config.PORT)
    nodo_b = (ip_b, config.PORT)
    if nodo_a == nodo_b:
        print("Los nodos deben tener direcciones distintas")
        return
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", PORT_ATACANTE))
    print("Atacante escuchando en el puerto", PORT_ATACANTE)
    print("Modo:", mode)
    print("Nodo A:", nodo_a)
    print("Nodo B:", nodo_b)
    ataque_hecho = False
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            if addr == nodo_a:
                destino = nodo_b
                print("A -> B")
            elif addr == nodo_b:
                destino = nodo_a
                print("B -> A")
            else:
                print("Paquete de origen desconocido:", addr)
                continue
            ataque_hecho = procesar_paquete(
                sock,
                data,
                destino,
                mode,
                ataque_hecho
            )
    except KeyboardInterrupt:
        print("\nAtacante detenido")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
