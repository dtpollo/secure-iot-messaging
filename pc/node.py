# node.py - Nodo en el PC (hace de segundo dispositivo)
# Responsable: Integrante B
#
# Uso:
#   python pc/node.py               nodo normal
#   python pc/node.py --id 0x99     dispositivo NO autorizado
#   python pc/node.py --bench       medir tamanos, tiempos y latencia
#
# Por hacer:
#   [ ] Abrir un socket UDP en config.PORT
#   [ ] Hacer el handshake (Initiator o Responder segun config.INITIATOR)
#   [ ] Leer mensajes del teclado, sellarlos con session.seal() y enviarlos
#   [ ] Recibir paquetes, abrirlos con session.open() e imprimirlos
#   [ ] Si llega protocol.Rejected, imprimir el motivo
#   [ ] --id: usar otro ID para probar un dispositivo no autorizado
#   [ ] --bench: medir tamano del mensaje y del paquete, tiempo de cifrado,
#       tiempo de descifrado + verificacion y latencia

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))

import config      # noqa: E402
import protocol    # noqa: E402
