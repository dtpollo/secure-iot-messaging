# main.py - Programa de la ESP32 (se ejecuta solo al prender la placa)
# Responsable: Integrante B
#
# Por hacer:
#   [ ] Conectar al Wi-Fi e imprimir la IP
#   [ ] Abrir un socket UDP en config.PORT
#   [ ] Hacer el handshake (Initiator o Responder segun config.INITIATOR)
#   [ ] Imprimir el SID y prender el LED 1 s
#   [ ] Recibir paquetes, abrirlos con session.open() e imprimir el mensaje
#   [ ] Si llega protocol.Rejected, imprimir el motivo y hacer led.rechazado()
#   [ ] Enviar mensajes con session.seal()
#   [ ] Medir los tiempos con time.ticks_us() (para la evaluacion)

import config
import led
import protocol
