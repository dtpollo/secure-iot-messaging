# Copiar este archivo como config.py y llenar los datos.
# config.py NO se sube a GitHub.

import binascii

WIFI_SSID = "MiRed"
WIFI_PASSWORD = "clave"

MY_ID = 0x01
PORT = 5005
INITIATOR = True                # True = esta placa manda el HELLO

PEERS = {0x02: ("192.168.1.20", 5005)}     # IP y puerto del otro nodo

# PSK de 32 bytes, la misma en los dos nodos. Generarla con:
#   python -c "import os; print(os.urandom(32).hex())"
PSKS = {0x02: binascii.unhexlify("00" * 32)}

LED_PIN = 2
