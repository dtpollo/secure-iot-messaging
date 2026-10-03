# Copiar este archivo como config.py y llenar los datos.
# config.py NO se sube a GitHub.

import binascii

MY_ID = 0x02
PORT = 5005
INITIATOR = False               # el PC espera el HELLO de la ESP32

PEERS = {0x01: ("192.168.1.30", 5005)}     # IP y puerto de la ESP32

# La misma PSK que en el config.py de la ESP32
PSKS = {0x01: binascii.unhexlify("00" * 32)}
