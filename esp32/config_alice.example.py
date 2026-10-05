# ALICE config (the board that starts the handshake)
# Copy as esp32/config_alice.py and fill in the data. config_alice.py is NOT pushed to GitHub.
# subir.ps1 copies it to the board with the name config.py.

import binascii

WIFI_SSID = "MyNetwork"             # 2.4 GHz network (e.g. phone hotspot)
WIFI_PASSWORD = "password"

# Network IPs
IP_BOB = "192.168.1.31"
IP_ATACANTE = "192.168.1.20"

MY_ID = 0x01
PORT = 5005                         # port this board listens on (do not change it)
INITIATOR = True                    # Alice sends the HELLO

PEERS = {0x02: (IP_BOB, 5005)}     # Bob's IP (Bob prints it when it starts)

# 32-byte PSK, the SAME on Alice and Bob. Generate it with:
#   python -c "import os; print(os.urandom(32).hex())"
PSKS = {0x02: binascii.unhexlify("00" * 32)}

# Attack tests: with  .\subir.ps1 alice -Atacante  the packets go to the attacker PC
ATACANTE = (IP_ATACANTE, 6000)          # IP of the PC that runs attacker.py
USAR_ATACANTE = False

LED_PIN = 2
