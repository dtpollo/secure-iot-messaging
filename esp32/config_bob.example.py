# BOB config (the board that waits for the HELLO)
# Copy as esp32/config_bob.py and fill in the data. config_bob.py is NOT pushed to GitHub.
# subir.ps1 copies it to the board with the name config.py.

import binascii

WIFI_SSID = "MyNetwork"             # the same network as Alice
WIFI_PASSWORD = "password"

# Network IPs
IP_ALICE = "192.168.1.30"
IP_ATACANTE = "192.168.1.20"

MY_ID = 0x02
PORT = 5005                         # port this board listens on (do not change it)
INITIATOR = False                   # Bob waits for the HELLO

PEERS = {0x01: (IP_ALICE, 5005)}     # Alice's IP (Alice prints it when it starts)

# The SAME PSK as in config_alice.py
PSKS = {0x01: binascii.unhexlify("00" * 32)}

# Attack tests: with  .\subir.ps1 bob -Atacante  the packets go to the attacker PC
ATACANTE = (IP_ATACANTE, 6000)          # IP of the PC that runs attacker.py
USAR_ATACANTE = False

LED_PIN = 2
