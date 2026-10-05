# PC config for node.py. Copy it as pc/config.py and fill in the data.
# config.py is NOT uploaded to GitHub.
#
# With two ESP32 boards the PC acts as the INTRUDER against Bob (unauthorized device test):
#   python pc/node.py --id 0x99       ID that is not authorized
#   python pc/node.py --psk-falsa     pretends to be Alice (MY_ID) but without the PSK
# The intruder makes up its own PSK, so PSKS is not used in those tests.
# (attacker.py does not use this file.)

import binascii

MY_ID = 0x01                    # ID it claims to have (Alice's)
PORT = 5005
INITIATOR = True                # the intruder starts the communication

PEERS = {0x02: ("192.168.1.31", 5005)}     # Bob's IP

# Only to use node.py as a legitimate node (without --id or --psk-falsa)
PSKS = {0x02: binascii.unhexlify("00" * 32)}
