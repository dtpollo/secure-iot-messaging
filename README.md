# Project 1 - Secure messaging between IoT devices

Two ESP32 boards with MicroPython (Alice and Bob) send short messages to each other over Wi-Fi (UDP). The messages have confidentiality, integrity, device authentication and replay protection.

- Session key: ephemeral Diffie-Hellman (ffdhe2048) authenticated with a pre-shared key (PSK), then HKDF
- Encryption: AES-256-CBC with a random IV
- Integrity and authentication of each message: HMAC-SHA256 (Encrypt-then-MAC)
- Replay protection: session ID (SID) + sequence number (SEQ)

The design is explained piece by piece in [`docs/apuntes.md`](docs/apuntes.md).

## Folders

| Folder | Contents |
|---|---|
| `common/` | Cryptography and protocol (same code on the boards and on the PC): `padding.py`, `aes_cbc.py`, `tag.py`, `hkdf.py`, `dh.py`, `protocol.py` and `medir.py` (measurements) |
| `esp32/` | Board program (`main.py`), LED (`led.py`) and example configs |
| `pc/` | Attacker (`attacker.py`), unauthorized device (`node.py`) and example config |
| `docs/` | Notes and work plan |
| `results/` | Measurement CSV files, plots and `plot_results.py` |

## 1. What you need

- 2 ESP32 boards, Alice and Bob (tested with a generic ESP32, LED on GPIO2)
- A PC with Python 3.10 or newer, on the same Wi-Fi network as the boards. The PC is only used to upload the code, to attack, and as the unauthorized device
- MicroPython firmware for ESP32: https://micropython.org/download/ESP32_GENERIC/

## 2. Install on the PC

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## 3. Prepare each ESP32 (only once)

Flash MicroPython (change `COM5` to the board's port):

```
python -m esptool --port COM5 erase_flash
python -m esptool --port COM5 --baud 460800 write_flash 0x1000 ESP32_GENERIC-<version>.bin
```

Check that the board has `hmac`:

```
python -m mpremote connect COM5 exec "import hmac; print('hmac OK')"
```

If you get `ImportError`, install it from micropython-lib: `python -m mpremote connect COM5 mip install hmac`

## 4. Configure

Board **Alice** (`0x01`, starts the handshake, COM5) and board **Bob** (`0x02`, waits, COM7).

| Copy | As | Fill in |
|---|---|---|
| `esp32/config_alice.example.py` | `esp32/config_alice.py` | Wi-Fi, Bob's IP, PSK, PC's IP (`ATACANTE`) |
| `esp32/config_bob.example.py` | `esp32/config_bob.py` | Wi-Fi, Alice's IP, the **same** PSK, PC's IP (`ATACANTE`) |
| `pc/config.example.py` | `pc/config.py` | Bob's IP (only for the unauthorized device test) |

- Create the PSK with `python -c "import os; print(os.urandom(32).hex())"`
- Each board prints its IP when it starts (`IP: ...`). The PC's IP comes from `ipconfig` (Wi-Fi adapter)
- `PORT` is always 5005: the port where each node listens. The attacker uses port 6000
- The real configs contain the PSK and the Wi-Fi password: they are not uploaded to GitHub
- If your ports are not COM5 and COM7, change `$PUERTOS` at the top of `subir.ps1`

## 5. Upload the code to the boards

```
.\subir.ps1 ambas                 (Windows, "ambas" = both boards)
bash subir.sh ambas               (Linux / WSL / Git Bash)
```

It copies `common/*.py`, `esp32/led.py` and `esp32/main.py` to each board, plus `config_alice.py` or `config_bob.py` renamed to `config.py`. To upload only one board: `.\subir.ps1 alice` or `.\subir.ps1 bob`.

## 6. Module tests (no network)

Each file in `common/` has its own test at the end (`if __name__ == "__main__":`). Run it on a board with `-Prueba` ("test"):

| Module | What it tests | Command |
|---|---|---|
| `padding.py` | PKCS#7, invalid padding rejected | `.\subir.ps1 alice -Prueba padding.py` |
| `aes_cbc.py` | NIST SP 800-38A vector, encrypt/decrypt, bit-flipping | `.\subir.ps1 alice -Prueba aes_cbc.py` |
| `tag.py` | RFC 4231 vectors, `ct_equal`, Encrypt-then-MAC | `.\subir.ps1 alice -Prueba tag.py` |
| `hkdf.py` | RFC 5869 vector, same keys on A and B | `.\subir.ps1 alice -Prueba hkdf.py` |
| `dh.py` | Safe prime, same Z on both sides, invalid Y rejected | `.\subir.ps1 alice -Prueba dh.py` |
| `protocol.py` | Handshake + every attack, without network | `.\subir.ps1 alice -Prueba protocol.py` |
| `led.py` | The 3 LED patterns | `.\subir.ps1 alice -Prueba led.py` |
| `attacker.py` | Each attack against `protocol.py`, without network (on the PC) | `python pc/attacker.py --test` |

Instead of `alice` you can use `bob` or `ambas`.

## 7. Run the secure chat (Alice ↔ Bob)

Open one terminal per board:

```
python -m mpremote connect COM7 repl        (Bob)
python -m mpremote connect COM5 repl        (Alice)
```

1. In **Bob**'s console press **Ctrl+C** and then **Ctrl+D**: the board restarts, runs `main.py` and shows `Waiting for HELLO...`
2. Do the same in **Alice**'s console: she sends the HELLO and the handshake runs
3. Both show `Handshake complete | SID: ...` with the **same SID** and turn the LED on for 1 s
4. Menu on each board: `1` send, `2` receive, `3` measure latency, `4` exit. For example, Bob picks `2` and Alice picks `1`

Packets that arrive while a board is not in "Receive" wait in a queue and are read when you pick `2`. To leave a console: **Ctrl+]**.

If Alice starts before Bob, nothing breaks: she sends the HELLO again about every 12 s.

## 8. Security tests (PDF §4)

**With the attacker in the middle.** The PC is the attacker.

1. Upload the boards in attacker mode: `.\subir.ps1 ambas -Atacante` ("with attacker"). Now they send everything to the PC (`ATACANTE` in the config), so `PEERS` does not change
2. Start the attacker: `python pc/attacker.py --mode sniff --a ALICE_IP --b BOB_IP`
3. Start the boards (section 7) and send a message
4. For the next attack do **not** restart the boards: stop the attacker with Ctrl+C and start it again with another `--mode`

| Test | Mode | What the receiving board must show |
|---|---|---|
| Normal communication | `sniff` | The message arrives. The attacker only sees nonces, DH public values, HMACs and ciphertext |
| Modified ciphertext | `tamper_c` | `Rejected: TAG` (LED blinks 3 times) |
| Modified TAG | `tamper_tag` | `Rejected: TAG` |
| Replay | `replay` | `Message received: ...` and then `Rejected: replay` |
| Forged packet | `forge` | `Rejected: TAG` |
| MITM in the handshake | `mitm` | Alice: `Rejected: handshake`. Then she retries and connects (the attack is done only once). This mode needs the boards restarted |

To go back to direct communication: `.\subir.ps1 ambas`, without `-Atacante`.

**Unauthorized device** (no attacker). The PC is the intruder and **starts** the communication with Bob. Use `pc/config.py` with Bob's IP. Bob must be uploaded without `-Atacante` and waiting for the HELLO. The intruder does not know the PSK, so it makes one up.

| Test | Command | What Bob must show |
|---|---|---|
| Unauthorized ID | `python pc/node.py --id 0x99` | `Rejected: handshake` when the HELLO arrives (Bob does not even answer) |
| Valid ID without the PSK | `python pc/node.py --psk-falsa` ("fake PSK") | Bob answers the HELLO, but shows `Rejected: handshake` when the CONFIRM arrives |

In both cases Bob keeps waiting for another HELLO and the intruder never gets a session.

## 9. Measurements on the ESP32 (PDF §5)

| What | How |
|---|---|
| Message size, packet size, seal time (encrypt) and open time (verify + decrypt) for L = 8, 32, 128, 512 B (n = 100 each), handshake time, cost of rejecting a packet | `.\subir.ps1 alice -Prueba medir.py` |
| Time of each real message and of the handshake | `main.py` prints it on every send and receive |
| Latency | Option `3` on Alice while Bob is in `2` (50 protected PING/PONG, mean RTT and RTT/2) |

Every measurement is saved to a CSV file, and the plots are made from those files:

1. `.\subir.ps1 alice -Prueba medir.py` leaves `measure_esp32.csv` on the board. Close the console (Ctrl+]) and copy it to the PC:
   `python -m mpremote connect COM5 fs cp :measure_esp32.csv results/measure_esp32.csv`
2. Option `3` on Alice leaves `latency_esp32.csv` on the board. Close the console (Ctrl+]) and copy it:
   `python -m mpremote connect COM5 fs cp :latency_esp32.csv results/latency_esp32.csv`
3. Make the plots: `python results/plot_results.py`. It saves `packet_size.png`, `crypto_time.png`, `latency.png` and `operation_cost.png` in `results/` and prints a table with the results. If a CSV is missing, the plot that needs it is skipped
