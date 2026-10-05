# Project 1 - Secure messaging between IoT devices

Two ESP32 boards with MicroPython (Alice and Bob) send short messages to each other over Wi-Fi (UDP) with confidentiality, integrity, device authentication and replay protection.

- Session key: ephemeral Diffie-Hellman (ffdhe2048) authenticated with a pre-shared key (PSK), then HKDF
- Messages: AES-256-CBC with a random IV + HMAC-SHA256 (Encrypt-then-MAC)
- Replay protection: session ID (SID) + sequence number (SEQ)

The design, the packet format, the diagrams and the results are in the report (`Formato/main.pdf`). The notes behind the design are in [`docs/apuntes.md`](docs/apuntes.md).

## Folders

| Folder | Contents |
|---|---|
| `common/` | Cryptography and protocol (same code on the boards and on the PC) and `medir.py` (measurements) |
| `esp32/` | Board program (`main.py`), LED (`led.py`) and example configs |
| `pc/` | Attacker (`attacker.py`) and unauthorized device (`node.py`) |
| `results/` | Measurement CSV files, plots, screenshots of the security tests |
| `Formato/` | LaTeX source of the report |

## Quick start

Requirements: 2 ESP32 boards with [MicroPython](https://micropython.org/download/ESP32_GENERIC/) and its `hmac` module, and a PC with Python 3.10+ on the same 2.4 GHz Wi-Fi network.

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

1. Copy `esp32/config_alice.example.py` to `esp32/config_alice.py`, `esp32/config_bob.example.py` to `esp32/config_bob.py` and `pc/config.example.py` to `pc/config.py`. Fill in the Wi-Fi data, the IPs, and the **same** PSK (`python -c "import os; print(os.urandom(32).hex())"`). These files are not uploaded to GitHub.
2. Upload the code: `.\subir.ps1 ambas` (Windows) or `bash subir.sh ambas` (Linux). If your ports are not `COM5` and `COM7`, edit `$PUERTOS` in `subir.ps1`.
3. Open a console per board (`python -m mpremote connect COM7 repl`), press Ctrl+C and Ctrl+D. Both must print `Handshake complete` with the same SID. Menu: `1` send, `2` receive, `3` latency, `4` exit.

Every step of the tests and measurements (self-tests, attacks, intruder, CSV files and plots) is in [`INSTRUCTIONS.md`](INSTRUCTIONS.md).
