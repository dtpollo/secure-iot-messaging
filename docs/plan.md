# Work plan

**Deadline: Sunday, October 4.**
Each of us works on their part with their own ESP32 and PC. At the end we meet to test ESP32 ↔ ESP32 and record the demo.

## 1. What the professor asks for

- [ ] Set up a session key (DH + PSK) and explain how the devices are authenticated
- [ ] Encrypt every message
- [ ] Reject messages with a changed ciphertext, TAG, sender or SEQ
- [ ] Detect repeated messages (replay)
- [ ] Use only standard algorithms and libraries
- [ ] Test: normal communication, modified ciphertext, modified TAG, replay, forged packet and unauthorized device
- [ ] Measure on the ESP32: message size, packet size, encryption time, decryption time and latency
- [ ] Deliver: code, architecture diagram, sequence diagram, packet format and report

## 2. Who does what

| | Member A: ________ | Member B: ________ |
|---|---|---|
| Part | Cryptography and protocol | Network, ESP32 and attacks |
| Files | `common/padding.py`, `aes_cbc.py`, `tag.py`, `hkdf.py`, `dh.py`, `protocol.py`, `medir.py` | `esp32/main.py`, `esp32/led.py`, `pc/node.py`, `pc/attacker.py` |

## 3. How the two parts connect

B only uses these functions from `protocol.py`:

```python
# the one who starts
hs = protocol.Initiator(my_id, psks)
hello = hs.hello(peer_id)
confirm, session = hs.on_response(response)

# the one who answers
hs = protocol.Responder(my_id, psks)
response = hs.on_hello(hello)
session = hs.on_confirm(confirm)

# messages
packet = session.seal(b"Hello")
message = session.open(packet)     # if it fails it raises protocol.Rejected("reason")
```

`protocol.py` is already the **real version** (DH + PSK, AES-CBC, HMAC). The names did not change.

## 4. Status

**Code (done)**
- [x] Implement the crypto modules, each with its own test (`padding`, `aes_cbc`, `tag`, `hkdf`, `dh`, `protocol`)
- [x] Write the chat in `main.py` (handshake retry, time per message, latency)
- [x] Write `led.py` with its test
- [x] Write the 6 modes of `attacker.py` and its offline test (`--test`)
- [x] Write the intruder in `node.py` (`--id 0x99` and `--psk-falsa`)
- [x] Write `common/medir.py` (sizes and times with n = 100)

**Prepare the two boards**
- [x] Flash MicroPython on both and check `import hmac` (README §3)
- [x] Create `esp32/config_alice.py` (COM5) and `esp32/config_bob.py` (COM7) with the same PSK
- [x] Put Bob's IP in `config_alice.py` and in `pc/config.py`
- [x] Upload the code to both boards with `.\subir.ps1 ambas`

**Test (README §6–§9)**
- [ ] Run each module's test on the board
- [x] Test ESP32 ↔ ESP32
- [ ] Run the attacks in the table
- [x] Measure with `medir.py` on the board
- [ ] Measure the latency again with option `3` (50 PINGs) and copy `latency_esp32.csv` to `results/`
- [ ] Make the plots with `python results/plot_results.py`
- [ ] Record a video and take screenshots

| Test | How | What you must see |
|---|---|---|
| Normal communication | `.\subir.ps1 ambas -Atacante` and `attacker.py --mode sniff` | The message arrives; the attacker only sees ciphertext |
| Modified ciphertext | `--mode tamper_c` | `Rejected: TAG` |
| Modified TAG | `--mode tamper_tag` | `Rejected: TAG` |
| Replay | `--mode replay` | `Message received` and then `Rejected: replay` |
| Forged packet | `--mode forge` | `Rejected: TAG` |
| MITM | `--mode mitm` | `Rejected: handshake` on Alice, then she connects |
| Unauthorized ID | `node.py --id 0x99` against Bob | `Rejected: handshake` |
| Valid ID without PSK | `node.py --psk-falsa` against Bob | `Rejected: handshake` |

## 5. Rules

- Never upload `config.py`, `config_alice.py` or `config_bob.py` (they have the keys)
- Run `git pull` before you start working
- Do not change the function names in section 3 without telling the other member
