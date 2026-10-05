# Instructions

Run every step in order. Commands are for Windows PowerShell from the project root, with the venv active. On Linux use `bash subir.sh alice|bob|ambas [--atacante] [file.py]` instead of `.\subir.ps1`, and `/dev/ttyUSBx` instead of `COM5`/`COM7`.

Status of the tests: 1, 2, 4 and 5 are **done** (screenshots in `results/Screenshots/`). **Still to run:** 3 (`tamper_tag`), 6 (`mitm`), 7a and 7b (intruder).

## 0. Setup (once)

```powershell
venv\Scripts\activate
python -m mpremote devs                       # Alice = COM5, Bob = COM7
python -m mpremote connect COM5 exec "import sys; print(sys.version)"   # MicroPython version
python pc/attacker.py --test                  # no boards needed: must end with "Rejected: handshake"
```

Configs (`esp32/config_alice.py`, `esp32/config_bob.py`, `pc/config.py`) must exist and have the Wi-Fi data and the same PSK. Open UDP 5005 and 6000 in the PC firewall.

Set the IPs in every PowerShell terminal you open (Alice and Bob print theirs as `IP: ...`; the PC's comes from `ipconfig`):

```powershell
$IP_ALICE    = "x.x.x.x"
$IP_BOB      = "x.x.x.x"
$IP_ATACANTE = "x.x.x.x"
```

Write the same IPs in the configs: `IP_BOB` and `IP_ATACANTE` in `config_alice.py`, `IP_ALICE` and `IP_ATACANTE` in `config_bob.py`, Bob's IP in `pc/config.py`.

## 1. Module self-tests on the board

Each command prints OK lines; none must print an error.

```powershell
.\subir.ps1 alice -Prueba padding.py
.\subir.ps1 alice -Prueba aes_cbc.py
.\subir.ps1 alice -Prueba tag.py
.\subir.ps1 alice -Prueba hkdf.py
.\subir.ps1 alice -Prueba dh.py
.\subir.ps1 alice -Prueba protocol.py
```

## 2. Normal chat (Alice and Bob)

```powershell
.\subir.ps1 ambas
python -m mpremote connect COM7 repl      # Bob: Ctrl+C, Ctrl+D
python -m mpremote connect COM5 repl      # Alice: Ctrl+C, Ctrl+D
```

Both must print `Handshake complete | SID: ...` with the same SID. Bob: option `2`. Alice: option `1`, text `Hey Bob!`. Leave a console with **Ctrl+]**.

## 3. Measurements (done; repeat only if needed)

```powershell
.\subir.ps1 alice -Prueba medir.py
python -m mpremote connect COM5 fs cp :measure_esp32.csv results/measure_esp32.csv
```

Latency: Bob in option `2`, Alice option `3`, then

```powershell
python -m mpremote connect COM5 fs cp :latency_esp32.csv results/latency_esp32.csv
python results/plot_results.py
```

## 4. Security tests with the attacker

Close the board consoles (Ctrl+]) and upload in attacker mode:

```powershell
.\subir.ps1 ambas -Atacante               # both boards must say "(WITH attacker)"
```

Terminal 1 (attacker). For each test: Ctrl+C the attacker, start it with the new `--mode`, do **not** restart the boards (except test 6).

Terminal 2: Bob (`python -m mpremote connect COM7 repl`, Ctrl+C, Ctrl+D). Terminal 3: Alice (same with COM5). Both must print `Test mode: packets go through the attacker` and `Handshake complete`. Then, in every test below: Bob option `2`, Alice option `1` and a short text.

| # | Test | Attacker command | Bob must show | Screenshots |
|---|---|---|---|---|
| 1 | Normal (sniff), done | `python pc/attacker.py --mode sniff --a $IP_ALICE --b $IP_BOB` | The message | `01_normal_sniff`, `01_normal_bob` |
| 2 | Modified C, done | `python pc/attacker.py --mode tamper_c --a $IP_ALICE --b $IP_BOB` | `Rejected: TAG` | `02_tamper_c_attacker`, `02_tamper_c_bob` |
| 3 | **Modified TAG** | `python pc/attacker.py --mode tamper_tag --a $IP_ALICE --b $IP_BOB` | `Rejected: TAG` | `03_tamper_tag_attacker`, `03_tamper_tag_bob` |
| 4 | Replay, done | `python pc/attacker.py --mode replay --a $IP_ALICE --b $IP_BOB` | Message, then `Rejected: replay` | `04_replay_attacker`, `04_replay_bob` |
| 5 | Forged packet, done | `python pc/attacker.py --mode forge --a $IP_ALICE --b $IP_BOB` | `Rejected: TAG` | `05_forge_attacker`, `05_forge_bob` |

### Test 6. MITM in the handshake (needs a restart)

```powershell
python pc/attacker.py --mode mitm --a $IP_ALICE --b $IP_BOB
```

Restart Bob, then Alice (Ctrl+C, Ctrl+D in each). Alice must show `Rejected: handshake` and then retry. Screenshots: `06_mitm_attacker`, `06_mitm_alice`.

## 5. Unauthorized device (no attacker)

Upload without the attacker and leave Bob waiting:

```powershell
.\subir.ps1 ambas
python -m mpremote connect COM7 repl      # Bob: Ctrl+C, Ctrl+D, then option 2
```

Check that `pc/config.py` has Bob's IP. In another terminal:

| Test | Command | Bob must show | Screenshots |
|---|---|---|---|
| 7a Unauthorized ID | `python pc/node.py --id 0x99` | `Rejected: handshake` on the HELLO | `07a_intruder_id` |
| 7b Valid ID, fake PSK | `python pc/node.py --psk-falsa` | Answers the HELLO, then `Rejected: handshake` on the CONFIRM | `07b_intruder_psk` |

Take each screenshot with the PC output and Bob's console visible.

## 6. After the tests

1. Save the screenshots in `results/Screenshots/` with the names above.
2. In `Formato/main.tex`, section 6.2 (Security Tests) and appendix A.1: add a paragraph and the figures for tests 3, 6, 7a and 7b, using `\reportfigure` like the existing ones. Write only what the consoles showed.
3. Update the Discussion and the Conclusions (they now say that the MITM and unauthorized-device tests were not run).
4. Compile `Formato/main.tex` and check that the body stays within 12 pages.

## Quick demo order

`.\subir.ps1 ambas` → normal chat (step 2) → `.\subir.ps1 ambas -Atacante` → tests 1 to 5 (step 4) → test 6 → `.\subir.ps1 ambas` → tests 7a and 7b (step 5).

## Troubleshooting

- `Rejected: handshake` on a normal run: the PSK differs between the configs, or the wrong IP is set.
- Nothing arrives in attacker mode: wrong `$IP_ATACANTE`, firewall blocking UDP 6000, or the boards were uploaded without `-Atacante`.
- Board does not answer in `mpremote`: close any other console on that port (Ctrl+]) and retry.
- Packets sent while a board is not in option `2` wait in a queue and are read when you pick `2`.
