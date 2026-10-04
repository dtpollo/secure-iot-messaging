# Proyecto 1 - Mensajería segura entre dispositivos IoT

Dos ESP32 con MicroPython se mandan mensajes por Wi-Fi (UDP) con confidencialidad, integridad, autenticación y protección contra replay.

- Clave de sesión: Diffie-Hellman (ffdhe2048) + PSK, con HKDF
- Cifrado: AES-256-CBC
- Integridad y autenticación: HMAC-SHA256 (Encrypt-then-MAC)
- Anti-replay: SID + número de secuencia

## Carpetas

| Carpeta | Qué tiene |
|---|---|
| `common/` | `padding.py`, `aes_cbc.py`, `tag.py`, `hkdf.py`, `dh.py` y `protocol.py`: el mismo código para el PC y la ESP32 |
| `esp32/` | Programa de la placa |
| `pc/` | Nodo del PC y atacante |
| `docs/` | Apuntes y plan de trabajo |

## Instalar

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Copiar `esp32/config.example.py` como `esp32/config.py` y `pc/config.example.py` como `pc/config.py`, y llenar los datos.

## Pasar el código a la ESP32

```
mpremote connect COM5 fs cp common/padding.py :padding.py
mpremote connect COM5 fs cp common/aes_cbc.py :aes_cbc.py
mpremote connect COM5 fs cp common/tag.py :tag.py
mpremote connect COM5 fs cp common/hkdf.py :hkdf.py
mpremote connect COM5 fs cp common/dh.py :dh.py
mpremote connect COM5 fs cp common/protocol.py :protocol.py
mpremote connect COM5 fs cp esp32/led.py :led.py
mpremote connect COM5 fs cp esp32/config.py :config.py
mpremote connect COM5 fs cp esp32/main.py :main.py
mpremote connect COM5 reset
```

Para ver la consola de la placa: `mpremote connect COM5 repl`

## Ejecutar en el PC

```
python pc/node.py
python pc/attacker.py --mode sniff
```
