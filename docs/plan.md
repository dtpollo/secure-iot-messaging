# Plan de trabajo

**Entrega: domingo 4 de octubre.**
Cada uno trabaja su parte con su propia ESP32 y su PC. Al final nos juntamos para probar ESP32 ↔ ESP32 y grabar la demo.

## 1. Qué pide el profe

- [ ] Establecer una clave de sesión (DH + PSK) y explicar cómo se autentican los dispositivos
- [ ] Cifrar todos los mensajes
- [ ] Rechazar mensajes con el ciphertext, el TAG, el remitente o el SEQ cambiados
- [ ] Detectar mensajes repetidos (replay)
- [ ] Usar solo algoritmos y librerías estándar
- [ ] Probar: comunicación normal, ciphertext alterado, TAG alterado, replay, paquete falso y dispositivo no autorizado
- [ ] Medir: tamaño del mensaje, tamaño del paquete, tiempo de cifrado, tiempo de descifrado y latencia
- [ ] Entregar: código, diagrama de arquitectura, diagrama de secuencia, formato del paquete e informe

## 2. Quién hace qué

| | Integrante A: ________ | Integrante B: ________ |
|---|---|---|
| Parte | Criptografía y protocolo | Red, ESP32 y ataques |
| Archivos | `common/padding.py`, `aes_cbc.py`, `tag.py`, `hkdf.py`, `dh.py`, `protocol.py` | `esp32/main.py`, `esp32/led.py`, `pc/node.py`, `pc/attacker.py` |

Cada archivo tiene arriba su lista **"Por hacer"**.

## 3. Cómo se conectan las dos partes

B usa solo estas funciones de `protocol.py`:

```python
# el que inicia
hs = protocol.Initiator(my_id, psks)
hello = hs.hello(peer_id)
confirm, session = hs.on_response(response)

# el que responde
hs = protocol.Responder(my_id, psks)
response = hs.on_hello(hello)
session = hs.on_confirm(confirm)

# mensajes
paquete = session.seal(b"Hola")
mensaje = session.open(paquete)     # si falla lanza protocol.Rejected("motivo")
```

`protocol.py` ya es la **versión real** (DH + PSK, AES-CBC, HMAC). Los nombres no cambiaron.

## 4. Cronograma

### Hoy (sábado) en la noche

- [ ] Hacer `git pull` y leer este plan
- [ ] Instalar: `pip install -r requirements.txt`
- [ ] Crear los `config.py` a partir de los `config.example.py`
- [ ] Decidir quién es A y quién es B

### Mañana en la mañana: cada uno su parte

**A**
- [x] Implementar los módulos cripto (`padding`, `aes_cbc`, `tag`, `hkdf`, `dh`)
- [x] Cambiar `protocol.py` a la versión real (DH + PSK, AES-CBC, HMAC)
- [ ] Probar el handshake ESP32 ↔ PC con su placa

**B**
- [ ] Conectar la ESP32 al Wi-Fi y mandar un mensaje UDP al PC
- [ ] Programar el chat en `main.py` y `node.py`
- [ ] Programar `led.py`
- [ ] Programar los 5 modos de `attacker.py`
- [ ] Programar `--id` y `--bench` en `node.py`

### Mañana al mediodía: juntar las partes (cada uno en su casa)

- [ ] A: subir el `protocol.py` real y avisar
- [ ] B: hacer `git pull` y copiar el código nuevo a su placa
- [ ] Los dos: probar todo con su ESP32 + PC (tabla de abajo)

| Prueba | Qué se debe ver |
|---|---|
| Comunicación normal | El mensaje llega igual |
| `--mode sniff` | Solo se ve texto cifrado |
| `--mode tamper_c` | `Rechazado: TAG` |
| `--mode tamper_tag` | `Rechazado: TAG` |
| `--mode replay` | `Rechazado: replay` |
| `--mode forge` | `Rechazado: TAG` |
| `node.py --id 0x99` | `Rechazado: handshake` |

### Mañana en la tarde: prueba final juntos

- [ ] Generar una PSK nueva y ponerla en las dos placas
- [ ] Probar ESP32 ↔ ESP32 y todos los ataques de la tabla
- [ ] Medir los tiempos
- [ ] Grabar video y sacar capturas

### Mañana en la noche: entregar

- [ ] Hacer el diagrama de arquitectura y el de secuencia
- [ ] Escribir el formato del paquete
- [ ] Escribir el informe con los resultados
- [ ] Hacer el último push y entregar

## 5. Reglas

- No subir nunca `config.py` (tiene las claves)
- Hacer `git pull` antes de empezar a trabajar
- No cambiar los nombres de las funciones de la sección 3 sin avisar al otro
