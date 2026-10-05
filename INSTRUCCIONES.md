# Instrucciones

## EXP1. Subir códigos y obtener la IP de cada placa

**Bob**

```powershell
.\subir.ps1 bob
python -m mpremote connect COM7 repl
```

**Alice**

```powershell
.\subir.ps1 alice
python -m mpremote connect COM5 repl
```

## EXP2. Mediciones

1. Subir los códigos a la vez:
   ```powershell
   .\subir.ps1 ambas
   ```
2. Igual que antes.
3. Bob recibe y Alice prueba latencia.
4. Bajar los resultados al PC:
   ```powershell
   python -m mpremote connect COM5 fs cp :latencia_esp32.csv results/latencia_esp32.csv
   ```
5. Correr las mediciones en Alice y bajarlas al PC:
   ```powershell
   .\subir.ps1 alice -Prueba medir.py
   python -m mpremote connect COM5 fs cp :medir_esp32.csv results/medir_esp32.csv
   ```

## EXP3. Pruebas de seguridad (PDF sección 4)

Las capturas van en `results/Screenshots/` con el nombre indicado en cada prueba.

### Variables de IP

Las IPs se escriben una sola vez aquí. Abre cada terminal de PowerShell y pega estas tres líneas con las IPs actuales (las variables solo viven en esa terminal):

```powershell
$IP_ALICE    = "x.x.x.x"   # la que imprime Alice (IP: ...)
$IP_BOB      = "x.x.x.x"   # la que imprime Bob (IP: ...)
$IP_ATACANTE = "x.x.x.x"   # ipconfig en el laptop atacante (Wi-Fi)
```

Todos los comandos de abajo usan `$IP_ALICE`, `$IP_BOB` y `$IP_ATACANTE`.

### Preparación (una sola vez para las pruebas 1 a 5)

1. Cambiar solo las variables de IP de cada config, con los mismos valores que las de PowerShell: en `esp32/config_alice.py` son `IP_BOB` e `IP_ATACANTE`, y en `esp32/config_bob.py` son `IP_ALICE` e `IP_ATACANTE`. Lo demás del archivo toma las IPs de ahí.
2. Cerrar las consolas de las placas (Ctrl+]) y subir con atacante:
   ```powershell
   .\subir.ps1 ambas -Atacante
   ```
   Debe decir `(WITH attacker)` en las dos.
3. Terminal 1 (venv), atacante:
   ```powershell
   python pc/attacker.py --mode sniff --a $IP_ALICE --b $IP_BOB
   ```
   Debe decir `Attacker listening on port 6000 | mode: sniff`.
4. Terminal 2, Bob: `python -m mpremote connect COM7 repl` → Ctrl+C, Ctrl+D.
5. Terminal 3, Alice: `python -m mpremote connect COM5 repl` → Ctrl+C, Ctrl+D.

Ambas deben mostrar `Test mode: packets go through the attacker` y `Handshake complete | SID: ...`.

Para cambiar de prueba: Ctrl+C al atacante y relanzarlo con otro `--mode`. **No** reiniciar las placas (excepto en la prueba 6).

---

### Prueba 1. Comunicación normal (sniff)

**Requisito del profesor:** el mensaje llega correctamente; confidencialidad (un espía no puede leer el contenido).

**Comandos**
- Atacante: `--mode sniff` (ya corriendo)
- Bob: opción `2` (recibir)
- Alice: opción `1`, escribir `Hello Bob`

**Debe verse:** Bob `Message received: Hello Bob`; el atacante solo muestra TYPE/IDS/SID/SEQ/IV/C/TAG en bytes, sin texto legible.

**Capturas**
- `01_normal_alice_bob.png` (consolas de Alice y Bob con el mensaje)
- `01_normal_sniff.png` (atacante viendo solo bytes cifrados)

**Preguntas importantes**
1. ¿Por qué el atacante no puede leer "Hello Bob"? AES-256-CBC con `K_enc` derivada por DHE-PSK; IV aleatorio por paquete.
2. ¿Qué ve el atacante y qué no? Cabecera en claro (TYPE, IDS, SID, SEQ, IV); C y TAG son opacos.
3. ¿Por qué la clave es distinta en cada sesión? DH efímero + nonces NA/NB en HKDF → forward secrecy.

### Prueba 2. Ciphertext modificado (`tamper_c`)

**Requisito del profesor:** modificar C en tránsito → el receptor debe detectarlo (integridad).

**Comandos**
- Ctrl+C al atacante y relanzar:
  ```powershell
  python pc/attacker.py --mode tamper_c --a $IP_ALICE --b $IP_BOB
  ```
- Bob opción `2`; Alice opción `1`, `Hello Bob`

**Debe verse:** Bob `Rejected: TAG` (el LED 3 parpadea); no muestra mensaje.

**Capturas**
- `02_tamper_c_attacker.png` (atacante indicando que alteró C)
- `02_tamper_c_bob.png` (Bob con `Rejected: TAG`)

**Preguntas importantes**
1. ¿Por qué se rechaza? El HMAC se calcula sobre IV‖C; al cambiar C el TAG ya no coincide.
2. ¿Por qué se verifica el TAG antes de descifrar? Encrypt-then-MAC: no se procesa nada no autenticado; evita padding oracle.
3. ¿Por qué la comparación del TAG es en tiempo constante? Evita ataques de temporización.

### Prueba 3. TAG modificado (`tamper_tag`)

**Requisito del profesor:** modificar el TAG → debe ser rechazado.

**Comandos**
- Ctrl+C al atacante y relanzar:
  ```powershell
  python pc/attacker.py --mode tamper_tag --a $IP_ALICE --b $IP_BOB
  ```
- Bob opción `2`; Alice opción `1`, `Hello Bob`

**Debe verse:** Bob `Rejected: TAG`.

**Capturas**
- `03_tamper_tag_attacker.png`
- `03_tamper_tag_bob.png`

**Preguntas importantes**
1. ¿Qué pasa si cambia un solo bit del TAG? HMAC distinto → rechazo; no hay forma de acertarlo sin `K_mac`.
2. ¿Qué longitud tiene el TAG y qué seguridad da? 16 B = 128 bits.
3. ¿Por qué `K_enc` y `K_mac` son claves separadas? HKDF con etiquetas distintas; evita mezclar usos.

### Prueba 4. Replay

**Requisito del profesor:** reenviar un paquete válido capturado → debe rechazarse (protección contra replay).

**Comandos**
- Ctrl+C al atacante y relanzar:
  ```powershell
  python pc/attacker.py --mode replay --a $IP_ALICE --b $IP_BOB
  ```
- Bob opción `2`; Alice opción `1`, `Hello Bob`

**Debe verse:** Bob `Message received: Hello Bob` una vez y luego `Rejected: replay`.

**Capturas**
- `04_replay_attacker.png` (atacante reenviando el paquete)
- `04_replay_bob.png` (mensaje recibido + `Rejected: replay`)

**Preguntas importantes**
1. ¿Por qué el TAG del paquete repetido es válido pero se rechaza? SEQ no es mayor que el último recibido.
2. ¿Dónde va SEQ y por qué está protegido? En la cabecera, cubierto por el HMAC; no se puede subir sin romper el TAG.
3. ¿Se puede reusar el paquete en otra sesión? No: el SID y las claves cambian en cada handshake.

### Prueba 5. Paquete falsificado (`forge`)

**Requisito del profesor:** el atacante fabrica un paquete sin conocer las claves → debe rechazarse (autenticidad).

**Comandos**
- Ctrl+C al atacante y relanzar:
  ```powershell
  python pc/attacker.py --mode forge --a $IP_ALICE --b $IP_BOB
  ```
- Bob opción `2`; Alice opción `1` (cualquier mensaje)

**Debe verse:** Bob `Rejected: TAG`.

**Capturas**
- `05_forge_attacker.png`
- `05_forge_bob.png`

**Preguntas importantes**
1. ¿Qué necesita el atacante para falsificar un paquete válido? `K_mac`, que solo sale del DH + PSK.
2. ¿Por qué conocer el SID y el IDS no le sirve? Van en claro, pero el TAG depende de `K_mac`.
3. ¿Qué garantiza el PSK? Autenticación mutua de los dispositivos.

### Prueba 6. MITM en el handshake (`mitm`) — extra, requiere reiniciar placas

**Requisito del profesor:** autenticación de dispositivos; un intermediario no puede establecer la sesión.

**Comandos**
- Ctrl+C al atacante y relanzar:
  ```powershell
  python pc/attacker.py --mode mitm --a $IP_ALICE --b $IP_BOB
  ```
- Reiniciar Bob y luego Alice (Ctrl+C, Ctrl+D)

**Debe verse:** Alice `Rejected: handshake`; después reintenta y conecta.

**Capturas**
- `06_mitm_attacker.png`
- `06_mitm_alice.png`

**Preguntas importantes**
1. ¿Por qué el DH solo no basta contra MITM? Sin autenticación el atacante hace dos DH; aquí RESPONSE/CONFIRM llevan HMAC con PSK.
2. ¿Qué campo falla? HMAC(PSK, "B"‖τ) en RESPONSE.
3. ¿Se filtra algo si el handshake falla? No, se borran `a` y `Z`.

### Prueba 7. Dispositivo no autorizado (intruso)

**Requisito del profesor:** un dispositivo no autorizado no puede unirse ni comunicarse.

**Preparación:** subir **sin** atacante y dejar a Bob esperando HELLO.
```powershell
.\subir.ps1 ambas
```
Bob en repl, opción `2` (esperando); `pc/config.py` con la IP de Bob.

**Comandos** (terminal del PC con venv)
- a) ID distinto:
  ```powershell
  python pc/node.py --id 0x99
  ```
  → Bob `Rejected: handshake` en HELLO
- b) PSK falsa:
  ```powershell
  python pc/node.py --psk-falsa
  ```
  → Bob responde al HELLO y luego `Rejected: handshake` en CONFIRM

**Capturas**
- `07a_intruso_id.png` (PC + Bob)
- `07b_intruso_psk.png` (PC + Bob)

**Preguntas importantes**
1. ¿Qué lo detiene si copia el protocolo pero no el PSK? No puede calcular HMAC(PSK, "A"‖τ) en CONFIRM.
2. ¿Por qué Bob contesta al HELLO con PSK falsa? El HELLO no está autenticado; la autenticación llega en CONFIRM.
3. ¿Qué limitación tiene el PSK compartido? Si se filtra, cae todo; no hay identidad individual por dispositivo.

---

**Después:** rellenar los `% TODO` de `Formato/main.tex` (tabla Prueba | Esperado | Observado) solo con lo que mostraron las consolas.
