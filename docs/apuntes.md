# Apuntes — Proyecto 1: Mensajería segura entre dispositivos IoT

> **Para qué sirven estos apuntes:** entender **cada pieza** del sistema antes de programarla.
> De cada pieza se explica: qué hace, **qué le entra, qué sale y a dónde va**, **qué pasaría si no estuviera**
> y qué requisito del profe cubre.

| Sección | Contenido |
|---|---|
| §1 | El problema: qué puede hacer el atacante y qué hay que proteger |
| §2 | Mapa del sistema completo (las 3 fases) |
| §3 | **Las piezas, una por una** (fichas) |
| §4 | Recorrido completo de un mensaje con tamaños reales |
| §5 | Ejemplos manuales resueltos (DH, MITM, CBC, paquete, receptor) |
| §6 | Ejercicios para resolver (con soluciones) |
| §7 | Defensa requisito por requisito + preguntas del profe |
| §8 | Limitaciones (lo que **no** protegemos y por qué) |
| §9 | Plan de trabajo y métricas |

---

## 1. El problema

### 1.1 El atacante controla la red

Las ESP32 hablan por Wi-Fi (UDP). El enunciado dice que el canal **no es confiable**, así que asumimos que el atacante controla la red (modelo **Dolev–Yao**):

| El atacante puede… | En nuestra demo |
|---|---|
| **Leer** todo lo que pasa | `attacker.py --mode sniff` |
| **Modificar** paquetes | `--mode tamper_c`, `--mode tamper_tag` |
| **Inyectar** paquetes inventados | `--mode forge` |
| **Repetir** paquetes viejos | `--mode replay` |
| **Hacerse pasar** por un dispositivo | `node.py --id 0x99` |
| **Meterse en medio** del handshake (MITM) | relevo en `attacker.py` |

Lo que **no** puede: romper AES, SHA-256 o el logaritmo discreto, ni conocer la PSK.

### 1.2 Las 4 propiedades que exige el profe

| Propiedad | Pregunta que responde | Piezas que la dan |
|---|---|---|
| **Confidencialidad** | ¿Alguien más puede leerlo? | DH + HKDF → `K_enc` → AES-CBC |
| **Integridad** | ¿Alguien lo cambió? | TAG (HMAC con `K_mac`) |
| **Autenticación** | ¿De verdad viene de mi par? | PSK + HMAC del handshake + TAG |
| **Anti-replay** | ¿Es nuevo o repetido? | SID + SEQ |

> **Encryption alone ≠ Secure Communication.** El cifrado oculta el contenido, pero **no impide** que lo
> modifiquen (§5.5) ni que lo repitan (§5.7). Por eso cada pieza de abajo tiene su función.

---

## 2. Mapa del sistema

El sistema trabaja en **3 fases**. Lo que sale de una fase es lo que entra en la siguiente.

```
╔══════════════════════════ FASE 1: HANDSHAKE (una vez por sesión, ~2,2 s en la ESP32) ══════════════════════════╗
║                                                                                                                 ║
║  ENTRA: PSK (config.py), ID propio, ID del par                                                                  ║
║                                                                                                                 ║
║   urandom ─► NA, a ──► YA = g^a mod p ──── HELLO ────►                                                          ║
║                                         ◄── RESPONSE (NB, YB, HMAC_B) ──                                         ║
║   validar YB ─► verificar HMAC_B con PSK ─► Z = YB^a mod p ─► HKDF(NA‖NB, Z‖PSK) ─► borrar a y Z               ║
║                                         ──── CONFIRM (HMAC_A) ────►                                             ║
║                                                                                                                 ║
║  SALE: K_enc, K_mac, SID, SEQ = 0, ultimo_seq = 0      ──────────────► van a la FASE 2 y a la FASE 3             ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════ FASE 2: ENVIAR UN MENSAJE (cada mensaje) ═════════════════════════════════════════════╗
║                                                                                                                 ║
║  "Hola" ─► PKCS#7 ─► AES-256-CBC(K_enc, IV aleatorio) ─► C                                                       ║
║                                                          │                                                       ║
║  TYPE ‖ IDS ‖ SID ‖ SEQ+1 ‖ IV ‖ C ─► HMAC(K_mac)[:16] ─► TAG                                                    ║
║                                                                                                                 ║
║  SALE: paquete = TYPE‖IDS‖SID‖SEQ‖IV‖C‖TAG  ─────────────────────────► socket UDP ─► red (atacante) ─►           ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════ FASE 3: RECIBIR UN MENSAJE (cada mensaje) ════════════════════════════════════════════╗
║                                                                                                                 ║
║  paquete ─► ① ¿TYPE, IDS, SID correctos? ─► ② ¿TAG correcto? ─► ③ ¿SEQ > ultimo_seq? ─► ultimo_seq = SEQ         ║
║                 │ no                          │ no                  │ no                                         ║
║                 └──────────────► RECHAZO + motivo + LED 3 parpadeos ◄┘                                           ║
║                                                                                                                 ║
║  ─► AES-CBC descifrar(K_enc, IV) ─► quitar PKCS#7 ─► "Hola" ─► pantalla + LED 1 parpadeo                         ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
```

---

## 3. Las piezas, una por una

Cada ficha tiene el mismo formato:
**Qué hace** · **Entra / Sale / Va a** · **Cómo funciona** · **Si no estuviera** · **Requisito del profe** · **En el código**

---

### FASE 1: HANDSHAKE

### 3.1 PSK (Pre-Shared Key)

**Qué hace:** es el secreto que el par de dispositivos comparte desde "fábrica". Sirve para **autenticar**: demostrar que el otro es quien dice ser.

| Entra | Sale | Va a |
|---|---|---|
| Se escribe a mano en `config.py` (32 bytes aleatorios) | La misma PSK, sin cambios | ① HMAC de autenticación (§3.7) ② HKDF (§3.8) |

**Cómo funciona:** cada dispositivo tiene una tabla `{ID_del_par: PSK}`. Si llega un ID que no está en la tabla, no hay PSK para él y se rechaza.

**Si no estuviera:** DH no sabe con quién habla, así que un atacante se mete en medio y lee todo (**MITM**, §5.2). Con DH solo **no hay autenticación**.

**¿Por qué PSK y no firmas digitales?** Para autenticar un DH hacen falta firmas (RSA/ECDSA) o un secreto compartido. MicroPython no trae firmas, así que usamos la PSK.

**Requisito del profe:** autenticación de dispositivos (10 %) y "explicar cómo se autentican".
**En el código:** `esp32/config.py`, `pc/config.py`.

---

### 3.2 IDs de dispositivo (IDA, IDB, IDS)

**Qué hace:** identifica a cada dispositivo con 1 byte (`0x01`, `0x02`, …).

| Entra | Sale | Va a |
|---|---|---|
| `config.py` | 1 byte | ① el receptor busca la PSK con él ② entra al HMAC del handshake ③ va en cada paquete como `IDS` |

**Si no estuviera:** con 2 dispositivos funcionaría, pero con más el receptor no sabría qué PSK usar. Además, como el ID entra al HMAC y al TAG, el atacante **no puede cambiar el remitente** sin que se note (el profe pide rechazar si se altera la *sender information*).

**Requisito del profe:** formato de paquete (`IDS` del formato de referencia) + rechazo si se altera el remitente.

---

### 3.3 Nonces (NA, NB)

**Qué hace:** cada lado aporta 16 bytes **aleatorios y nuevos** en cada handshake.

| Entra | Sale | Va a |
|---|---|---|
| `os.urandom(16)` | NA (de A), NB (de B) | ① HMAC del handshake ② *salt* del HKDF |

**Cómo funciona:** como son nuevos en cada sesión, cualquier cosa calculada con ellos **solo sirve para esta sesión**.

**Si no estuviera:** con DH, los valores YA y YB ya son aleatorios, así que la sesión seguiría siendo fresca. **Los nonces son una segunda garantía:** aseguran frescura aunque algún día se reutilice el exponente DH (por ejemplo, para ahorrar 1 s) y sirven de *salt* estándar en HKDF. TLS 1.3 hace lo mismo: manda `random` **y** `key_share`.

**Requisito del profe:** frescura / anti-replay del handshake.

---

### 3.4 Diffie–Hellman: exponente secreto y valor público (a → YA)

**Qué hace:** cada lado genera un número secreto y publica un valor derivado de él. Con eso, ambos llegan al **mismo secreto Z sin que Z viaje nunca** por la red.

| Entra | Sale | Va a |
|---|---|---|
| `a` = 32 bytes aleatorios (`urandom`) + constantes públicas `p` y `g` | `YA = g^a mod p` (256 bytes) | `YA` → mensaje HELLO (público). `a` → **solo** a §3.6, y luego se **borra** |

**Cómo funciona (la matemática):**

```
A elige a (secreto)    →  publica YA = g^a mod p
B elige b (secreto)    →  publica YB = g^b mod p

A calcula  Z = YB^a = (g^b)^a = g^(ab) mod p
B calcula  Z = YA^b = (g^a)^b = g^(ab) mod p      ← ¡el mismo número!
```

El atacante ve `p`, `g`, `YA` y `YB`. Para obtener Z necesitaría sacar `a` de `YA`, es decir, resolver el **logaritmo discreto**. Con números de 2048 bits eso es inviable.

**Parámetros que usamos:**

| Parámetro | Valor | Por qué |
|---|---|---|
| Grupo | `ffdhe2048` (RFC 7919) | Primo estándar y auditado. **No** inventamos el primo (eso sería cripto propia) |
| `p` | primo seguro de 2048 bits | ≈112 bits de seguridad (recomendación NIST) |
| `g` | 2 | El que define el RFC |
| tamaño de `a` | 256 bits | RFC 7919 pide al menos 2 × 112 = 224 bits. Por eso la ESP32 tarda **1 s** y no 8 s |
| Operación | `pow(g, a, p)` | Viene en Python y en MicroPython: no es código nuestro |

**Si no estuviera (solo PSK):** las claves saldrían solo de la PSK y de los nonces, que viajan en claro. Si la PSK se filtra algún día, **todas las sesiones grabadas** se podrían descifrar. Con DH eso no pasa: es la **forward secrecy**.

**Por qué se borra `a`:** si `a` quedara guardado en memoria y alguien robara la placa después, podría recalcular Z. Borrarlo es lo que hace a DH **efímero** ("DHE").

**Requisito del profe:** "establish a session key using Diffie–Hellman" (15 %). Es la **primera opción** que propone el PDF.
**En el código:** `common/crypto.py` → `dh_keygen()`.

---

### 3.5 Validación del valor público recibido (YB)

**Qué hace:** antes de usar el `YB` que llegó, se comprueba que `1 < YB < p − 1`.

| Entra | Sale | Va a |
|---|---|---|
| `YB` recibido | ✅ seguir / ❌ abortar el handshake | §3.6 |

**Si no estuviera:** con `YB = 1` el secreto es `Z = 1^a = 1`, y con `YB = p−1` es `Z = ±1`. Cualquiera conocería Z (§5.3).
En nuestro diseño, un atacante **externo** no puede colar `YB = 1`, porque YB va dentro del HMAC con la PSK (§3.7). La validación nos protege de un dispositivo autorizado con un error o comprometido. Es **defensa en profundidad** y **RFC 7919 la exige**.

**En el código:** `common/crypto.py` → dentro de `dh_shared()`.

---

### 3.6 Secreto compartido Z

| Entra | Sale | Va a |
|---|---|---|
| `YB` (validado) + `a` | `Z = YB^a mod p` (256 bytes) | HKDF (§3.8), y luego se **borra** |

**Clave:** Z **nunca** se envía. Cada lado lo calcula por su cuenta.
**Si no estuviera:** no hay forward secrecy (ver §3.4).
**En el código:** `common/crypto.py` → `dh_shared()`.

---

### 3.7 HMAC de autenticación del handshake (HMAC_B y HMAC_A)

**Qué hace:** cada lado demuestra que **conoce la PSK sin enviarla** y, al mismo tiempo, **firma todo lo que vio** del handshake.

| Entra | Sale | Va a |
|---|---|---|
| PSK + etiqueta (`"B"` o `"A"`) + *transcript* = `IDA‖IDB‖NA‖NB‖YA‖YB` | 32 bytes | B lo manda en RESPONSE y A en CONFIRM. El otro lado lo recalcula y compara |

```
HMAC_B = HMAC-SHA256(PSK, "B" ‖ IDA ‖ IDB ‖ NA ‖ NB ‖ YA ‖ YB)     ← lo envía B
HMAC_A = HMAC-SHA256(PSK, "A" ‖ IDA ‖ IDB ‖ NA ‖ NB ‖ YA ‖ YB)     ← lo envía A
```

**Por qué incluye YA y YB:** así se evita el MITM. Si el atacante cambia YA o YB, cada lado ve un transcript distinto y el HMAC no coincide (§5.2).
**Por qué incluye NA y NB:** así un HMAC de una sesión vieja no sirve en una nueva.
**Por qué las etiquetas "A" y "B":** sin ellas HMAC_A y HMAC_B serían iguales, y el atacante podría devolverle a B su propio HMAC como si fuera de A (**ataque de reflexión**, ejercicio 6).

**Si no estuviera:** DH queda sin autenticar → MITM.

**Requisito del profe:** autenticación de dispositivos + prueba con un dispositivo no autorizado.
**En el código:** `common/protocol.py` → handshake.

---

### 3.8 HKDF: derivar las claves de sesión

**Qué hace:** convierte Z (que no es uniforme: es un número módulo p) y la PSK en **claves limpias de 32 bytes, una para cada uso**.

| Entra | Sale | Va a |
|---|---|---|
| Z, PSK, NA, NB | `K_enc` (32 B), `K_mac` (32 B), `SID` (4 B) | `K_enc` → AES (§3.11) · `K_mac` → TAG (§3.13) · `SID` → cabecera (§3.12) |

```
Extract:  PRK   = HMAC(clave = NA‖NB,  mensaje = Z‖PSK)          (RFC 5869)
Expand:   K_enc = HMAC(PRK, "enc" ‖ 0x01)
          K_mac = HMAC(PRK, "mac" ‖ 0x01)
          SID   = HMAC(PRK, "sid" ‖ 0x01)[:4]
```

**Por qué no usar Z directamente como clave AES:** Z mide 256 bytes y sus bits no son uniformes. Además, **nunca se usa la misma clave para dos cosas** (cifrar y autenticar), y eso se llama **separación de claves**.
**Por qué meter también la PSK en el HKDF:** como segunda barrera. Aunque un atacante lograra engañar la autenticación (por ejemplo con el ataque de reflexión), sin la PSK no podría derivar las claves.

**Si no estuviera:** se usaría la misma clave para AES y HMAC, o una clave con sesgo. Ninguna de las dos cosas es aceptable en un diseño estándar.

**Requisito del profe:** "appropriate management of cryptographic material" (15 %).
**En el código:** `common/crypto.py` → `hkdf()`.

---

### FASE 2: ENVIAR

### 3.9 Padding PKCS#7

**Qué hace:** completa el mensaje hasta un múltiplo de 16 bytes, porque AES trabaja con bloques de 16.

| Entra | Sale | Va a |
|---|---|---|
| mensaje de L bytes | `16·(⌊L/16⌋+1)` bytes | AES-CBC (§3.11) |

**Cómo funciona:** se agregan `n` bytes, todos con el valor `n`. **Siempre** se agrega al menos 1 byte; si el mensaje ya mide un múltiplo de 16, se agrega un bloque entero de `0x10`.

| L | Relleno |
|---|---|
| 10 | `06 06 06 06 06 06` |
| 15 | `01` |
| 16 | `10` × 16 |

**Si no estuviera:** AES-CBC no puede cifrar un mensaje como `"Hola"` (4 bytes).

---

### 3.10 IV (vector de inicialización)

**Qué hace:** son 16 bytes aleatorios, **nuevos en cada mensaje**, que inician la cadena de CBC.

| Entra | Sale | Va a |
|---|---|---|
| `os.urandom(16)` | IV | ① AES-CBC ② se copia **en claro** en el paquete ③ entra al TAG |

**Si no estuviera (IV fijo):** el mismo mensaje daría siempre el mismo ciphertext. El atacante sabría cuándo se repite un mensaje ("otra vez mandaron *ABRIR*") sin descifrarlo.
**Ojo:** el IV **no es secreto**, solo tiene que ser impredecible. Es el `N` del formato de referencia del profe.

---

### 3.11 AES-256-CBC

**Qué hace:** cifra. Es la pieza que da la **confidencialidad**.

| Entra | Sale | Va a |
|---|---|---|
| mensaje con padding + `K_enc` + IV | C (mismo tamaño que la entrada) | paquete + TAG |

**Cómo funciona:**
- **AES** es un cifrador de bloque: transforma 16 bytes en otros 16 bytes usando la clave. AES-256 usa una clave de 32 bytes.
- **CBC** encadena los bloques: cada bloque se mezcla (XOR) con el ciphertext anterior antes de cifrarlo.

```
C1 = AES(K_enc, P1 ⊕ IV)          P1 = AES⁻¹(K_enc, C1) ⊕ IV
C2 = AES(K_enc, P2 ⊕ C1)          P2 = AES⁻¹(K_enc, C2) ⊕ C1
```

**Si no estuviera:** el sniffer lee los mensajes en claro.
**Debilidad conocida:** CBC es **maleable**. Si se invierte un bit de C1, se invierte el mismo bit de P2 (§5.5). Por eso el TAG es obligatorio.

**¿Por qué CBC y no AES-GCM (lo que recomienda el profe)?** `cryptolib` de MicroPython solo trae ECB, CBC y CTR. Programar GCM a mano sería criptografía propia, que está prohibida. El PDF permite cifrado y autenticación separados **si se justifica**, y esta es la justificación.

**Requisito del profe:** confidencialidad (15 %).
**En el código:** `common/crypto.py` → `aes_cbc_encrypt()` / `aes_cbc_decrypt()`.

---

### 3.12 Cabecera: TYPE, IDS, SID, SEQ

| Campo | Tamaño | Qué hace | Entra de | Si no estuviera |
|---|---|---|---|---|
| `TYPE` | 1 B | Dice qué es el paquete: `0x01` HELLO, `0x02` RESPONSE, `0x03` CONFIRM, `0x10` DATA | constante | El receptor podría confundir un tipo de mensaje con otro (*type confusion*). Como entra al TAG, no se puede cambiar |
| `IDS` | 1 B | Quién envía | `config.py` | Ver §3.2 |
| `SID` | 4 B | A qué sesión pertenece | HKDF (§3.8) | Un paquete de otra sesión igual fallaría en el TAG, porque `K_mac` es distinta. El SID permite **descartarlo rápido, sin calcular el HMAC**, deja el motivo claro en el log y es parte del formato que pide el profe ("associate the message with a valid session") |
| `SEQ` | 4 B | Número de mensaje: 1, 2, 3… | contador del emisor | **Replay**: el atacante reenvía un paquete viejo y se acepta como nuevo (§5.7) |

**Por qué SEQ y no timestamps:** las ESP32 no tienen reloj sincronizado. El profe acepta *"sequence numbers, counters, timestamps, nonces, or session identifiers"*.

---

### 3.13 TAG (HMAC-SHA256 truncado, Encrypt-then-MAC)

**Qué hace:** es el "sello" del paquete. Da **integridad y autenticación** de cada mensaje.

| Entra | Sale | Va a |
|---|---|---|
| `K_mac` + `TYPE‖IDS‖SID‖SEQ‖IV‖C` | 16 bytes | final del paquete |

**Cómo funciona:**
- **SHA-256** resume cualquier mensaje en 32 bytes. Si cambia un solo bit, el resumen cambia por completo. Pero no usa clave: cualquiera puede calcularlo.
- **HMAC** = SHA-256 con clave: `SHA256((K⊕opad) ‖ SHA256((K⊕ipad) ‖ m))`. Solo quien tiene `K_mac` puede generar un TAG válido.
- **¿Por qué no `SHA256(K‖m)`?** Por el ataque de *length-extension*: se puede calcular `SHA256(K‖m‖extra)` sin conocer K. HMAC no tiene ese problema.
- **Truncado a 16 B:** la probabilidad de adivinarlo es 2⁻¹²⁸. NIST SP 800-107 lo permite.

**Encrypt-then-MAC (el orden importa):**

| Orden | Qué se envía | ¿Seguro? |
|---|---|---|
| Encrypt-and-MAC | `Enc(m)`, `MAC(m)` | ❌ el MAC puede filtrar información de m |
| MAC-then-Encrypt | `Enc(m‖MAC(m))` | ⚠️ *padding oracle* (Lucky13, POODLE en TLS) |
| **Encrypt-then-MAC** ✅ | `C = Enc(m)`, `TAG = MAC(C)` | Demostrado seguro (Bellare–Namprempre, 2000). Es el que usa TLS con CBC (RFC 7366) |

**Por qué el TAG cubre la cabecera y no solo C:** si solo cubriera C, el atacante podría cambiar SEQ (y saltarse el anti-replay), IDS (y cambiar el remitente) o SID sin que se note (ejercicio 5b).

**Si no estuviera:** el atacante modifica mensajes (bit-flipping, §5.5) o inventa paquetes.

**Requisito del profe:** integridad y autenticación de mensajes (15 %) + "reject any message whose ciphertext, authentication information, sender information, or freshness data has been altered".
**En el código:** `common/crypto.py` → `hmac_sha256()`; `common/protocol.py` → `seal()`.

---

### FASE 3: RECIBIR

### 3.14 Orden de verificación del receptor

```
① ¿TYPE == 0x10, IDS == mi par y SID == sesión activa?   no → RECHAZO "sesión/ID"
② ¿TAG == HMAC(K_mac, cabecera‖IV‖C)[:16]?                no → RECHAZO "TAG inválido"
③ ¿SEQ > ultimo_seq?                                     no → RECHAZO "replay"
④ ultimo_seq = SEQ
⑤ descifrar → quitar padding → ACEPTADO
```

| Entra | Sale | Va a |
|---|---|---|
| paquete UDP + `K_enc`, `K_mac`, `SID`, `ultimo_seq` | mensaje en claro **o** RECHAZO + motivo | pantalla / log / LED |

**Por qué este orden y qué pasa si se cambia:**

| Si se hiciera… | Pasaría… |
|---|---|
| descifrar **antes** de verificar el TAG | *Padding oracle*: el atacante prueba ciphertexts modificados, observa si el padding fue válido y descifra byte a byte |
| revisar y guardar SEQ **antes** del TAG | DoS: un paquete falso con `SEQ = 4 000 000 000` sube `ultimo_seq` y bloquea todos los mensajes legítimos |
| actualizar `ultimo_seq` aunque falle el TAG | lo mismo: el atacante controla el contador |

**Regla de oro:** **no se confía en ningún campo hasta haber verificado el TAG.**

---

### 3.15 Comparación en tiempo constante

**Qué hace:** compara el TAG recibido con el calculado **mirando todos los bytes**, aunque el primero ya sea distinto.

```python
def ct_equal(a, b):
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y          # acumula diferencias sin salir antes
    return r == 0
```

**Si no estuviera (usar `==`):** `==` se detiene en el primer byte distinto. Midiendo cuánto tarda el rechazo, el atacante podría adivinar el TAG byte a byte (**timing attack**).
MicroPython no trae `hmac.compare_digest`; por eso esta función de 6 líneas. No es un algoritmo criptográfico propio, es una comparación.

---

### 3.16 Estado anti-replay (`ultimo_seq`)

| Entra | Sale | Va a |
|---|---|---|
| SEQ del paquete (ya verificado por el TAG) | aceptar / rechazar | se actualiza `ultimo_seq` |

**Regla:** solo se acepta `SEQ > ultimo_seq`. Al empezar una sesión, `ultimo_seq = 0` y el emisor empieza en `SEQ = 1`.
**Costo:** un paquete UDP legítimo que llegue **desordenado** se descarta (ver §8). Aceptamos ese costo porque el enunciado no exige tolerar desorden.

**Requisito del profe:** replay protection (10 %).

---

### 3.17 LED (no es una pieza de seguridad)

| Evento | LED (GPIO2) |
|---|---|
| Handshake completado | encendido 1 s |
| Mensaje aceptado | 1 parpadeo |
| Mensaje rechazado | 3 parpadeos rápidos |

No toca el protocolo: solo **muestra** en la demo lo que decidió el receptor.

---

### Resumen: si quitamos cada pieza, ¿qué ataque funciona?

| Pieza que se quita | Ataque que funcionaría |
|---|---|
| PSK / HMAC del handshake | MITM: el atacante lee y cambia todo |
| YA, YB en el transcript | MITM: el atacante cambia los valores DH sin que se note |
| Etiquetas "A"/"B" | Reflexión: B cree que A está autenticado |
| Validación de Y | Z = 1, conocido por todos (si el otro lado es malicioso o tiene un bug) |
| DH (dejar solo PSK) | Si se filtra la PSK, se descifran todas las sesiones grabadas |
| Borrar `a` y Z | Quien robe la placa después recalcula las claves de sesión |
| HKDF | Misma clave para dos usos / clave con sesgo |
| IV aleatorio | Se detecta cuándo se repite un mensaje |
| AES | Sniffer lee todo |
| TAG | Bit-flipping, paquetes falsos |
| Cabecera dentro del TAG | Cambiar SEQ → replay; cambiar IDS → suplantar remitente |
| SEQ | Replay |
| Orden ①②③ | Padding oracle / DoS del contador |
| Comparación en tiempo constante | Timing attack sobre el TAG |

---

## 4. Recorrido completo con tamaños reales

### 4.1 Handshake

| Mensaje | Contenido | Tamaño |
|---|---|---|
| HELLO (A→B) | `0x01 ‖ IDA ‖ NA ‖ YA` | 1 + 1 + 16 + 256 = **274 B** |
| RESPONSE (B→A) | `0x02 ‖ IDB ‖ NB ‖ YB ‖ HMAC_B` | 1 + 1 + 16 + 256 + 32 = **306 B** |
| CONFIRM (A→B) | `0x03 ‖ IDA ‖ HMAC_A` | 1 + 1 + 32 = **34 B** |
| **Total** | | **614 B**, una vez por sesión |

```
  A (ESP32)                                                     B (PC / ESP32)
  ─────────                                                     ──────────────
  NA ← urandom(16)
  a  ← urandom(32)
  YA ← g^a mod p                         (~1 s)
         ───── HELLO: 0x01‖IDA‖NA‖YA ───────────────────────►
                                                                ¿IDA en mi tabla? → PSK
                                                                ¿1 < YA < p−1?
                                                                NB ← urandom(16), b ← urandom(32)
                                                                YB ← g^b mod p
                                                                HMAC_B ← HMAC(PSK, "B"‖transcript)
         ◄──── RESPONSE: 0x02‖IDB‖NB‖YB‖HMAC_B ─────────────
  ¿1 < YB < p−1?
  ¿HMAC_B correcto?  → B es auténtico
  Z ← YB^a mod p                         (~1 s)
  K_enc, K_mac, SID ← HKDF(NA‖NB, Z‖PSK)
  borrar a, Z
         ───── CONFIRM: 0x03‖IDA‖HMAC_A ────────────────────►
                                                                ¿HMAC_A correcto? → A es auténtico
                                                                Z ← YA^b mod p
                                                                K_enc, K_mac, SID ← HKDF(...)
                                                                borrar b, Z
  LED 1 s ✓                                                     sesión lista ✓
```

### 4.2 Mensaje de datos

```
┌──────┬─────┬───────┬───────┬────────┬───────────┬─────────┐
│ TYPE │ IDS │  SID  │  SEQ  │   IV   │     C     │   TAG   │
│  1 B │ 1 B │  4 B  │  4 B  │  16 B  │  16·n B   │  16 B   │
└──────┴─────┴───────┴───────┴────────┴───────────┴─────────┘
  0x10                                 AES-256-CBC(K_enc, IV, PKCS7(msg))
  TAG = HMAC-SHA256(K_mac, TYPE‖IDS‖SID‖SEQ‖IV‖C)[:16]

  tamaño = 42 + 16·(⌊L/16⌋ + 1)
```

---

## 5. Ejemplos manuales resueltos

Los números reales (2048 bits, AES de 128 bits) no se pueden calcular a mano.
Para practicar la **lógica** usamos números pequeños. **Solo sirven para entender: no son seguros.**

### 5.1 Diffie–Hellman con números pequeños

Parámetros públicos: `p = 23`, `g = 5`. Secretos: `a = 6` (A), `b = 15` (B).

**Truco para calcular potencias módulo p:** se eleva al cuadrado repetidamente y se reduce en cada paso.

Potencias de 5 módulo 23:

| | Cálculo | mod 23 |
|---|---|---|
| 5¹ | | 5 |
| 5² | 25 | **2** |
| 5⁴ | 2² = 4 | **4** |
| 5⁸ | 4² = 16 | **16** |

**A publica:** `YA = 5⁶ = 5⁴ · 5² = 4 · 2 = 8` → **YA = 8**
**B publica:** `YB = 5¹⁵ = 5⁸ · 5⁴ · 5² · 5¹ = 16 · 4 · 2 · 5 = 640 mod 23 = 640 − 621 =` **19**

**A calcula Z = YB^a = 19⁶ mod 23:**
19 ≡ −4 (mod 23), así que `19⁶ = (−4)⁶ = 4096`. Como `23 · 178 = 4094`, queda `4096 − 4094 =` **2**

**B calcula Z = YA^b = 8¹⁵ mod 23:**

| | Cálculo | mod 23 |
|---|---|---|
| 8² | 64 | 18 |
| 8⁴ | 18² = 324 | 2 |
| 8⁸ | 2² | 4 |
| 8¹⁵ = 8⁸·8⁴·8²·8¹ | 4·2·18·8 = 1152 | 1152 − 1150 = **2** |

✅ **Ambos obtienen Z = 2**, y el atacante solo vio 23, 5, 8 y 19.

### 5.2 Ataque MITM a DH **sin** PSK… y cómo la PSK lo detecta

El atacante M elige su propio secreto `m = 3` y calcula `YM = 5³ = 125 mod 23 =` **10**.

```
A ──YA=8──►  M  ──YM=10──► B        (M cambia YA por YM)
A ◄─YM=10──  M  ◄──YB=19── B        (M cambia YB por YM)
```

| Quién | Calcula | Resultado |
|---|---|---|
| A | `YM^a = 10⁶ mod 23` → 10²=8, 10⁴=18, 10⁶=18·8=144 → 144−138 | **6** |
| M (con A) | `YA^m = 8³ = 512 mod 23` → 512−506 | **6** ✓ igual que A |
| B | `YM^b = 10¹⁵ mod 23` → 10⁸=2, 10¹⁵=10⁸·10⁴·10²·10 = 2·18·8·10 = 2880 → 2880−2875 | **5** |
| M (con B) | `YB^m = 19³ = (−4)³ = −64 mod 23` → −64+69 | **5** ✓ igual que B |

**Sin PSK:** A cree que comparte 6 con B, y B cree que comparte 5 con A, pero **M conoce los dos**. Descifra todo lo que manda A, lo lee, lo vuelve a cifrar y se lo pasa a B. Nadie se da cuenta.

**Con nuestro protocolo:**
- B calcula `HMAC_B = HMAC(PSK, "B"‖…‖YA=10‖YB=19)`, porque B vio YA = 10.
- A espera `HMAC(PSK, "B"‖…‖YA=8‖YB=10)`, porque A vio esos valores.
- **Los transcripts son distintos**, así que A rechaza.
- M podría intentar fabricar el HMAC correcto, pero **no tiene la PSK**.

→ **Por eso la PSK es imprescindible y por eso YA y YB van dentro del HMAC.**

### 5.3 Valor público inválido

Si un dispositivo malicioso o con un bug manda `YB = 1`:
`Z = 1^a = 1` para cualquier `a`. Todo el mundo conoce Z.

Si manda `YB = p − 1 = 22 ≡ −1`:
`Z = (−1)^a` = 1 si `a` es par, 22 si es impar. Solo 2 opciones posibles.

→ La regla `1 < Y < p−1` descarta los dos casos.

### 5.4 CBC con un cifrador de juguete de 4 bits

Cifrador de juguete:

```
E_K(x) = rotl1(x ⊕ K)        (XOR con la clave y rotar 1 bit a la izquierda)
D_K(y) = rotr1(y) ⊕ K        (rotar 1 bit a la derecha y XOR con la clave)
```

Ejemplos de rotación: `rotl1(1101) = 1011`, `rotr1(1011) = 1101`.

Datos: `K = 1010`, `IV = 0110`, `P1 = 0001`, `P2 = 1001`.

**Cifrar:**

| Paso | Cálculo | Resultado |
|---|---|---|
| P1 ⊕ IV | 0001 ⊕ 0110 | 0111 |
| ⊕ K | 0111 ⊕ 1010 | 1101 |
| rotl1 → **C1** | | **1011** |
| P2 ⊕ C1 | 1001 ⊕ 1011 | 0010 |
| ⊕ K | 0010 ⊕ 1010 | 1000 |
| rotl1 → **C2** | | **0001** |

**Descifrar:**

| Paso | Cálculo | Resultado |
|---|---|---|
| rotr1(C1) ⊕ K | 1101 ⊕ 1010 | 0111 |
| ⊕ IV → **P1** | 0111 ⊕ 0110 | **0001** ✓ |
| rotr1(C2) ⊕ K | 1000 ⊕ 1010 | 0010 |
| ⊕ C1 → **P2** | 0010 ⊕ 1011 | **1001** ✓ |

### 5.5 Bit-flipping: por qué el cifrado solo no basta

El atacante invierte el último bit de C1: `C1' = 1010`. No conoce K.

| Bloque | Cálculo del receptor | Obtiene | Original |
|---|---|---|---|
| P1' | rotr1(1010)=0101 → ⊕K=1111 → ⊕IV | 1001 | 0001 (basura) |
| P2' | D_K(C2)=0010 → ⊕ **C1'**=1010 | **1000** | 1001 (**cambió justo el último bit**) |

El atacante cambió **exactamente el bit que eligió** sin saber la clave. Si P2 fuera `"ABRIR=0"`, lo podría convertir en `"ABRIR=1"`.
**Con el TAG:** el receptor calcula `HMAC(K_mac, …C1'…)`, que no coincide con el TAG del paquete, y **rechaza antes de descifrar**.

### 5.6 Armar el paquete de `"Hola ESP32"`

1. Bytes: `48 6f 6c 61 20 45 53 50 33 32` → **L = 10**
2. PKCS#7: `+ 06 06 06 06 06 06` → 16 bytes
3. AES-256-CBC → **C = 16 bytes**
4. Cabecera: `TYPE=10 IDS=01 SID=3a7f00c2 SEQ=00000005 IV=<16 B aleatorios>`
5. `TAG = HMAC(K_mac, 10 01 3a7f00c2 00000005 IV C)[:16]`
6. **Total = 42 + 16 = 58 bytes** para 10 bytes útiles (overhead de 48 B, 5,8 veces el mensaje).

### 5.7 Traza del receptor

Estado inicial: `SID = 3a7f00c2`, `ultimo_seq = 3`.

| # | Llega | ① SID | ② TAG | ③ SEQ | Veredicto | `ultimo_seq` |
|---|---|---|---|---|---|---|
| 1 | SEQ 4, legítimo | ✓ | ✓ | 4>3 ✓ | **ACEPTADO** | 4 |
| 2 | el mismo paquete otra vez | ✓ | ✓ | 4>4 ✗ | **RECHAZO: replay** | 4 |
| 3 | SEQ 5 con un byte de C cambiado | ✓ | ✗ | — | **RECHAZO: TAG** | 4 |
| 4 | SEQ 5, legítimo | ✓ | ✓ | 5>4 ✓ | **ACEPTADO** | 5 |
| 5 | paquete de la sesión anterior (`SID = 11223344`) | ✗ | — | — | **RECHAZO: sesión** | 5 |

Fila 3: como el TAG falló, `ultimo_seq` **no** cambió, y por eso la fila 4 sí se acepta.

---

## 6. Ejercicios para resolver

> Resuélvelos en papel antes de abrir las soluciones.

**Ejercicio 1 · DH a mano.** `p = 23`, `g = 5`, `a = 4`, `b = 9`.
a) Calcula YA y YB. b) Calcula Z desde A y desde B, y comprueba que coinciden.

**Ejercicio 2 · MITM.** Con los mismos `a = 4` y `b = 9`, el atacante usa `m = 2`.
a) ¿Cuánto vale YM? b) ¿Qué Z calcula A? ¿Y B? ¿Qué Z calcula M con cada uno?
c) Explica en una frase por qué en nuestro protocolo A detecta el ataque.

**Ejercicio 3 · Y inválido.** Con `p = 23`, un dispositivo manda `Y = 22`. ¿Qué Z se obtiene con `a = 4`? ¿Y con `a = 9`?

**Ejercicio 4 · CBC de juguete.** `K = 0011`, `IV = 1000`, `P1 = 0101`, `P2 = 0110`.
a) Calcula C1 y C2. b) Descifra y comprueba. c) Si el atacante cambia C1 por `C1 ⊕ 0100`, ¿qué P2 obtiene el receptor?

**Ejercicio 5 · Paquete y TAG.**
a) Mensaje `"Temperatura=23.5C"`: ¿cuánto mide L, cuánto padding se agrega (y con qué valor) y cuánto mide el paquete?
b) El atacante captura un paquete con `SEQ = 5` y cambia el campo a `SEQ = 50`. ¿Qué paso del receptor lo detecta? ¿Qué pasaría si el TAG solo cubriera `IV‖C`?

**Ejercicio 6 · Reflexión.** Supón que HMAC_A y HMAC_B **no** tuvieran las etiquetas "A" y "B". Describe cómo un atacante sin PSK haría que B crea que A está autenticado. ¿Podría el atacante después leer o enviar mensajes? ¿Por qué?

**Ejercicio 7 · Traza.** `ultimo_seq = 7`. Llegan, en orden: SEQ 8 legítimo · SEQ 8 repetido · SEQ 6 viejo · SEQ 9 con TAG alterado · SEQ 12 legítimo · SEQ 10 legítimo pero retrasado. Para cada uno: veredicto, motivo y `ultimo_seq`.

**Ejercicio 8 · "¿Y si no estuviera…?"** Para cada caso, di qué ataque funcionaría o qué se rompería:
a) No se borra `a` después del handshake.
b) Se usa `K_enc` también como clave del HMAC.
c) Se compara el TAG con `==`.
d) El receptor descifra antes de verificar el TAG.
e) El IV es siempre `00…00`.

---

<details>
<summary><b>Soluciones (no abrir antes de intentarlo)</b></summary>

**Ejercicio 1**
a) `YA = 5⁴ =` **4** (de la tabla del §5.1). `YB = 5⁹ = 5⁸·5 = 16·5 = 80 mod 23 = 80−69 =` **11**.
b) Desde A: `Z = 11⁴` → `11² = 121 mod 23 = 6` → `6² = 36 mod 23 =` **13**.
Desde B: `Z = 4⁹` → `4²=16`, `4⁴=256 mod 23=3`, `4⁸=9`, `4⁹=9·4=36 mod 23 =` **13** ✓.

**Ejercicio 2**
a) `YM = 5² =` **2**.
b) A: `YM^a = 2⁴ =` **16**. M con A: `YA^m = 4² =` **16** ✓.
B: `YM^b = 2⁹ = 512 mod 23 = 512−506 =` **6**. M con B: `YB^m = 11² = 121 mod 23 =` **6** ✓.
c) A y B ven YA y YB distintos, así que sus transcripts no coinciden y el HMAC_B que llega no verifica. M no puede recalcularlo porque no tiene la PSK.

**Ejercicio 3**
`22 ≡ −1`. Con `a = 4` (par): **Z = 1**. Con `a = 9` (impar): **Z = 22**. En ambos casos Z es adivinable, y por eso se rechaza `Y = p−1`.

**Ejercicio 4**
a) `P1⊕IV = 1101` → `⊕K = 1110` → `rotl1 =` **C1 = 1101**. `P2⊕C1 = 1011` → `⊕K = 1000` → `rotl1 =` **C2 = 0001**.
b) `rotr1(1101)=1110 ⊕K=1101 ⊕IV=0101` ✓ · `rotr1(0001)=1000 ⊕K=1011 ⊕C1=0110` ✓.
c) `C1' = 1001` → `P2' = 1011 ⊕ 1001 =` **0010**. Cambió exactamente el bit `0100`.

**Ejercicio 5**
a) L = 11 + 1 + 5 = **17**. `16·(1+1) = 32` → **15 bytes con valor `0x0f`**. Paquete = 42 + 32 = **74 B**.
b) Lo detecta el **paso ②**: el SEQ entra al HMAC, así que al cambiarlo el TAG no coincide, y M no tiene `K_mac` para recalcularlo. Si el TAG solo cubriera `IV‖C`, **el replay funcionaría**: el TAG seguiría siendo válido y 50 > `ultimo_seq`.

**Ejercicio 6**
1. M manda a B `HELLO(IDA, NA', YM)`, con valores elegidos por él.
2. B responde con `HMAC(PSK, IDA‖IDB‖NA'‖NB‖YM‖YB)`.
3. M **copia ese mismo HMAC** en el CONFIRM. Sin etiquetas el cálculo es idéntico, así que B lo acepta.

Después de eso M **no puede** leer ni enviar mensajes. M conoce Z (porque eligió `m`), pero las claves salen de `HKDF(NA‖NB, Z‖PSK)` y le falta la PSK. Aun así, la **autenticación está rota** (B cree que habló con A), y por eso existen las etiquetas. Este caso muestra además por qué metemos la PSK también en el HKDF: es una segunda barrera.

**Ejercicio 7**

| Llega | Veredicto | Motivo | `ultimo_seq` |
|---|---|---|---|
| SEQ 8 | ACEPTADO | 8 > 7 | 8 |
| SEQ 8 | RECHAZO | replay | 8 |
| SEQ 6 | RECHAZO | replay | 8 |
| SEQ 9 (TAG alterado) | RECHAZO | TAG inválido (no se llega a mirar el SEQ) | 8 |
| SEQ 12 | ACEPTADO | 12 > 8 | 12 |
| SEQ 10 | RECHAZO | 10 ≤ 12: legítimo pero tarde (limitación §8) | 12 |

**Ejercicio 8**
a) Quien robe la placa más tarde lee `a` de la RAM o la flash, recalcula Z con el YB grabado y descifra la sesión. **Se pierde la forward secrecy.**
b) Se rompe la separación de claves: una misma clave usada en dos algoritmos distintos puede filtrar información de uno a otro. No hay un ataque directo conocido, pero ningún diseño estándar lo permite.
c) **Timing attack**: el rechazo tarda más cuantos más bytes iniciales acierta el atacante, así que puede adivinar el TAG byte a byte.
d) **Padding oracle**: según si el padding salió válido o no, el receptor se comporta distinto, y con eso el atacante descifra mensajes sin la clave.
e) El mismo mensaje da siempre el mismo C: el atacante sabe cuándo se repite un mensaje y qué mensajes empiezan igual.

</details>

---

## 7. Defensa requisito por requisito

| # | Lo que pide el profe | Nuestra decisión | Justificación | Evidencia |
|---|---|---|---|---|
| 1 | ≥2 dispositivos IoT, canal no confiable (§1) | 2 ESP32 por Wi-Fi UDP. La seguridad no depende del Wi-Fi | Modelo Dolev–Yao | Demo ESP32 ↔ ESP32 con el atacante en medio |
| 2 | Clave de sesión con DH/ECDH/PSK (§2) | **DH ffdhe2048 efímero** + HKDF | 1ª opción del profe, grupo estándar RFC 7919, da forward secrecy | SID distinto en cada sesión, tiempo del handshake medido |
| 3 | Explicar la autenticación de dispositivos (§2) | HMAC con la PSK sobre todo el transcript, con etiquetas A/B | DH solo es vulnerable a MITM. MicroPython no tiene firmas | Prueba con un nodo no autorizado |
| 4 | Cifrar todo; AEAD o **separados justificados** (§2) | AES-256-CBC + HMAC-SHA256, Encrypt-then-MAC, claves separadas | `cryptolib` no trae GCM. EtM está demostrado seguro (RFC 7366) | Sniffer: solo se ve ciphertext |
| 5 | Rechazar si se altera C, TAG, remitente o frescura (§2) | TAG sobre `TYPE‖IDS‖SID‖SEQ‖IV‖C`, verificado primero y en tiempo constante | Cualquier bit cambiado invalida el TAG | tamper_c, tamper_tag |
| 6 | Detectar repetidos (§2) | SID + SEQ creciente | Sin relojes sincronizados no sirven los timestamps | replay |
| 7 | Sin cripto propia, librerías estándar (§2) | ESP32: `cryptolib`, `hashlib`, `hmac`, `urandom`, `pow`. PC: `cryptography`, `hmac`, `hashlib` | AES, SHA-256, HMAC, HKDF y DH son estándares | `import` del código |
| 8 | Formato documentado (§3) | El de referencia + `TYPE`. El `N` es el IV | TYPE distingue handshake y datos | §4 de estos apuntes |
| 9 | 6 pruebas de seguridad (§4) | `attacker.py` (sniff, tamper_c, tamper_tag, replay, forge) + `node.py --id 0x99` + MITM | Una prueba por cada caso del enunciado | Demo + capturas |
| 10 | Métricas y overhead (§5) | `node.py --bench` + tiempo del handshake | La latencia es RTT/2 | Tablas en el informe |
| 11 | Código, diagramas, formato, informe, reproducible (§6) | `docs/` + README | — | Entrega |
| 12 | Las 4 propiedades en **un** protocolo (§8) | Todo en `protocol.py` | — | Demo completa |

### Preguntas probables del profe

| Pregunta | Respuesta corta |
|---|---|
| ¿Por qué no AES-GCM? | `cryptolib` no lo trae y programarlo sería cripto propia. CBC + HMAC en EtM es la alternativa estándar, y el PDF la permite si se justifica |
| ¿Para qué la PSK si ya tienen DH? | DH sin autenticar sufre MITM (§5.2). MicroPython no tiene firmas, así que la PSK autentica |
| ¿Qué pasa si se filtra la PSK? | Las sesiones **pasadas** siguen seguras gracias a DH efímero. Las **futuras** podrían sufrir MITM, así que hay que cambiar la PSK |
| ¿Por qué ffdhe2048 y no un primo propio? | Inventar parámetros es cripto propia y es fácil equivocarse. RFC 7919 está auditado |
| ¿Por qué exponente de 256 bits y no 2048? | RFC 7919 pide al menos 2 × 112 bits. Además es 8 veces más rápido en la ESP32 |
| ¿Por qué truncar el TAG? | 2⁻¹²⁸ de probabilidad de falsificarlo. NIST SP 800-107 lo permite |
| ¿Para qué el SID si las claves ya cambian por sesión? | Descarta rápido sin calcular el HMAC, deja claro el motivo del rechazo y es parte del formato de referencia |
| ¿Por qué el handshake tarda 2 s? | Son 2 exponenciaciones de 2048 bits en un CPU de 240 MHz. Es una sola vez por sesión; los mensajes siguen tardando milisegundos |

---

## 8. Limitaciones (lo que no protegemos, y lo decimos)

| Limitación | Por qué no la resolvemos |
|---|---|
| **DoS por HELLO**: cada HELLO le cuesta ~2 s a la ESP32 | Fuera del alcance del enunciado. Ninguna criptografía impide que el atacante sature la red |
| **Bloquear o descartar paquetes** | Igual que arriba: es un ataque de disponibilidad |
| **PSK guardada en la flash** | Con acceso físico se puede extraer. Haría falta hardware seguro (eFuse, secure boot) |
| **UDP desordenado** se descarta | Es el costo de la regla simple `SEQ > ultimo_seq`. El enunciado no exige tolerar desorden |
| **IDs en claro** | Se sabe *quién* habla, aunque no *qué* dice. El enunciado no pide anonimato |

---

## 9. Plan de trabajo

| Hito | Qué se construye | Fichas que usa |
|---|---|---|
| 0 ✅ | ESP32 verificada: AES-CBC, SHA-256, `urandom`, `hmac` y `pow` de 2048 bits (1075 ms) | — |
| 1 | `common/crypto.py`: AES-CBC + PKCS7, HMAC, HKDF, DH, `ct_equal`. El mismo archivo corre en el PC y en la ESP32 | 3.4–3.11, 3.13, 3.15 |
| 2 | Wi-Fi + eco UDP ESP32 ↔ PC, sin cripto | — |
| 3 | `common/protocol.py`: handshake, `seal()` y `open()` de paquetes | 3.1–3.3, 3.7, 3.12–3.16 |
| 4 | `pc/node.py` + `esp32/main.py` + `esp32/led.py` → chat seguro | todo |
| 5 | `pc/attacker.py`: sniff, tamper_c, tamper_tag, replay, forge, MITM + nodo no autorizado | §3, resumen |
| 6 | `--bench`: métricas | §4 |
| 7 | Diagramas + informe | §7, §8 |
| 8 | Demo con la segunda ESP32 | — |

### Métricas (Hito 6)

| Métrica | Cómo se mide | Esperado |
|---|---|---|
| Tamaño del mensaje | `len(msg)` | — |
| Tamaño del paquete | `len(paquete)` | `42 + 16·(⌊L/16⌋+1)` |
| Tiempo de cifrado (padding + AES + TAG) | `time.ticks_us()` en la ESP32 / `time.perf_counter()` en el PC | ms en la ESP32, µs en el PC |
| Tiempo de descifrado + verificación | lo mismo | similar |
| Latencia | RTT de un eco / 2 | ms |
| **Tiempo del handshake** | desde HELLO hasta CONFIRM | ~2,2 s en la ESP32 |

Para cada métrica conviene repetir la medición unas 100 veces y reportar el promedio y la desviación estándar, con varios tamaños de mensaje (por ejemplo 8, 32, 128 y 512 B).
