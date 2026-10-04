# Apuntes — Proyecto 1: Mensajería segura entre dispositivos IoT

> **Para qué sirven estos apuntes:** entender **cada pieza** del sistema antes de programarla.
> De cada pieza se explica: qué hace, **qué le entra, qué sale y a dónde va**, **qué pasaría si no estuviera**
> y qué requisito del profe cubre.

| Sección | Contenido |
|---|---|
| §0 | Notación |
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

## 0. Notación

### 0.1 Operaciones

| Símbolo | Significa | Ejemplo |
|---|---|---|
| $A \Vert B$ | Concatenar: poner los bytes de $B$ después de los de $A$ | $\texttt{0x01} \Vert \mathit{ID}_A$ son 2 bytes |
| $a \oplus b$ | XOR bit a bit | $0110 \oplus 1010 = 1100$ |
| $x \bmod p$ | Resto de dividir $x$ entre $p$ | $25 \bmod 23 = 2$ |
| $x \equiv y \pmod{p}$ | $x$ e $y$ dejan el mismo resto al dividir entre $p$ | $19 \equiv -4 \pmod{23}$ |
| $g^{a} \bmod p$ | Exponenciación modular (en Python: `pow(g, a, p)`) | $5^{2} \bmod 23 = 2$ |
| $\lfloor x \rfloor$ | Parte entera hacia abajo | $\lfloor 17/16 \rfloor = 1$ |
| $\mathrm{rand}(n)$ | $n$ bytes aleatorios (`os.urandom(n)`) | $N_A = \mathrm{rand}(16)$ |
| $H(m)$ | SHA-256 de $m$ (32 bytes) | |
| $\mathrm{HMAC}(K, m)$ | HMAC-SHA256 con clave $K$ sobre el mensaje $m$ (32 bytes) | |
| $\mathrm{trunc}_{n}(x)$ | Los primeros $n$ bytes de $x$ (en Python: `x[:n]`) | $\mathrm{trunc}_{16}(\mathrm{HMAC}(\dots))$ |
| $\mathrm{AES}_K(x)$, $\mathrm{AES}^{-1}_K(y)$ | Cifrar / descifrar **un** bloque de 16 bytes con la clave $K$ | |
| $\texttt{"B"}$, $\texttt{0x01}$ | Bytes literales (texto o hexadecimal) | |

### 0.2 Variables

| Símbolo | Qué es | Tamaño |
|---|---|---|
| $\mathit{PSK}$ | Clave pre-compartida del par de dispositivos | 32 B |
| $\mathit{ID}_A$, $\mathit{ID}_B$, $\mathit{ID}_S$ | ID de A, de B y del emisor de un paquete | 1 B |
| $N_A$, $N_B$ | Nonces de A y de B | 16 B |
| $p$, $g$ | Primo y generador de Diffie–Hellman (públicos) | 256 B, $g = 2$ |
| $a$, $b$ | Exponentes secretos de A y de B | 32 B |
| $Y_A$, $Y_B$ | Valores públicos DH: $Y_A = g^{a} \bmod p$ | 256 B |
| $Z$ | Secreto compartido DH: $Z = g^{ab} \bmod p$ | 256 B |
| $\tau$ | *Transcript* del handshake: $\mathit{ID}_A \Vert \mathit{ID}_B \Vert N_A \Vert N_B \Vert Y_A \Vert Y_B$ | 546 B |
| $\mathit{PRK}$ | Clave intermedia del HKDF | 32 B |
| $K_{\text{enc}}$, $K_{\text{mac}}$ | Clave de cifrado y clave del TAG | 32 B cada una |
| $\mathit{SID}$ | Identificador de sesión | 4 B |
| $\mathit{SEQ}$ | Número de secuencia del paquete | 4 B |
| $\mathit{SEQ}_{\max}$ | Último SEQ aceptado (`ultimo_seq` en el código) | — |
| $\mathit{IV}$ | Vector de inicialización de CBC | 16 B |
| $P_i$, $C_i$ | Bloque $i$ del mensaje (con padding) y del ciphertext | 16 B |
| $\mathit{TAG}$ | Sello del paquete | 16 B |
| $L$ | Largo del mensaje en bytes | — |

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

Lo que **no** puede: romper AES, SHA-256 o el logaritmo discreto, ni conocer la $\mathit{PSK}$.

### 1.2 Las 4 propiedades que exige el profe

| Propiedad | Pregunta que responde | Piezas que la dan |
|---|---|---|
| **Confidencialidad** | ¿Alguien más puede leerlo? | DH + HKDF $\rightarrow K_{\text{enc}} \rightarrow$ AES-CBC |
| **Integridad** | ¿Alguien lo cambió? | $\mathit{TAG}$ (HMAC con $K_{\text{mac}}$) |
| **Autenticación** | ¿De verdad viene de mi par? | $\mathit{PSK}$ + HMAC del handshake + $\mathit{TAG}$ |
| **Anti-replay** | ¿Es nuevo o repetido? | $\mathit{SID}$ + $\mathit{SEQ}$ |

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
| Se escribe a mano en `config.py` (32 bytes aleatorios) | La misma $\mathit{PSK}$, sin cambios | ① HMAC de autenticación (§3.7) ② HKDF (§3.8) |

**Cómo funciona:** cada dispositivo tiene una tabla $\mathit{ID} \rightarrow \mathit{PSK}$. Si llega un ID que no está en la tabla, no hay $\mathit{PSK}$ para él y se rechaza.

**Si no estuviera:** DH no sabe con quién habla, así que un atacante se mete en medio y lee todo (**MITM**, §5.2). Con DH solo **no hay autenticación**.

**¿Por qué PSK y no firmas digitales?** Para autenticar un DH hacen falta firmas (RSA/ECDSA) o un secreto compartido. MicroPython no trae firmas, así que usamos la $\mathit{PSK}$.

**Requisito del profe:** autenticación de dispositivos (10 %) y "explicar cómo se autentican".
**En el código:** `esp32/config.py`, `pc/config.py`.

---

### 3.2 IDs de dispositivo ($\mathit{ID}_A$, $\mathit{ID}_B$, $\mathit{ID}_S$)

**Qué hace:** identifica a cada dispositivo con 1 byte (`0x01`, `0x02`, …).

| Entra | Sale | Va a |
|---|---|---|
| `config.py` | 1 byte | ① el receptor busca la $\mathit{PSK}$ con él ② entra al HMAC del handshake (dentro de $\tau$) ③ va en cada paquete como $\mathit{ID}_S$ |

**Si no estuviera:** con 2 dispositivos funcionaría, pero con más el receptor no sabría qué $\mathit{PSK}$ usar. Además, como el ID entra al HMAC y al $\mathit{TAG}$, el atacante **no puede cambiar el remitente** sin que se note (el profe pide rechazar si se altera la *sender information*).

**Requisito del profe:** formato de paquete ($\mathit{ID}_S$ del formato de referencia) + rechazo si se altera el remitente.

---

### 3.3 Nonces ($N_A$, $N_B$)

**Qué hace:** cada lado aporta 16 bytes **aleatorios y nuevos** en cada handshake.

| Entra | Sale | Va a |
|---|---|---|
| $\mathrm{rand}(16)$ | $N_A$ (de A), $N_B$ (de B) | ① HMAC del handshake ② *salt* del HKDF |

**Cómo funciona:** como son nuevos en cada sesión, cualquier cosa calculada con ellos **solo sirve para esta sesión**.

**Si no estuviera:** con DH, los valores $Y_A$ y $Y_B$ ya son aleatorios, así que la sesión seguiría siendo fresca. **Los nonces son una segunda garantía:** aseguran frescura aunque algún día se reutilice el exponente DH (por ejemplo, para ahorrar 1 s) y sirven de *salt* estándar en HKDF. TLS 1.3 hace lo mismo: manda `random` **y** `key_share`.

**Requisito del profe:** frescura / anti-replay del handshake.

---

### 3.4 Diffie–Hellman: exponente secreto y valor público ($a \rightarrow Y_A$)

**Qué hace:** cada lado genera un número secreto y publica un valor derivado de él. Con eso, ambos llegan al **mismo secreto $Z$ sin que $Z$ viaje nunca** por la red.

| Entra | Sale | Va a |
|---|---|---|
| $a = \mathrm{rand}(32)$ + constantes públicas $p$ y $g$ | $Y_A = g^{a} \bmod p$ (256 bytes) | $Y_A \rightarrow$ mensaje HELLO (público). $a \rightarrow$ **solo** a §3.6, y luego se **borra** |

**Cómo funciona (la matemática):**

$$
\begin{aligned}
\text{A elige } a \text{ (secreto) y publica } \quad Y_A &= g^{a} \bmod p \\
\text{B elige } b \text{ (secreto) y publica } \quad Y_B &= g^{b} \bmod p \\[6pt]
\text{A calcula } \quad Z &= Y_B^{\,a} = \left(g^{b}\right)^{a} = g^{ab} \bmod p \\
\text{B calcula } \quad Z &= Y_A^{\,b} = \left(g^{a}\right)^{b} = g^{ab} \bmod p
\end{aligned}
$$

**¡Los dos obtienen el mismo número!** El atacante ve $p$, $g$, $Y_A$ y $Y_B$. Para obtener $Z$ necesitaría sacar $a$ de $Y_A = g^{a} \bmod p$, es decir, resolver el **logaritmo discreto**. Con números de 2048 bits eso es inviable.

**Parámetros que usamos:**

| Parámetro | Valor | Por qué |
|---|---|---|
| Grupo | `ffdhe2048` (RFC 7919) | Primo estándar y auditado. **No** inventamos el primo (eso sería cripto propia) |
| $p$ | Primo seguro de 2048 bits ($p = 2q + 1$, con $q$ primo) | $\approx 112$ bits de seguridad (recomendación NIST) |
| $g$ | $2$ | El que define el RFC |
| Tamaño de $a$ | 256 bits | RFC 7919 pide al menos $2 \times 112 = 224$ bits. Por eso la ESP32 tarda **1 s** y no 8 s |
| Operación | `pow(g, a, p)` | Viene en Python y en MicroPython: no es código nuestro |

**Si no estuviera (solo PSK):** las claves saldrían solo de la $\mathit{PSK}$ y de los nonces, que viajan en claro. Si la $\mathit{PSK}$ se filtra algún día, **todas las sesiones grabadas** se podrían descifrar. Con DH eso no pasa: es la **forward secrecy**.

**Por qué se borra $a$:** si $a$ quedara guardado en memoria y alguien robara la placa después, podría recalcular $Z$. Borrarlo es lo que hace a DH **efímero** ("DHE").

**Requisito del profe:** "establish a session key using Diffie–Hellman" (15 %). Es la **primera opción** que propone el PDF.
**En el código:** `common/dh.py` → `dh_keygen()`.

---

### 3.5 Validación del valor público recibido ($Y_B$)

**Qué hace:** antes de usar el $Y_B$ que llegó, se comprueba que

$$
1 < Y_B < p - 1
$$

| Entra | Sale | Va a |
|---|---|---|
| $Y_B$ recibido | ✅ seguir / ❌ abortar el handshake | §3.6 |

**Si no estuviera:** con $Y_B = 1$ el secreto es $Z = 1^{a} = 1$, y con $Y_B = p - 1$ es $Z = (-1)^{a}$, que vale $1$ o $p-1$. Cualquiera conocería $Z$ (§5.3).
En nuestro diseño, un atacante **externo** no puede colar $Y_B = 1$, porque $Y_B$ va dentro del HMAC con la $\mathit{PSK}$ (§3.7). La validación nos protege de un dispositivo autorizado con un error o comprometido. Es **defensa en profundidad** y **RFC 7919 la exige**.

**En el código:** `common/dh.py` → dentro de `dh_shared()`.

---

### 3.6 Secreto compartido $Z$

| Entra | Sale | Va a |
|---|---|---|
| $Y_B$ (validado) + $a$ | $Z = Y_B^{\,a} \bmod p$ (256 bytes) | HKDF (§3.8), y luego se **borra** |

**Clave:** $Z$ **nunca** se envía. Cada lado lo calcula por su cuenta.
**Si no estuviera:** no hay forward secrecy (ver §3.4).
**En el código:** `common/dh.py` → `dh_shared()`.

---

### 3.7 HMAC de autenticación del handshake ($\mathit{HMAC}_B$ y $\mathit{HMAC}_A$)

**Qué hace:** cada lado demuestra que **conoce la $\mathit{PSK}$ sin enviarla** y, al mismo tiempo, **firma todo lo que vio** del handshake.

| Entra | Sale | Va a |
|---|---|---|
| $\mathit{PSK}$ + etiqueta ($\texttt{"B"}$ o $\texttt{"A"}$) + transcript $\tau$ | 32 bytes | B lo manda en RESPONSE y A en CONFIRM. El otro lado lo recalcula y compara |

$$
\begin{aligned}
\tau &= \mathit{ID}_A \Vert \mathit{ID}_B \Vert N_A \Vert N_B \Vert Y_A \Vert Y_B \\[4pt]
\mathit{HMAC}_B &= \mathrm{HMAC}\left(\mathit{PSK},\ \texttt{"B"} \Vert \tau\right) \qquad \text{(lo envía B)} \\
\mathit{HMAC}_A &= \mathrm{HMAC}\left(\mathit{PSK},\ \texttt{"A"} \Vert \tau\right) \qquad \text{(lo envía A)}
\end{aligned}
$$

**Por qué $\tau$ incluye $Y_A$ y $Y_B$:** así se evita el MITM. Si el atacante cambia $Y_A$ o $Y_B$, cada lado ve un $\tau$ distinto y el HMAC no coincide (§5.2).
**Por qué incluye $N_A$ y $N_B$:** así un HMAC de una sesión vieja no sirve en una nueva.
**Por qué las etiquetas $\texttt{"A"}$ y $\texttt{"B"}$:** sin ellas $\mathit{HMAC}_A = \mathit{HMAC}_B$, y el atacante podría devolverle a B su propio HMAC como si fuera de A (**ataque de reflexión**, ejercicio 6).

**Si no estuviera:** DH queda sin autenticar → MITM.

**Requisito del profe:** autenticación de dispositivos + prueba con un dispositivo no autorizado.
**En el código:** `common/protocol.py` → handshake.

---

### 3.8 HKDF: derivar las claves de sesión

**Qué hace:** convierte $Z$ (que no es uniforme: es un número módulo $p$) y la $\mathit{PSK}$ en **claves limpias de 32 bytes, una para cada uso**.

| Entra | Sale | Va a |
|---|---|---|
| $Z$, $\mathit{PSK}$, $N_A$, $N_B$ | $K_{\text{enc}}$ (32 B), $K_{\text{mac}}$ (32 B), $\mathit{SID}$ (4 B) | $K_{\text{enc}} \rightarrow$ AES (§3.11) · $K_{\text{mac}} \rightarrow \mathit{TAG}$ (§3.13) · $\mathit{SID} \rightarrow$ cabecera (§3.12) |

**Extract** (RFC 5869): concentra la aleatoriedad de $Z$ en 32 bytes uniformes.

$$
\mathit{PRK} = \mathrm{HMAC}\left(N_A \Vert N_B,\ Z \Vert \mathit{PSK}\right)
$$

**Expand:** saca de $\mathit{PRK}$ una clave distinta para cada uso.

$$
\begin{aligned}
K_{\text{enc}} &= \mathrm{HMAC}\left(\mathit{PRK},\ \texttt{"enc"} \Vert \texttt{0x01}\right) \\
K_{\text{mac}} &= \mathrm{HMAC}\left(\mathit{PRK},\ \texttt{"mac"} \Vert \texttt{0x01}\right) \\
\mathit{SID} &= \mathrm{trunc}_{4}\left(\mathrm{HMAC}\left(\mathit{PRK},\ \texttt{"sid"} \Vert \texttt{0x01}\right)\right)
\end{aligned}
$$

**Por qué no usar $Z$ directamente como clave AES:** $Z$ mide 256 bytes y sus bits no son uniformes. Además, **nunca se usa la misma clave para dos cosas** (cifrar y autenticar), y eso se llama **separación de claves**.
**Por qué meter también la $\mathit{PSK}$ en el HKDF:** como segunda barrera. Aunque un atacante lograra engañar la autenticación (por ejemplo con el ataque de reflexión), sin la $\mathit{PSK}$ no podría derivar las claves.

**Si no estuviera:** se usaría la misma clave para AES y HMAC, o una clave con sesgo. Ninguna de las dos cosas es aceptable en un diseño estándar.

**Requisito del profe:** "appropriate management of cryptographic material" (15 %).
**En el código:** `common/hkdf.py` → `derive_keys()`.

---

### FASE 2: ENVIAR

### 3.9 Padding PKCS#7

**Qué hace:** completa el mensaje hasta un múltiplo de 16 bytes, porque AES trabaja con bloques de 16.

| Entra | Sale | Va a |
|---|---|---|
| Mensaje de $L$ bytes | $16\left(\lfloor L/16 \rfloor + 1\right)$ bytes | AES-CBC (§3.11) |

**Cómo funciona:** se agregan $n = 16 - (L \bmod 16)$ bytes, todos con el valor $n$. Como $1 \le n \le 16$, **siempre** se agrega al menos 1 byte; si el mensaje ya mide un múltiplo de 16, se agrega un bloque entero de `0x10`.

| $L$ | $n$ | Relleno |
|---|---|---|
| 10 | 6 | `06 06 06 06 06 06` |
| 15 | 1 | `01` |
| 16 | 16 | `10` × 16 |

**Si no estuviera:** AES-CBC no puede cifrar un mensaje como `"Hola"` (4 bytes).

---

### 3.10 IV (vector de inicialización)

**Qué hace:** son 16 bytes aleatorios, **nuevos en cada mensaje**, que inician la cadena de CBC.

| Entra | Sale | Va a |
|---|---|---|
| $\mathrm{rand}(16)$ | $\mathit{IV}$ | ① AES-CBC ② se copia **en claro** en el paquete ③ entra al $\mathit{TAG}$ |

**Si no estuviera ($\mathit{IV}$ fijo):** el mismo mensaje daría siempre el mismo ciphertext. El atacante sabría cuándo se repite un mensaje ("otra vez mandaron *ABRIR*") sin descifrarlo.
**Ojo:** el $\mathit{IV}$ **no es secreto**, solo tiene que ser impredecible. Es el $N$ del formato de referencia del profe.

---

### 3.11 AES-256-CBC

**Qué hace:** cifra. Es la pieza que da la **confidencialidad**.

| Entra | Sale | Va a |
|---|---|---|
| Mensaje con padding $P_1 \Vert P_2 \Vert \dots \Vert P_n$ + $K_{\text{enc}}$ + $\mathit{IV}$ | $C = C_1 \Vert C_2 \Vert \dots \Vert C_n$ (mismo tamaño que la entrada) | Paquete + $\mathit{TAG}$ |

**Cómo funciona:**
- **AES** es un cifrador de bloque: transforma 16 bytes en otros 16 bytes usando la clave. AES-256 usa una clave de 32 bytes.
- **CBC** encadena los bloques: cada bloque se mezcla (XOR) con el ciphertext anterior antes de cifrarlo. Tomando $C_0 = \mathit{IV}$:

$$
\begin{aligned}
\text{Cifrar:} \quad C_i &= \mathrm{AES}_{K_{\text{enc}}}\left(P_i \oplus C_{i-1}\right) \\
\text{Descifrar:} \quad P_i &= \mathrm{AES}^{-1}_{K_{\text{enc}}}\left(C_i\right) \oplus C_{i-1}
\end{aligned}
$$

**Si no estuviera:** el sniffer lee los mensajes en claro.
**Debilidad conocida:** CBC es **maleable**. Si el atacante cambia $C_1$ por $C_1' = C_1 \oplus \Delta$, el receptor obtiene

$$
P_2' = \mathrm{AES}^{-1}_{K_{\text{enc}}}(C_2) \oplus C_1' = \underbrace{\mathrm{AES}^{-1}_{K_{\text{enc}}}(C_2) \oplus C_1}_{P_2} \oplus\, \Delta = P_2 \oplus \Delta
$$

es decir, **cambia en $P_2$ exactamente los bits que el atacante eligió** (§5.5). Por eso el $\mathit{TAG}$ es obligatorio.

**¿Por qué CBC y no AES-GCM (lo que recomienda el profe)?** `cryptolib` de MicroPython solo trae ECB, CBC y CTR. Programar GCM a mano sería criptografía propia, que está prohibida. El PDF permite cifrado y autenticación separados **si se justifica**, y esta es la justificación.

**Requisito del profe:** confidencialidad (15 %).
**En el código:** `common/aes_cbc.py` → `aes_cbc_encrypt()` / `aes_cbc_decrypt()`.

---

### 3.12 Cabecera: $\mathit{TYPE}$, $\mathit{ID}_S$, $\mathit{SID}$, $\mathit{SEQ}$

| Campo | Tamaño | Qué hace | Entra de | Si no estuviera |
|---|---|---|---|---|
| $\mathit{TYPE}$ | 1 B | Dice qué es el paquete: `0x01` HELLO, `0x02` RESPONSE, `0x03` CONFIRM, `0x10` DATA | constante | El receptor podría confundir un tipo de mensaje con otro (*type confusion*). Como entra al $\mathit{TAG}$, no se puede cambiar |
| $\mathit{ID}_S$ | 1 B | Quién envía | `config.py` | Ver §3.2 |
| $\mathit{SID}$ | 4 B | A qué sesión pertenece | HKDF (§3.8) | Un paquete de otra sesión igual fallaría en el $\mathit{TAG}$, porque $K_{\text{mac}}$ es distinta. El $\mathit{SID}$ permite **descartarlo rápido, sin calcular el HMAC**, deja el motivo claro en el log y es parte del formato que pide el profe ("associate the message with a valid session") |
| $\mathit{SEQ}$ | 4 B | Número de mensaje: $1, 2, 3, \dots$ | contador del emisor | **Replay**: el atacante reenvía un paquete viejo y se acepta como nuevo (§5.7) |

**Por qué $\mathit{SEQ}$ y no timestamps:** las ESP32 no tienen reloj sincronizado. El profe acepta *"sequence numbers, counters, timestamps, nonces, or session identifiers"*.

---

### 3.13 TAG (HMAC-SHA256 truncado, Encrypt-then-MAC)

**Qué hace:** es el "sello" del paquete. Da **integridad y autenticación** de cada mensaje.

| Entra | Sale | Va a |
|---|---|---|
| $K_{\text{mac}}$ + $\mathit{TYPE} \Vert \mathit{ID}_S \Vert \mathit{SID} \Vert \mathit{SEQ} \Vert \mathit{IV} \Vert C$ | 16 bytes | Final del paquete |

$$
\mathit{TAG} = \mathrm{trunc}_{16}\Big(\mathrm{HMAC}\big(K_{\text{mac}},\ \mathit{TYPE} \Vert \mathit{ID}_S \Vert \mathit{SID} \Vert \mathit{SEQ} \Vert \mathit{IV} \Vert C\big)\Big)
$$

**Cómo funciona:**
- **SHA-256** ($H$) resume cualquier mensaje en 32 bytes. Si cambia un solo bit, el resumen cambia por completo. Pero no usa clave: cualquiera puede calcularlo.
- **HMAC** es SHA-256 con clave. Solo quien tiene $K_{\text{mac}}$ puede generar un $\mathit{TAG}$ válido:

$$
\mathrm{HMAC}(K, m) = H\Big(\left(K \oplus \mathit{opad}\right) \Vert H\big(\left(K \oplus \mathit{ipad}\right) \Vert m\big)\Big)
$$

- **¿Por qué no simplemente $H(K \Vert m)$?** Por el ataque de *length-extension*: conociendo $H(K \Vert m)$ se puede calcular $H(K \Vert m \Vert \mathit{extra})$ sin conocer $K$. HMAC no tiene ese problema.
- **Truncado a 16 B:** la probabilidad de adivinarlo es $2^{-128}$. NIST SP 800-107 lo permite.

**Encrypt-then-MAC (el orden importa):**

| Orden | Qué se envía | ¿Seguro? |
|---|---|---|
| Encrypt-and-MAC | $\mathrm{Enc}(m)$ y $\mathrm{MAC}(m)$ | ❌ el MAC puede filtrar información de $m$ |
| MAC-then-Encrypt | $\mathrm{Enc}\left(m \Vert \mathrm{MAC}(m)\right)$ | ⚠️ *padding oracle* (Lucky13, POODLE en TLS) |
| **Encrypt-then-MAC** ✅ | $C = \mathrm{Enc}(m)$ y $\mathrm{MAC}(C)$ | Demostrado seguro (Bellare–Namprempre, 2000). Es el que usa TLS con CBC (RFC 7366) |

**Por qué el $\mathit{TAG}$ cubre la cabecera y no solo $C$:** si solo cubriera $C$, el atacante podría cambiar $\mathit{SEQ}$ (y saltarse el anti-replay), $\mathit{ID}_S$ (y cambiar el remitente) o $\mathit{SID}$ sin que se note (ejercicio 5b).

**Si no estuviera:** el atacante modifica mensajes (bit-flipping, §5.5) o inventa paquetes.

**Requisito del profe:** integridad y autenticación de mensajes (15 %) + "reject any message whose ciphertext, authentication information, sender information, or freshness data has been altered".
**En el código:** `common/tag.py` → `make_tag()`; `common/protocol.py` → `seal()`.

---

### FASE 3: RECIBIR

### 3.14 Orden de verificación del receptor

1. ¿$\mathit{TYPE} = \texttt{0x10}$, $\mathit{ID}_S$ es mi par y $\mathit{SID}$ es la sesión activa? Si no → **RECHAZO "sesión/ID"**
2. ¿$\mathit{TAG} = \mathrm{trunc}_{16}\left(\mathrm{HMAC}(K_{\text{mac}},\ \text{cabecera} \Vert \mathit{IV} \Vert C)\right)$? Si no → **RECHAZO "TAG inválido"**
3. ¿$\mathit{SEQ} > \mathit{SEQ}_{\max}$? Si no → **RECHAZO "replay"**
4. Actualizar $\mathit{SEQ}_{\max} \leftarrow \mathit{SEQ}$
5. Descifrar → quitar padding → **ACEPTADO**

| Entra | Sale | Va a |
|---|---|---|
| Paquete UDP + $K_{\text{enc}}$, $K_{\text{mac}}$, $\mathit{SID}$, $\mathit{SEQ}_{\max}$ | Mensaje en claro **o** RECHAZO + motivo | Pantalla / log / LED |

**Por qué este orden y qué pasa si se cambia:**

| Si se hiciera… | Pasaría… |
|---|---|
| Descifrar **antes** de verificar el $\mathit{TAG}$ | *Padding oracle*: el atacante prueba ciphertexts modificados, observa si el padding fue válido y descifra byte a byte |
| Revisar y guardar $\mathit{SEQ}$ **antes** del $\mathit{TAG}$ | DoS: un paquete falso con $\mathit{SEQ} = 4\,000\,000\,000$ sube $\mathit{SEQ}_{\max}$ y bloquea todos los mensajes legítimos |
| Actualizar $\mathit{SEQ}_{\max}$ aunque falle el $\mathit{TAG}$ | Lo mismo: el atacante controla el contador |

**Regla de oro:** **no se confía en ningún campo hasta haber verificado el $\mathit{TAG}$.**

---

### 3.15 Comparación en tiempo constante

**Qué hace:** compara el $\mathit{TAG}$ recibido con el calculado **mirando todos los bytes**, aunque el primero ya sea distinto. Matemáticamente calcula

$$
r = \bigvee_{i} \left(x_i \oplus y_i\right) \qquad \text{y acepta solo si } r = 0
$$

(el OR de todas las diferencias: basta un byte distinto para que $r \neq 0$).

```python
def ct_equal(a, b):
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y          # acumula diferencias sin salir antes
    return r == 0
```

**Si no estuviera (usar `==`):** `==` se detiene en el primer byte distinto. Midiendo cuánto tarda el rechazo, el atacante podría adivinar el $\mathit{TAG}$ byte a byte (**timing attack**).
MicroPython no trae `hmac.compare_digest`; por eso esta función de 6 líneas. No es un algoritmo criptográfico propio, es una comparación.

---

### 3.16 Estado anti-replay ($\mathit{SEQ}_{\max}$)

| Entra | Sale | Va a |
|---|---|---|
| $\mathit{SEQ}$ del paquete (ya verificado por el $\mathit{TAG}$) | Aceptar / rechazar | Se actualiza $\mathit{SEQ}_{\max}$ |

**Regla:** solo se acepta si $\mathit{SEQ} > \mathit{SEQ}_{\max}$. Al empezar una sesión, $\mathit{SEQ}_{\max} = 0$ y el emisor empieza en $\mathit{SEQ} = 1$.
**Costo:** un paquete UDP legítimo que llegue **desordenado** se descarta (ver §8). Aceptamos ese costo porque el enunciado no exige tolerar desorden.

**Requisito del profe:** replay protection (10 %).

---

### 3.17 LED (no es una pieza de seguridad)

| Evento | LED (GPIO2) |
|---|---|
| Handshake completado | Encendido 1 s |
| Mensaje aceptado | 1 parpadeo |
| Mensaje rechazado | 3 parpadeos rápidos |

No toca el protocolo: solo **muestra** en la demo lo que decidió el receptor.

---

### Resumen: si quitamos cada pieza, ¿qué ataque funciona?

| Pieza que se quita | Ataque que funcionaría |
|---|---|
| $\mathit{PSK}$ / HMAC del handshake | MITM: el atacante lee y cambia todo |
| $Y_A$, $Y_B$ en el transcript $\tau$ | MITM: el atacante cambia los valores DH sin que se note |
| Etiquetas $\texttt{"A"}$ / $\texttt{"B"}$ | Reflexión: B cree que A está autenticado |
| Validación $1 < Y < p - 1$ | $Z = 1$, conocido por todos (si el otro lado es malicioso o tiene un bug) |
| DH (dejar solo $\mathit{PSK}$) | Si se filtra la $\mathit{PSK}$, se descifran todas las sesiones grabadas |
| Borrar $a$ y $Z$ | Quien robe la placa después recalcula las claves de sesión |
| HKDF | Misma clave para dos usos / clave con sesgo |
| $\mathit{IV}$ aleatorio | Se detecta cuándo se repite un mensaje |
| AES | Sniffer lee todo |
| $\mathit{TAG}$ | Bit-flipping, paquetes falsos |
| Cabecera dentro del $\mathit{TAG}$ | Cambiar $\mathit{SEQ}$ → replay; cambiar $\mathit{ID}_S$ → suplantar remitente |
| $\mathit{SEQ}$ | Replay |
| Orden ① ② ③ | Padding oracle / DoS del contador |
| Comparación en tiempo constante | Timing attack sobre el $\mathit{TAG}$ |

---

## 4. Recorrido completo con tamaños reales

### 4.1 Handshake

| Mensaje | Contenido | Tamaño |
|---|---|---|
| HELLO (A→B) | $\texttt{0x01} \Vert \mathit{ID}_A \Vert N_A \Vert Y_A$ | $1 + 1 + 16 + 256 = \mathbf{274}$ B |
| RESPONSE (B→A) | $\texttt{0x02} \Vert \mathit{ID}_B \Vert N_B \Vert Y_B \Vert \mathit{HMAC}_B$ | $1 + 1 + 16 + 256 + 32 = \mathbf{306}$ B |
| CONFIRM (A→B) | $\texttt{0x03} \Vert \mathit{ID}_A \Vert \mathit{HMAC}_A$ | $1 + 1 + 32 = \mathbf{34}$ B |
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
                                                                Z ← YA^b mod p, HKDF, borrar b y Z
                                                                HMAC_B ← HMAC(PSK, "B"‖transcript)
         ◄──── RESPONSE: 0x02‖IDB‖NB‖YB‖HMAC_B ─────────────
  ¿1 < YB < p−1?
  ¿HMAC_B correcto?  → B es auténtico
  Z ← YB^a mod p                         (~1 s)
  K_enc, K_mac, SID ← HKDF(NA‖NB, Z‖PSK)
  borrar a, Z
         ───── CONFIRM: 0x03‖IDA‖HMAC_A ────────────────────►
                                                                ¿HMAC_A correcto? → A es auténtico
                                                                (recién aquí se entrega la sesión)
  LED 1 s ✓                                                     sesión lista ✓
```

### 4.2 Mensaje de datos

```
┌──────┬─────┬───────┬───────┬────────┬───────────┬─────────┐
│ TYPE │ IDS │  SID  │  SEQ  │   IV   │     C     │   TAG   │
│  1 B │ 1 B │  4 B  │  4 B  │  16 B  │  16·n B   │  16 B   │
└──────┴─────┴───────┴───────┴────────┴───────────┴─────────┘
```

$$
\begin{aligned}
C &= \text{AES-256-CBC}\left(K_{\text{enc}},\ \mathit{IV},\ \mathrm{PKCS7}(m)\right) \\
\mathit{TAG} &= \mathrm{trunc}_{16}\left(\mathrm{HMAC}\left(K_{\text{mac}},\ \mathit{TYPE} \Vert \mathit{ID}_S \Vert \mathit{SID} \Vert \mathit{SEQ} \Vert \mathit{IV} \Vert C\right)\right) \\[6pt]
\text{tamaño} &= \underbrace{1 + 1 + 4 + 4 + 16 + 16}_{42\ \text{B fijos}} + 16\left(\left\lfloor L/16 \right\rfloor + 1\right)
\end{aligned}
$$

---

## 5. Ejemplos manuales resueltos

Los números reales (2048 bits, AES de 128 bits) no se pueden calcular a mano.
Para practicar la **lógica** usamos números pequeños. **Solo sirven para entender: no son seguros.**

### 5.1 Diffie–Hellman con números pequeños

Parámetros públicos: $p = 23$, $g = 5$. Secretos: $a = 6$ (A), $b = 15$ (B).

**Truco para calcular potencias módulo $p$:** se eleva al cuadrado repetidamente y se reduce en cada paso.

Potencias de 5 módulo 23:

| Potencia | Cálculo | $\bmod 23$ |
|---|---|---|
| $5^{1}$ | | $5$ |
| $5^{2}$ | $25$ | $\mathbf{2}$ |
| $5^{4}$ | $2^{2} = 4$ | $\mathbf{4}$ |
| $5^{8}$ | $4^{2} = 16$ | $\mathbf{16}$ |

**A publica:**

$$
Y_A = 5^{6} = 5^{4} \cdot 5^{2} \equiv 4 \cdot 2 = \mathbf{8} \pmod{23}
$$

**B publica:**

$$
Y_B = 5^{15} = 5^{8} \cdot 5^{4} \cdot 5^{2} \cdot 5^{1} \equiv 16 \cdot 4 \cdot 2 \cdot 5 = 640 = 27 \cdot 23 + 19 \equiv \mathbf{19} \pmod{23}
$$

**A calcula $Z = Y_B^{\,a} = 19^{6} \bmod 23$.** Como $19 \equiv -4 \pmod{23}$:

$$
19^{6} \equiv (-4)^{6} = 4096 = 178 \cdot 23 + 2 \equiv \mathbf{2} \pmod{23}
$$

**B calcula $Z = Y_A^{\,b} = 8^{15} \bmod 23$:**

| Potencia | Cálculo | $\bmod 23$ |
|---|---|---|
| $8^{2}$ | $64$ | $18$ |
| $8^{4}$ | $18^{2} = 324$ | $2$ |
| $8^{8}$ | $2^{2}$ | $4$ |
| $8^{15} = 8^{8} \cdot 8^{4} \cdot 8^{2} \cdot 8^{1}$ | $4 \cdot 2 \cdot 18 \cdot 8 = 1152 = 50 \cdot 23 + 2$ | $\mathbf{2}$ |

✅ **Ambos obtienen $Z = 2$**, y el atacante solo vio $23$, $5$, $8$ y $19$.

### 5.2 Ataque MITM a DH **sin** PSK… y cómo la PSK lo detecta

El atacante M elige su propio secreto $m = 3$ y calcula $Y_M = 5^{3} = 125 = 5 \cdot 23 + 10 \equiv \mathbf{10} \pmod{23}$.

```
A ──YA=8──►  M  ──YM=10──► B        (M cambia YA por YM)
A ◄─YM=10──  M  ◄──YB=19── B        (M cambia YB por YM)
```

| Quién | Calcula | Resultado |
|---|---|---|
| A | $Y_M^{\,a} = 10^{6}$: $\ 10^{2} \equiv 8,\ 10^{4} \equiv 18,\ 10^{6} \equiv 18 \cdot 8 = 144 \equiv 6$ | $\mathbf{6}$ |
| M (con A) | $Y_A^{\,m} = 8^{3} = 512 = 22 \cdot 23 + 6$ | $\mathbf{6}$ ✓ igual que A |
| B | $Y_M^{\,b} = 10^{15} = 10^{8} \cdot 10^{4} \cdot 10^{2} \cdot 10 \equiv 2 \cdot 18 \cdot 8 \cdot 10 = 2880 \equiv 5$ | $\mathbf{5}$ |
| M (con B) | $Y_B^{\,m} = 19^{3} \equiv (-4)^{3} = -64 \equiv -64 + 69 = 5$ | $\mathbf{5}$ ✓ igual que B |

**Sin PSK:** A cree que comparte $6$ con B, y B cree que comparte $5$ con A, pero **M conoce los dos**. Descifra todo lo que manda A, lo lee, lo vuelve a cifrar y se lo pasa a B. Nadie se da cuenta.

**Con nuestro protocolo:**
- B calcula $\mathit{HMAC}_B = \mathrm{HMAC}(\mathit{PSK},\ \texttt{"B"} \Vert \dots \Vert Y_A{=}10 \Vert Y_B{=}19)$, porque B vio $Y_A = 10$.
- A espera $\mathrm{HMAC}(\mathit{PSK},\ \texttt{"B"} \Vert \dots \Vert Y_A{=}8 \Vert Y_B{=}10)$, porque A vio esos valores.
- **Los transcripts $\tau$ son distintos**, así que A rechaza.
- M podría intentar fabricar el HMAC correcto, pero **no tiene la $\mathit{PSK}$**.

→ **Por eso la $\mathit{PSK}$ es imprescindible y por eso $Y_A$ y $Y_B$ van dentro del HMAC.**

### 5.3 Valor público inválido

Si un dispositivo malicioso o con un bug manda $Y_B = 1$:

$$
Z = 1^{a} = 1 \quad \text{para cualquier } a
$$

Todo el mundo conoce $Z$.

Si manda $Y_B = p - 1 = 22 \equiv -1 \pmod{23}$:

$$
Z = (-1)^{a} =
\begin{cases}
1 & \text{si } a \text{ es par} \\
22 & \text{si } a \text{ es impar}
\end{cases}
$$

Solo 2 opciones posibles.

→ La regla $1 < Y < p - 1$ descarta los dos casos.

### 5.4 CBC con un cifrador de juguete de 4 bits

Cifrador de juguete (XOR con la clave y rotar 1 bit):

$$
E_K(x) = \mathrm{rotl}_1(x \oplus K) \qquad\qquad D_K(y) = \mathrm{rotr}_1(y) \oplus K
$$

Ejemplos de rotación: $\mathrm{rotl}_1(1101) = 1011$, $\mathrm{rotr}_1(1011) = 1101$.

Datos: $K = 1010$, $\mathit{IV} = 0110$, $P_1 = 0001$, $P_2 = 1001$.

**Cifrar** ($C_i = E_K(P_i \oplus C_{i-1})$, con $C_0 = \mathit{IV}$):

| Paso | Cálculo | Resultado |
|---|---|---|
| $P_1 \oplus \mathit{IV}$ | $0001 \oplus 0110$ | $0111$ |
| $\oplus K$ | $0111 \oplus 1010$ | $1101$ |
| $\mathrm{rotl}_1 \rightarrow C_1$ | | $\mathbf{1011}$ |
| $P_2 \oplus C_1$ | $1001 \oplus 1011$ | $0010$ |
| $\oplus K$ | $0010 \oplus 1010$ | $1000$ |
| $\mathrm{rotl}_1 \rightarrow C_2$ | | $\mathbf{0001}$ |

**Descifrar** ($P_i = D_K(C_i) \oplus C_{i-1}$):

| Paso | Cálculo | Resultado |
|---|---|---|
| $\mathrm{rotr}_1(C_1) \oplus K$ | $1101 \oplus 1010$ | $0111$ |
| $\oplus \mathit{IV} \rightarrow P_1$ | $0111 \oplus 0110$ | $\mathbf{0001}$ ✓ |
| $\mathrm{rotr}_1(C_2) \oplus K$ | $1000 \oplus 1010$ | $0010$ |
| $\oplus C_1 \rightarrow P_2$ | $0010 \oplus 1011$ | $\mathbf{1001}$ ✓ |

### 5.5 Bit-flipping: por qué el cifrado solo no basta

El atacante invierte el último bit de $C_1$, es decir, usa $\Delta = 0001$: $C_1' = C_1 \oplus \Delta = 1010$. No conoce $K$.

| Bloque | Cálculo del receptor | Obtiene | Original |
|---|---|---|---|
| $P_1'$ | $\mathrm{rotr}_1(1010) = 0101 \rightarrow \oplus K = 1111 \rightarrow \oplus \mathit{IV}$ | $1001$ | $0001$ (basura) |
| $P_2'$ | $D_K(C_2) = 0010 \rightarrow \oplus\, C_1' = 1010$ | $\mathbf{1000}$ | $1001$ (**cambió justo el último bit**) |

Comprobación con la fórmula de §3.11: $P_2' = P_2 \oplus \Delta = 1001 \oplus 0001 = 1000$ ✓.

El atacante cambió **exactamente el bit que eligió** sin saber la clave. Si $P_2$ fuera `"ABRIR=0"`, lo podría convertir en `"ABRIR=1"`.
**Con el TAG:** el receptor calcula $\mathrm{HMAC}(K_{\text{mac}}, \dots \Vert C_1' \Vert \dots)$, que no coincide con el $\mathit{TAG}$ del paquete, y **rechaza antes de descifrar**.

### 5.6 Armar el paquete de `"Hola ESP32"`

1. Bytes: `48 6f 6c 61 20 45 53 50 33 32` → $L = 10$
2. PKCS#7: $n = 16 - 10 = 6$ → se agrega `06 06 06 06 06 06` → 16 bytes
3. AES-256-CBC → $C$ de 16 bytes
4. Cabecera: `TYPE=10 IDS=01 SID=3a7f00c2 SEQ=00000005 IV=<16 B aleatorios>`
5. $\mathit{TAG} = \mathrm{trunc}_{16}\left(\mathrm{HMAC}(K_{\text{mac}},\ \texttt{10} \Vert \texttt{01} \Vert \texttt{3a7f00c2} \Vert \texttt{00000005} \Vert \mathit{IV} \Vert C)\right)$
6. **Total** $= 42 + 16 = 58$ bytes para 10 bytes útiles: overhead de 48 B, $58 / 10 = 5{,}8$ veces el mensaje.

### 5.7 Traza del receptor

Estado inicial: $\mathit{SID} = \texttt{3a7f00c2}$, $\mathit{SEQ}_{\max} = 3$.

| # | Llega | ① SID | ② TAG | ③ SEQ | Veredicto | $\mathit{SEQ}_{\max}$ |
|---|---|---|---|---|---|---|
| 1 | SEQ 4, legítimo | ✓ | ✓ | $4 > 3$ ✓ | **ACEPTADO** | 4 |
| 2 | El mismo paquete otra vez | ✓ | ✓ | $4 > 4$ ✗ | **RECHAZO: replay** | 4 |
| 3 | SEQ 5 con un byte de $C$ cambiado | ✓ | ✗ | — | **RECHAZO: TAG** | 4 |
| 4 | SEQ 5, legítimo | ✓ | ✓ | $5 > 4$ ✓ | **ACEPTADO** | 5 |
| 5 | Paquete de la sesión anterior ($\mathit{SID} = \texttt{11223344}$) | ✗ | — | — | **RECHAZO: sesión** | 5 |

Fila 3: como el $\mathit{TAG}$ falló, $\mathit{SEQ}_{\max}$ **no** cambió, y por eso la fila 4 sí se acepta.

---

## 6. Ejercicios para resolver

> Resuélvelos en papel antes de abrir las soluciones.

**Ejercicio 1 · DH a mano.** $p = 23$, $g = 5$, $a = 4$, $b = 9$.
a) Calcula $Y_A$ y $Y_B$. b) Calcula $Z$ desde A y desde B, y comprueba que coinciden.

**Ejercicio 2 · MITM.** Con los mismos $a = 4$ y $b = 9$, el atacante usa $m = 2$.
a) ¿Cuánto vale $Y_M$? b) ¿Qué $Z$ calcula A? ¿Y B? ¿Qué $Z$ calcula M con cada uno?
c) Explica en una frase por qué en nuestro protocolo A detecta el ataque.

**Ejercicio 3 · $Y$ inválido.** Con $p = 23$, un dispositivo manda $Y = 22$. ¿Qué $Z$ se obtiene con $a = 4$? ¿Y con $a = 9$?

**Ejercicio 4 · CBC de juguete.** $K = 0011$, $\mathit{IV} = 1000$, $P_1 = 0101$, $P_2 = 0110$.
a) Calcula $C_1$ y $C_2$. b) Descifra y comprueba. c) Si el atacante cambia $C_1$ por $C_1 \oplus 0100$, ¿qué $P_2$ obtiene el receptor?

**Ejercicio 5 · Paquete y TAG.**
a) Mensaje `"Temperatura=23.5C"`: ¿cuánto mide $L$, cuánto padding se agrega (y con qué valor) y cuánto mide el paquete?
b) El atacante captura un paquete con $\mathit{SEQ} = 5$ y cambia el campo a $\mathit{SEQ} = 50$. ¿Qué paso del receptor lo detecta? ¿Qué pasaría si el $\mathit{TAG}$ solo cubriera $\mathit{IV} \Vert C$?

**Ejercicio 6 · Reflexión.** Supón que $\mathit{HMAC}_A$ y $\mathit{HMAC}_B$ **no** tuvieran las etiquetas $\texttt{"A"}$ y $\texttt{"B"}$. Describe cómo un atacante sin $\mathit{PSK}$ haría que B crea que A está autenticado. ¿Podría el atacante después leer o enviar mensajes? ¿Por qué?

**Ejercicio 7 · Traza.** $\mathit{SEQ}_{\max} = 7$. Llegan, en orden: SEQ 8 legítimo · SEQ 8 repetido · SEQ 6 viejo · SEQ 9 con $\mathit{TAG}$ alterado · SEQ 12 legítimo · SEQ 10 legítimo pero retrasado. Para cada uno: veredicto, motivo y $\mathit{SEQ}_{\max}$.

**Ejercicio 8 · "¿Y si no estuviera…?"** Para cada caso, di qué ataque funcionaría o qué se rompería:
a) No se borra $a$ después del handshake.
b) Se usa $K_{\text{enc}}$ también como clave del HMAC.
c) Se compara el $\mathit{TAG}$ con `==`.
d) El receptor descifra antes de verificar el $\mathit{TAG}$.
e) El $\mathit{IV}$ es siempre `00…00`.

---

<details>
<summary><b>Soluciones (no abrir antes de intentarlo)</b></summary>

**Ejercicio 1**

a) De la tabla del §5.1: $Y_A = 5^{4} \equiv \mathbf{4}$. Y $Y_B = 5^{9} = 5^{8} \cdot 5 \equiv 16 \cdot 5 = 80 = 3 \cdot 23 + 11 \equiv \mathbf{11} \pmod{23}$.

b) Desde A: $Z = 11^{4}$. Como $11^{2} = 121 \equiv 6$, queda $11^{4} \equiv 6^{2} = 36 \equiv \mathbf{13}$.
Desde B: $Z = 4^{9}$. Como $4^{2} = 16$, $4^{4} = 256 \equiv 3$ y $4^{8} \equiv 9$, queda $4^{9} = 4^{8} \cdot 4 \equiv 36 \equiv \mathbf{13}$ ✓.

**Ejercicio 2**

a) $Y_M = 5^{2} \equiv \mathbf{2}$.

b) A: $Y_M^{\,a} = 2^{4} = \mathbf{16}$. M con A: $Y_A^{\,m} = 4^{2} = \mathbf{16}$ ✓.
B: $Y_M^{\,b} = 2^{9} = 512 = 22 \cdot 23 + 6 \equiv \mathbf{6}$. M con B: $Y_B^{\,m} = 11^{2} = 121 \equiv \mathbf{6}$ ✓.

c) A y B ven $Y_A$ y $Y_B$ distintos, así que sus transcripts $\tau$ no coinciden y el $\mathit{HMAC}_B$ que llega no verifica. M no puede recalcularlo porque no tiene la $\mathit{PSK}$.

**Ejercicio 3**

$22 \equiv -1 \pmod{23}$. Con $a = 4$ (par): $Z = (-1)^{4} = \mathbf{1}$. Con $a = 9$ (impar): $Z = (-1)^{9} \equiv \mathbf{22}$. En ambos casos $Z$ es adivinable, y por eso se rechaza $Y = p - 1$.

**Ejercicio 4**

a) $P_1 \oplus \mathit{IV} = 1101 \rightarrow \oplus K = 1110 \rightarrow \mathrm{rotl}_1$: $\ C_1 = \mathbf{1101}$.
$P_2 \oplus C_1 = 1011 \rightarrow \oplus K = 1000 \rightarrow \mathrm{rotl}_1$: $\ C_2 = \mathbf{0001}$.

b) $\mathrm{rotr}_1(1101) = 1110 \rightarrow \oplus K = 1101 \rightarrow \oplus \mathit{IV} = 0101$ ✓.
$\mathrm{rotr}_1(0001) = 1000 \rightarrow \oplus K = 1011 \rightarrow \oplus C_1 = 0110$ ✓.

c) $C_1' = 1101 \oplus 0100 = 1001$, así que $P_2' = 1011 \oplus 1001 = \mathbf{0010}$. Comprobación: $P_2 \oplus \Delta = 0110 \oplus 0100 = 0010$ ✓. Cambió exactamente el bit $0100$.

**Ejercicio 5**

a) $L = 11 + 1 + 5 = \mathbf{17}$. Tamaño con padding: $16\left(\lfloor 17/16 \rfloor + 1\right) = 32$, así que $n = 32 - 17 = \mathbf{15}$ bytes con valor `0x0f`. Paquete $= 42 + 32 = \mathbf{74}$ B.

b) Lo detecta el **paso ②**: el $\mathit{SEQ}$ entra al HMAC, así que al cambiarlo el $\mathit{TAG}$ no coincide, y M no tiene $K_{\text{mac}}$ para recalcularlo. Si el $\mathit{TAG}$ solo cubriera $\mathit{IV} \Vert C$, **el replay funcionaría**: el $\mathit{TAG}$ seguiría siendo válido y $50 > \mathit{SEQ}_{\max}$.

**Ejercicio 6**

1. M manda a B un HELLO con $\mathit{ID}_A$ y valores elegidos por él: $N_A'$ y $Y_M$.
2. B responde con $\mathrm{HMAC}(\mathit{PSK},\ \mathit{ID}_A \Vert \mathit{ID}_B \Vert N_A' \Vert N_B \Vert Y_M \Vert Y_B)$.
3. M **copia ese mismo HMAC** en el CONFIRM. Sin etiquetas el cálculo es idéntico, así que B lo acepta.

Después de eso M **no puede** leer ni enviar mensajes. M conoce $Z$ (porque eligió $m$), pero las claves salen de $\mathrm{HKDF}(N_A \Vert N_B,\ Z \Vert \mathit{PSK})$ y le falta la $\mathit{PSK}$. Aun así, la **autenticación está rota** (B cree que habló con A), y por eso existen las etiquetas. Este caso muestra además por qué metemos la $\mathit{PSK}$ también en el HKDF: es una segunda barrera.

**Ejercicio 7**

| Llega | Veredicto | Motivo | $\mathit{SEQ}_{\max}$ |
|---|---|---|---|
| SEQ 8 | ACEPTADO | $8 > 7$ | 8 |
| SEQ 8 | RECHAZO | replay ($8 \le 8$) | 8 |
| SEQ 6 | RECHAZO | replay ($6 \le 8$) | 8 |
| SEQ 9 ($\mathit{TAG}$ alterado) | RECHAZO | $\mathit{TAG}$ inválido (no se llega a mirar el SEQ) | 8 |
| SEQ 12 | ACEPTADO | $12 > 8$ | 12 |
| SEQ 10 | RECHAZO | $10 \le 12$: legítimo pero tarde (limitación §8) | 12 |

**Ejercicio 8**

a) Quien robe la placa más tarde lee $a$ de la RAM o la flash, recalcula $Z = Y_B^{\,a} \bmod p$ con el $Y_B$ grabado y descifra la sesión. **Se pierde la forward secrecy.**
b) Se rompe la separación de claves: una misma clave usada en dos algoritmos distintos puede filtrar información de uno a otro. No hay un ataque directo conocido, pero ningún diseño estándar lo permite.
c) **Timing attack**: el rechazo tarda más cuantos más bytes iniciales acierta el atacante, así que puede adivinar el $\mathit{TAG}$ byte a byte.
d) **Padding oracle**: según si el padding salió válido o no, el receptor se comporta distinto, y con eso el atacante descifra mensajes sin la clave.
e) El mismo mensaje da siempre el mismo $C$: el atacante sabe cuándo se repite un mensaje y qué mensajes empiezan igual.

</details>

---

## 7. Defensa requisito por requisito

| # | Lo que pide el profe | Nuestra decisión | Justificación | Evidencia |
|---|---|---|---|---|
| 1 | ≥2 dispositivos IoT, canal no confiable (§1) | 2 ESP32 por Wi-Fi UDP. La seguridad no depende del Wi-Fi | Modelo Dolev–Yao | Demo ESP32 ↔ ESP32 con el atacante en medio |
| 2 | Clave de sesión con DH/ECDH/PSK (§2) | **DH ffdhe2048 efímero** + HKDF | 1ª opción del profe, grupo estándar RFC 7919, da forward secrecy | $\mathit{SID}$ distinto en cada sesión, tiempo del handshake medido |
| 3 | Explicar la autenticación de dispositivos (§2) | HMAC con la $\mathit{PSK}$ sobre todo el transcript $\tau$, con etiquetas A/B | DH solo es vulnerable a MITM. MicroPython no tiene firmas | Prueba con un nodo no autorizado |
| 4 | Cifrar todo; AEAD o **separados justificados** (§2) | AES-256-CBC + HMAC-SHA256, Encrypt-then-MAC, claves separadas | `cryptolib` no trae GCM. EtM está demostrado seguro (RFC 7366) | Sniffer: solo se ve ciphertext |
| 5 | Rechazar si se altera $C$, $\mathit{TAG}$, remitente o frescura (§2) | $\mathit{TAG}$ sobre $\mathit{TYPE} \Vert \mathit{ID}_S \Vert \mathit{SID} \Vert \mathit{SEQ} \Vert \mathit{IV} \Vert C$, verificado primero y en tiempo constante | Cualquier bit cambiado invalida el $\mathit{TAG}$ | tamper_c, tamper_tag |
| 6 | Detectar repetidos (§2) | $\mathit{SID}$ + $\mathit{SEQ}$ creciente | Sin relojes sincronizados no sirven los timestamps | replay |
| 7 | Sin cripto propia, librerías estándar (§2) | ESP32: `cryptolib`, `hashlib`, `hmac`, `urandom`, `pow`. PC: `cryptography`, `hmac`, `hashlib` | AES, SHA-256, HMAC, HKDF y DH son estándares | `import` del código |
| 8 | Formato documentado (§3) | El de referencia + $\mathit{TYPE}$. El $N$ es el $\mathit{IV}$ | $\mathit{TYPE}$ distingue handshake y datos | §4 de estos apuntes |
| 9 | 6 pruebas de seguridad (§4) | `attacker.py` (sniff, tamper_c, tamper_tag, replay, forge) + `node.py --id 0x99` + MITM | Una prueba por cada caso del enunciado | Demo + capturas |
| 10 | Métricas y overhead (§5) | `node.py --bench` + tiempo del handshake | La latencia es $\mathrm{RTT}/2$ | Tablas en el informe |
| 11 | Código, diagramas, formato, informe, reproducible (§6) | `docs/` + README | — | Entrega |
| 12 | Las 4 propiedades en **un** protocolo (§8) | Todo en `protocol.py` | — | Demo completa |

### Preguntas probables del profe

| Pregunta | Respuesta corta |
|---|---|
| ¿Por qué no AES-GCM? | `cryptolib` no lo trae y programarlo sería cripto propia. CBC + HMAC en EtM es la alternativa estándar, y el PDF la permite si se justifica |
| ¿Para qué la PSK si ya tienen DH? | DH sin autenticar sufre MITM (§5.2). MicroPython no tiene firmas, así que la $\mathit{PSK}$ autentica |
| ¿Qué pasa si se filtra la PSK? | Las sesiones **pasadas** siguen seguras gracias a DH efímero. Las **futuras** podrían sufrir MITM, así que hay que cambiar la $\mathit{PSK}$ |
| ¿Por qué ffdhe2048 y no un primo propio? | Inventar parámetros es cripto propia y es fácil equivocarse. RFC 7919 está auditado |
| ¿Por qué exponente de 256 bits y no 2048? | RFC 7919 pide al menos $2 \times 112$ bits. Además es 8 veces más rápido en la ESP32 |
| ¿Por qué truncar el TAG? | $2^{-128}$ de probabilidad de falsificarlo. NIST SP 800-107 lo permite |
| ¿Para qué el SID si las claves ya cambian por sesión? | Descarta rápido sin calcular el HMAC, deja claro el motivo del rechazo y es parte del formato de referencia |
| ¿Por qué el handshake tarda 2 s? | Son 2 exponenciaciones de 2048 bits en un CPU de 240 MHz. Es una sola vez por sesión; los mensajes siguen tardando milisegundos |

---

## 8. Limitaciones (lo que no protegemos, y lo decimos)

| Limitación | Por qué no la resolvemos |
|---|---|
| **DoS por HELLO**: cada HELLO le cuesta ~2 s a la ESP32 | Fuera del alcance del enunciado. Ninguna criptografía impide que el atacante sature la red |
| **Bloquear o descartar paquetes** | Igual que arriba: es un ataque de disponibilidad |
| **PSK guardada en la flash** | Con acceso físico se puede extraer. Haría falta hardware seguro (eFuse, secure boot) |
| **UDP desordenado** se descarta | Es el costo de la regla simple $\mathit{SEQ} > \mathit{SEQ}_{\max}$. El enunciado no exige tolerar desorden |
| **IDs en claro** | Se sabe *quién* habla, aunque no *qué* dice. El enunciado no pide anonimato |

---

## 9. Plan de trabajo

| Hito | Qué se construye | Fichas que usa |
|---|---|---|
| 0 ✅ | ESP32 verificada: AES-CBC, SHA-256, `urandom`, `hmac` y `pow` de 2048 bits (1075 ms) | — |
| 1 ✅ | `common/padding.py`, `aes_cbc.py`, `tag.py`, `hkdf.py`, `dh.py`: un archivo por pieza. Los mismos archivos corren en el PC y en la ESP32 | 3.4–3.11, 3.13, 3.15 |
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
| Tamaño del mensaje | `len(msg)` | $L$ |
| Tamaño del paquete | `len(paquete)` | $42 + 16\left(\lfloor L/16 \rfloor + 1\right)$ |
| Tiempo de cifrado (padding + AES + TAG) | `time.ticks_us()` en la ESP32 / `time.perf_counter()` en el PC | ms en la ESP32, µs en el PC |
| Tiempo de descifrado + verificación | Lo mismo | Similar |
| Latencia | $\mathrm{RTT}/2$ de un eco | ms |
| **Tiempo del handshake** | Desde HELLO hasta CONFIRM | ~2,2 s en la ESP32 |

Para cada métrica conviene repetir la medición unas $n = 100$ veces y reportar el promedio $\bar{x}$ y la desviación estándar $s$, con varios tamaños de mensaje (por ejemplo $L = 8, 32, 128, 512$ B):

$$
\bar{x} = \frac{1}{n} \sum_{i=1}^{n} x_i \qquad\qquad s = \sqrt{\frac{1}{n-1} \sum_{i=1}^{n} \left(x_i - \bar{x}\right)^2}
$$
