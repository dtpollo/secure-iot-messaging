# Apuntes de estudio: cómo funciona el protocolo

Notas personales para entender el algoritmo (sin entrar al código). Orden: problema → Diffie-Hellman → autenticación con PSK → handshake → claves → paquetes de datos → defensas → ejercicios.

---

## 1. El problema

Alice y Bob se mandan mensajes por Wi-Fi. Cualquiera en la red puede **leer** los paquetes (sniff), **modificarlos** (tamper), **reenviarlos** (replay), **inventarlos** (forge) o **colarse** como un dispositivo falso.

| Propiedad | Qué significa | Contra qué defiende | Mecanismo |
|---|---|---|---|
| Confidencialidad | nadie más entiende el mensaje | sniff | AES-256-CBC |
| Integridad | si cambian un bit, se nota | tamper_c, tamper_tag | TAG = HMAC-SHA256 |
| Autenticidad | solo Alice y Bob pueden crear paquetes válidos | forge, MITM, intruso | PSK + `K_mac` |
| Anti-replay | un paquete viejo no sirve | replay | SEQ y SID |

Para cifrar y autenticar hacen falta **claves**. El problema de fondo: **¿cómo se ponen de acuerdo en una clave si todo lo que se dicen lo puede leer cualquiera?** Eso lo resuelve Diffie-Hellman.

---

## 2. Diffie-Hellman (DH)

### Analogía de la pintura

1. Alice y Bob acuerdan en público un color base: **amarillo**.
2. Cada uno elige un color **secreto**: Alice, rojo; Bob, azul.
3. Cada uno mezcla su secreto con el amarillo y manda el resultado en público: Alice manda `amarillo+rojo`, Bob manda `amarillo+azul`.
4. Cada uno agrega **su propio secreto** a lo que recibió: Alice obtiene `amarillo+azul+rojo`, Bob obtiene `amarillo+rojo+azul`.
5. Los dos llegan al **mismo color final**.

El espía vio el amarillo y las dos mezclas, pero separar una mezcla para sacar el secreto es prácticamente imposible. No puede obtener el color final.

### Definición formal

- Se acuerda un número primo grande `p` y un generador `g` (públicos).
- Alice elige un secreto `a` y calcula `YA = g^a mod p`. Lo manda.
- Bob elige un secreto `b` y calcula `YB = g^b mod p`. Lo manda.
- Alice calcula `Z = YB^a mod p`. Bob calcula `Z = YA^b mod p`.
- Los dos obtienen `Z = g^(ab) mod p`.

Calcular `YA` a partir de `a` es fácil. Sacar `a` a partir de `YA` es el **problema del logaritmo discreto**, que es difícil con números grandes.

### En nuestro proyecto

| Elemento | Valor |
|---|---|
| Grupo | ffdhe2048 (RFC 7919): `p` de 2048 bits, `g = 2` |
| Secreto `a` o `b` | 256 bits (32 B), aleatorio en cada sesión |
| `YA`, `YB`, `Z` | 256 B cada uno |
| Validación | `1 < Y < p-1`, para rechazar valores trucados |
| Después de usarlos | se borran `a`, `b` y `Z` (DH **efímero**) |

**Efímero** quiere decir que las claves de una sesión no se pueden recuperar después, ni aunque se filtre el PSK. Eso se llama *forward secrecy*.

---

## 3. Por qué el DH solo no basta (MITM) y qué agrega el PSK

El DH da un secreto compartido, pero **no dice con quién lo compartes**. Con un atacante en medio:

```
Alice --YA-->  Atacante --Y1--> Bob
Alice <--Y2--  Atacante <--YB-- Bob
```

Alice termina con una clave compartida con el atacante, y Bob con otra. El atacante lee todo y reenvía, y nadie lo nota.

### La solución: PSK (Pre-Shared Key)

Alice y Bob tienen una **clave de 32 bytes grabada de antemano** (el PSK). Nunca viaja por la red. Se usa para firmar con HMAC todo lo que cada uno vio en el handshake. Si el atacante cambió algo, las firmas no cuadran.

Por eso el protocolo se llama **DHE-PSK**: DH efímero para tener claves nuevas cada sesión, y PSK para saber con quién se habla.

---

## 4. El handshake: tres mensajes

Se hace una vez al arrancar. Alice es la iniciadora y Bob espera.

```
Alice                                   Bob
  | -- HELLO:    IDA, NA, YA --------->  |
  | <-- RESPONSE: IDB, NB, YB, HMAC_B --- |
  | -- CONFIRM:  IDA, HMAC_A ---------->  |
  |        (los dos tienen K_enc, K_mac, SID)
```

### 4.1 Los campos

| Campo | Tamaño | Qué es |
|---|---|---|
| `0x01`, `0x02`, `0x03` | 1 B | Tipo de mensaje (HELLO, RESPONSE, CONFIRM) |
| `IDA`, `IDB` | 1 B | Identificador del dispositivo (Alice = 0x01, Bob = 0x02) |
| `NA`, `NB` | 16 B | **Nonce**: número aleatorio nuevo en cada sesión |
| `YA`, `YB` | 256 B | Valor público del DH |
| `HMAC_B`, `HMAC_A` | 32 B | Firma con el PSK sobre la transcripción |

### 4.2 Tamaños de cada paquete

| Paquete | Estructura | Tamaño |
|---|---|---|
| HELLO | `0x01 ‖ IDA ‖ NA ‖ YA` = 1+1+16+256 | **274 B** |
| RESPONSE | `0x02 ‖ IDB ‖ NB ‖ YB ‖ HMAC_B` = 1+1+16+256+32 | **306 B** |
| CONFIRM | `0x03 ‖ IDA ‖ HMAC_A` = 1+1+32 | **34 B** |

Total: 614 B, una sola vez por sesión.

### 4.3 La transcripción τ

`τ = IDA ‖ IDB ‖ NA ‖ NB ‖ YA ‖ YB`

Es el **resumen de todo lo que cada uno vio** en el handshake. Las dos firmas son:

- `HMAC_B = HMAC(PSK, "B" ‖ τ)` (lo manda Bob en el RESPONSE)
- `HMAC_A = HMAC(PSK, "A" ‖ τ)` (lo manda Alice en el CONFIRM)

La letra `"A"` o `"B"` evita que alguien **refleje** (devuelva) una firma como si fuera la otra.

### 4.4 Paso a paso

1. **Alice → HELLO.** Genera `NA` y `a`, calcula `YA`, y manda `IDA, NA, YA`.
2. **Bob recibe el HELLO.**
   - Si `IDA` no está en su lista de PSKs, **rechaza** (dispositivo no autorizado).
   - Genera `NB` y `b`, calcula `YB` y el secreto `Z`.
   - Construye `τ` con lo que recibió, y firma `HMAC_B`.
   - Manda `RESPONSE`.
3. **Alice recibe el RESPONSE.**
   - Construye **su** `τ` con lo que ella mandó y lo que recibió.
   - Recalcula `HMAC_B` y lo compara con el recibido. Si no coincide, **`Rejected: handshake`**.
   - Si coincide, calcula `Z`, deriva las claves, y manda `CONFIRM` con `HMAC_A`.
4. **Bob recibe el CONFIRM.** Compara `HMAC_A` con el que él calculó. Si coincide, ambos están autenticados y Bob entrega la sesión.

### 4.5 Qué pasó en el MITM de la prueba 6

El atacante cambió `YA` por el suyo en el HELLO:
- **Bob** construyó su `τ` con el `YA` **falso**, y firmó `HMAC_B` sobre eso.
- **Alice** construyó su `τ` con el `YA` **original**, el que ella mandó.
- Los dos `τ` son distintos, así que el `HMAC_B` de Bob no coincide con el que Alice calcula → **`Rejected: handshake`**.
- El atacante no puede corregir `HMAC_B`, porque necesitaría el **PSK**. Lo que tenía Alice y el atacante no es el PSK.

---

## 5. De dónde salen las claves (HKDF)

Con `Z` y el PSK, los dos derivan **tres valores** con HKDF:

```
salt = NA ‖ NB
ikm  = Z ‖ PSK
K_enc = HKDF(salt, ikm, "enc")   (32 B)  cifra con AES
K_mac = HKDF(salt, ikm, "mac")   (32 B)  calcula el TAG
SID   = HKDF(salt, ikm, "sid")   ( 4 B)  identifica la sesión
```

- **Por qué dos claves separadas:** no se usa la misma clave para dos cosas (cifrar y autenticar).
- **Por qué `NA` y `NB`:** son nuevos cada sesión, así que aunque `Z` se repitiera, las claves serían distintas.
- **Por qué `SID`:** un paquete de una sesión vieja no sirve en la nueva.

---

## 6. Los paquetes de datos

Una vez hecha la sesión, cada mensaje se manda así:

```
TYPE | IDS | SID | SEQ | IV | C | TAG
 1 B   1 B   4 B   4 B  16 B  n×16  16 B
```

| Campo | Qué es | Para qué sirve |
|---|---|---|
| `TYPE` | `0x10` | Dice que es un paquete de datos |
| `IDS` | ID del emisor | Dice quién lo manda |
| `SID` | 4 B de la sesión | Descarta paquetes de otra sesión rápido |
| `SEQ` | contador, desde 1 | Detecta replay |
| `IV` | 16 B aleatorios | Hace que el mismo mensaje cifrado salga distinto cada vez |
| `C` | mensaje cifrado | El contenido, ilegible |
| `TAG` | 16 B | Firma que protege todo lo anterior |

**Tamaño del paquete:** `42 + 16·(⌊L/16⌋ + 1)` bytes, con `L` = largo del mensaje. Ejemplo: `Hello Bob` (9 B) → 58 B.

### 6.1 Cifrado: AES-256-CBC y padding

- **AES** cifra bloques de 16 B. El mensaje se rellena (**padding PKCS7**) hasta ser múltiplo de 16: se agregan `n` bytes de valor `n` (siempre de 1 a 16, incluso si ya era múltiplo).
- **CBC** encadena los bloques: cada bloque se mezcla (XOR) con el cifrado del anterior. El primero usa el `IV`. Así, bloques de texto iguales cifran distinto.

### 6.2 El TAG

`TAG = primeros 16 B de HMAC-SHA256(K_mac, TYPE ‖ IDS ‖ SID ‖ SEQ ‖ IV ‖ C)`

Cubre **todo** menos el propio TAG. Esto se llama **Encrypt-then-MAC**: primero se cifra y luego se firma lo cifrado.

### 6.3 Qué hace el receptor, en orden

1. **Formato:** largo mínimo y múltiplo de 16 → si no, `format`.
2. **SID e IDS:** ¿son de mi sesión y de mi par? → si no, `session/ID`. (Descarte rápido, sin calcular el HMAC.)
3. **TAG:** recalcular y comparar en tiempo constante → si no, `TAG`.
4. **SEQ:** debe ser **mayor** que el último aceptado → si no, `replay`.
5. **Descifrar** y quitar el padding.

**Por qué ese orden:** el TAG va antes de descifrar para no procesar nada que no esté autenticado (evita el padding oracle). El SEQ va después del TAG porque solo se puede confiar en él cuando ya está autenticado.

---

## 7. Las defensas, ataque por ataque

| Ataque | Qué hace el atacante | Qué lo detiene | Mensaje |
|---|---|---|---|
| sniff | lee el tráfico | AES: `C` es ilegible | no se rechaza nada |
| tamper_c | cambia un bit de `C` | el TAG ya no coincide | `Rejected: TAG` |
| tamper_tag | cambia un bit del TAG | el TAG ya no coincide | `Rejected: TAG` |
| replay | reenvía un paquete válido | `SEQ` no es mayor que el último | `Rejected: replay` |
| forge | inventa `IV`, `C`, `TAG` | no tiene `K_mac` | `Rejected: TAG` |
| mitm | cambia `YA` en el HELLO | los `τ` no coinciden y no tiene el PSK | `Rejected: handshake` |
| intruso (ID) | se presenta con un ID desconocido | el ID no está en la lista de PSKs | `Rejected: handshake` |
| intruso (PSK falsa) | usa otro PSK | no puede firmar `HMAC_A` bien | `Rejected: handshake` |

**Dos ideas clave:**
- El TAG prueba que el paquete es **auténtico**, no que es **nuevo**. Por eso hace falta SEQ.
- El atacante no puede subir `SEQ` porque está dentro del HMAC. Si lo toca, falla el TAG.

---

## 8. Ejercicios a mano

### Ejercicio 1. DH con números chicos

Usa `p = 23` y `g = 5`. Alice elige `a = 6` y Bob elige `b = 15`.

1. Calcula `YA = 5^6 mod 23`.
2. Calcula `YB = 5^15 mod 23`.
3. Calcula `Z` como lo haría Alice: `YB^6 mod 23`.
4. Calcula `Z` como lo haría Bob: `YA^15 mod 23`.
5. ¿Qué valores vio el espía? ¿Cuáles nunca vio?

Pista: ve reduciendo módulo 23 en cada paso. Por ejemplo, `5^2 = 25 = 2 (mod 23)`.

### Ejercicio 2. Tamaño de paquetes

Calcula el tamaño del paquete de datos para estos mensajes (fórmula `42 + 16·(⌊L/16⌋ + 1)`):

| Mensaje | L |
|---|---|
| `Hi` | 2 |
| `Hello Bob` | 9 |
| 15 bytes | 15 |
| 16 bytes | 16 |
| 33 bytes | 33 |

Y responde: ¿cuántos bytes de padding se agregan en `Hello Bob`?

### Ejercicio 3. Decisión del receptor

Bob está en la sesión con `SID = bee1d104` y el último `SEQ` que aceptó es **5**. Para cada paquete di si lo acepta o con qué razón lo rechaza (todos vienen de Alice).

| # | SID | SEQ | TAG | Resultado |
|---|---|---|---|---|
| a | `bee1d104` | 6 | válido | ? |
| b | `bee1d104` | 5 | válido | ? |
| c | `bee1d104` | 7 | inválido | ? |
| d | `5f92b010` | 6 | válido (de la sesión anterior) | ? |
| e | `bee1d104` | 3 | inválido | ? |

Pista: sigue el orden SID → TAG → SEQ de la sección 6.3.

### Ejercicio 4. Qué ve el espía

Para un paquete de datos, marca qué puede **leer en claro** un espía:

`TYPE`, `IDS`, `SID`, `SEQ`, `IV`, `C`, `TAG`, el texto del mensaje, `K_mac`.

### Ejercicio 5. Explícalo con tus palabras

En 3 líneas: ¿por qué falla el MITM aunque el atacante cambie `YA` y reenvíe todo lo demás?

---

## 9. Respuestas

<details>
<summary>Ver respuestas</summary>

**Ejercicio 1**
1. `YA = 5^6 mod 23 = 8` (porque `5^2=2`, `5^4=4`, `5^6=8`).
2. `YB = 5^15 mod 23 = 19`.
3. `Z = 19^6 mod 23 = 2` (como `19 = -4`, `(-4)^6 = 4096`, y `4096 mod 23 = 2`).
4. `Z = 8^15 mod 23 = 2` (como `8 = 2^3`, es `2^45`, y `2^11 = 1 mod 23`, así que `2^45 = 2^1 = 2`).
5. El espía vio `p = 23`, `g = 5`, `YA = 8` y `YB = 19`. Nunca vio `a = 6`, `b = 15` ni `Z = 2`.

**Ejercicio 2**
- `Hi` (2): 42 + 16·1 = **58 B**
- `Hello Bob` (9): 42 + 16·1 = **58 B**
- 15 bytes: 42 + 16·1 = **58 B**
- 16 bytes: 42 + 16·2 = **74 B** (el padding agrega un bloque entero de 16 B)
- 33 bytes: 42 + 16·3 = **90 B**

En `Hello Bob` se agregan 16 − 9 = **7 bytes** de padding, todos con valor `0x07`.

**Ejercicio 3**
- a) **Acepta.** SID bien, TAG válido, `6 > 5`.
- b) **`Rejected: replay`.** SID y TAG bien, pero `5` no es mayor que `5`.
- c) **`Rejected: TAG`.** El TAG inválido falla antes de mirar el SEQ.
- d) **`Rejected: session/ID`.** El SID no es el de esta sesión (el descarte rápido).
- e) **`Rejected: TAG`.** El TAG inválido falla antes de mirar el SEQ. (No llega a decir replay.)

**Ejercicio 4**
Ve en claro: `TYPE`, `IDS`, `SID`, `SEQ`, `IV`. Ve bytes **ilegibles**: `C`, `TAG`. **No ve**: el texto del mensaje ni `K_mac`.

**Ejercicio 5**
Respuesta modelo: Bob firma `HMAC_B` sobre una transcripción que contiene el `YA` falso, y Alice calcula la suya con el `YA` original, así que no coinciden. El atacante no puede arreglar `HMAC_B` porque necesitaría el PSK, que nunca viaja por la red. Por eso Alice rechaza el handshake.

</details>
