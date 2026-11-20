# Entrega 2 — Especificación, implementación y resultados

**Proyecto 1: Votación electrónica binaria con ElGamal y pruebas de conocimiento cero no interactivas (NIZK)**
Criptografía Aplicada · Álvaro Jiménez Doria · Samuel Ricardo Arrieta

Este documento contiene el material para el informe de la Entrega 2. Responde a las tres correcciones de la
evaluación de la Entrega 1 y a lo pedido para esta entrega:

| Observación de la evaluación | Dónde se responde |
|---|---|
| 1. Faltan compromisos, retos, respuestas, ecuaciones del verificador y bytes del transcript (§4.3) | [§1](#1-prueba-or-no-interactiva-reemplaza-43) |
| 2. El verificador no puede comprobar el descifrado; limitar la garantía (§4.7) | [§2](#2-qué-garantiza-el-verificador-independiente-reemplaza-47) |
| 3. Elegir una sola combinación de grupo, biblioteca y serialización y definir el rechazo de elementos inválidos (§7) | [§3](#3-suite-criptográfica-fija-y-reglas-de-rechazo-reemplaza-7) |
| Probar voto 2, compromiso modificado, reto alterado y token repetido, indicando el paso de rechazo | [§4](#4-casos-negativos-y-paso-de-rechazo) |
| Expediente autocontenido; informar por separado el agregado recalculado y el resultado anunciado | [§5](#5-expediente-agregado-recalculado-y-resultado-anunciado) |
| Métricas para 1, 5, 10 y 20 votos (§8.3 del Entregable 1) | [§6](#6-métricas-experimentales) |

**Notación.** Se mantiene la notación multiplicativa del Entregable 1. El código usa Ristretto255, que es un grupo
aditivo; la correspondencia es directa: `g^r` ↔ `r·G`, `g^v·h^r` ↔ `v·G + r·H`, `α^{-c}` ↔ `−c·α`, y el producto de
ciphertexts ↔ la suma de puntos.

---

## 1. Prueba OR no interactiva (reemplaza §4.3)

### 1.1 Enunciado

Sean `g` el generador de un grupo de orden primo `q`, `h = g^x` la clave pública de la autoridad y
`(α, β) = (g^r, g^v·h^r)` el cifrado ElGamal exponencial del voto `v`. Para cada rama `j ∈ {0, 1}` se define

```
β_j = β · g^{-j}
```

El ciphertext cifra `j` si y solo si `log_g(α) = log_h(β_j)`, es decir, si `(g, h, α, β_j)` es una tupla
Diffie–Hellman (relación de Chaum–Pedersen). La prueba demuestra la disyunción *"cifra 0 **o** cifra 1"* sin revelar
cuál de las dos ramas es la verdadera (Cramer–Damgård–Schoenmakers).

### 1.2 Probador

El votante conoce `v ∈ {0, 1}` y `r`. Sea `f = 1 − v` la rama falsa.

| Paso | Rama falsa `f` (se simula) | Rama verdadera `v` (se prueba) |
|---|---|---|
| 1. Elección | `c_f, s_f ← Z_q` al azar | `w ← Z_q*` al azar |
| 2. Compromisos | `a_f = g^{s_f} · α^{-c_f}` y `b_f = h^{s_f} · β_f^{-c_f}` | `a_v = g^w` y `b_v = h^w` |
| 3. Reto global | `c = H(T) mod q`, con `T` el transcript de §1.4 | (el mismo) |
| 4. Reto de la rama | `c_f` (ya elegido) | `c_v = c − c_f mod q` |
| 5. Respuesta | `s_f` (ya elegida) | `s_v = w + c_v · r mod q` |

**Prueba publicada:** `π = (a_0, b_0, a_1, b_1, c_0, c_1, s_0, s_1)`, es decir, 4 elementos del grupo y 4 escalares
(256 bytes). Junto con `(α, β)`, el ballot criptográfico ocupa **320 bytes**.

### 1.3 Verificador

La urna y el verificador independiente ejecutan exactamente la misma función:
`verifyVoteProofHex` en `src/crypto/orProof.ts`. Cada paso tiene un código de rechazo propio:

| Paso | Comprobación | Código si falla |
|---|---|---|
| V1 | `α, β, a_0, b_0, a_1, b_1` son codificaciones canónicas de elementos del grupo y `α ≠ 1` | `E_POINT_ENCODING` / `E_IDENTITY` |
| V2 | `c_0, c_1, s_0, s_1` son escalares canónicos `< q` | `E_SCALAR_RANGE` |
| V3 | `c_0 + c_1 ≡ H(T) (mod q)` | `E_PROOF_CHALLENGE` |
| V4 | `g^{s_0} = a_0 · α^{c_0}` **y** `h^{s_0} = b_0 · β_0^{c_0}` | `E_PROOF_EQ_0` |
| V5 | `g^{s_1} = a_1 · α^{c_1}` **y** `h^{s_1} = b_1 · β_1^{c_1}` | `E_PROOF_EQ_1` |

**Completitud.** En la rama verdadera, `g^{s_v} = g^{w + c_v r} = a_v · (g^r)^{c_v} = a_v · α^{c_v}` y
`h^{s_v} = h^w · (h^r)^{c_v} = b_v · β_v^{c_v}`, porque `β_v = h^r`. En la rama falsa las dos ecuaciones se cumplen por
construcción (`a_f` y `b_f` se despejaron de ellas). Además, `c_0 + c_1 = c_f + (c − c_f) = c`.

**Solidez (por qué un 2 no pasa).** Si `(α, β)` cifra `m ∉ {0, 1}`, ninguna rama es una tupla Diffie–Hellman. En una
rama falsa, para unos compromisos `(a_j, b_j)` dados existe a lo sumo un reto `c_j` que satisface ambas ecuaciones: si
hubiera dos, de las respuestas se podría extraer un `r` con `log_g α = log_h β_j`, lo cual contradice que la rama sea
falsa. Por tanto, el probador tramposo queda obligado a fijar `c_0` y `c_1` antes de conocer `c = H(T)`, y solo acierta
`c_0 + c_1 = H(T)` con probabilidad despreciable (~1/q por consulta al hash, en el modelo de oráculo aleatorio). Las
pruebas muestran las dos formas en que falla: si simula ambas ramas, falla en **V3**; si fuerza `c_j = c − c_f`, falla
la ecuación de la rama forzada (**V4** o **V5**).

**Conocimiento cero (HVZK).** Una rama simulada `(a_f, b_f, c_f, s_f)` tiene exactamente la misma distribución que una
real: `c_f` y `s_f` son uniformes y los compromisos quedan determinados por las ecuaciones. Por eso el verificador no
distingue qué rama es la verdadera.

### 1.4 Transcript de Fiat–Shamir: bytes exactos

```
T = DST ‖ LP(version) ‖ LP(suite_id) ‖ LP(election_id) ‖ LP(token_id)
      ‖ g ‖ h ‖ α ‖ β ‖ a_0 ‖ b_0 ‖ a_1 ‖ b_1

c = SHA-512(T) interpretado como entero little-endian, mod q
```

| Componente | Bytes | Contenido |
|---|---|---|
| `DST` | 24 | ASCII `VOTE-BIN-v1/cds-or-proof`, sin prefijo de longitud |
| `LP(version)` | 4 + 2 | `uint32` big-endian con la longitud, seguido de `"v1"` en UTF-8 |
| `LP(suite_id)` | 4 + 51 | `VOTE-BIN-v1:ristretto255:sha512:hmac-sha256:ed25519` |
| `LP(election_id)` | 4 + 32 | identificador de la elección (32 caracteres hex) |
| `LP(token_id)` | 4 + 32 | identificador del token (32 caracteres hex) |
| 8 elementos del grupo | 8 × 32 | codificación canónica Ristretto255 de `g, h, α, β, a_0, b_0, a_1, b_1`, en ese orden |
| **Total** | **413** | |

Decisiones y su justificación:

- **Prefijos de longitud en lugar de JSON.** La codificación es inyectiva: `("ab","c")` y `("a","bc")` producen
  transcripts distintos. No hay ambigüedad de serialización entre cliente, urna y verificador.
- **`token_id` dentro de `T`.** Ata la prueba a un token. Copiar el `(α, β, π)` de otro votante y enviarlo con un token
  propio falla en V3.
- **`election_id` y `h` dentro de `T`.** Impiden reutilizar una prueba en otra elección o bajo otra clave.
- **SHA-512 reducido mod q.** Con 512 bits el sesgo de la reducción es < 2^-259. Con SHA-256 no sería despreciable,
  porque `2^256 ≈ 16·q`.
- **Vectores de prueba.** `test/vectors/or-proof.json` contiene, para un voto 0 y un voto 1, la clave, `r`, el
  ciphertext, el transcript completo en hex, el reto y la prueba. Una prueba automática regenera los vectores y exige
  que coincidan byte a byte con los guardados.

---

## 2. Qué garantiza el verificador independiente (reemplaza §4.7)

La afirmación del Entregable 1 —que el verificador comprueba la corrección del resultado anunciado sin la clave
privada— **se retira**. Con el expediente publicado, el verificador puede revalidar los ballots y recomponer el
agregado, pero **no** puede comprobar el descifrado, porque no hay prueba de descifrado (que está fuera de alcance). El
reporte del verificador (`npm run verify`) separa explícitamente dos secciones:

**A. Verificado criptográficamente** (solo con el expediente, sin clave privada, red ni base de datos):

| Comprobación | Qué verifica |
|---|---|
| A1 | El expediente cumple el esquema v1 estricto |
| A2 | Versión y suite criptográfica esperadas |
| A3 | Generador estándar y clave pública válida (no identidad) |
| A4 | Firma Ed25519 de la autoridad sobre `"VOTE-BIN-v1/election-record" ‖ SHA-256(JCS(expediente sin firma))`, con la clave publicada antes de abrir |
| A5 | Tokens sin repetidos, consumidos ⊆ emitidos, emitidos ≤ `n_max_voters` |
| A6 | Cada ballot: `ballot_hash` correcto, elección correcta, token emitido y usado una sola vez, sin ciphertexts repetidos; consumidos = tokens de los ballots |
| A7 | La prueba OR de cada ballot es válida (cada voto publicado cifra 0 o 1) |
| A8 | **Agregado recalculado** a partir de los ballots publicados = agregado publicado |
| A9 | `n_ballots` declarado = ballots publicados ≤ `n_max_voters` |

**B. Declarado por la autoridad (NO verificado criptográficamente):**

- **El resultado sí/no.** Solo se comprueba su consistencia trivial: `0 ≤ sí ≤ total` y `sí + no = total`. Sin una
  prueba de descifrado (Chaum–Pedersen sobre `(g, h, A, B·g^{-k})`), el verificador no puede confirmar que el resultado
  anunciado corresponde al agregado.
- **La elegibilidad.** La autoridad emite los tokens y conoce la clave HMAC. Si emite 20 tokens y solo 15 votantes
  reales los reciben, puede votar con los 5 restantes: esos ballots tienen tokens válidos y pruebas OR válidas, y ni la
  urna ni el verificador pueden distinguirlos de votos legítimos. **La elegibilidad no es verificable públicamente.**

Lo que sí puede hacer cada votante es comprobar que **su** ballot está en el expediente:
`npm run verify -- expediente.json --ballot-hash <recibo>`.

Estas dos limitaciones no están solo declaradas: hay pruebas automáticas que las **demuestran**. En
`test/verifier/verifyRecord.test.ts`, un resultado anunciado falso pero consistente (7/13 en lugar de 13/7, re-firmado)
y una elección con votos de relleno pasan ambos la verificación.

---

## 3. Suite criptográfica fija y reglas de rechazo (reemplaza §7)

Se eligió una sola combinación, identificada en el código y en todos los mensajes como
`suite_id = VOTE-BIN-v1:ristretto255:sha512:hmac-sha256:ed25519`:

| Necesidad | Elección | Biblioteca (versión exacta) |
|---|---|---|
| Lenguaje y entorno | TypeScript sobre Node.js 24 | `typescript 5.9.3` |
| Grupo de orden primo | Ristretto255 (RFC 9496), `q = 2^252 + 27742317777372353535851937790883648493` | `@noble/curves 2.4.0` |
| Reto Fiat–Shamir | SHA-512 reducido mod q | `@noble/hashes 2.4.0` |
| Hash de ballots y expediente | SHA-256 sobre JSON canónico | `@noble/hashes 2.4.0` |
| Serialización canónica | JSON Canonicalization Scheme (RFC 8785) para lo que se hashea o firma; transcript binario (§1.4) | `canonicalize 5.1.0` |
| Autenticación de tokens | HMAC-SHA256 con clave de la autoridad | `@noble/hashes 2.4.0` |
| Firma del expediente | Ed25519 (RFC 8032), verificación estricta | `@noble/curves 2.4.0` |
| Servicio HTTP y validación | Express 5 + esquemas `zod` estrictos | `express 5.3.0`, `zod 4.6.7` |
| Persistencia | SQLite | `better-sqlite3 13.2.0` |
| Pruebas | Jest + ts-jest + supertest | `jest 30.5.2` |

**Por qué no PyNaCl.** El Entregable 1 proponía Ristretto255 vía PyNaCl, pero PyNaCl 1.6.2 no expone las operaciones
de Ristretto255 (solo `crypto_core_ed25519_*`). `@noble/curves` sí las ofrece, con la decodificación canónica de
RFC 9496, y está auditada.

### 3.1 Rechazo de elementos inválidos

Todo dato externo pasa por `src/crypto/encoding.ts` y `src/crypto/group.ts` **antes** de cualquier operación. No hay
otra vía para convertir bytes en puntos o escalares.

| Elemento | Formato aceptado | Se rechaza si… | Código |
|---|---|---|---|
| Elemento del grupo | 64 caracteres hex en minúsculas (32 bytes) | longitud distinta, mayúsculas, prefijo `0x`, caracteres no hex, o decodificación Ristretto255 no canónica | `E_POINT_ENCODING` |
| `α` del ciphertext, clave pública | ídem | además, es la identidad (`r = 0` dejaría el voto en claro) | `E_IDENTITY` |
| Escalar | 64 caracteres hex en minúsculas, little-endian | formato inválido o valor `≥ q` (no canónico) | `E_SCALAR_RANGE` |
| Mensaje JSON | esquema `zod` estricto | campo faltante, campo extra, tipo incorrecto, cadena demasiado larga | `E_FORMAT` |
| Versión / elección | `version = "v1"`, `election_id` de la ruta | otro valor | `E_VERSION` / `E_ELECTION` |
| Credencial | `<token_id 32 hex>.<mac 64 hex>` | otro formato | `E_TOKEN_FORMAT` |

Las pruebas usan los vectores oficiales de RFC 9496 (codificaciones de `0·G` a `3·G` y codificaciones inválidas).

---

## 4. Casos negativos y paso de rechazo

La urna valida cada ballot en seis pasos (`src/protocol/ballotBox.ts`) y reporta `{step, code}`:

| Paso | Qué valida |
|---|---|
| U0 | Esquema del mensaje, versión, elección existente y abierta |
| U1 | Decodificación estricta (V1–V2) |
| U2 | Token: formato → MAC → emitido → no consumido |
| U3 | Prueba OR atada a (elección, token, clave pública) (V3–V5) |
| U4 | Duplicados: `ballot_hash` y `(α, β)` no aceptados antes |
| U5 | Transacción: consumir el token y guardar el ballot, todo o nada |

Un ballot rechazado en U0–U4 **no consume** el token; si en U5 falla la inserción, el consumo se deshace.

### 4.1 Casos pedidos por la evaluación

| Caso | Cómo se construye | Paso de la urna | Paso de la prueba | Código |
|---|---|---|---|---|
| **Voto de valor 2**, simulando ambas ramas | `(g^r, g^2·h^r)` con las dos ramas simuladas | U3 | V3 | `E_PROOF_CHALLENGE` |
| **Voto de valor 2**, forzando la rama 0 | simula la rama 1 y responde la rama 0 con `s = w + c_0·r` | U3 | V4 | `E_PROOF_EQ_0` |
| **Voto de valor 2**, forzando la rama 1 | simula la rama 0 y fuerza la rama 1 | U3 | V5 | `E_PROOF_EQ_1` |
| **Compromiso modificado** | `a_0`, `b_0`, `a_1` o `b_1` reemplazado por otro elemento válido | U3 | V3 | `E_PROOF_CHALLENGE` |
| Compromiso con un bit volteado | bit 0 del primer byte de `a_0` (codificación "negativa") | U1 | V1 | `E_POINT_ENCODING` |
| **Reto alterado** | `c_0 + 1` | U3 | V3 | `E_PROOF_CHALLENGE` |
| Reto alterado conservando la suma | `c_0 + 1`, `c_1 − 1` | U3 | V4 | `E_PROOF_EQ_0` |
| Retos intercambiados | `c_0 ↔ c_1` | U3 | V4 | `E_PROOF_EQ_0` |
| Reto no canónico | `c_0 ≥ q` | U1 | V2 | `E_SCALAR_RANGE` |
| **Token repetido** | el mismo votante vota dos veces | U2 | — | `E_TOKEN_USED` |

Con valores −1, 3 y 20 se obtienen los mismos tres resultados que con el valor 2. Como control, el mismo probador
"forzado" usado con `m = 0` produce una prueba válida; esto demuestra que el rechazo se debe al valor y no a un error
del probador malicioso.

### 4.2 Otros casos cubiertos

| Caso | Paso | Código |
|---|---|---|
| Cuerpo no JSON, campo extra o faltante | U0 | `E_FORMAT` |
| Versión desconocida | U0 | `E_VERSION` |
| `election_id` distinto o elección inexistente | U0 | `E_ELECTION` |
| Elección cerrada | U0 (o U5 si se cierra durante el envío) | `E_CLOSED` |
| `α` = identidad | U1 | `E_IDENTITY` |
| `β` fuera del grupo | U1 | `E_POINT_ENCODING` |
| Credencial mal formada | U2 | `E_TOKEN_FORMAT` |
| MAC alterado, credencial de otra elección o inventada sin la clave | U2 | `E_TOKEN_MAC` |
| MAC válido pero token nunca emitido | U2 | `E_TOKEN_UNKNOWN` |
| Reenvío exacto de un ballot aceptado (replay) | U2 | `E_TOKEN_USED` |
| Dos solicitudes con el mismo token en carrera | U5 | `E_TOKEN_USED` |
| `(α, β, π)` de otro votante enviados con un token propio | U3 / V3 | `E_PROOF_CHALLENGE` |
| Respuesta alterada (`s_0 + 1` o `s_1 + 1`) | U3 / V4 o V5 | `E_PROOF_EQ_0` / `E_PROOF_EQ_1` |
| Mismo `(α, β)` re-probado con otro token (quien conoce `r`) | U4 | `E_DUP_CIPHERTEXT` |

`E_REPLAY` queda como restricción `UNIQUE` de la base de datos: el `ballot_hash` incluye el `token_id`, así que un
reenvío siempre choca antes en U2.

### 4.3 Manipulaciones del expediente

Las manipulaciones que se muestran aquí las hace una autoridad deshonesta que **vuelve a firmar** el expediente con su
propia clave. Aun así, el verificador las detecta (sin re-firmar, cualquier cambio falla en A4):

| Manipulación | Comprobaciones que fallan |
|---|---|
| Borrar un ballot | A6, A8, A9 |
| Duplicar un ballot | A6, A8, A9 |
| Cambiar `β` de un ballot sin rehacer su hash | A6, A7, A8 |
| Cambiar el voto de un ballot y rehacer su hash | A7 (V3), A8 |
| Publicar un agregado que no es la suma de los ballots | A8 |
| Declarar un `n_ballots` falso | A9 (y B inconsistente) |
| Token consumido que no fue emitido | A5, A6 |
| Firmar con otra clave | A4 |
| **Resultado anunciado falso pero consistente** | **ninguna** (limitación de §2) |
| **Votos de relleno con tokens sobrantes** | **ninguna** (limitación de §2) |

---

## 5. Expediente, agregado recalculado y resultado anunciado

El expediente (`AuditRecord`, en `src/schema/record.ts`) es un JSON autocontenido que incluye:

- los parámetros públicos;
- los tokens emitidos y consumidos (solo `token_id`, nunca el MAC);
- los ballots aceptados con sus pruebas y `ballot_hash`;
- el agregado, el resultado anunciado y los metadatos de cierre;
- la firma Ed25519.

Se guarda inmutable al cerrar y se publica en `GET /elections/:id/record`.

**Ejemplo reproducible** (`npm run demo`; archivos en [`docs/ejemplo/`](ejemplo/)): 20 votantes, 13 sí y 7 no.

| | Valor | Origen |
|---|---|---|
| **Agregado recalculado por el verificador** | `α = 5e67ea79e4a13dcbcb2b09b67df519bb6759386949018e7874630e3ab67d922f`<br>`β = b0ef019417923e7e458721ddb8a906e0e2949e7b31df4d5fc3286a442b986a06` | suma de los 20 ballots publicados (A8) |
| Agregado publicado por la autoridad | idéntico al anterior | `aggregate` del expediente |
| **Resultado anunciado por la autoridad** | sí = 13, no = 7, total = 20 | `declared_result`: descifrado de la autoridad, no verificable (§2-B) |

El reporte completo del verificador está en [`docs/ejemplo/reporte-verificador.txt`](ejemplo/reporte-verificador.txt).
Muestra las nueve comprobaciones de A en OK, las dos notas de la sección B y la confirmación de que el recibo del
votante 1 está incluido. La salida de la demo, con los tres ataques y su paso de rechazo, está en
[`docs/ejemplo/salida-demo.txt`](ejemplo/salida-demo.txt).

---

## 6. Métricas experimentales

Se obtuvieron con `npm run bench`: 30 elecciones independientes por tamaño, con una ronda de calentamiento descartada.
Los tiempos están en ms como **mediana (p95)**. Equipo: Intel Core i5-10300H, Node.js 24.11.1, Windows 11. Los datos
completos están en [`results/metrics.md`](../results/metrics.md) y `results/metrics.csv`.

| N.º de votos | Tamaño de ballot (bytes) | Tiempo de creación (ms) | Tiempo de verificación por voto (ms) | Tiempo total de auditoría (ms) |
|---:|---:|---:|---:|---:|
| 1 | 320 binario / 928 JSON | 12,610 (14,883) | 10,857 (12,531) | 13,460 (16,937) |
| 5 | 320 binario / 928 JSON | 12,263 (13,812) | 10,452 (11,781) | 55,217 (60,618) |
| 10 | 320 binario / 928 JSON | 12,075 (13,311) | 10,285 (11,305) | 106,024 (109,992) |
| 20 | 320 binario / 928 JSON | 12,032 (13,666) | 10,256 (12,631) | 210,316 (228,984) |

Qué mide cada columna:

- **Tamaño de ballot:** binario = `α, β` más la prueba (10 × 32 bytes). JSON = mensaje completo del cliente
  (hex, credencial y metadatos).
- **Creación:** en el cliente, cifrado más prueba OR.
- **Verificación por voto:** en la urna, el envío completo U0–U5, incluida la transacción SQLite.
- **Auditoría:** el verificador independiente sobre el expediente de N ballots (A1–A9).

Interpretación:

- **Creación y verificación no dependen de N.** Cada voto cuesta lo mismo sin importar cuántos haya.
- **La auditoría crece linealmente**, unos 10,5 ms por ballot, porque verifica N pruebas OR.
- **La criptografía domina el costo de la urna.** La verificación criptográfica aislada (U1 + U3: unos 10 ms) es
  cerca del 95 % del tiempo de la urna; esquema, HMAC y SQLite suman menos de 1 ms.
- **De dónde sale el costo:** son las 8 exponenciaciones (multiplicaciones escalares) de la prueba OR, en
  JavaScript puro.
- **Tamaños:** el expediente crece unos 1,05 KB por ballot (22 KB con 20 votos).

---

## 7. Desviaciones respecto al Entregable 1

| Entregable 1 | Implementación | Motivo |
|---|---|---|
| Ristretto255 vía PyNaCl o `@noble/curves` | `@noble/curves` (TypeScript) | PyNaCl no expone Ristretto255 |
| SHA-256 para el reto | SHA-512 reducido mod q | sesgo despreciable de la reducción |
| JSON canónico para el transcript | transcript binario con prefijos de longitud (§1.4) | codificación inyectiva y exacta; JSON canónico se mantiene para hashes y firma |
| Transcript con parámetros, elección, ciphertext y compromisos | se añade `token_id` | impide copiar `(α, β, π)` de otro votante |
| "Hash encadenado o firma" del expediente | firma Ed25519 con clave publicada antes de abrir | una sola opción, verificable por terceros |
| El verificador confirma el resultado | el verificador confirma el agregado; el resultado queda como declarado | corrección 2 de la evaluación |
| — | huella de parámetros `SHA-256(JCS(params))` fijable en el cliente (`--params-sha256`) | evita que la urna sustituya la clave pública |
| — | se valida U1 (decodificación) antes de U2 (token) | no se consulta la base por mensajes mal formados |

---

## 8. Limitaciones declaradas

1. **Sin prueba de descifrado:** el resultado anunciado no es verificable criptográficamente (§2).
2. **Elegibilidad no verificable públicamente:** la autoridad puede emitir votos de relleno con tokens sobrantes (§2).
3. **Autoridad única y confiable:** no hay descifrado por umbral. Quien obtenga la clave `x` puede descifrar votos
   individuales.
4. **Secretos en claro en la base local:** `x`, la clave HMAC y la clave de firma se guardan sin cifrar en SQLite, en
   una tabla separada de los parámetros públicos. Es coherente con el supuesto anterior, pero no es apto para
   producción.
5. **Borrado de secretos en memoria:** en JavaScript los `bigint` son inmutables y los gestiona el recolector de
   basura, así que no se puede garantizar el borrado de `r` y `w`. Los ataques a la memoria del cliente están fuera del
   modelo de adversario.
6. Sin anonimato de red ni resistencia a coerción, como se declaró en el Entregable 1.

---

## 9. Arquitectura y reproducción

```
src/crypto       Primitivas: grupo, codificación estricta, ElGamal, prueba OR, transcript, HMAC, Ed25519
src/schema       Formatos versionados: parámetros, ballot, expediente; JSON canónico
src/protocol     Dominio: elección, tokens, urna U0–U5, escrutinio; interfaces de persistencia
src/persistence  SQLite: migraciones y triggers de inmutabilidad
src/api          Express: rutas de administración y públicas
src/client       Construcción del ballot y CLI de votación
src/verifier     Verificador independiente (solo importa crypto y schema)
```

ESLint hace cumplir las dependencias permitidas entre capas, y `npm run lint` falla si se violan. Para reproducir:

```bash
npm install
npm run check     # tipos + lint + 337 pruebas
npm run demo      # elección completa, ataques y verificación
npm run bench     # métricas → results/
npm run verify -- docs/ejemplo/expediente.json
```

## Referencias

[1] D. Boneh y V. Shoup, *A Graduate Course in Applied Cryptography*, v0.6, §§11.5, 19.7, 20.3.
[2] B. Adida, "Helios: Web-based open-audit voting", USENIX Security 2008.
[3] A. Fiat y A. Shamir, "How to prove yourself", CRYPTO '86.
[4] R. Cramer, I. Damgård y B. Schoenmakers, "Proofs of partial knowledge and simplified design of witness hiding
protocols", CRYPTO '94.
[5] H. de Valence et al., RFC 9496, *The ristretto255 and decaf448 Groups*, 2023.
[6] A. Rundgren, B. Jordan y S. Erdtman, RFC 8785, *JSON Canonicalization Scheme*, 2020.
[7] S. Josefsson e I. Liusvaara, RFC 8032, *Edwards-Curve Digital Signature Algorithm (EdDSA)*, 2017.
