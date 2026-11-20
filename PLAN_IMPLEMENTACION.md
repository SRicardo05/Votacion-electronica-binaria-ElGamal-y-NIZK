# Plan de implementación — Votación binaria con ElGamal exponencial y prueba OR (NIZK)

Stack fijado: **TypeScript (Node 24) + Express + Jest**.
Este plan responde a las tres correcciones de la evaluación de la Entrega 1 y a lo pedido para la Entrega 2.

---

## 0. Suite criptográfica fija (corrección 3)

Una sola combinación, sin alternativas:

| Necesidad | Decisión | Paquete |
|---|---|---|
| Grupo de orden primo | **Ristretto255** (orden `q = 2^252 + 27742317777372353535851937790883648493`) | `@noble/curves` (`ristretto255`), versión exacta fijada en `package.json` |
| Hash del reto Fiat–Shamir | **SHA-512**, salida de 64 bytes reducida mod `q` (sesgo despreciable; con SHA-256 mod q el sesgo no es despreciable porque `2^256 ≈ 16q`) | `@noble/hashes` |
| Hash de ballots / expediente | SHA-256 sobre JSON canónico | `@noble/hashes` |
| Autenticación de tokens | HMAC-SHA256 con clave `k_tok` de la autoridad | `@noble/hashes/hmac` |
| Firma del expediente | Ed25519 de la autoridad (clave de firma publicada en los parámetros antes de abrir) | `@noble/curves/ed25519` |
| Serialización canónica (JSON) | RFC 8785 (JCS) — solo para hash de ballot y del expediente | `canonicalize` |
| Transcript Fiat–Shamir | **Binario** con prefijo de longitud (ver §2.4), no JSON | propio (≈30 líneas) |
| Aleatoriedad | `crypto.randomBytes(64)` reducido mod `q`, rechazar 0 | `node:crypto` |
| HTTP | Express 5 + validación de esquemas con `zod` | `express`, `zod` |
| Persistencia | SQLite vía `better-sqlite3` (síncrono, transacciones, `UNIQUE`) | `better-sqlite3` |
| Pruebas | Jest + `ts-jest`; HTTP con `supertest` | `jest`, `ts-jest`, `supertest` |

> Nota para el informe: el Entregable 1 mencionaba PyNaCl; PyNaCl 1.6.2 **no expone** Ristretto255 (solo `crypto_core_ed25519_*`), por eso se fija `@noble/curves`.

**Identificador de suite:** `group_id = "ristretto255"`, `suite_id = "VOTE-BIN-v1:ristretto255:sha512:hmac-sha256:ed25519"`.

### 0.1 Reglas de rechazo de elementos (antes de cualquier operación)

| Elemento | Codificación | Se rechaza si… | Código |
|---|---|---|---|
| Punto | 32 bytes, hex minúscula (64 chars) | longitud ≠ 64, hex inválido, **decodificación Ristretto no canónica** (noble lanza excepción) | `E_POINT_ENCODING` |
| `α` del ciphertext | punto | es la **identidad** (implica `r = 0`, el voto quedaría en claro) | `E_IDENTITY` |
| Escalar | 32 bytes little-endian, hex minúscula | longitud ≠ 64, hex inválido, **valor ≥ q** (no canónico) | `E_SCALAR_RANGE` |
| Objeto JSON | esquema `zod` estricto | campo faltante, campo extra, tipo incorrecto | `E_FORMAT` |
| Versión / elección | — | `version ≠ "v1"`, `group_id ≠ "ristretto255"`, `election_id` distinto | `E_VERSION` / `E_ELECTION` |

Todo esto vive en `src/crypto/encoding.ts`; ninguna otra capa toca bytes crudos.

---

## 1. Notación

Ristretto es aditivo. Correspondencia con el PDF: `g^r ↔ r·G`, `g^v·h^r ↔ v·G + r·H`, producto de ciphertexts ↔ suma de puntos.

- Autoridad: `x ← Zq*`, `H = x·G`.
- Cifrado de `v ∈ {0,1}`: `r ← Zq*`, `α = r·G`, `β = v·G + r·H`.
- Para la rama `j ∈ {0,1}` se define `β_j = β − j·G`. "El ciphertext cifra `j`" ⇔ `log_G(α) = log_H(β_j)` (igualdad de logaritmos, Chaum–Pedersen).

---

## 2. Prueba OR de Cramer–Damgård–Schoenmakers completa (corrección 1)

### 2.1 Probador (conoce `v` y `r`; rama falsa `f = 1 − v`)

1. **Simular la rama falsa:** elegir `c_f, s_f ← Zq` y calcular
   - `A_f = s_f·G − c_f·α`
   - `B_f = s_f·H − c_f·β_f`
2. **Comprometer la rama real:** elegir `w ← Zq*` y calcular
   - `A_v = w·G`
   - `B_v = w·H`
3. **Reto global:** `c = SHA-512(T) mod q`, con `T` el transcript de §2.4.
4. **Reto de la rama real:** `c_v = c − c_f mod q`.
5. **Respuesta real:** `s_v = w + c_v·r mod q`.
6. Descartar `w` y `r` (no se devuelven ni se persisten). *Limitación declarada:* en JavaScript los `bigint` son inmutables y los gestiona el recolector de basura, así que no se puede garantizar su borrado de memoria; los ataques sobre la memoria del cliente están fuera del modelo de adversario (§2.4 del Entregable 1).

**Prueba publicada:** `π = (A0, B0, A1, B1, c0, c1, s0, s1)`: 4 puntos y 4 escalares = **256 bytes**.
**Ballot criptográfico:** `(α, β, π)` = **320 bytes** en binario (≈ 640 caracteres hex en JSON).

### 2.2 Verificador (urna y verificador independiente usan **la misma función**)

Entrada: parámetros, `token_id`, `(α, β)`, `π`.

| Paso | Comprobación | Código si falla |
|---|---|---|
| V1 | Decodificar `α, β, A0, B0, A1, B1` como puntos canónicos; `α ≠ identidad` | `E_POINT_ENCODING` / `E_IDENTITY` |
| V2 | `c0, c1, s0, s1` son escalares canónicos `< q` | `E_SCALAR_RANGE` |
| V3 | `c0 + c1 ≡ SHA-512(T) mod q` | `E_PROOF_CHALLENGE` |
| V4 | `s0·G == A0 + c0·α` **y** `s0·H == B0 + c0·β` | `E_PROOF_EQ_0` |
| V5 | `s1·G == A1 + c1·α` **y** `s1·H == B1 + c1·(β − G)` | `E_PROOF_EQ_1` |

Se acepta solo si V1–V5 pasan. La igualdad de puntos se compara con `equals()` de noble (sobre codificación canónica).

### 2.3 Por qué un voto de valor 2 falla (para el informe)

Con `v = 2`, `β_0 = 2G + rH` y `β_1 = G + rH`. Ninguna rama es una tupla DH válida, así que el probador solo puede simular **una** rama con reto libre. La otra rama necesita su reto antes de conocer `c`; para que `c0 + c1 = c` pase, debería predecir la salida de SHA-512. En la práctica, la prueba construida falla en **V3** (si se fijan ambos retos de antemano) o en **V4/V5** (si un reto se fuerza a `c − c_f`).

### 2.4 Transcript de Fiat–Shamir: bytes exactos

```
T = DST || LP(version) || LP(suite_id) || LP(election_id) || LP(token_id)
       || G || H || α || β || A0 || B0 || A1 || B1

DST   = ASCII "VOTE-BIN-v1/cds-or-proof" (24 bytes, sin prefijo)
LP(s) = uint32 big-endian con la longitud en bytes de UTF-8(s) || UTF-8(s)
G, H, α, β, A_i, B_i = codificación Ristretto canónica de 32 bytes, en ese orden
```

- `c = bytesToNumberLE(SHA-512(T)) mod q`.
- Incluir `token_id` **ata la prueba al token**: copiar `(α, β, π)` de otro votante bajo un token propio hace fallar V3 (defensa contra copia de ballots).
- Incluir `election_id` y `H` evita reutilizar la prueba entre elecciones.
- Se publicarán **vectores de prueba** fijos (semilla determinista → `T` en hex → `c` → `π`) en `test/vectors/or-proof.json`.

---

## 3. Tokens

- `token_id`: 16 bytes aleatorios en hex.
- `mac = HMAC-SHA256(k_tok, "VOTE-BIN-v1/token" || LP(election_id) || LP(token_id))`.
- Credencial entregada al votante fuera de banda: `token_id.mac` (hex).
- La urna recalcula el MAC (comparación en tiempo constante) y consulta la tabla `tokens`.
- El expediente publica **solo `token_id`**, sin MAC, en dos listas: emitidos y consumidos.
- **Limitación declarada:** el verificador independiente no puede comprobar el MAC porque no tiene `k_tok`. Solo verifica que cada ballot use un `token_id` emitido, sin repeticiones, y que `#ballots ≤ n_max`.

---

## 4. Validación en la urna: orden y códigos

Para cada caso negativo se puede decir en qué paso se rechaza:

| Paso | Qué se valida | Códigos |
|---|---|---|
| U0 | Elección abierta; esquema JSON; `version`, `group_id`, `election_id` | `E_CLOSED`, `E_FORMAT`, `E_VERSION`, `E_ELECTION` |
| U1 | Decodificación de puntos y escalares (§0.1) | `E_POINT_ENCODING`, `E_IDENTITY`, `E_SCALAR_RANGE` |
| U2 | Token: MAC válido → existe → no consumido | `E_TOKEN_MAC`, `E_TOKEN_UNKNOWN`, `E_TOKEN_USED` |
| U3 | Prueba OR (V3–V5) | `E_PROOF_CHALLENGE`, `E_PROOF_EQ_0`, `E_PROOF_EQ_1` |
| U4 | No duplicado: `ballot_hash` nuevo **y** `(α, β)` no aceptado antes | `E_REPLAY`, `E_DUP_CIPHERTEXT` |
| U5 | **Transacción SQLite:** `UPDATE tokens SET used=1 WHERE id=? AND used=0` (debe afectar exactamente 1 fila) + `INSERT ballot` | `E_TOKEN_USED` (por carrera) |

- `ballot_hash = SHA-256(JCS(ballot sin timestamp))`. El `timestamp` lo pone la urna, no el cliente.
- Al cliente se le responde `{accepted: false, code}`. El log interno guarda el detalle. El código no le da al atacante un oráculo útil porque el algoritmo de verificación es público.
- Restricciones en BD: `tokens.id PRIMARY KEY`, `ballots.token_id UNIQUE`, `ballots.ballot_hash UNIQUE`, `ballots.alpha_beta UNIQUE`.

---

## 5. Cierre, descifrado y expediente (corrección 2)

### 5.1 Cierre (autoridad)

1. `A = Σ α_i`, `B = Σ β_i` sobre los ballots aceptados.
2. `M = B − x·A` (que vale `(Σv)·G`).
3. Buscar `k ∈ [0, n_aceptados]` con `k·G == M` (tabla precomputada de 21 puntos). Si no aparece → error fatal `E_TALLY_OUT_OF_RANGE`.
4. Resultado declarado: `sí = k`, `no = n_aceptados − k`.

### 5.2 Expediente (`election_record.json`, versión `v1`)

```json
{
  "version": "v1",
  "suite_id": "VOTE-BIN-v1:ristretto255:sha512:hmac-sha256:ed25519",
  "params": { "election_id", "question", "options": ["no","si"], "n_max_voters",
              "generator", "public_key", "authority_sign_pk", "opened_at" },
  "tokens": { "issued": ["<token_id>", ...], "consumed": ["<token_id>", ...] },
  "ballots": [ { "version", "election_id", "token_id",
                 "ciphertext": {"alpha","beta"},
                 "proof": {"A0","B0","A1","B1","c0","c1","s0","s1"},
                 "timestamp", "ballot_hash" } ],
  "aggregate": { "alpha", "beta" },
  "declared_result": { "yes", "no", "n_ballots" },
  "closing": { "closed_at", "software_version" },
  "signature": "<Ed25519 sobre SHA-256(JCS(expediente sin 'signature'))>"
}
```

### 5.3 Verificador independiente: qué garantiza y qué no

El verificador está en `src/verifier/`, **importa solo `src/crypto/` y `src/schema/`** y funciona sin red ni BD. Su reporte tiene dos secciones separadas, como pide la evaluación:

**A. Verificado criptográficamente**
- La firma Ed25519 del expediente es válida.
- Versión y suite son correctas, y los parámetros son coherentes (`H` decodifica y no es la identidad).
- Cada ballot: el token está emitido, no hay `token_id`, `ballot_hash` ni `(α, β)` repetidos, el hash recalculado coincide y la prueba OR es válida (misma función de §2.2).
- `#ballots ≤ n_max_voters` y `consumed == {token_id de los ballots}`.
- **Agregado recalculado == agregado publicado.** Se reporta el agregado recalculado.

**B. Declarado por la autoridad (NO verificado criptográficamente)**
- El resultado `yes/no` anunciado. Solo se comprueban consistencias triviales: `0 ≤ yes ≤ n_ballots` y `yes + no = n_ballots`.
- Texto fijo en el reporte: *"Sin prueba de descifrado (Chaum–Pedersen sobre (G, H, A, B − k·G)), el verificador no puede confirmar que el resultado corresponde al agregado. Esta prueba está fuera de alcance; la confianza en el descifrado recae en la autoridad."*

Esto corrige la afirmación de la §4.7 del Entregable 1, que debe reescribirse en el informe.

---

## 6. Estructura del repositorio

```
src/
  crypto/            # Capa de primitivas: sin Express, sin BD
    group.ts         # envoltura de noble: Point, Scalar, G, identidad, decode/encode (único archivo que importa noble)
    encoding.ts      # hex <-> bytes, reglas de rechazo §0.1, errores tipados
    random.ts        # escalares aleatorios
    elgamal.ts       # keygen, encrypt(v, r?), add, decryptAggregate, discreteLogSmall
    transcript.ts    # construcción exacta de T (§2.4)
    orProof.ts       # prove(params, tokenId, v, r, ct) / verify(...)
    hashing.ts       # sha512ToScalar, sha256, hmac
    sign.ts          # Ed25519 del expediente
  schema/            # Formatos de mensaje versionados (zod): Params, Ballot, Record — compartidos por urna, cliente y verificador
  protocol/          # Lógica de dominio
    errors.ts        # códigos E_*
    election.ts      # crear elección, claves, abrir/cerrar
    tokens.ts        # emitir/validar tokens
    ballotBox.ts     # pipeline U0–U5
    tally.ts         # agregación + descifrado
    record.ts        # construir y firmar expediente
  persistence/
    db.ts            # better-sqlite3, migraciones, transacciones
  api/
    adminRoutes.ts   # POST /admin/elections, POST /admin/tokens, POST /admin/close, GET /admin/record
    boxRoutes.ts     # GET /params, POST /ballots, GET /status (solo conteo de ballots)
    server.ts
  client/
    voterCli.ts      # `vote --token <t> --choice si|no --server <url>`
  verifier/
    verifyRecord.ts  # importa solo ../crypto
    cli.ts           # `verify election_record.json` → reporte A/B + código de salida
bench/
  metrics.ts         # métricas de §8.3 → results/metrics.csv + .md
test/
  crypto/  protocol/  api/  verifier/  vectors/
```

Scripts de `package.json`: `build`, `test`, `test:coverage`, `start` (servidor), `vote`, `verify`, `bench`, `demo` (elección completa de extremo a extremo con 20 votantes simulados).

---

## 7. Fases de implementación

Ordenadas según lo que pide la evaluación: **primero el núcleo criptográfico y sus pruebas negativas**.

### Fase 1: Esqueleto y suite fija
- `npm init`, TypeScript `strict`, Jest + ts-jest, ESLint, `.gitignore`.
- Instalar dependencias con **versiones exactas**.
- `group.ts` + `encoding.ts` con sus pruebas: identidad, punto no canónico, escalar ≥ q, longitud incorrecta.
- **Hecho cuando:** `npm test` pasa con las reglas de §0.1 cubiertas.

### Fase 2: ElGamal exponencial
- `keygen`, `encrypt`, suma homomórfica, `decryptAggregate` + logaritmo acotado.
- Pruebas: cifrar 0 y 1 y descifrar; la suma de 20 votos aleatorios coincide con lo esperado; dos cifrados del mismo voto difieren (aleatorización).

### Fase 3: Prueba OR CDS (lo central de la Entrega 2)
- `transcript.ts`, `orProof.prove/verify` exactamente como en §2.
- Vectores deterministas en `test/vectors/`.
- Pruebas positivas: `v=0` y `v=1` verifican.
- **Pruebas negativas obligatorias, cada una con el paso donde falla:**

| Caso (evaluación) | Construcción | Paso esperado |
|---|---|---|
| Voto de valor 2 | Cifrar `2·G + r·H`; probador "malicioso" que simula una rama y fuerza la otra | V4/V5 (o V3) |
| Compromiso modificado | Cambiar `A0` (u otro `A/B`) por otro punto válido | V3 (el reto ya no coincide) |
| Reto alterado | `c0 += 1` | V3; y `c0 += 1, c1 −= 1` → V4 |
| Respuesta alterada | `s1 += 1` | V5 |
| Bit flip en codificación | Voltear un bit de `A0` | V1 (no canónico) o V3 |
| Prueba copiada con otro token | Mismo `(α, β, π)`, distinto `token_id` | V3 |
| Prueba de otra elección | Distinto `election_id` / `H` | V3 |

### Fase 4: Tokens y persistencia
- HMAC, tabla `tokens`, transacción de consumo atómico.
- Pruebas: token inexistente → U2 `E_TOKEN_UNKNOWN`; MAC alterado → U2 `E_TOKEN_MAC`; **token repetido** → U2 `E_TOKEN_USED`; carrera simulada (dos inserciones) → solo una gana.

### Fase 5: Urna (`ballotBox.ts`) y API Express
- Pipeline U0–U5 en la capa de protocolo; las rutas solo validan el esquema y delegan.
- Pruebas con `supertest`: todos los códigos de §4, replay exacto → `E_TOKEN_USED` (U2 llega antes que U4; se documenta), ciphertext duplicado con token nuevo → V3 por el atado al token (y U4 como segunda barrera).

### Fase 6: Cierre, expediente y verificador
- `tally.ts`, `record.ts` (JCS + firma), `verifier/`.
- Pruebas positivas: todos 0, todos 1, mezcla conocida (p. ej. 13 sí / 7 no); el verificador reproduce el agregado.
- Pruebas de manipulación del expediente: borrar un ballot, cambiar un `β`, alterar `declared_result`, cambiar la firma, duplicar un ballot. El verificador debe reportar la falla concreta en la sección A, o en B si se altera el resultado *y se re-firma* (eso demuestra la limitación de la corrección 2).

### Fase 7: Cliente CLI y demo de extremo a extremo
- `voterCli.ts` (construye el ballot localmente; nunca recibe claves de la autoridad).
- `npm run demo`: crea la elección, emite 20 tokens, simula votos, cierra, exporta `election_record.json` y ejecuta `verify`.
- Opcional, si sobra tiempo: una página web mínima servida por Express que use el mismo `src/crypto` empaquetado.

### Fase 8: Métricas (§8.3 del PDF)
- `bench/metrics.ts` para N = 1, 5, 10, 20 (repetir cada medida ≥ 30 veces y reportar mediana y p95 con `performance.now()`):
  - tamaño del ballot en bytes, tanto binario (320 B) como JSON serializado;
  - tiempo de creación (cifrar + probar);
  - tiempo de verificación por voto en la urna (U1–U3);
  - tiempo total de auditoría del verificador sobre el expediente de N votos.
- Salida en `results/metrics.csv` y en tabla markdown lista para el informe.

### Fase 9: Documentación para la Entrega 2
- Reescribir la §4.3 del informe con §2 de este plan (ecuaciones + transcript).
- Reescribir la §4.7 con §5.3 (garantías A vs B).
- Reemplazar la §7 por la tabla de §0 (una sola suite + reglas de rechazo).
- Tabla de casos negativos → paso de rechazo (salida de la Fase 3 y la Fase 5).
- Reportar por separado el **agregado recalculado** y el **resultado anunciado**.
- README: instalación, `npm run demo`, `npm run verify`, `npm run bench`.

---

## 8. Criterios de aceptación globales

- [ ] Una sola suite criptográfica, declarada en código (`suite_id`) y en el informe.
- [ ] La prueba OR está especificada con ecuaciones y bytes exactos, y tiene vectores de prueba.
- [ ] Casos de la evaluación (voto 2, compromiso modificado, reto alterado, token repetido) pasan con el **código y el paso** esperados.
- [ ] El verificador no importa `protocol/`, `persistence/` ni `api/` (comprobado con `no-restricted-imports` en `eslint.config.js`).
- [ ] El reporte del verificador separa "verificado" de "declarado por la autoridad".
- [ ] Las métricas para 1, 5, 10 y 20 votos se generan automáticamente.
- [ ] Las limitaciones (sin prueba de descifrado, MAC de tokens no verificable públicamente, autoridad única, sin anonimato de red ni resistencia a coerción) están declaradas en el README y en el informe.
