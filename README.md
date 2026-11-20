# Votación electrónica binaria con ElGamal y NIZK

Prototipo de votación de aula (una pregunta sí/no, máximo 20 votantes, una autoridad). Los votos se cifran con
**ElGamal exponencial sobre Ristretto255**, se acompañan de una **prueba OR no interactiva** (Cramer–Damgård–Schoenmakers
+ Fiat–Shamir) de que contienen 0 o 1, y se suman homomórficamente sin descifrar cada voto. Tokens de un solo uso
controlan quién vota y un expediente público permite auditar lo que aceptó la urna.

El diseño detallado y las fases están en [`PLAN_IMPLEMENTACION.md`](PLAN_IMPLEMENTACION.md).

## Requisitos

- Node.js ≥ 22.12 (desarrollado con Node 24)

## Uso

```bash
npm install
npm run check        # typecheck + lint + pruebas
npm test             # solo pruebas (Jest)
npm run test:coverage
npm run build        # compila a dist/
npm run demo         # elección completa de 20 votantes (13 sí / 7 no) + ataques + verificación
npm start            # urna + administración en http://127.0.0.1:3000
npm run vote -- --server <url> --election <id> --credential <token_id.mac> --choice si|no [--params-sha256 <huella>]
npm run verify -- expediente.json [--ballot-hash <recibo>] [--json]   # verificador independiente
```

`npm run demo` acepta `--voters N --yes K --out <archivo> --db <archivo.db>` y deja el expediente en
`data/demo/expediente.json`. El cliente de votación cifra el voto y genera la prueba OR localmente; con
`--params-sha256` compara la huella de los parámetros (SHA-256 de su JSON canónico) y, si no coincide, no envía nada:
así un servidor malicioso no puede sustituir la clave pública. Códigos de salida de `vote`: 0 aceptado, 1 rechazado
por la urna, 2 uso incorrecto, error de red o parámetros no confiables.

El verificador trabaja solo sobre el archivo del expediente (sin red ni base de datos). Sale con código 0 si todo lo
verificable pasa, 1 si algo falla y 2 si el uso es incorrecto. Su reporte separa **A. Verificado criptográficamente**
(A1 esquema, A2 suite, A3 parámetros, A4 firma, A5 tokens, A6 integridad de ballots, A7 pruebas OR, A8 agregado
recalculado, A9 conteo) de **B. Declarado por la autoridad** (resultado sí/no, sin prueba de descifrado).
Con `--ballot-hash` un votante comprueba que su recibo está incluido.

Variables de `npm start`: `PORT` (3000), `HOST` (127.0.0.1), `DB_PATH` (`data/urna.db`) y `ADMIN_API_KEY`
(≥ 16 caracteres; si falta se genera una y se muestra al arrancar).

### API HTTP

| Método | Ruta | Acceso | Respuesta |
|---|---|---|---|
| POST | `/admin/elections` `{question, n_max_voters}` | admin | parámetros públicos |
| POST | `/admin/elections/:id/tokens` `{count}` | admin | credenciales `<token_id>.<mac>` |
| POST | `/admin/elections/:id/close` | admin | cierra, escruta y devuelve el expediente firmado |
| GET | `/elections/:id/params` | público | parámetros públicos |
| GET | `/elections/:id/status` | público | conteos (sin ballots individuales) |
| POST | `/elections/:id/ballots` | público (con credencial) | `201 {accepted, ballot_hash, …}` o `{accepted: false, step, code}` |
| GET | `/elections/:id/record` | público | expediente firmado (409 `E_NOT_CLOSED` antes del cierre) |

Las rutas `admin` exigen `Authorization: Bearer <ADMIN_API_KEY>`. Estados HTTP de rechazo: 400 (U0 formato/versión),
403 (token inválido), 404 (elección inexistente), 409 (token usado, duplicado, elección cerrada), 422 (U1 codificación,
U3 prueba).

## Suite criptográfica (fija)

`VOTE-BIN-v1:ristretto255:sha512:hmac-sha256:ed25519` — grupo Ristretto255 (`@noble/curves`), reto Fiat–Shamir con
SHA-512 reducido mod q, tokens con HMAC-SHA256, expediente firmado con Ed25519. Versiones de dependencias fijadas
exactamente en `package.json`.

## Arquitectura

```
src/
  crypto/       Primitivas puras: grupo, codificación estricta, ElGamal, prueba OR, hashes. Sin E/S.
  schema/       Formatos de mensaje versionados (params, ballot, expediente) y su validación.
  protocol/     Lógica de dominio: elección, tokens, urna, escrutinio. Define puertos (interfaces) de persistencia.
  persistence/  Adaptadores SQLite que implementan los puertos de protocol/.
  api/          Servidor Express: rutas de administración y de urna (raíz de composición).
  client/       Cliente de votación (CLI). Construye el ballot localmente; nunca ve claves de la autoridad.
  verifier/     Auditor independiente: solo lee el expediente; no usa red ni base de datos.
test/           Pruebas Jest, organizadas por capa.
```

Dependencias permitidas entre capas (las hace cumplir ESLint con `no-restricted-imports`; `npm run lint` falla si se violan):

| Capa | Puede importar |
|---|---|
| `crypto` | — (solo `@noble/*` y `node:crypto`) |
| `schema` | `crypto` |
| `protocol` | `crypto`, `schema` |
| `persistence` | `crypto`, `schema`, `protocol` |
| `api` | todas |
| `client` | `crypto`, `schema` |
| `verifier` | `crypto`, `schema` |

Dentro de `crypto/`, solo `group.ts` importa la biblioteca de curva; el resto del código usa los tipos `Point` y `Scalar`.

## Estado

- [x] Fase 1 — Esqueleto, suite fija, grupo Ristretto255 y reglas de rechazo de elementos (§0.1 del plan)
- [x] Fase 2 — ElGamal exponencial (cifrado de votos, agregación homomórfica, descifrado acotado)
- [x] Fase 3 — Prueba OR CDS + Fiat–Shamir, con vectores deterministas (`npm run vectors`) y casos negativos por paso V1–V5
- [x] Fase 4 — Tokens HMAC de un solo uso y persistencia SQLite (consumo atómico, triggers, migraciones)
- [x] Fase 5 — Urna (pasos U0–U5), elecciones y API Express
- [x] Fase 6 — Cierre con escrutinio del agregado, expediente firmado (Ed25519) y verificador independiente
- [x] Fase 7 — CLI de votación (con fijación de huella de parámetros) y demo de extremo a extremo
- [ ] Fases 8–9 — métricas, informe

## Limitaciones declaradas

- **Sin prueba de descifrado:** el verificador no confirma criptográficamente el resultado anunciado.
- **Elegibilidad no verificable públicamente:** la autoridad emite los tokens y conoce la clave HMAC, así que podría
  votar con tokens sobrantes (votos de relleno) sin que el verificador lo detecte. Cada votante sí puede comprobar que su
  propio ballot aparece en el expediente.
- **Secretos de la autoridad en claro en la base local:** la clave ElGamal `x`, la clave HMAC y la clave de firma se
  guardan sin cifrar en SQLite (tabla separada de los parámetros públicos). Quien lea `data/urna.db` puede descifrar
  votos individuales. Es coherente con el supuesto de autoridad única y confiable, pero no apto para producción.
- Autoridad única (sin umbral), sin anonimato de red ni resistencia a coerción.

Ver §3 y §5.3 del plan.
