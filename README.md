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
```

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
- [ ] Fases 5–9 — urna, API, expediente, verificador, CLI, métricas, informe

## Limitaciones declaradas

- **Sin prueba de descifrado:** el verificador no confirma criptográficamente el resultado anunciado.
- **Elegibilidad no verificable públicamente:** la autoridad emite los tokens y conoce la clave HMAC, así que podría
  votar con tokens sobrantes (votos de relleno) sin que el verificador lo detecte. Cada votante sí puede comprobar que su
  propio ballot aparece en el expediente.
- Autoridad única (sin umbral), sin anonimato de red ni resistencia a coerción.

Ver §3 y §5.3 del plan.
