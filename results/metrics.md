# Métricas experimentales

Generado con `npm run bench` — 30 elecciones por tamaño; tiempos en ms como **mediana (p95)**.

- **fecha:** 2026-11-20T06:48:13.841Z
- **node:** v24.11.1
- **so:** win32 10.0.26300
- **cpu:** Intel(R) Core(TM) i5-10300H CPU @ 2.50GHz (8 hilos)

## Tabla del Entregable 1 (§8.3)

| N.º de votos | Tamaño de ballot (bytes) | Tiempo de creación (ms) | Tiempo de verificación por voto (ms) | Tiempo total de auditoría (ms) |
|---:|---:|---:|---:|---:|
| 1 | 320 binario / 928 JSON | 12.610 (p95 14.883) | 10.857 (p95 12.531) | 13.460 (p95 16.937) |
| 5 | 320 binario / 928 JSON | 12.263 (p95 13.812) | 10.452 (p95 11.781) | 55.217 (p95 60.618) |
| 10 | 320 binario / 928 JSON | 12.075 (p95 13.311) | 10.285 (p95 11.305) | 106.024 (p95 109.992) |
| 20 | 320 binario / 928 JSON | 12.032 (p95 13.666) | 10.256 (p95 12.631) | 210.316 (p95 228.984) |

## Detalle

| N | Ballot publicado (bytes JSON) | Expediente (bytes JSON) | Verificación cripto U1+U3 (ms) | Muestras por voto | Muestras de auditoría |
|---:|---:|---:|---:|---:|---:|
| 1 | 983 | 2106 | 10.271 (p95 12.203) | 30 | 30 |
| 5 | 983 | 6322 | 10.061 (p95 11.279) | 150 | 30 |
| 10 | 983 | 11593 | 9.906 (p95 10.864) | 300 | 30 |
| 20 | 983 | 22135 | 9.954 (p95 11.361) | 600 | 30 |

## Qué mide cada columna

- **Tamaño de ballot:** binario = α, β y la prueba OR (A0, B0, A1, B1, c0, c1, s0, s1): 10 × 32 = 320 bytes. JSON = mensaje enviado por el cliente en JSON canónico (hex + credencial + metadatos).
- **Tiempo de creación:** en el cliente, cifrado ElGamal + prueba OR (`buildBallot`).
- **Tiempo de verificación por voto:** en la urna, el envío completo U0–U5 (esquema, decodificación, HMAC del token, prueba OR, duplicados y transacción SQLite). La columna "Verificación cripto" aísla U1 + U3.
- **Tiempo total de auditoría:** el verificador independiente sobre el expediente de N ballots (A1–A9: firma, hashes, N pruebas OR y agregado recalculado). Crece linealmente con N.
