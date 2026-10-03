# SmartSeal gateway

FastAPI service that receives sensor records from the seal (Wokwi ESP32 or real hardware), keeps them in
SQLite (off-chain), maintains the SHA-256 hash chain, groups records into batches, computes Merkle roots,
gets each batch signed by a secure-element provider (ECDSA P-256 + monotonic counter), and queues
commitments for the blockchain.

## Run on Windows 11
CMD:
```
cd SmartSeal\gateway
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
python -m pytest -q
python -m uvicorn app:create_app --factory --port 8000
```
PowerShell: activate with `.venv\Scripts\Activate.ps1` (if blocked: `Set-ExecutionPolicy -Scope Process Bypass`).
Or just double-click `run_tests.bat` / `run_gateway.bat`. API docs: http://127.0.0.1:8000/docs

Feed it data without Wokwi (second terminal, same venv):
```
python ..\integration\simulate_device.py --count 8
```

## Modules
| file | job |
|---|---|
| hashing.py | canonical format, SHA-256, exact signed payloads |
| merkle.py | tree, root, proofs |
| secure_element.py | provider interface, mock provider (real ECDSA), production stub |
| models.py | request validation, `SealError` codes |
| storage.py | SQLite schema and queries, outbox queue |
| batching.py | seal/shipment lifecycle, ingest, batching, signing, replay checks |
| verifier.py | hash-chain + batch/Merkle/signature/counter checks (pure functions) |
| blockchain.py | ledger interface, `OfflineLedger`, outbox sync, `BesuLedger` (real contracts), `ChainReader`, `qbft_status` |
| custody.py | dual-signature handoffs (digest, nonce, route rules) |
| demo_accounts.py | DEMO ONLY role keys derived from public strings |
| app.py | HTTP API |

## Error codes (machine-readable, in `{"error":{"code":...}}`)
STALE_COUNTER, BATCH_SEQUENCE_ERROR, PREV_ROOT_MISMATCH, SIGNATURE_INVALID, WRONG_SHIPMENT, WRONG_SEAL,
SEAL_REVOKED, ROLE_DENIED, HASH_MISMATCH, PREV_HASH_MISMATCH, SEQ_GAP, SEQ_DUPLICATE, TIMESTAMP_ORDER,
MERKLE_MISMATCH, MISSING_DATA, SCHEMA_INVALID, UNAUTHORIZED, DEVICE_SIGNS.
Custody adds NONCE_REUSED, NEED_BOTH_SIGNATURES, NOT_CURRENT_CUSTODIAN, ROUTE_VIOLATION, ROUTE_COMPLETE, BAD_SIGNATURE_FROM/TO, MALFORMED_SIGNATURE.

## Endpoints
Write endpoints need header `X-API-Key` (default `demo-only-change-me`, DEMO ONLY).

| method | path | purpose |
|---|---|---|
| GET | /api/health, /api/status | liveness, counts, ledger state, simulated-vs-real notes |
| POST/GET | /api/seals, /api/shipments | register seal (mock SE provisions a key, or supply `publicKey`), start shipment |
| POST | /api/seals/{id}/revoke | body `{"by":"REGULATOR"}` (only REGULATOR/MANUFACTURER) |
| POST | /api/record | ingest one record |
| GET | /api/records, /api/records/latest | read records |
| GET | /api/verify-chain | gateway-local integrity check (NOT independent) |
| POST | /api/batch/close | force-close the open batch (mock SE signs) |
| POST | /api/batch/submit | batch signed by the seal itself (real hardware path) |
| GET | /api/batches, /api/batches/{id} | batches; detail includes Merkle leaves and levels |
| POST/GET | /api/tamper-event(s) | signed tamper event, closes the batch |
| GET/POST | /api/queue, /api/queue/sync | commitments waiting for the ledger |
| GET | /api/audit | audit log |
| GET/POST | /api/export, /api/import, /api/audit-copies | evidence bundles for audit copies |

## Behaviour worth knowing
* A duplicate POST of an identical record is accepted idempotently (`"duplicate": true`), so a device can safely retry.
* A seal registered with its own `publicKey` signs its own batches; the gateway refuses to sign for it (`DEVICE_SIGNS`).
* The device's counter advances on every signature, including ones that are later rejected or never sent.
  The verifier reports such holes as `COUNTER_GAP`.
* Batch ids and `prevRoot` chain per shipment; the counter is per seal and never repeats.

## Added endpoints
| method | path | purpose |
|---|---|---|
| POST | /api/custody/handoff | both parties' signatures over the shared digest |
| POST | /api/custody/demo-handoff | DEMO ONLY: gateway signs with demo keys; modes both, sender_only, receiver_only, reuse_nonce, wrong_receiver_signer |
| GET | /api/custody | route, handoffs, current holder |
| GET | /api/blockchain/status, /validators, /blocks | measured QBFT state (asks each node over JSON-RPC), latest blocks with commit-seal count |
| GET | /api/blockchain/shipments/{id}, /batches/{id}, /custody/{id} | what the contracts hold |
| GET/POST | /api/verifier/result, /api/verifier/run | proxy to the verifier service |
| GET/POST | /api/attacks, /api/attacks/run | attack-suite report; run on isolated in-memory chains |

When `blockchain\deployment.json` exists the gateway connects to the chain; commitments that cannot be sent wait in `/api/queue` and a background thread retries every 5 seconds.
Without a chain it runs queue-only (`SMARTSEAL_CHAIN=off`).
