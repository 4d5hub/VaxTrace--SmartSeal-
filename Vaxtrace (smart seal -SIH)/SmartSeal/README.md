# SmartSeal: tamper-evident smart seal for multi-party custody of critical goods

A hardware-rooted, cryptographically verifiable, **offline-first** shipment-evidence and multi-party custody architecture.
Many of the individual technologies here already exist (signed data loggers, hash chains, Merkle anchoring, permissioned
ledgers, blockchain traceability platforms). The contribution is the **focused integration and threat-driven design**:

physical sensing, device-rooted identity, hash-chained records, batched Merkle proofs, signed commitments, dual-party custody,
a permissioned shared ledger, independent verification and automatic disposition (ACCEPT / QUARANTINE / REJECT).

This system makes unauthorized changes **detectable**. It is not tamper-proof, and the README says plainly where it stops (see "Honest limits").

## Status
**Fully functional backend.** The FastAPI gateway, the independent verifier service and the four Solidity contracts (including on-chain P-256
signature verification) run end to end and are covered by **87 automated tests**: gateway 43, smart contracts 19, integration and attack scenarios 25.
A browser dashboard drives it, with a self-contained Simulation mode and a Real backend mode that reads the live gateway, chain and verifier.

**What is simulated or not yet verified (see "Real vs simulated" below):** the secure element is a software mock (a physical ATECC608 is planned),
the automated tests run the contracts on an in-process EVM, and the 4-node Besu QBFT network is configured (`demo.bat`) but is not part of the automated tests.

## What is in the box
```
SmartSeal/
├── gateway/        FastAPI gateway: records, hash chain, SQLite, Merkle batching, signing, custody, queue, chain access
├── blockchain/     4 Solidity contracts + P-256 library, compile/deploy scripts, Besu QBFT Docker network, contract tests
├── verifier/       independent verifier service: 25 checks, policy, verdict, optional on-chain finalization
├── dashboard/      index.html = the simulation + a one-minute guide + "Real backend" mode with 8 tabs
├── integration/    in-process full stack, 16 attack scenarios, end-to-end tests, live-demo helper, sample payloads
├── demo.bat  demo_nodocker.bat  run_all_tests.bat
└── requirements.txt  requirements-dev.txt
```

## Architecture
```
 Wokwi / real ESP32
        | HTTP JSON (+ X-API-Key)
        v
 +-----------------------------+      +---------------------------+
 | FASTAPI GATEWAY  :8000      |      | VERIFIER SERVICE  :8100   |
 |  validate -> hash chain     |      |  reads chain + evidence   |
 |  SQLite (off-chain records) |      |  25 checks -> verdict     |
 |  4-record batches -> Merkle |      |  (never the gateway DB)   |
 |  mock secure element signs  |      +-------------+-------------+
 |  custody (2 signatures)     |                    |  reads / finalizes
 |  outbox queue (offline-first)                    |
 +--------------+--------------+                    |
                | signed transactions               |
                v                                   v
 +--------------------------------------------------------------+
 |  HYPERLEDGER BESU QBFT  (4 validators, needs 3 to commit)     |
 |  node1 Manufacturer  node2 Transporter  node3 Pharmacy  node4 Regulator   RPC 8545-8548
 |  Contracts: SmartSealRegistry  BatchAnchor  ShipmentCustody  VerdictRegistry
 +--------------------------------------------------------------+
                ^
                |  GET /api/*  (JSON)
        dashboard/index.html  ("Real backend" mode)   <- also keeps the self-contained Simulation mode
```

### What goes on-chain and what does not (hybrid on purpose)
| on-chain (compact proofs and shared state) | off-chain (bulk data, in the gateway database) |
|---|---|
| seal id, public key, revocation | every raw sensor record (temperatures, shock, lid, light, timestamps) |
| shipment id, bound seal, policy **hash** | full policy values |
| per batch: id, first/last seq, count, **Merkle root**, previous root, counter, signature | the records the root covers |
| signed tamper events | detailed logs and the audit trail |
| custody handoffs: parties, nonce, position, both signatures | queue state, exports, audit copies |
| final verdict, reason codes, report hash | the full verifier report |

Why: storing readings on a ledger is expensive, slow and exposes everything to every validator. A 32-byte root commits to hundreds of
records, and anyone holding the records can prove they match it. The chain is the neutral notary; the database is the warehouse.

### Cryptography, kept separate
* **SHA-256** hashes records (hash chain), builds Merkle trees, and digests signed messages.
* **ECDSA P-256** signs batches and tamper events (the curve an ATECC608-class chip uses). The contract **verifies it on-chain** with a plain-Solidity
  library (`P256.sol`, about 520k gas per signature, measured in the tests). That library is **demo grade and not audited**.
* **secp256k1 / ecrecover** is used for the parties' custody signatures, which the EVM verifies natively.
* **Nonce**: a unique value in every handoff. A nonce can be used once per shipment, so an old valid approval cannot be replayed.
* **Monotonic counter**: increments on every secure-element signature and never goes back; the ledger rejects counters that are not newer.
* **Hash chain vs Merkle vs signature vs anchoring**: the chain links records in order; the Merkle root summarizes a batch; the signature proves which seal committed to that root; anchoring puts it where no single party can rewrite it.

## Run it on Windows 11 (clean machine)
Install: Git, Python 3.11+, Node.js LTS (only needed to recompile contracts), Docker Desktop (WSL2 backend), VS Code.
```
git clone <your repo> SmartSeal            (or unzip it)
cd SmartSeal
demo.bat
```
`demo.bat` checks Docker, creates `.venv`, installs requirements, generates the Besu keys and genesis with Besu itself, starts the 4 validators, waits for
blocks, deploys the contracts, starts the gateway (8000) and verifier (8100) in their own windows, seeds a shipment and opens the dashboard.
Switch the dashboard to **Real backend**; the API key is `demo-only-change-me`.

No Docker, or Docker misbehaving? `demo_nodocker.bat` runs the same contracts, gateway, custody and verifier on an in-process EVM (API key `stack-key`).
It has no validator network, so the validator panel honestly shows the Besu nodes as unreachable.

Step by step instead (CMD):
```
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
blockchain\start_network.bat
blockchain\deploy.bat
cd gateway  && python -m uvicorn app:create_app --factory --port 8000       (window 1)
cd verifier && python -m uvicorn app:create_app --factory --port 8100       (window 2)
python integration\live_demo.py seed --shipment SHP-DEMO --seal SEAL-DEMO
```
PowerShell: activate with `.venv\Scripts\Activate.ps1` (if blocked: `Set-ExecutionPolicy -Scope Process Bypass`).
Stop: `blockchain\stop_network.bat`. Start over completely: `blockchain\reset_network.bat`.

### Run all tests
```
pip install -r requirements-dev.txt
run_all_tests.bat
```
Gateway 43 tests, smart contracts 19 (real Solidity executed in an in-process EVM, including P-256 signature verification), integration 25
(end-to-end flows, verifier service, custody, 15 attack scenarios). Optional dashboard smoke test: `cd dashboard\tests`, `npm install`, start `python integration\serve_stack.py --seed`, `npm test`.

## The 5-minute live demo (real network)
1. `python integration\live_demo.py seed --shipment SHP-HOT --seal SEAL-HOT --hot 5,6` plants a genuine 10-minute excursion.
2. Dashboard > Destination verifier > **Run verification**: `QUARANTINE`, `EXCURSION_SHORT`.
3. `python integration\live_demo.py attack edit --shipment SHP-HOT` rewrites the hot readings and recomputes the whole hash chain. The chain check alone would pass.
4. Run verification again: **`REJECT` with `MERKLE_MISMATCH`**, because the ledger still holds the root committed before the edit.
5. Custody tab: "Only the sender signs" gets `NEED_BOTH_SIGNATURES`; "Reuse an old nonce" gets `NONCE_REUSED`.
6. `docker stop smartseal-node4`: still commits (3 of 4). `docker stop smartseal-node3`: no quorum, new commitments wait in the queue (Blockchain tab).
   `docker start` both: the queue drains by itself.
7. Attacks tab > **Run the attack suite**: 16 scenarios with expected vs actual, what caught it and the limitation.

## Honest limits
| limitation | status | note |
|---|---|---|
| Sensor spoofing / oracle problem | NOT SOLVED | a signature proves origin, not truth; one fooled probe is caught by probe comparison |
| Physical sensor manipulation | NOT SOLVED | heating, cooling, shielding a probe is outside what cryptography can see |
| Both redundant sensors fooled | NOT SOLVED | attack scenario 7 shows the verdict is ACCEPT |
| Laboratory-grade secure-element key extraction | NOT SOLVED | a hardware property; the mock provider keeps its key in a file |
| Physical removal and re-binding of the seal | PARTIALLY MITIGATED | binding is recorded at `startShipment`; strap and NFC tie-in are future work |
| Collusion between parties | NOT SOLVED | dual signatures show agreement, not honesty |
| Majority validator compromise | NOT SOLVED | 3 of 4 colluding validators can rewrite state |
| Off-chain data loss | PARTIALLY MITIGATED | the chain proves what existed; audit copies can restore it |
| Jamming / network outage | PARTIALLY MITIGATED | offline-first queue and `OFFLINE_GAP` flag; jamming itself is not prevented |
| Gateway compromise | PARTIALLY MITIGATED | cannot forge seal or party signatures, tampered evidence is caught, but it can withhold, delay or censor |
| Malicious firmware | NOT SOLVED | secure boot and multi-party firmware approval are not built |
| Insider misuse of admin powers | NOT SOLVED | the registry admin can assign roles and revoke participants; production needs multi-party governance |

A single SQLite file is **not** decentralized. `GET /api/export` and `POST /api/import` create audit copies so several authorized parties can each hold the evidence,
and the verifier can check a copy (`POST /verify-bundle`).

**Policy numbers** (2 to 8 °C, 15 minutes, 2.5 g, 20 minutes, 3 °C) are **demo policy values**, not universal vaccine safety limits and not a regulatory or medical certification. They are editable per shipment; their hash is anchored on-chain.

## Real vs simulated
REAL: SHA-256, Merkle trees, ECDSA P-256 and secp256k1 signing and verification, the hash chain, SQLite storage, the HTTP APIs, Solidity contracts executing on a real EVM
(Besu when you run `demo.bat`), on-chain P-256 and ecrecover verification, QBFT consensus across 4 Besu containers (`demo.bat`), the verifier and its 25 checks.
SIMULATED / STAND-IN: the physical sensors (Wokwi, or `live_demo.py`); the secure element (a software mock, **not equivalent to a physical ATECC608**: its key sits in a file);
battery, enclosure, GPS, NFC; the demo participants' keys (derived from public strings in `gateway/demo_accounts.py`, **DEMO ONLY**, anyone can compute them).
`demo_nodocker.bat` swaps only the Besu network for an in-process EVM.

## What was tested, and what was not
Verified by automated tests in a Linux sandbox: gateway logic, the compiled contracts on an in-process EVM, the verifier, custody (including Python digest equals contract digest),
15 of 16 attack scenarios, the full HTTP stack, and the dashboard's Real backend mode through a DOM emulator (19 checks).
The dashboard was also driven in a real Chromium browser against the running in-process stack (33 checks: connect, all 8 tabs, verifier ACCEPT / QUARANTINE / REJECT with `MERKLE_MISMATCH` after a genuine tamper of the gateway database, five custody attacks, audit export, wrong API key, gateway off), and its attack-suite panel finished with 15 passed, 0 failed, 1 skipped of 16.
**Not verifiable in that sandbox:** running Docker. The Besu files (`docker-compose.yml`, `prepare_network.py`, the `.bat` scripts) follow the Besu QBFT documentation and their
structure is tested, but they have not been run against real containers. The Besu image is not pinned (`hyperledger/besu:latest`, override with `BESU_IMAGE`; pin a tag you have checked).
Attack scenario 12 (validators stopped) only runs against a live network: `python -m integration.attack_tests.harness --rpc http://127.0.0.1:8545 --docker`.
Use the checklist in `blockchain/README.md` on first run.

## Ports
| port | what |
|---|---|
| 8000 | gateway (API docs at /docs) |
| 8100 | verifier service |
| 8545, 8546, 8547, 8548 | Besu JSON-RPC of node1 to node4, bound to 127.0.0.1 only |
| 30303 | Besu peer-to-peer, inside the Docker network 172.28.0.0/24 only |
dashboard: a plain file, no port.

## Environment variables
| variable | default | meaning |
|---|---|---|
| SMARTSEAL_API_KEY | demo-only-change-me | required header `X-API-Key` for write endpoints. **Change it before any tunnel** |
| SMARTSEAL_DATA_DIR / SMARTSEAL_DB | gateway\data / data\smartseal.db | database and mock secure-element keys |
| SMARTSEAL_BATCH_SIZE | 4 | records per batch |
| SMARTSEAL_CORS_ORIGINS | * | allowed browser origins |
| SMARTSEAL_POLICY_<FIELD> | see policy | e.g. `SMARTSEAL_POLICY_TEMPMAXC=8` |
| SMARTSEAL_DEPLOYMENT / _ARTIFACTS / _NETWORK | blockchain\deployment.json etc. | contract addresses, compiled contracts, node list |
| SMARTSEAL_RPC_URL | from deployment.json | JSON-RPC endpoint |
| SMARTSEAL_CHAIN | on | `off` runs the gateway without any chain (queue only) |
| SMARTSEAL_GAS_PRICE | auto | `auto` asks the node; or an integer in wei |
| SMARTSEAL_SYNC_INTERVAL | 5 | seconds between background retries of the queue (0 = off) |
| SMARTSEAL_VERIFIER_URL | http://127.0.0.1:8100 | where the gateway proxies verification |
| SMARTSEAL_KEY_<ROLE> | derived demo key | override a demo role key (ADMIN, MANUFACTURER, TRANSPORTER, WAREHOUSE, PHARMACY, REGULATOR, VERIFIER, GATEWAY) |
| BESU_IMAGE | hyperledger/besu:latest | Besu Docker image (also read by `blockchain\.env`) |
| BOOTNODE_ENODE | generated | written to `blockchain\.env` by `prepare_network.py` |

## Wokwi / ESP32
The firmware must build the hash chain itself and send records in the **canonical format** below (the gateway recomputes and rejects any mismatch).
```
{"lid":false,"light":false,"prevHash":"0","sealId":"SEAL-A1","seq":1,"shipmentId":"SHP-001","shock":0.20,"temperature1":5.20,"temperature2":5.30,"timestamp":"2026-01-01T00:05:00Z"}
SHA-256 = a79bd1e10c2b76264645634aa4daa4431a99dfc0177e206db2a2cac3b87e22dd
```
Rules: keys sorted, no whitespace, measured values with exactly 2 decimals, UTC timestamp `YYYY-MM-DDTHH:MM:SSZ`, first `prevHash` is `"0"`. POST it to `/api/record` with header `X-API-Key`.
Wokwi's default WiFi reaches the internet, not your PC: use the Wokwi IoT Gateway (paid feature) or an HTTPS tunnel (ngrok / Cloudflare Tunnel), after changing `SMARTSEAL_API_KEY`.
Sample requests and responses captured from the running system are in `integration\sample_payloads\`.

## Troubleshooting
| symptom | fix |
|---|---|
| `Docker is not running` | start Docker Desktop (WSL2 backend), wait for the whale icon to settle; or use `demo_nodocker.bat` |
| network never produces blocks | `cd blockchain && docker compose logs node1`. Make sure at least 3 containers are up (`docker ps`). Then `reset_network.bat` and `start_network.bat` |
| generator fails or image not found | check the name with `docker pull hyperledger/besu:latest`; set `BESU_IMAGE` to a tag you have checked |
| address already in use | `netstat -ano \| findstr :8000` (or 8100, 8545), end that process |
| subnet 172.28.0.0/24 conflicts | change `SUBNET_PREFIX` in `scripts/prepare_network.py` and the addresses in `docker-compose.yml` |
| dashboard says DISCONNECTED | gateway not running, wrong URL, or wrong port; the badge turns green within 4 seconds of a healthy `/api/health` |
| `LEDGER_NOT_CONNECTED` | `blockchain\deployment.json` is missing: run `blockchain\deploy.bat`, restart the gateway |
| writes return 401 | the dashboard API key box differs from `SMARTSEAL_API_KEY` |
| deploy hangs or times out | no QBFT quorum or chain not up: `python blockchain\scripts\wait_for_chain.py` |
| commitments stay queued | `GET /api/queue`: `PENDING` means the ledger is unreachable or has no quorum, `REJECTED` shows the contract's reason code |
| verdict shows `OFFLINE_GAP` unexpectedly | a batch was anchored more than 20 minutes after signing (for example the laptop slept) |
| verdict shows `POLICY_MISMATCH` | the shipment policy was changed after `startShipment`; the on-chain hash no longer matches |
| `pip install` of `web3[tester]` fails | only needed for tests; `demo.bat` does not need it |
| PowerShell blocks venv activation | `Set-ExecutionPolicy -Scope Process Bypass` |
| a `StarletteDeprecationWarning` about httpx in tests | harmless |
