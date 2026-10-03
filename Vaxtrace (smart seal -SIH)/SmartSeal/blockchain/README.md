# Blockchain layer

## Contracts (`contracts/`, Solidity ^0.8.20, compiled for the London EVM)
| contract | purpose | key functions (revert strings are the machine-readable codes) |
|---|---|---|
| `SmartSealRegistry` | roles, seals, shipments | `setRole`, `revokeParticipant`, `registerSeal` (MANUFACTURER, key must be on the P-256 curve), `revokeSeal` (REGULATOR, or the seal's manufacturer), `startShipment` (binds seal, policy hash, initial custodian), `closeShipment` (verdict module only) |
| `BatchAnchor` | Merkle roots and tamper events | `commitBatchRoot`, `recordTamperEvent`: rebuild the exact canonical message, verify the **ECDSA P-256** signature against the registered seal key, enforce `STALE_COUNTER`, `BATCH_SEQUENCE_ERROR`, `PREV_ROOT_MISMATCH`, `SEAL_REVOKED`, `WRONG_SEAL`, `WRONG_SHIPMENT`, `SHIPMENT_INACTIVE`. Only the GATEWAY role may relay |
| `ShipmentCustody` | dual-signature handoffs | `transferCustody`: both signatures recovered with `ecrecover`; `NEED_BOTH_SIGNATURES`, `NONCE_REUSED`, `NOT_CURRENT_CUSTODIAN`, `ROUTE_VIOLATION`, `ROUTE_COMPLETE`, `PARTICIPANT_REVOKED`, `BAD_SIGNATURE_FROM/TO`, `MALFORMED_SIGNATURE` |
| `VerdictRegistry` | final decision | `finalizeVerdict` (VERIFIER, PHARMACY or REGULATOR): stores verdict, reason codes, report hash, issuer; closes the shipment; one verdict per shipment |
| `P256` (library) | P-256 verification in Solidity | **demo grade, not audited**, about 520k gas per signature |

Stored per the brief: seal (id, public key, manufacturer, revoked); shipment (id, seal, current custodian, active, policy reference); batch (id, seal, shipment, root, first/last seq, count, counter, timestamp); custody (from, to, nonce, atSeq, both signatures, timestamp); tamper event (type, seq, counter, signature, timestamp); verdict (value, reasons, verifier, timestamp).

Trust model: admin (deploys, assigns roles) is a single demo key. Participants never need gas-paying infrastructure: the gateway relays their signed messages, and cannot forge them.

## Compile and test
```
cd blockchain
npm install            (installs solc-js)
node scripts\compile.js            writes artifacts\*.json (already included in the zip)
cd tests && python -m pytest -q    (needs pip install -r ..\..\requirements-dev.txt)
```
Hardhat is not used: it downloads compilers from a host that could not be tested in the build environment, so compilation uses `solc-js` directly.

## Besu QBFT network
`start_network.bat` does everything: `scripts\prepare_network.py` runs Besu's own `operator generate-blockchain-config` through Docker (validator keys and the QBFT genesis `extraData`),
pre-funds the demo accounts in the genesis, copies each key to `nodes\nodeN\key`, writes `nodes\network.json` and `.env` (bootnode enode); then `docker compose up -d`.
Chain id 2026, block period 2 s, London rules, RPC only on 127.0.0.1. Validators: node1 Manufacturer, node2 Transporter, node3 Pharmacy, node4 Regulator.
**QBFT needs 2f+1 of N validators: 3 of 4.** Permissioning is by validator set (only validators seal blocks) and by contract roles; node-level allowlisting is not enabled.

### First-run checklist (I could not run Docker while building this)
1. `docker version` works, Docker Desktop is running.
2. `start_network.bat` ends with `chain is sealing blocks`. If not: `docker compose logs node1`, and confirm `docker ps` lists 4 `smartseal-node*` containers.
3. `curl http://127.0.0.1:8545 -X POST -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"method\":\"qbft_getValidatorsByBlockNumber\",\"params\":[\"latest\"],\"id\":1}"` lists 4 addresses.
4. `deploy.bat` prints four contract addresses. 5. `python integration\attack_tests\harness.py --rpc http://127.0.0.1:8545` passes 15 scenarios (12 needs `--docker`).
If the image tag or a flag differs in your Besu version, fix `docker-compose.yml` (all four services use the same flags) and report the error text.

### Quorum demo
`docker stop smartseal-node4` then send a record: still commits. `docker stop smartseal-node3`: no quorum; the gateway keeps the commitment in its queue; the dashboard Blockchain tab
shows `2 of 4 reachable, QBFT needs 3`. `docker start smartseal-node3 smartseal-node4`: the queue drains. The gateway reads real JSON-RPC answers; nothing is faked.

### Single-node fallback
If the 4-node network gives trouble, any EVM JSON-RPC works for the contracts and the gateway (set `SMARTSEAL_RPC_URL`, run `deploy.bat`). `demo_nodocker.bat` uses an in-process EVM for the same purpose.

DEMO ONLY: validator keys in `nodes\` and the participant keys are not secret. Never reuse them.
