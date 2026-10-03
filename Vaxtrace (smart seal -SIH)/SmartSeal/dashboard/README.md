# Dashboard

`index.html` is the one file to open (double-click it). A bar at the top switches between two modes.

**Simulation** (default) is fully self-contained and needs nothing running. It opens with a one-minute guide
("New here?": what it is, four steps to try, what ACCEPT / QUARANTINE / REJECT mean, a plain-English glossary), then the
seal, the transporter's editable records, 16 attack and policy scenarios, the destination verifier, custody, the validators,
a self-test, a guided demo, an audit-JSON export and the India vaccine cold-chain case study. Hashes, signatures and Merkle
roots are computed for real in the browser; sensors, the secure element and the four validators are stand-ins.

**Real backend** reads the running gateway, the blockchain and the verifier service. Eight tabs: Hardware, Records,
Cryptographic evidence, Custody, Blockchain, Attacks, Destination verifier, India case study. The badge shows
`LIVE BACKEND: CONNECTED / DISCONNECTED`; if the backend is off, nothing breaks and the simulation still works.

## Connect
| how you started the backend | gateway URL | API key |
|---|---|---|
| `demo.bat` (Besu network in Docker) | `http://127.0.0.1:8000` | `demo-only-change-me` (pre-filled) |
| `demo_nodocker.bat` / `integration\serve_stack.py` | `http://127.0.0.1:8000` | `stack-key` (type it in) |

Then pick a shipment in the bar. Export audit report downloads `audit-report.json` and a printable `audit-report.html`
(records, hash-chain status, batches, roots, signatures, counters, custody, tamper events, chain references, validator
state, checks, verdict, reason codes, limitations).

## Things to know
* **Reads are open, writes need the key.** The gateway checks `X-API-Key` on every POST (records, custody, revoke, import,
  verifier run, attack suite) and not on GET. With a wrong key the tabs still display data, and the buttons that write
  (Run verification, custody handoffs, Run the attack suite) fail with `401`. Reads and CORS (`*`) are open for the demo only.
* **The attack suite takes about a minute** (16 scenarios, each on its own fresh in-memory chain, so live data is never touched).
  Scenario 12 (validator compromise) is shown as SKIPPED unless a live Besu network is running.
* **Without Docker the Blockchain tab says "0 of 4 validators reachable"**, because there is no validator network, only an
  in-process EVM running the same contracts. That is the honest state, not a fault. Use `demo.bat` for the real Besu network.
* **The India case study tab runs the browser simulation**, not the live backend.
* **Hosting the file online** (for example GitHub Pages) gives visitors the Simulation mode. Real backend mode calls a
  gateway on your own machine, so run it locally for that demo.
* The source pieces of the injected parts are in `parts/` (`modebar.html`, `live.html`, `live.css`, `live.js`, `guide.html`,
  `guide.css`). `index.html` is the assembled single file.

## Tests
`tests/smoke.test.js` drives Real backend mode in a DOM emulator against a running stack:
```
python integration\serve_stack.py --seed        (one window)
cd dashboard\tests && npm install && npm test   (another window)
```
