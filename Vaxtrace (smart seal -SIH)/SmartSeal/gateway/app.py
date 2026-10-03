from __future__ import annotations

import hmac
import json
import sys
import threading

import httpx
from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from batching import SealService, utc_now
from blockchain import BesuLedger, ChainReader, Deployment, OfflineLedger, make_w3, qbft_status, sync_outbox
from config import Config, POLICY_DISCLAIMER, ROOT
from custody import CustodyService
from demo_accounts import demo_accounts
from hashing import sha256_hex
from merkle import merkle_levels
from models import (BatchSubmitIn, CloseIn, DemoHandoffIn, HandoffIn, ImportIn, RecordIn, RevokeIn, SealError, SealIn, ShipmentIn, TamperIn)
from secure_element import MockSecureElementProvider
from storage import Storage
from verifier import verify_integrity


def create_app(config: Config | None = None, provider=None, ledger=None, clock=None, deployment=None, accounts=None, reader=None) -> FastAPI:
    cfg = config or Config.from_env()
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    store = Storage(cfg.db_path)
    provider = provider or MockSecureElementProvider(cfg.data_dir / "mock_se")
    svc = SealService(store, provider, cfg, clock or utc_now)
    app = FastAPI(title="SmartSeal Gateway", version="0.1.0",
                  description="Off-chain evidence store, hash chain, Merkle batching and signed commitments.")
    dep = deployment
    if dep is None and cfg.chain_enabled and cfg.deployment_path.exists():
        dep = Deployment.load(cfg.deployment_path)
        if cfg.rpc_url:
            dep.rpc_url = cfg.rpc_url
    accts = accounts if accounts is not None else (demo_accounts() if dep else {})
    if ledger is None and dep is not None and cfg.chain_enabled:
        w3 = make_w3(dep.rpc_url)
        ledger = BesuLedger(w3, dep, accts, cfg.artifacts_dir, gas_price=cfg.gas_price)
        reader = ChainReader(w3, dep, cfg.artifacts_dir)
    custody = CustodyService(store, svc, dep, accts)
    app.state.store, app.state.svc, app.state.ledger, app.state.cfg = store, svc, ledger or OfflineLedger(), cfg
    app.state.reader, app.state.deployment, app.state.custody = reader, dep, custody
    sync_lock = threading.Lock()
    app.add_middleware(CORSMiddleware, allow_origins=list(cfg.cors_origins), allow_methods=["*"], allow_headers=["*"])

    def require_key(x_api_key: str | None = Header(default=None)):
        if cfg.api_key and not hmac.compare_digest((x_api_key or "").encode(), cfg.api_key.encode()):
            raise SealError("UNAUTHORIZED", "missing or wrong X-API-Key", 401)

    auth = [Depends(require_key)]

    @app.exception_handler(SealError)
    async def _seal_error(_: Request, e: SealError):
        return JSONResponse(e.body(), status_code=e.status)

    @app.exception_handler(RequestValidationError)
    async def _schema_error(_: Request, e: RequestValidationError):
        details = [{"field": ".".join(str(p) for p in x["loc"][1:]), "message": x["msg"]} for x in e.errors()]
        return JSONResponse({"error": {"code": "SCHEMA_INVALID", "message": "request failed validation", "details": details}}, status_code=422)

    def sync():
        try:
            ledger_ = app.state.ledger
            if ledger_.is_available():
                with sync_lock:
                    return sync_outbox(store, ledger_, svc.now())
        except Exception as ex:
            store.audit("gateway", "SYNC_ERROR", {"error": str(ex)}, svc.now())
        return None

    def ship_id(shipment_id):
        if shipment_id:
            if not store.get_shipment(shipment_id):
                raise SealError("WRONG_SHIPMENT", f"unknown shipment {shipment_id}", 404)
            return shipment_id
        s = store.latest_shipment()
        if not s:
            raise SealError("NO_SHIPMENT", "no shipment exists yet", 404)
        return s["shipmentId"]

    @app.get("/api/health")
    def health():
        return {"status": "ok", "service": "smartseal-gateway"}

    @app.get("/api/status")
    def status():
        latest = store.latest_shipment()
        return {"service": "smartseal-gateway", "version": app.version, "time": svc.now(),
                "seals": len(store.list_seals()), "shipments": len(store.list_shipments()),
                "records": store.count_records(), "batchSize": cfg.batch_size,
                "queuePending": store.pending_count(), "ledger": app.state.ledger.status(),
                "latestShipment": latest["shipmentId"] if latest else None,
                "defaultPolicy": cfg.default_policy, "policyDisclaimer": POLICY_DISCLAIMER,
                "simulated": {"secureElement": type(provider).__name__,
                              "note": "Mock secure element keeps its key in a file: NOT equivalent to a physical ATECC608."},
                "chain": {"deployment": bool(dep), "reader": app.state.reader is not None, "chainId": dep.chain_id if dep else None},
                "storage": "single local SQLite file (not decentralized); use /api/export and /api/import for audit copies"}

    @app.post("/api/seals", status_code=201, dependencies=auth)
    def create_seal(body: SealIn):
        out = svc.register_seal(body.sealId, body.manufacturer, body.publicKey); sync(); return out

    @app.get("/api/seals")
    def seals():
        return store.list_seals()

    @app.post("/api/seals/{seal_id}/revoke", dependencies=auth)
    def revoke(seal_id: str, body: RevokeIn):
        out = svc.revoke_seal(seal_id, body.by); sync(); return out

    @app.post("/api/shipments", status_code=201, dependencies=auth)
    def create_shipment(body: ShipmentIn):
        out = svc.start_shipment(body.shipmentId, body.sealId, body.policy); sync(); return out

    @app.get("/api/shipments")
    def shipments():
        return store.list_shipments()

    @app.post("/api/record", status_code=201, dependencies=auth)
    def post_record(body: RecordIn):
        rec, batch, dup = svc.ingest_record(body); sync()
        return {"record": rec, "duplicate": dup, "batchClosed": batch}

    @app.get("/api/records")
    def records(shipmentId: str | None = None, fromSeq: int = 1, limit: int = 500, offset: int = 0):
        sid = ship_id(shipmentId)
        return {"shipmentId": sid, "records": store.list_records(sid, fromSeq, min(limit, 5000), offset)}

    @app.get("/api/records/latest")
    def latest(shipmentId: str | None = None):
        sid = ship_id(shipmentId)
        rec = store.last_record(sid)
        if not rec:
            raise SealError("NO_RECORDS", "no records yet", 404)
        return rec

    @app.get("/api/verify-chain")
    def verify_chain(shipmentId: str | None = None):
        sid = ship_id(shipmentId)
        ship = store.get_shipment(sid)
        seal = store.get_seal(ship["sealId"])
        res = verify_integrity(store.list_records(sid, 1, 100000), store.list_batches(sid), store.list_tamper(sid), seal["publicKey"])
        return {"shipmentId": sid, "scope": "gateway-local check of its own database; NOT an independent verification", **res}

    @app.post("/api/batch/close", dependencies=auth)
    def close_batch(body: CloseIn):
        b = svc.close_batch(body.shipmentId, force=True); sync()
        return {"batch": b, "note": None if b else "no unbatched records"}

    @app.post("/api/batch/submit", status_code=201, dependencies=auth)
    def submit_batch(body: BatchSubmitIn):
        b = svc.submit_signed_batch(body); sync(); return b

    @app.get("/api/batches")
    def batches(shipmentId: str | None = None):
        sid = ship_id(shipmentId)
        return {"shipmentId": sid, "batches": store.list_batches(sid)}

    @app.get("/api/batches/{batch_id}")
    def batch(batch_id: int, shipmentId: str | None = None):
        sid = ship_id(shipmentId)
        b = store.get_batch(sid, batch_id)
        if not b:
            raise SealError("NO_BATCH", f"batch {batch_id} not found", 404)
        recs = store.records_between(sid, b["firstSeq"], b["lastSeq"])
        leaves = [r["hash"] for r in recs]
        return {**b, "records": recs, "merkle": {"leaves": leaves, "levels": merkle_levels(leaves) if leaves else []}}

    @app.post("/api/tamper-event", status_code=201, dependencies=auth)
    def tamper(body: TamperIn):
        e = svc.record_tamper(body); sync(); return e

    @app.get("/api/tamper-events")
    def tamper_events(shipmentId: str | None = None):
        return {"events": store.list_tamper(ship_id(shipmentId))}

    @app.get("/api/queue")
    def queue():
        return {"pending": store.pending_count(), "items": store.list_outbox()}

    @app.post("/api/queue/sync", dependencies=auth)
    def queue_sync():
        if not app.state.ledger.is_available():
            return {"anchored": 0, "rejected": 0, "pending": store.pending_count(), "stoppedBecause": "ledger unavailable"}
        with sync_lock:
            return sync_outbox(store, app.state.ledger, svc.now())

    @app.get("/api/audit")
    def audit(limit: int = 200):
        return {"entries": store.list_audit(min(limit, 1000))}

    @app.get("/api/export")
    def export(shipmentId: str | None = None):
        sid = ship_id(shipmentId)
        ship = store.get_shipment(sid)
        bundle = {"schema": "smartseal-evidence/v1", "exportedAt": svc.now(), "seal": store.get_seal(ship["sealId"]),
                  "shipment": ship, "records": store.list_records(sid, 1, 100000), "batches": store.list_batches(sid),
                  "tamperEvents": store.list_tamper(sid), "custody": store.list_custody(sid)}
        return {"bundle": bundle, "bundleHash": sha256_hex(json.dumps(bundle, sort_keys=True, separators=(",", ":")))}

    @app.post("/api/import", status_code=201, dependencies=auth)
    def import_copy(body: ImportIn):
        b = body.bundle
        try:
            res = verify_integrity(b["records"], b["batches"], b["tamperEvents"], b["seal"]["publicKey"])
            sid = b["shipment"]["shipmentId"]
        except (KeyError, TypeError) as e:
            raise SealError("BUNDLE_INVALID", f"bundle malformed: {e}", 422)
        h = sha256_hex(json.dumps(b, sort_keys=True, separators=(",", ":")))
        store.add_audit_copy(sid, h, svc.now(), json.dumps(b))
        store.audit("gateway", "AUDIT_COPY_IMPORTED", {"shipmentId": sid, "bundleHash": h}, svc.now())
        return {"stored": True, "bundleHash": h, "selfConsistency": res}

    @app.get("/api/audit-copies")
    def audit_copies():
        return {"copies": store.list_audit_copies()}

    @app.post("/api/custody/handoff", status_code=201, dependencies=auth)
    def custody_handoff(body: HandoffIn):
        out = custody.submit(body); sync(); return out

    @app.post("/api/custody/demo-handoff", status_code=201, dependencies=auth)
    def custody_demo(body: DemoHandoffIn):
        out = custody.demo_handoff(body); sync(); return out

    @app.get("/api/custody")
    def custody_state(shipmentId: str | None = None):
        return custody.state(ship_id(shipmentId))

    def network():
        try:
            return json.loads(cfg.network_path.read_text())["nodes"]
        except Exception:
            names = ["Manufacturer", "Transporter", "Pharmacy", "Regulator"]
            return [{"name": n, "rpc": f"http://127.0.0.1:{8545 + i}"} for i, n in enumerate(names)]

    def chain():
        if app.state.reader is None:
            raise SealError("LEDGER_NOT_CONNECTED", "no deployment.json found; deploy the contracts first (see blockchain/README.md)", 503)
        return app.state.reader

    def chain_call(fn):
        try:
            return fn()
        except SealError:
            raise
        except Exception as e:
            raise SealError("LEDGER_UNAVAILABLE", f"{type(e).__name__}: {e}", 503)

    @app.get("/api/blockchain/status")
    def bc_status():
        nodes = network()
        out = {"ledger": app.state.ledger.status(), "queuePending": store.pending_count(),
               "qbft": qbft_status([n["rpc"] for n in nodes], [n["name"] for n in nodes])}
        if dep:
            out["deployment"] = {"chainId": dep.chain_id, "contracts": dep.addresses, "deployedAt": dep.deployed_at}
        return out

    @app.get("/api/blockchain/validators")
    def bc_validators():
        nodes = network()
        return qbft_status([n["rpc"] for n in nodes], [n["name"] for n in nodes])

    @app.get("/api/blockchain/blocks")
    def bc_blocks(limit: int = 10):
        return {"blocks": chain_call(lambda: chain().blocks(min(max(limit, 1), 50)))}

    @app.get("/api/blockchain/shipments/{shipment_id}")
    def bc_shipment(shipment_id: str):
        def go():
            r = chain(); sh = r.shipment(shipment_id)
            if not sh:
                raise SealError("WRONG_SHIPMENT", f"shipment {shipment_id} is not on the chain", 404)
            return {"shipment": sh, "seal": r.seal(sh["sealId"]), "batchCount": len(r.batches(shipment_id)),
                    "tamperCount": len(r.tamper_events(shipment_id)), "handoffCount": len(r.handoffs(shipment_id)),
                    "lastCounter": r.last_counter(sh["sealId"]), "verdict": r.verdict(shipment_id)}
        return chain_call(go)

    @app.get("/api/blockchain/batches/{shipment_id}")
    def bc_batches(shipment_id: str):
        return chain_call(lambda: {"shipmentId": shipment_id, "batches": chain().batches(shipment_id), "tamperEvents": chain().tamper_events(shipment_id)})

    @app.get("/api/blockchain/custody/{shipment_id}")
    def bc_custody(shipment_id: str):
        return chain_call(lambda: {"shipmentId": shipment_id, "handoffs": chain().handoffs(shipment_id)})

    @app.get("/api/verifier/result")
    def verifier_result(shipmentId: str | None = None):
        sid = ship_id(shipmentId)
        try:
            r = httpx.get(f"{cfg.verifier_url}/result", params={"shipmentId": sid}, timeout=10)
            return JSONResponse(r.json(), status_code=r.status_code)
        except httpx.HTTPError as e:
            raise SealError("VERIFIER_UNAVAILABLE", f"verifier service not reachable at {cfg.verifier_url}: {type(e).__name__}", 503)

    @app.post("/api/verifier/run", dependencies=auth)
    def verifier_run(request: Request, shipmentId: str | None = None, finalize: bool = False):
        sid = ship_id(shipmentId)
        try:
            r = httpx.post(f"{cfg.verifier_url}/verify", json={"shipmentId": sid, "gatewayUrl": str(request.base_url).rstrip("/"), "finalize": finalize}, timeout=120)
            return JSONResponse(r.json(), status_code=r.status_code)
        except httpx.HTTPError as e:
            raise SealError("VERIFIER_UNAVAILABLE", f"verifier service not reachable at {cfg.verifier_url}: {type(e).__name__}", 503)

    attack = {"running": False, "error": None}
    report_path = cfg.data_dir / "attack_report.json"

    @app.get("/api/attacks")
    def attacks():
        rep = json.loads(report_path.read_text()) if report_path.exists() else None
        return {"running": attack["running"], "error": attack["error"], "report": rep}

    @app.post("/api/attacks/run", status_code=202, dependencies=auth)
    def attacks_run():
        if attack["running"]:
            raise SealError("ATTACKS_RUNNING", "the attack suite is already running", 409)

        def work():
            attack.update(running=True, error=None)
            try:
                sys.path.insert(0, str(ROOT))
                from integration.attack_tests.harness import run_all, save_report
                save_report(run_all(), report_path)
            except Exception as e:
                attack["error"] = f"{type(e).__name__}: {e}"
            finally:
                attack["running"] = False
        threading.Thread(target=work, daemon=True).start()
        return {"started": True, "note": "runs on its own in-memory test chain; poll GET /api/attacks"}

    if cfg.sync_interval > 0:
        def loop():
            stop = threading.Event()
            while not stop.wait(cfg.sync_interval):
                sync()
        threading.Thread(target=loop, daemon=True).start()

    return app
