from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import verification
from blockchain import BesuLedger, ChainReader, Deployment, LedgerRejected, LedgerUnavailable, make_w3
from config import Config
from demo_accounts import demo_accounts
from verification.engine import Verifier
from verification.evidence import BundleEvidence, HttpEvidence


class VerifyIn(BaseModel):
    shipmentId: str
    gatewayUrl: str = "http://127.0.0.1:8000"
    finalize: bool = False
    policyOverride: dict | None = None


class BundleIn(BaseModel):
    shipmentId: str
    bundle: dict
    finalize: bool = False


def create_app(reader=None, ledger=None, results_path=None) -> FastAPI:
    cfg = Config.from_env()
    if reader is None:
        if not cfg.deployment_path.exists():
            raise SystemExit(f"no deployment file at {cfg.deployment_path}: deploy the contracts first (blockchain/README.md)")
        dep = Deployment.load(cfg.deployment_path)
        if cfg.rpc_url:
            dep.rpc_url = cfg.rpc_url
        w3 = make_w3(dep.rpc_url)
        reader = ChainReader(w3, dep, cfg.artifacts_dir)
        ledger = ledger or BesuLedger(w3, dep, demo_accounts(), cfg.artifacts_dir, gas_price=cfg.gas_price)
    path = Path(results_path) if results_path else cfg.data_dir / "verifier_results.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    results = json.loads(path.read_text()) if path.exists() else {}
    app = FastAPI(title="SmartSeal Verifier", version="0.1.0")
    app.add_middleware(CORSMiddleware, allow_origins=list(cfg.cors_origins), allow_methods=["*"], allow_headers=["*"])

    def finish(sid, result, finalize):
        if finalize and ledger is not None:
            try:
                if reader.verdict(sid):
                    result["finalized"] = {"status": "already-final", "onChain": reader.verdict(sid)}
                else:
                    rc = ledger.submit("VERDICT", {"shipmentId": sid, "verdict": result["verdict"], "reasonCodes": result["codes"], "reportHash": result["reportHash"]})
                    result["finalized"] = {"status": "on-chain", "txHash": rc.tx_hash}
            except (LedgerRejected, LedgerUnavailable) as e:
                result["finalized"] = {"status": "failed", "error": str(e)}
        results[sid] = result
        path.write_text(json.dumps(results))
        return result

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "smartseal-verifier", "chainConnected": reader.connected()}

    @app.post("/verify")
    def verify(body: VerifyIn):
        result = Verifier(reader, HttpEvidence(body.gatewayUrl)).run(body.shipmentId, body.policyOverride)
        return finish(body.shipmentId, result, body.finalize)

    @app.post("/verify-bundle")
    def verify_bundle(body: BundleIn):
        return finish(body.shipmentId, Verifier(reader, BundleEvidence(body.bundle)).run(body.shipmentId), body.finalize)

    @app.get("/result")
    def result(shipmentId: str):
        if shipmentId not in results:
            return JSONResponse({"error": {"code": "NO_RESULT", "message": "no verification has been run for this shipment yet"}}, status_code=404)
        return results[shipmentId]

    return app
