from __future__ import annotations

import os
from datetime import datetime

from eth_abi import encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak

from models import DemoHandoffIn, HandoffIn, SealError

ROUTE = ("MANUFACTURER", "TRANSPORTER", "WAREHOUSE", "PHARMACY")
HANDOFF_TYPEHASH = keccak(text="SmartSealHandoff/v1")


def handoff_digest(chain_id: int, custody_address: str, shipment_id: str, frm: str, to: str, nonce: str, at_seq: int, timestamp: str) -> bytes:
    return keccak(encode(
        ["bytes32", "uint256", "address", "bytes32", "address", "address", "bytes32", "uint64", "bytes32"],
        [HANDOFF_TYPEHASH, chain_id, custody_address, keccak(text=shipment_id), frm, to, bytes.fromhex(nonce[2:]), at_seq, keccak(text=timestamp)]))


def sign_digest(account, digest: bytes) -> str:
    return "0x" + bytes(account.sign_message(encode_defunct(primitive=digest)).signature).hex()


def recover_signer(digest: bytes, signature: str) -> str | None:
    try:
        return Account.recover_message(encode_defunct(primitive=digest), signature=signature)
    except Exception:
        return None


class CustodyService:
    def __init__(self, store, svc, deployment, accounts=None):
        self.store, self.svc, self.dep, self.accounts = store, svc, deployment, accounts or {}

    def _require_deployment(self):
        if self.dep is None or not self.dep.participants:
            raise SealError("DEPLOYMENT_REQUIRED", "custody needs deployed contracts (run blockchain/scripts/deploy.py)", 503)

    def state(self, shipment_id: str) -> dict:
        hs = self.store.list_custody(shipment_id)
        stage = len(hs)
        return {"shipmentId": shipment_id, "route": list(ROUTE), "handoffs": hs, "stage": stage,
                "currentCustodianRole": ROUTE[min(stage, 3)], "complete": stage >= 3}

    def submit(self, body: HandoffIn) -> dict:
        self._require_deployment()
        with self.store.transaction():
            ship = self.store.get_shipment(body.shipmentId)
            if not ship or ship["status"] != "ACTIVE":
                raise SealError("WRONG_SHIPMENT", f"shipment {body.shipmentId} not found or not active", 409)
            if not body.sigFrom or not body.sigTo:
                raise SealError("NEED_BOTH_SIGNATURES", "a custody transfer needs the sender AND the receiver signature", 409)
            if self.store.nonce_used(body.shipmentId, body.nonce):
                raise SealError("NONCE_REUSED", "this nonce was already used for the shipment (replay)", 409)
            stage = len(self.store.list_custody(body.shipmentId))
            if stage >= 3:
                raise SealError("ROUTE_COMPLETE", "custody already reached the pharmacy", 409)
            if body.fromRole != ROUTE[stage]:
                raise SealError("NOT_CURRENT_CUSTODIAN", f"{body.fromRole} is not the current custodian ({ROUTE[stage]})", 409)
            if body.toRole != ROUTE[stage + 1]:
                raise SealError("ROUTE_VIOLATION", f"next custodian must be {ROUTE[stage + 1]}", 409)
            frm, to = self.dep.participants[body.fromRole], self.dep.participants[body.toRole]
            digest = handoff_digest(self.dep.chain_id, self.dep.addresses["custody"], body.shipmentId, frm, to, body.nonce, body.atSeq, body.timestamp)
            for label, sig, who in (("FROM", body.sigFrom, frm), ("TO", body.sigTo, to)):
                got = recover_signer(digest, sig)
                if got is None:
                    raise SealError("MALFORMED_SIGNATURE", f"{label} signature cannot be recovered", 422)
                if got.lower() != who.lower():
                    raise SealError(f"BAD_SIGNATURE_{label}", f"{label} signature was not made by {body.fromRole if label == 'FROM' else body.toRole}", 409)
            rec = {"shipmentId": body.shipmentId, "fromRole": body.fromRole, "toRole": body.toRole, "fromAddress": frm, "toAddress": to,
                   "nonce": body.nonce, "atSeq": body.atSeq, "timestamp": body.timestamp, "sigFrom": body.sigFrom, "sigTo": body.sigTo}
            self.store.add_custody(rec)
            self.store.enqueue("HANDOFF", rec, self.svc.now())
            self.store.audit(body.fromRole, "CUSTODY_HANDOFF", {"shipmentId": body.shipmentId, "to": body.toRole, "nonce": body.nonce}, self.svc.now())
        return rec

    def demo_handoff(self, body: DemoHandoffIn) -> dict:
        self._require_deployment()
        frm, to = self.accounts.get(body.fromRole), self.accounts.get(body.toRole)
        if frm is None or to is None:
            raise SealError("DEMO_KEYS_MISSING", "demo signing keys are not loaded in this gateway", 503)
        last = self.store.last_record(body.shipmentId)
        hs = self.store.list_custody(body.shipmentId)
        nonce = hs[-1]["nonce"] if (body.mode == "reuse_nonce" and hs) else "0x" + os.urandom(32).hex()
        ts, at_seq = self.svc.now(), (last["seq"] if last else 0)
        digest = handoff_digest(self.dep.chain_id, self.dep.addresses["custody"], body.shipmentId, frm.address, to.address, nonce, at_seq, ts)
        sig_from = sign_digest(frm, digest) if body.mode != "receiver_only" else None
        sig_to = sign_digest(to, digest) if body.mode not in ("sender_only",) else None
        if body.mode == "wrong_receiver_signer":
            sig_to = sign_digest(self.accounts["REGULATOR"], digest)
        return self.submit(HandoffIn(shipmentId=body.shipmentId, fromRole=body.fromRole, toRole=body.toRole, nonce=nonce,
                                     atSeq=at_seq, timestamp=ts, sigFrom=sig_from, sigTo=sig_to))
