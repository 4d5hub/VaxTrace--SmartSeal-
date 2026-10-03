from __future__ import annotations

from datetime import datetime, timezone

from config import Config, POLICY_DISCLAIMER
from hashing import ZERO_HASH, ZERO_ROOT, batch_payload, canonical, parse_ts, record_hash, sha256_hex, tamper_payload
from merkle import merkle_root
from models import BatchSubmitIn, RecordIn, SealError, TamperIn
from secure_element import SecureElementProvider, is_valid_public_key, verify_signature

MANUFACTURER_ROLES = ("MANUFACTURER", "REGULATOR")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def policy_hash(policy: dict) -> str:
    return sha256_hex(canonical({k: str(v) for k, v in sorted(policy.items())}))


class SealService:
    def __init__(self, store, provider: SecureElementProvider, cfg: Config, clock=utc_now):
        self.store, self.provider, self.cfg, self.now = store, provider, cfg, clock

    def register_seal(self, seal_id: str, manufacturer: str, public_key: str | None = None) -> dict:
        with self.store.transaction():
            if self.store.get_seal(seal_id):
                raise SealError("SEAL_EXISTS", f"seal {seal_id} already registered")
            if public_key is None:
                public_key, provisioning = self.provider.provision(seal_id), "MOCK_SECURE_ELEMENT"
            else:
                if not is_valid_public_key(public_key):
                    raise SealError("BAD_PUBLIC_KEY", "not a valid P-256 uncompressed public key", 422)
                provisioning = "EXTERNAL_KEY"
            self.store.add_seal(seal_id, public_key, manufacturer, provisioning, self.now())
            self.store.enqueue("REGISTER_SEAL", {"sealId": seal_id, "publicKey": public_key, "manufacturer": manufacturer}, self.now())
            self.store.audit("gateway", "SEAL_REGISTERED", {"sealId": seal_id, "provisioning": provisioning}, self.now())
        return self.store.get_seal(seal_id)

    def revoke_seal(self, seal_id: str, by: str) -> dict:
        if by not in MANUFACTURER_ROLES:
            raise SealError("ROLE_DENIED", f"{by} may not revoke seals", 403)
        with self.store.transaction():
            if not self.store.get_seal(seal_id):
                raise SealError("WRONG_SEAL", f"unknown seal {seal_id}", 404)
            self.store.revoke_seal(seal_id)
            self.store.enqueue("REVOKE_SEAL", {"sealId": seal_id, "by": by}, self.now())
            self.store.audit(by, "SEAL_REVOKED", {"sealId": seal_id}, self.now())
        return self.store.get_seal(seal_id)

    def merge_policy(self, overrides: dict | None) -> dict:
        policy = dict(self.cfg.default_policy)
        for k, v in (overrides or {}).items():
            if k not in policy:
                raise SealError("SCHEMA_INVALID", f"unknown policy field {k}", 422)
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
                raise SealError("SCHEMA_INVALID", f"policy field {k} must be a positive number", 422)
            policy[k] = type(policy[k])(v)
        if policy["tempMinC"] >= policy["tempMaxC"]:
            raise SealError("SCHEMA_INVALID", "tempMinC must be below tempMaxC", 422)
        return policy

    def start_shipment(self, shipment_id: str, seal_id: str, overrides: dict | None) -> dict:
        with self.store.transaction():
            seal = self.store.get_seal(seal_id)
            if not seal:
                raise SealError("WRONG_SEAL", f"unknown seal {seal_id}", 404)
            if seal["revoked"]:
                raise SealError("SEAL_REVOKED", f"seal {seal_id} is revoked", 403)
            if self.store.get_shipment(shipment_id):
                raise SealError("SHIPMENT_EXISTS", f"shipment {shipment_id} already exists")
            if self.store.active_shipment_for_seal(seal_id):
                raise SealError("SEAL_BUSY", f"seal {seal_id} already has an active shipment")
            policy = self.merge_policy(overrides)
            self.store.add_shipment(shipment_id, seal_id, policy, self.now())
            self.store.enqueue("START_SHIPMENT", {"shipmentId": shipment_id, "sealId": seal_id, "policyHash": policy_hash(policy)}, self.now())
            self.store.audit("gateway", "SHIPMENT_STARTED", {"shipmentId": shipment_id, "sealId": seal_id, "disclaimer": POLICY_DISCLAIMER}, self.now())
        return self.store.get_shipment(shipment_id)

    def _context(self, seal_id: str, shipment_id: str):
        seal = self.store.get_seal(seal_id)
        if not seal:
            raise SealError("WRONG_SEAL", f"seal {seal_id} is not registered", 409)
        if seal["revoked"]:
            raise SealError("SEAL_REVOKED", f"seal {seal_id} is revoked", 403)
        ship = self.store.get_shipment(shipment_id)
        if not ship or ship["sealId"] != seal_id:
            raise SealError("WRONG_SHIPMENT", f"shipment {shipment_id} does not belong to seal {seal_id}", 409)
        if ship["status"] != "ACTIVE":
            raise SealError("SHIPMENT_INACTIVE", f"shipment {shipment_id} is {ship['status']}", 409)
        return seal, ship

    def ingest_record(self, rec: RecordIn) -> tuple:
        data = rec.model_dump()
        with self.store.transaction():
            self._context(data["sealId"], data["shipmentId"])
            computed = record_hash(data)
            if data["hash"] is not None and data["hash"] != computed:
                raise SealError("HASH_MISMATCH", "supplied hash does not match the canonical record", 422, {"computed": computed})
            data["hash"] = computed
            last = self.store.last_record(data["shipmentId"])
            if last and data["seq"] <= last["seq"]:
                existing = self.store.get_record(data["shipmentId"], data["seq"])
                if existing and existing["hash"] == computed:
                    return existing, None, True
                raise SealError("SEQ_DUPLICATE", f"seq {data['seq']} already stored with different content")
            expected = last["seq"] + 1 if last else 1
            if data["seq"] != expected:
                raise SealError("SEQ_GAP", f"expected seq {expected}, got {data['seq']}", 409, {"expectedSeq": expected})
            want_prev = last["hash"] if last else ZERO_HASH
            if data["prevHash"] != want_prev:
                raise SealError("PREV_HASH_MISMATCH", "prevHash does not match the previous record", 409, {"expectedPrevHash": want_prev})
            if last and parse_ts(data["timestamp"]) < parse_ts(last["timestamp"]):
                raise SealError("TIMESTAMP_ORDER", "timestamp is earlier than the previous record")
            self.store.insert_record(data, self.now())
            batch = None
            mock_signs = self.store.get_seal(data["sealId"])["provisioning"] == "MOCK_SECURE_ELEMENT"
            if mock_signs and len(self.store.unbatched_records(data["shipmentId"])) >= self.cfg.batch_size:
                batch = self.close_batch(data["shipmentId"], force=False)
        return data, batch, False

    def close_batch(self, shipment_id: str, force: bool = True):
        with self.store.transaction():
            ship = self.store.get_shipment(shipment_id)
            if not ship:
                raise SealError("WRONG_SHIPMENT", f"unknown shipment {shipment_id}", 404)
            self._context(ship["sealId"], shipment_id)
            if self.store.get_seal(ship["sealId"])["provisioning"] != "MOCK_SECURE_ELEMENT":
                raise SealError("DEVICE_SIGNS", "this seal signs its own batches; send them to /api/batch/submit", 409)
            pending = self.store.unbatched_records(shipment_id, None if force else self.cfg.batch_size)
            if not pending:
                return None
            last = self.store.last_batch(shipment_id)
            meta = {"sealId": ship["sealId"], "shipmentId": shipment_id,
                    "batchId": (last["batchId"] + 1) if last else 1,
                    "firstSeq": pending[0]["seq"], "lastSeq": pending[-1]["seq"], "count": len(pending),
                    "prevRoot": last["root"] if last else ZERO_ROOT,
                    "root": merkle_root([r["hash"] for r in pending]), "timestamp": self.now()}
            signed = self.provider.sign_counted(ship["sealId"], lambda c: batch_payload(meta, c))
            batch = {**meta, "counter": signed.counter, "signature": signed.signature}
            self.store.insert_batch(batch)
            self.store.set_last_counter(ship["sealId"], signed.counter)
            self.store.enqueue("BATCH", batch, self.now())
            self.store.audit("secure-element(mock)", "BATCH_SIGNED", {"shipmentId": shipment_id, "batchId": meta["batchId"], "counter": signed.counter}, self.now())
            return self.store.get_batch(shipment_id, meta["batchId"])

    def submit_signed_batch(self, sub: BatchSubmitIn) -> dict:
        b = sub.model_dump()
        with self.store.transaction():
            seal, ship = self._context(b["sealId"], b["shipmentId"])
            if not verify_signature(seal["publicKey"], batch_payload(b, b["counter"]), b["signature"]):
                raise SealError("SIGNATURE_INVALID", "not signed by the registered secure-element key", 401)
            if b["counter"] <= seal["lastCounter"]:
                raise SealError("STALE_COUNTER", f"counter {b['counter']} <= last accepted {seal['lastCounter']} (replay)", 409)
            last = self.store.last_batch(b["shipmentId"])
            if b["batchId"] != ((last["batchId"] + 1) if last else 1):
                raise SealError("BATCH_SEQUENCE_ERROR", f"unexpected batchId {b['batchId']}", 409)
            if b["prevRoot"] != (last["root"] if last else ZERO_ROOT):
                raise SealError("PREV_ROOT_MISMATCH", "prevRoot does not chain to the previous batch", 409)
            if b["firstSeq"] != ((last["lastSeq"] + 1) if last else 1) or b["count"] != b["lastSeq"] - b["firstSeq"] + 1:
                raise SealError("BATCH_SEQUENCE_ERROR", "batch sequence range is inconsistent", 409)
            recs = self.store.records_between(b["shipmentId"], b["firstSeq"], b["lastSeq"])
            if len(recs) != b["count"]:
                raise SealError("MISSING_DATA", "gateway does not hold every record of this batch", 409)
            if merkle_root([r["hash"] for r in recs]) != b["root"]:
                raise SealError("MERKLE_MISMATCH", "root differs from the gateway's records", 409)
            self.store.insert_batch(b)
            self.store.set_last_counter(b["sealId"], b["counter"])
            self.store.enqueue("BATCH", b, self.now())
            self.store.audit("device", "BATCH_ACCEPTED", {"shipmentId": b["shipmentId"], "batchId": b["batchId"], "counter": b["counter"]}, self.now())
        return self.store.get_batch(b["shipmentId"], b["batchId"])

    def record_tamper(self, ev: TamperIn) -> dict:
        e = ev.model_dump()
        with self.store.transaction():
            seal, _ = self._context(e["sealId"], e["shipmentId"])
            last = self.store.last_record(e["shipmentId"])
            if not last or e["seq"] > last["seq"]:
                raise SealError("EVENT_SEQ_INVALID", "event refers to a record that does not exist yet", 422)
            if e["counter"] is None:
                if seal["provisioning"] != "MOCK_SECURE_ELEMENT":
                    raise SealError("DEVICE_SIGNS", "this seal must sign its own tamper events (counter + signature required)", 409)
                signed = self.provider.sign_counted(e["sealId"], lambda c: tamper_payload(e, c))
                e["counter"], e["signature"] = signed.counter, signed.signature
            else:
                if not verify_signature(seal["publicKey"], tamper_payload(e, e["counter"]), e["signature"]):
                    raise SealError("SIGNATURE_INVALID", "not signed by the registered secure-element key", 401)
                if e["counter"] <= seal["lastCounter"]:
                    raise SealError("STALE_COUNTER", f"counter {e['counter']} <= last accepted {seal['lastCounter']} (replay)", 409)
            self.store.insert_tamper(e)
            self.store.set_last_counter(e["sealId"], e["counter"])
            self.store.enqueue("TAMPER", e, self.now())
            self.store.audit("secure-element(mock)" if ev.counter is None else "device", "TAMPER_EVENT", {"type": e["eventType"], "seq": e["seq"], "counter": e["counter"]}, self.now())
            if seal["provisioning"] == "MOCK_SECURE_ELEMENT":
                self.close_batch(e["shipmentId"], force=True)
        return e
