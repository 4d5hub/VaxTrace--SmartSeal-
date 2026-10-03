from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass


class LedgerUnavailable(Exception):
    pass


class LedgerRejected(Exception):

    def __init__(self, code: str, message: str = ""):
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass(frozen=True)
class Receipt:
    tx_hash: str
    block_number: int | None = None


class LedgerClient(ABC):
    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    def submit(self, kind: str, payload: dict) -> Receipt:
        pass

    def status(self) -> dict:
        return {"available": self.is_available()}


class OfflineLedger(LedgerClient):
    def is_available(self) -> bool:
        return False

    def submit(self, kind, payload):
        raise LedgerUnavailable("no ledger configured")

    def status(self):
        return {"available": False, "mode": "offline", "note": "No blockchain connected; commitments are queued."}


def sync_outbox(store, ledger: LedgerClient, now: str) -> dict:
    done = rejected = 0
    stopped = None
    for item in store.pending_outbox():
        payload = json.loads(item["payload"])
        try:
            receipt = ledger.submit(item["kind"], payload)
        except LedgerUnavailable as e:
            store.mark_outbox(item["id"], "PENDING", now, attempts_inc=1)
            stopped = str(e)
            break
        except LedgerRejected as e:
            store.mark_outbox(item["id"], "REJECTED", now, error_code=e.code)
            store.set_anchor(item["kind"], payload, "REJECTED", None)
            store.audit("ledger", "REJECTED", {"kind": item["kind"], "code": e.code}, now)
            rejected += 1
            continue
        store.mark_outbox(item["id"], "ANCHORED", now, tx_hash=receipt.tx_hash)
        store.set_anchor(item["kind"], payload, "ANCHORED", receipt.tx_hash)
        done += 1
    return {"anchored": done, "rejected": rejected, "pending": store.pending_count(), "stoppedBecause": stopped}


import re
from dataclasses import dataclass, field
from pathlib import Path

ROLE_ENUM = {"NONE": 0, "MANUFACTURER": 1, "TRANSPORTER": 2, "WAREHOUSE": 3, "PHARMACY": 4,
             "REGULATOR": 5, "VERIFIER": 6, "GATEWAY": 7}
ROLE_NAMES = {v: k for k, v in ROLE_ENUM.items()}
VERDICT_ENUM = {"ACCEPT": 1, "QUARANTINE": 2, "REJECT": 3}
VERDICT_NAMES = {v: k for k, v in VERDICT_ENUM.items()}
CONTRACT_FILES = {"registry": "SmartSealRegistry", "anchor": "BatchAnchor",
                  "custody": "ShipmentCustody", "verdict": "VerdictRegistry"}
_REVERT_RE = re.compile(r"execution reverted:?\s*([A-Z][A-Z0-9_]{3,})")
_BARE_CODE_RE = re.compile(r"\b([A-Z][A-Z0-9_]{5,})\b")


def load_artifact(artifacts_dir, name: str) -> dict:
    with open(Path(artifacts_dir) / f"{name}.json", encoding="utf-8") as f:
        return json.load(f)


def revert_code(exc: Exception) -> str:
    text = str(exc)
    m = _REVERT_RE.search(text) or _BARE_CODE_RE.search(text)
    if m:
        return m.group(1)
    data = getattr(exc, "data", None)
    if isinstance(data, str) and data.startswith("0x08c379a0") and len(data) > 138:
        try:
            raw = bytes.fromhex(data[10:])
            length = int.from_bytes(raw[32:64], "big")
            return raw[64:64 + length].decode()
        except ValueError:
            pass
    return "TX_REVERTED"


def make_w3(rpc_url: str, timeout: int = 10):
    from web3 import Web3
    return Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": timeout}))


@dataclass
class Deployment:
    chain_id: int
    addresses: dict
    participants: dict = field(default_factory=dict)
    rpc_url: str = "http://127.0.0.1:8545"
    deployed_at: str = ""

    @staticmethod
    def load(path) -> "Deployment":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        return Deployment(d["chainId"], d["addresses"], d.get("participants", {}), d.get("rpcUrl", "http://127.0.0.1:8545"), d.get("deployedAt", ""))

    def save(self, path) -> None:
        Path(path).write_text(json.dumps({"chainId": self.chain_id, "rpcUrl": self.rpc_url, "addresses": self.addresses,
                                          "participants": self.participants, "deployedAt": self.deployed_at,
                                          "note": "public addresses only; demo keys are derived in gateway/demo_accounts.py"}, indent=1))


def send_tx(w3, account, fn, gas: int = 8_000_000, gas_price=None, timeout: int = 30):
    from web3.exceptions import TimeExhausted
    try:
        try:
            fn.call({"from": account.address})
        except Exception as e:
            if "revert" in str(e).lower() or "TransactionFailed" in type(e).__name__ or "ContractLogic" in type(e).__name__:
                raise LedgerRejected(revert_code(e), str(e)) from e
            raise
        price = w3.eth.gas_price if gas_price is None else gas_price
        tx = fn.build_transaction({"from": account.address, "nonce": w3.eth.get_transaction_count(account.address, "pending"),
                                   "gas": gas, "gasPrice": price, "chainId": w3.eth.chain_id})
        h = w3.eth.send_raw_transaction(account.sign_transaction(tx).raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(h, timeout=timeout, poll_latency=0.2)
    except LedgerRejected:
        raise
    except TimeExhausted as e:
        raise LedgerUnavailable("transaction not mined in time (network down or no QBFT quorum)") from e
    except Exception as e:
        if "revert" in str(e).lower():
            raise LedgerRejected(revert_code(e), str(e)) from e
        raise LedgerUnavailable(f"{type(e).__name__}: {e}") from e
    if receipt.status != 1:
        raise LedgerRejected("TX_REVERTED", "transaction mined with failure status")
    return Receipt(tx_hash=h.hex() if h.hex().startswith("0x") else "0x" + h.hex(), block_number=receipt.blockNumber)


def _contracts(w3, deployment: Deployment, artifacts_dir) -> dict:
    from web3 import Web3
    return {k: w3.eth.contract(address=Web3.to_checksum_address(deployment.addresses[k]),
                               abi=load_artifact(artifacts_dir, CONTRACT_FILES[k])["abi"]) for k in CONTRACT_FILES}


def _bytes32(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr.removeprefix("0x"))


def _rs(sig_hex: str):
    return int(sig_hex[:64], 16), int(sig_hex[64:], 16)


class BesuLedger(LedgerClient):

    def __init__(self, w3, deployment: Deployment, accounts: dict, artifacts_dir, gas_price=None, gas_limit=8_000_000, receipt_timeout=30):
        self.w3, self.dep, self.accounts, self.gas_price = w3, deployment, accounts, gas_price
        self.gas_limit, self.timeout = gas_limit, receipt_timeout
        self.c = _contracts(w3, deployment, artifacts_dir)

    def is_available(self) -> bool:
        try:
            self.w3.eth.block_number
            return True
        except Exception:
            return False

    def status(self) -> dict:
        try:
            return {"available": True, "mode": "besu", "chainId": self.w3.eth.chain_id, "blockNumber": self.w3.eth.block_number,
                    "contracts": self.dep.addresses}
        except Exception as e:
            return {"available": False, "mode": "besu", "error": f"{type(e).__name__}: {e}"}

    def submit(self, kind: str, payload: dict) -> Receipt:
        try:
            fn, role, already = self._plan(kind, payload)
            if already():
                return Receipt(tx_hash="already-anchored", block_number=None)
        except LedgerRejected:
            raise
        except Exception as e:
            raise LedgerUnavailable(f"{type(e).__name__}: {e}") from e
        return send_tx(self.w3, self.accounts[role], fn, self.gas_limit, self.gas_price, self.timeout)

    def _plan(self, kind, p):
        reg, anc, cus, ver = (self.c[k] for k in ("registry", "anchor", "custody", "verdict"))
        if kind == "REGISTER_SEAL":
            x, y = int(p["publicKey"][2:66], 16), int(p["publicKey"][66:130], 16)
            return (reg.functions.registerSeal(p["sealId"], x, y), "MANUFACTURER",
                    lambda: reg.functions.getSeal(p["sealId"]).call()[0])
        if kind == "START_SHIPMENT":
            return (reg.functions.startShipment(p["shipmentId"], p["sealId"], _bytes32(p["policyHash"])), "MANUFACTURER",
                    lambda: reg.functions.getShipment(p["shipmentId"]).call()[0])
        if kind == "REVOKE_SEAL":
            return (reg.functions.revokeSeal(p["sealId"]), p["by"], lambda: reg.functions.getSeal(p["sealId"]).call()[1])
        if kind == "BATCH":
            r, s = _rs(p["signature"])
            tup = (p["sealId"], p["shipmentId"], p["batchId"], p["firstSeq"], p["lastSeq"], p["count"],
                   _bytes32(p["prevRoot"]), _bytes32(p["root"]), p["timestamp"], p["counter"])

            def done():
                n = anc.functions.batchCount(p["shipmentId"]).call()
                return n >= p["batchId"] and anc.functions.getBatch(p["shipmentId"], p["batchId"] - 1).call()[5] == _bytes32(p["root"])
            return anc.functions.commitBatchRoot(tup, r, s), "GATEWAY", done
        if kind == "TAMPER":
            r, s = _rs(p["signature"])
            tup = (p["sealId"], p["shipmentId"], p["eventType"], p["seq"], p["timestamp"], p["counter"])

            def done():
                n = anc.functions.tamperCount(p["shipmentId"]).call()
                return any(anc.functions.getTamper(p["shipmentId"], i).call()[3] == p["counter"] for i in range(n))
            return anc.functions.recordTamperEvent(tup, r, s), "GATEWAY", done
        if kind == "HANDOFF":
            tup = (p["shipmentId"], p["fromAddress"], p["toAddress"], _bytes32(p["nonce"]), p["atSeq"], p["timestamp"])
            return (cus.functions.transferCustody(tup, bytes.fromhex(p["sigFrom"].removeprefix("0x")), bytes.fromhex(p["sigTo"].removeprefix("0x"))),
                    "GATEWAY", lambda: cus.functions.nonceUsed(p["shipmentId"], _bytes32(p["nonce"])).call())
        if kind == "VERDICT":
            return (ver.functions.finalizeVerdict(p["shipmentId"], VERDICT_ENUM[p["verdict"]], p["reasonCodes"], _bytes32(p["reportHash"])),
                    "VERIFIER", lambda: ver.functions.getVerdict(p["shipmentId"]).call()[0] != 0)
        raise LedgerRejected("UNKNOWN_KIND", kind)


class ChainReader:

    def __init__(self, w3, deployment: Deployment, artifacts_dir):
        self.w3, self.dep = w3, deployment
        self.c = _contracts(w3, deployment, artifacts_dir)
        self.role_of_addr = {a.lower(): r for r, a in deployment.participants.items()}

    def connected(self) -> bool:
        try:
            self.w3.eth.block_number
            return True
        except Exception:
            return False

    def custody_domain(self) -> tuple:
        return self.w3.eth.chain_id, self.dep.addresses["custody"]

    def seal(self, seal_id):
        e, revoked, mfr, x, y = self.c["registry"].functions.getSeal(seal_id).call()
        return None if not e else {"sealId": seal_id, "revoked": revoked, "manufacturer": mfr,
                                   "publicKey": "04" + f"{x:064x}" + f"{y:064x}"}

    def shipment(self, shipment_id):
        e, active, seal_id, cust, ph = self.c["registry"].functions.getShipment(shipment_id).call()
        return None if not e else {"shipmentId": shipment_id, "active": active, "sealId": seal_id,
                                   "initialCustodian": cust, "policyHash": ph.hex()}

    def batches(self, shipment_id):
        anc, out = self.c["anchor"], []
        for i in range(anc.functions.batchCount(shipment_id).call()):
            b = anc.functions.getBatch(shipment_id, i).call()
            out.append({"batchId": b[0], "firstSeq": b[1], "lastSeq": b[2], "count": b[3], "prevRoot": b[4].hex(), "root": b[5].hex(),
                        "timestamp": b[6], "counter": b[7], "signature": f"{b[8]:064x}{b[9]:064x}", "anchoredAt": b[10]})
        return out

    def tamper_events(self, shipment_id):
        anc, out = self.c["anchor"], []
        for i in range(anc.functions.tamperCount(shipment_id).call()):
            t = anc.functions.getTamper(shipment_id, i).call()
            out.append({"eventType": t[0], "seq": t[1], "timestamp": t[2], "counter": t[3], "signature": f"{t[4]:064x}{t[5]:064x}", "anchoredAt": t[6]})
        return out

    def handoffs(self, shipment_id):
        cus, out = self.c["custody"], []
        for i in range(cus.functions.handoffCount(shipment_id).call()):
            h = cus.functions.getHandoff(shipment_id, i).call()
            out.append({"from": h[0], "to": h[1], "fromRole": self.role_of_addr.get(h[0].lower()), "toRole": self.role_of_addr.get(h[1].lower()),
                        "nonce": "0x" + h[2].hex(), "atSeq": h[3], "timestamp": h[4], "sigFrom": "0x" + h[5].hex(), "sigTo": "0x" + h[6].hex(), "anchoredAt": h[7]})
        return out

    def handoff_digest(self, shipment_id, frm, to, nonce, at_seq, timestamp) -> str:
        d = self.c["custody"].functions.handoffDigest((shipment_id, frm, to, _bytes32(nonce), at_seq, timestamp)).call()
        return "0x" + d.hex()

    def verdict(self, shipment_id):
        v, codes, rh, who, at = self.c["verdict"].functions.getVerdict(shipment_id).call()
        return None if v == 0 else {"verdict": VERDICT_NAMES[v], "reasonCodes": list(codes), "reportHash": "0x" + rh.hex(),
                                    "verifier": who, "verifierRole": self.role_of_addr.get(who.lower()), "finalizedAt": at}

    def last_counter(self, seal_id) -> int:
        return self.c["anchor"].functions.lastCounter(seal_id).call()

    def blocks(self, count: int = 10) -> list:
        head = self.w3.eth.block_number
        out = []
        for n in range(head, max(head - count, -1), -1):
            b = self.w3.eth.get_block(n, full_transactions=True)
            out.append({"number": b.number, "hash": "0x" + b.hash.hex().removeprefix("0x"), "timestamp": b.timestamp,
                        "proposer": getattr(b, "miner", None), "commitSeals": _commit_seals(bytes(b.extraData)),
                        "transactions": [{"hash": "0x" + t.hash.hex().removeprefix("0x"), "from": t["from"], "to": t.get("to"),
                                          "fromRole": self.role_of_addr.get(t["from"].lower())} for t in b.transactions]})
        return out


def _commit_seals(extra: bytes):
    try:
        import rlp
        items = rlp.decode(extra)
        return len(items[4]) if len(items) >= 5 else None
    except Exception:
        return None


def qbft_status(node_rpcs: list, names: list, timeout: float = 1.5) -> dict:
    from concurrent.futures import ThreadPoolExecutor
    from web3 import Web3

    def probe(pair):
        url, name = pair
        entry = {"name": name, "rpc": url, "reachable": False}
        try:
            w = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": timeout}))
            entry.update(reachable=True, blockNumber=w.eth.block_number)
            try:
                entry["peerCount"] = w.net.peer_count
            except Exception:
                pass
            try:
                entry["validators"] = w.provider.make_request("qbft_getValidatorsByBlockNumber", ["latest"]).get("result")
            except Exception:
                pass
        except Exception as e:
            entry["error"] = type(e).__name__
        return entry

    with ThreadPoolExecutor(max_workers=max(1, len(node_rpcs))) as pool:
        nodes = list(pool.map(probe, zip(node_rpcs, names)))
    n = len(node_rpcs)
    need = 2 * ((n - 1) // 3) + 1
    up = sum(1 for x in nodes if x["reachable"])
    vals = next((x.get("validators") for x in nodes if x.get("validators")), None)
    return {"validatorCount": n, "quorumRequired": need, "reachable": up, "canCommit": up >= need, "nodes": nodes,
            "validatorAddresses": vals,
            "note": "'reachable' means the node answers JSON-RPC. Blocks are being sealed only if blockNumber keeps advancing."}
