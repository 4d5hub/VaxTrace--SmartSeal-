from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS seals(
  seal_id TEXT PRIMARY KEY, public_key TEXT NOT NULL, manufacturer TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0, provisioning TEXT NOT NULL, last_counter INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS shipments(
  shipment_id TEXT PRIMARY KEY, seal_id TEXT NOT NULL REFERENCES seals(seal_id),
  policy_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'ACTIVE', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS records(
  shipment_id TEXT NOT NULL, seq INTEGER NOT NULL, seal_id TEXT NOT NULL, timestamp TEXT NOT NULL,
  temperature1 REAL NOT NULL, temperature2 REAL NOT NULL, shock REAL NOT NULL,
  lid INTEGER NOT NULL, light INTEGER NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL,
  received_at TEXT NOT NULL, PRIMARY KEY(shipment_id, seq));
CREATE TABLE IF NOT EXISTS batches(
  shipment_id TEXT NOT NULL, batch_id INTEGER NOT NULL, seal_id TEXT NOT NULL,
  first_seq INTEGER NOT NULL, last_seq INTEGER NOT NULL, count INTEGER NOT NULL,
  prev_root TEXT NOT NULL, root TEXT NOT NULL, timestamp TEXT NOT NULL, counter INTEGER NOT NULL,
  signature TEXT NOT NULL, anchor_status TEXT NOT NULL DEFAULT 'PENDING', anchor_tx TEXT,
  PRIMARY KEY(shipment_id, batch_id));
CREATE TABLE IF NOT EXISTS tamper_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, seal_id TEXT NOT NULL, shipment_id TEXT NOT NULL,
  event_type TEXT NOT NULL, seq INTEGER NOT NULL, timestamp TEXT NOT NULL, counter INTEGER NOT NULL,
  signature TEXT NOT NULL, anchor_status TEXT NOT NULL DEFAULT 'PENDING', anchor_tx TEXT);
CREATE TABLE IF NOT EXISTS outbox(
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, payload TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING', attempts INTEGER NOT NULL DEFAULT 0,
  tx_hash TEXT, error_code TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
  action TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS custody(
  id INTEGER PRIMARY KEY AUTOINCREMENT, shipment_id TEXT NOT NULL, from_role TEXT NOT NULL, to_role TEXT NOT NULL,
  from_address TEXT NOT NULL, to_address TEXT NOT NULL, nonce TEXT NOT NULL, at_seq INTEGER NOT NULL,
  timestamp TEXT NOT NULL, sig_from TEXT NOT NULL, sig_to TEXT NOT NULL,
  anchor_status TEXT NOT NULL DEFAULT 'PENDING', anchor_tx TEXT, UNIQUE(shipment_id, nonce));
CREATE TABLE IF NOT EXISTS audit_copies(
  id INTEGER PRIMARY KEY AUTOINCREMENT, shipment_id TEXT NOT NULL, bundle_hash TEXT NOT NULL,
  imported_at TEXT NOT NULL, bundle_json TEXT NOT NULL);
"""


def _rec(r):
    return {"sealId": r["seal_id"], "shipmentId": r["shipment_id"], "seq": r["seq"],
            "timestamp": r["timestamp"], "temperature1": r["temperature1"],
            "temperature2": r["temperature2"], "shock": r["shock"], "lid": bool(r["lid"]),
            "light": bool(r["light"]), "prevHash": r["prev_hash"], "hash": r["hash"]}


def _batch(r):
    return {"sealId": r["seal_id"], "shipmentId": r["shipment_id"], "batchId": r["batch_id"],
            "firstSeq": r["first_seq"], "lastSeq": r["last_seq"], "count": r["count"],
            "prevRoot": r["prev_root"], "root": r["root"], "timestamp": r["timestamp"],
            "counter": r["counter"], "signature": r["signature"],
            "anchorStatus": r["anchor_status"], "anchorTx": r["anchor_tx"]}


def _tamper(r):
    return {"id": r["id"], "sealId": r["seal_id"], "shipmentId": r["shipment_id"],
            "eventType": r["event_type"], "seq": r["seq"], "timestamp": r["timestamp"],
            "counter": r["counter"], "signature": r["signature"],
            "anchorStatus": r["anchor_status"], "anchorTx": r["anchor_tx"]}


def _seal(r):
    return None if r is None else {"sealId": r["seal_id"], "publicKey": r["public_key"],
            "manufacturer": r["manufacturer"], "revoked": bool(r["revoked"]),
            "provisioning": r["provisioning"], "lastCounter": r["last_counter"],
            "createdAt": r["created_at"]}


def _ship(r):
    return None if r is None else {"shipmentId": r["shipment_id"], "sealId": r["seal_id"],
            "policy": json.loads(r["policy_json"]), "status": r["status"], "createdAt": r["created_at"]}


class Storage:
    def __init__(self, path):
        self._c = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._c.row_factory = sqlite3.Row
        self._lock, self._depth = threading.RLock(), 0
        self._c.execute("PRAGMA journal_mode=WAL")
        self._c.executescript(SCHEMA)

    @contextmanager
    def transaction(self):
        with self._lock:
            if self._depth == 0:
                self._c.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield self._c
            except BaseException:
                self._depth -= 1
                if self._depth == 0:
                    self._c.execute("ROLLBACK")
                raise
            else:
                self._depth -= 1
                if self._depth == 0:
                    self._c.execute("COMMIT")

    def _all(self, sql, args=()):
        with self._lock:
            return self._c.execute(sql, args).fetchall()

    def _one(self, sql, args=()):
        with self._lock:
            return self._c.execute(sql, args).fetchone()

    def unsafe_execute(self, sql, args=()):
        with self.transaction() as c:
            return c.execute(sql, args).rowcount

    def add_seal(self, seal_id, public_key, manufacturer, provisioning, now):
        with self.transaction() as c:
            c.execute("INSERT INTO seals(seal_id,public_key,manufacturer,provisioning,created_at) VALUES(?,?,?,?,?)",
                      (seal_id, public_key, manufacturer, provisioning, now))

    def get_seal(self, seal_id):
        return _seal(self._one("SELECT * FROM seals WHERE seal_id=?", (seal_id,)))

    def list_seals(self):
        return [_seal(r) for r in self._all("SELECT * FROM seals ORDER BY created_at, seal_id")]

    def revoke_seal(self, seal_id):
        with self.transaction() as c:
            c.execute("UPDATE seals SET revoked=1 WHERE seal_id=?", (seal_id,))

    def set_last_counter(self, seal_id, counter):
        with self.transaction() as c:
            c.execute("UPDATE seals SET last_counter=? WHERE seal_id=? AND last_counter<?", (counter, seal_id, counter))

    def add_shipment(self, shipment_id, seal_id, policy, now):
        with self.transaction() as c:
            c.execute("INSERT INTO shipments(shipment_id,seal_id,policy_json,created_at) VALUES(?,?,?,?)",
                      (shipment_id, seal_id, json.dumps(policy, sort_keys=True), now))

    def get_shipment(self, shipment_id):
        return _ship(self._one("SELECT * FROM shipments WHERE shipment_id=?", (shipment_id,)))

    def active_shipment_for_seal(self, seal_id):
        return _ship(self._one("SELECT * FROM shipments WHERE seal_id=? AND status='ACTIVE'", (seal_id,)))

    def latest_shipment(self):
        return _ship(self._one("SELECT * FROM shipments ORDER BY created_at DESC, rowid DESC LIMIT 1"))

    def list_shipments(self):
        return [_ship(r) for r in self._all("SELECT * FROM shipments ORDER BY created_at, shipment_id")]

    def insert_record(self, rec, now):
        with self.transaction() as c:
            c.execute("INSERT INTO records VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                      (rec["shipmentId"], rec["seq"], rec["sealId"], rec["timestamp"], rec["temperature1"],
                       rec["temperature2"], rec["shock"], int(rec["lid"]), int(rec["light"]),
                       rec["prevHash"], rec["hash"], now))

    def get_record(self, shipment_id, seq):
        r = self._one("SELECT * FROM records WHERE shipment_id=? AND seq=?", (shipment_id, seq))
        return None if r is None else _rec(r)

    def last_record(self, shipment_id):
        r = self._one("SELECT * FROM records WHERE shipment_id=? ORDER BY seq DESC LIMIT 1", (shipment_id,))
        return None if r is None else _rec(r)

    def list_records(self, shipment_id, from_seq=1, limit=1000, offset=0):
        return [_rec(r) for r in self._all(
            "SELECT * FROM records WHERE shipment_id=? AND seq>=? ORDER BY seq LIMIT ? OFFSET ?",
            (shipment_id, from_seq, limit, offset))]

    def records_between(self, shipment_id, first, last):
        return [_rec(r) for r in self._all(
            "SELECT * FROM records WHERE shipment_id=? AND seq BETWEEN ? AND ? ORDER BY seq",
            (shipment_id, first, last))]

    def count_records(self, shipment_id=None):
        r = self._one("SELECT COUNT(*) n FROM records" + (" WHERE shipment_id=?" if shipment_id else ""),
                      (shipment_id,) if shipment_id else ())
        return r["n"]

    def insert_batch(self, b):
        with self.transaction() as c:
            c.execute("INSERT INTO batches(shipment_id,batch_id,seal_id,first_seq,last_seq,count,prev_root,root,timestamp,counter,signature) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                      (b["shipmentId"], b["batchId"], b["sealId"], b["firstSeq"], b["lastSeq"], b["count"],
                       b["prevRoot"], b["root"], b["timestamp"], b["counter"], b["signature"]))

    def last_batch(self, shipment_id):
        r = self._one("SELECT * FROM batches WHERE shipment_id=? ORDER BY batch_id DESC LIMIT 1", (shipment_id,))
        return None if r is None else _batch(r)

    def get_batch(self, shipment_id, batch_id):
        r = self._one("SELECT * FROM batches WHERE shipment_id=? AND batch_id=?", (shipment_id, batch_id))
        return None if r is None else _batch(r)

    def list_batches(self, shipment_id):
        return [_batch(r) for r in self._all("SELECT * FROM batches WHERE shipment_id=? ORDER BY batch_id", (shipment_id,))]

    def unbatched_records(self, shipment_id, limit=None):
        last = self.last_batch(shipment_id)
        return self.list_records(shipment_id, (last["lastSeq"] + 1) if last else 1, limit or 100000)

    def insert_tamper(self, e):
        with self.transaction() as c:
            c.execute("INSERT INTO tamper_events(seal_id,shipment_id,event_type,seq,timestamp,counter,signature) VALUES(?,?,?,?,?,?,?)",
                      (e["sealId"], e["shipmentId"], e["eventType"], e["seq"], e["timestamp"], e["counter"], e["signature"]))

    def list_tamper(self, shipment_id):
        return [_tamper(r) for r in self._all("SELECT * FROM tamper_events WHERE shipment_id=? ORDER BY counter", (shipment_id,))]

    def set_anchor(self, kind, payload, status, tx_hash):
        with self.transaction() as c:
            if kind == "BATCH":
                c.execute("UPDATE batches SET anchor_status=?, anchor_tx=? WHERE shipment_id=? AND batch_id=?",
                          (status, tx_hash, payload["shipmentId"], payload["batchId"]))
            elif kind == "HANDOFF":
                c.execute("UPDATE custody SET anchor_status=?, anchor_tx=? WHERE shipment_id=? AND nonce=?",
                          (status, tx_hash, payload["shipmentId"], payload["nonce"]))
            elif kind == "TAMPER":
                c.execute("UPDATE tamper_events SET anchor_status=?, anchor_tx=? WHERE shipment_id=? AND counter=?",
                          (status, tx_hash, payload["shipmentId"], payload["counter"]))

    def add_custody(self, h):
        with self.transaction() as c:
            c.execute("INSERT INTO custody(shipment_id,from_role,to_role,from_address,to_address,nonce,at_seq,timestamp,sig_from,sig_to) VALUES(?,?,?,?,?,?,?,?,?,?)",
                      (h["shipmentId"], h["fromRole"], h["toRole"], h["fromAddress"], h["toAddress"], h["nonce"], h["atSeq"], h["timestamp"], h["sigFrom"], h["sigTo"]))

    def list_custody(self, shipment_id):
        return [{"id": r["id"], "shipmentId": r["shipment_id"], "fromRole": r["from_role"], "toRole": r["to_role"], "fromAddress": r["from_address"],
                 "toAddress": r["to_address"], "nonce": r["nonce"], "atSeq": r["at_seq"], "timestamp": r["timestamp"], "sigFrom": r["sig_from"],
                 "sigTo": r["sig_to"], "anchorStatus": r["anchor_status"], "anchorTx": r["anchor_tx"]}
                for r in self._all("SELECT * FROM custody WHERE shipment_id=? ORDER BY id", (shipment_id,))]

    def nonce_used(self, shipment_id, nonce):
        return self._one("SELECT 1 FROM custody WHERE shipment_id=? AND nonce=?", (shipment_id, nonce)) is not None

    def enqueue(self, kind, payload, now):
        with self.transaction() as c:
            c.execute("INSERT INTO outbox(kind,payload,created_at,updated_at) VALUES(?,?,?,?)",
                      (kind, json.dumps(payload, sort_keys=True), now, now))

    def pending_outbox(self):
        return [dict(r) for r in self._all("SELECT * FROM outbox WHERE status='PENDING' ORDER BY id")]

    def list_outbox(self, limit=200):
        return [dict(r) for r in self._all("SELECT * FROM outbox ORDER BY id DESC LIMIT ?", (limit,))]

    def mark_outbox(self, item_id, status, now, tx_hash=None, error_code=None, attempts_inc=1):
        with self.transaction() as c:
            c.execute("UPDATE outbox SET status=?, tx_hash=?, error_code=?, attempts=attempts+?, updated_at=? WHERE id=?",
                      (status, tx_hash, error_code, attempts_inc, now, item_id))

    def pending_count(self):
        return self._one("SELECT COUNT(*) n FROM outbox WHERE status='PENDING'")["n"]

    def audit(self, actor, action, detail, now):
        with self.transaction() as c:
            c.execute("INSERT INTO audit_log(ts,actor,action,detail) VALUES(?,?,?,?)", (now, actor, action, json.dumps(detail, sort_keys=True)))

    def list_audit(self, limit=200):
        return [dict(r) for r in self._all("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]

    def add_audit_copy(self, shipment_id, bundle_hash, now, bundle_json):
        with self.transaction() as c:
            c.execute("INSERT INTO audit_copies(shipment_id,bundle_hash,imported_at,bundle_json) VALUES(?,?,?,?)",
                      (shipment_id, bundle_hash, now, bundle_json))

    def list_audit_copies(self):
        return [dict(r) for r in self._all("SELECT id,shipment_id,bundle_hash,imported_at FROM audit_copies ORDER BY id DESC")]
