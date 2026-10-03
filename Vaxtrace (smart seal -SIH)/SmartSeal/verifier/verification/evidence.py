from __future__ import annotations

import httpx


class HttpEvidence:
    def __init__(self, base_url: str, timeout: float = 15):
        self.base, self.timeout = base_url.rstrip("/"), timeout

    def fetch(self, shipment_id: str) -> dict:
        r = httpx.get(f"{self.base}/api/export", params={"shipmentId": shipment_id}, timeout=self.timeout)
        r.raise_for_status()
        return r.json()["bundle"]


class CallableEvidence:

    def __init__(self, fn):
        self.fn = fn

    def fetch(self, shipment_id: str) -> dict:
        return self.fn(shipment_id)


class BundleEvidence(CallableEvidence):
    def __init__(self, bundle: dict):
        super().__init__(lambda _sid: bundle)
