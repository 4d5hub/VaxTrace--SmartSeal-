from __future__ import annotations

import json
import os
import re
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


@dataclass(frozen=True)
class CountedSignature:
    counter: int
    message: str
    signature: str


def public_key_hex(pub: ec.EllipticCurvePublicKey) -> str:
    return pub.public_bytes(serialization.Encoding.X962,
                            serialization.PublicFormat.UncompressedPoint).hex()


def is_valid_public_key(hexstr: str) -> bool:
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(hexstr))
        return len(hexstr) == 130
    except (ValueError, TypeError):
        return False


def verify_signature(public_key: str, message, signature: str) -> bool:
    try:
        raw = bytes.fromhex(signature)
        if len(raw) != 64:
            return False
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(public_key))
        data = message.encode("utf-8") if isinstance(message, str) else message
        key.verify(der, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _sign(priv: ec.EllipticCurvePrivateKey, message: bytes) -> str:
    r, s = decode_dss_signature(priv.sign(message, ec.ECDSA(hashes.SHA256())))
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


class SecureElementProvider(ABC):

    @abstractmethod
    def provision(self, identity_id: str) -> str:
        pass

    @abstractmethod
    def get_public_key(self, identity_id: str) -> str: ...

    @abstractmethod
    def get_monotonic_counter(self, identity_id: str) -> int: ...

    @abstractmethod
    def sign(self, identity_id: str, message: bytes) -> str:
        pass

    @abstractmethod
    def sign_counted(self, identity_id: str, build_message: Callable[[int], str]) -> CountedSignature:
        pass


class MockSecureElementProvider(SecureElementProvider):
    def __init__(self, directory):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, identity_id: str) -> Path:
        if not ID_RE.match(identity_id):
            raise ValueError("invalid identity id")
        return self.dir / f"{identity_id}.json"

    def _load(self, identity_id: str):
        p = self._path(identity_id)
        return json.loads(p.read_text()) if p.exists() else None

    def _save(self, identity_id: str, data: dict) -> None:
        p = self._path(identity_id)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        os.replace(tmp, p)

    @staticmethod
    def _key(data: dict) -> ec.EllipticCurvePrivateKey:
        return serialization.load_pem_private_key(data["privateKeyPem"].encode(), password=None)

    def provision(self, identity_id: str) -> str:
        with self._lock:
            data = self._load(identity_id)
            if data is None:
                key = ec.generate_private_key(ec.SECP256R1())
                pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()).decode()
                data = {"identity": identity_id, "privateKeyPem": pem, "counter": 0,
                        "warning": "DEMO MOCK: a real secure element never exposes its key"}
                self._save(identity_id, data)
            return public_key_hex(self._key(data).public_key())

    def get_public_key(self, identity_id: str) -> str:
        data = self._load(identity_id)
        if data is None:
            raise KeyError(f"unknown identity {identity_id}")
        return public_key_hex(self._key(data).public_key())

    def get_monotonic_counter(self, identity_id: str) -> int:
        data = self._load(identity_id)
        if data is None:
            raise KeyError(f"unknown identity {identity_id}")
        return data["counter"]

    def sign(self, identity_id: str, message: bytes) -> str:
        data = self._load(identity_id)
        if data is None:
            raise KeyError(f"unknown identity {identity_id}")
        return _sign(self._key(data), message)

    def sign_counted(self, identity_id: str, build_message: Callable[[int], str]) -> CountedSignature:
        with self._lock:
            data = self._load(identity_id)
            if data is None:
                raise KeyError(f"unknown identity {identity_id}")
            counter = data["counter"] + 1
            data["counter"] = counter
            self._save(identity_id, data)
            message = build_message(counter)
            return CountedSignature(counter, message, _sign(self._key(data), message.encode("utf-8")))


class ProductionSecureElementProvider(SecureElementProvider):

    def _no(self, *a, **k):
        raise NotImplementedError("Requires physical secure-element hardware; use the mock for demos")

    provision = get_public_key = get_monotonic_counter = sign = sign_counted = _no
