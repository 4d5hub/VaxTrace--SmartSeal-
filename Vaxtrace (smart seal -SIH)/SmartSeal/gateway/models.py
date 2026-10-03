from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator, model_validator

from hashing import HEX64, ZERO_HASH, fmt2, parse_ts

ID = r"^[A-Za-z0-9_-]{1,64}$"
EVENT_TYPES = ("LID_OPEN", "LIGHT_EXPOSURE", "SHOCK_EVENT", "ENCLOSURE_BREACH", "PROBE_FAULT")


class SealError(Exception):

    def __init__(self, code: str, message: str, status: int = 409, details=None):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.status, self.details = code, message, status, details

    def body(self) -> dict:
        return {"error": {"code": self.code, "message": self.message, "details": self.details}}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RecordIn(Strict):
    sealId: str = Field(pattern=ID)
    shipmentId: str = Field(pattern=ID)
    seq: StrictInt = Field(ge=1)
    timestamp: str
    temperature1: float = Field(ge=-100, le=200, allow_inf_nan=False)
    temperature2: float = Field(ge=-100, le=200, allow_inf_nan=False)
    shock: float = Field(ge=0, le=500, allow_inf_nan=False)
    lid: StrictBool
    light: StrictBool
    prevHash: str
    hash: Optional[str] = None

    @field_validator("timestamp")
    @classmethod
    def _ts(cls, v):
        parse_ts(v)
        return v

    @field_validator("temperature1", "temperature2", "shock")
    @classmethod
    def _two_decimals(cls, v):
        fmt2(v)
        return v

    @field_validator("prevHash")
    @classmethod
    def _prev(cls, v):
        if v != ZERO_HASH and not HEX64.match(v):
            raise ValueError('prevHash must be "0" or 64 lowercase hex characters')
        return v

    @field_validator("hash")
    @classmethod
    def _hash(cls, v):
        if v is not None and not HEX64.match(v):
            raise ValueError("hash must be 64 lowercase hex characters")
        return v


class SealIn(Strict):
    sealId: str = Field(pattern=ID)
    manufacturer: str = Field(min_length=1, max_length=64)
    publicKey: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{130}$")


class ShipmentIn(Strict):
    shipmentId: str = Field(pattern=ID)
    sealId: str = Field(pattern=ID)
    policy: Optional[dict] = None


class CloseIn(Strict):
    shipmentId: str = Field(pattern=ID)


class RevokeIn(Strict):
    by: str = Field(pattern=ID)


class BatchSubmitIn(Strict):
    sealId: str = Field(pattern=ID)
    shipmentId: str = Field(pattern=ID)
    batchId: StrictInt = Field(ge=1)
    firstSeq: StrictInt = Field(ge=1)
    lastSeq: StrictInt = Field(ge=1)
    count: StrictInt = Field(ge=1)
    prevRoot: str = Field(pattern=r"^[0-9a-f]{64}$")
    root: str = Field(pattern=r"^[0-9a-f]{64}$")
    timestamp: str
    counter: StrictInt = Field(ge=1)
    signature: str = Field(pattern=r"^[0-9a-f]{128}$")

    @field_validator("timestamp")
    @classmethod
    def _ts(cls, v):
        parse_ts(v)
        return v


class TamperIn(Strict):
    sealId: str = Field(pattern=ID)
    shipmentId: str = Field(pattern=ID)
    eventType: Literal["LID_OPEN", "LIGHT_EXPOSURE", "SHOCK_EVENT", "ENCLOSURE_BREACH", "PROBE_FAULT"]
    seq: StrictInt = Field(ge=1)
    timestamp: str
    counter: Optional[StrictInt] = Field(default=None, ge=1)
    signature: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{128}$")

    @field_validator("timestamp")
    @classmethod
    def _ts(cls, v):
        parse_ts(v)
        return v

    @model_validator(mode="after")
    def _both_or_neither(self):
        if (self.counter is None) != (self.signature is None):
            raise ValueError("counter and signature must be supplied together (device-signed) or both omitted (mock secure element signs)")
        return self


class ImportIn(Strict):
    bundle: dict


ROLE_LITERAL = Literal["MANUFACTURER", "TRANSPORTER", "WAREHOUSE", "PHARMACY"]


class HandoffIn(Strict):
    shipmentId: str = Field(pattern=ID)
    fromRole: ROLE_LITERAL
    toRole: ROLE_LITERAL
    nonce: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    atSeq: StrictInt = Field(ge=0)
    timestamp: str
    sigFrom: Optional[str] = Field(default=None, pattern=r"^0x[0-9a-f]{130}$")
    sigTo: Optional[str] = Field(default=None, pattern=r"^0x[0-9a-f]{130}$")

    @field_validator("timestamp")
    @classmethod
    def _ts(cls, v):
        parse_ts(v)
        return v


class DemoHandoffIn(Strict):
    shipmentId: str = Field(pattern=ID)
    fromRole: ROLE_LITERAL
    toRole: ROLE_LITERAL
    mode: Literal["both", "sender_only", "receiver_only", "reuse_nonce", "wrong_receiver_signer"] = "both"
