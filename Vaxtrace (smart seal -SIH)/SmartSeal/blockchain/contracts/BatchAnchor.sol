// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "./SmartSealRegistry.sol";
import "./P256.sol";

contract BatchAnchor {
    SmartSealRegistry public immutable registry;

    struct BatchInput {
        string sealId; string shipmentId; uint64 batchId; uint64 firstSeq; uint64 lastSeq; uint64 count;
        bytes32 prevRoot; bytes32 root; string timestamp; uint64 counter;
    }
    struct Batch {
        uint64 batchId; uint64 firstSeq; uint64 lastSeq; uint64 count; bytes32 prevRoot; bytes32 root;
        string timestamp; uint64 counter; uint256 sigR; uint256 sigS; uint64 anchoredAt;
    }
    struct TamperInput { string sealId; string shipmentId; string eventType; uint64 seq; string timestamp; uint64 counter; }
    struct TamperEvent {
        string eventType; uint64 seq; string timestamp; uint64 counter; uint256 sigR; uint256 sigS; uint64 anchoredAt;
    }

    mapping(string => Batch[]) private _batches;
    mapping(string => TamperEvent[]) private _tamper;
    mapping(string => uint64) public lastCounter;

    event BatchAnchored(string indexed shipmentIdHash, string shipmentId, uint64 batchId, bytes32 root, uint64 counter);
    event TamperRecorded(string shipmentId, string eventType, uint64 seq, uint64 counter);

    constructor(SmartSealRegistry r) { registry = r; }

    function commitBatchRoot(BatchInput calldata b, uint256 sigR, uint256 sigS) external {
        _requireGateway();
        (uint256 px, uint256 py) = _checkSealAndShipment(b.sealId, b.shipmentId);
        require(P256.verify(sha256(_batchPayload(b)), sigR, sigS, px, py), "SIGNATURE_INVALID");
        require(b.counter > lastCounter[b.sealId], "STALE_COUNTER");
        Batch[] storage list = _batches[b.shipmentId];
        require(b.batchId == list.length + 1, "BATCH_SEQUENCE_ERROR");
        bytes32 wantPrev = list.length == 0 ? bytes32(0) : list[list.length - 1].root;
        require(b.prevRoot == wantPrev, "PREV_ROOT_MISMATCH");
        uint64 wantFirst = list.length == 0 ? 1 : list[list.length - 1].lastSeq + 1;
        require(b.firstSeq == wantFirst && b.lastSeq >= b.firstSeq && b.count == b.lastSeq - b.firstSeq + 1, "BATCH_SEQUENCE_ERROR");
        lastCounter[b.sealId] = b.counter;
        list.push(Batch(b.batchId, b.firstSeq, b.lastSeq, b.count, b.prevRoot, b.root, b.timestamp, b.counter, sigR, sigS, uint64(block.timestamp)));
        emit BatchAnchored(b.shipmentId, b.shipmentId, b.batchId, b.root, b.counter);
    }

    function recordTamperEvent(TamperInput calldata e, uint256 sigR, uint256 sigS) external {
        _requireGateway();
        (uint256 px, uint256 py) = _checkSealAndShipment(e.sealId, e.shipmentId);
        require(P256.verify(sha256(_tamperPayload(e)), sigR, sigS, px, py), "SIGNATURE_INVALID");
        require(e.counter > lastCounter[e.sealId], "STALE_COUNTER");
        lastCounter[e.sealId] = e.counter;
        _tamper[e.shipmentId].push(TamperEvent(e.eventType, e.seq, e.timestamp, e.counter, sigR, sigS, uint64(block.timestamp)));
        emit TamperRecorded(e.shipmentId, e.eventType, e.seq, e.counter);
    }

    function batchCount(string calldata shipmentId) external view returns (uint256) { return _batches[shipmentId].length; }
    function getBatch(string calldata shipmentId, uint256 index) external view returns (Batch memory) { return _batches[shipmentId][index]; }
    function tamperCount(string calldata shipmentId) external view returns (uint256) { return _tamper[shipmentId].length; }
    function getTamper(string calldata shipmentId, uint256 index) external view returns (TamperEvent memory) { return _tamper[shipmentId][index]; }

    function _requireGateway() private view {
        require(registry.roleOf(msg.sender) == SmartSealRegistry.Role.GATEWAY && !registry.participantRevoked(msg.sender), "ROLE_DENIED");
    }

    function _checkSealAndShipment(string calldata sealId, string calldata shipmentId) private view returns (uint256, uint256) {
        SmartSealRegistry.Seal memory s = registry.getSeal(sealId);
        require(s.exists, "WRONG_SEAL");
        require(!s.revoked, "SEAL_REVOKED");
        SmartSealRegistry.Shipment memory sh = registry.getShipment(shipmentId);
        require(sh.exists && keccak256(bytes(sh.sealId)) == keccak256(bytes(sealId)), "WRONG_SHIPMENT");
        require(sh.active, "SHIPMENT_INACTIVE");
        return (s.pubX, s.pubY);
    }

    function _batchPayload(BatchInput calldata b) private pure returns (bytes memory) {
        bytes memory p1 = bytes.concat(bytes('{"batchId":'), bytes(_u(b.batchId)),
            bytes(',"count":'), bytes(_u(b.count)), bytes(',"counter":'), bytes(_u(b.counter)));
        bytes memory p2 = bytes.concat(bytes(',"domain":"SMARTSEAL/BATCH/v1","firstSeq":'), bytes(_u(b.firstSeq)),
            bytes(',"lastSeq":'), bytes(_u(b.lastSeq)));
        bytes memory p3 = bytes.concat(bytes(',"prevRoot":"'), bytes(_hex(b.prevRoot)),
            bytes('","root":"'), bytes(_hex(b.root)));
        bytes memory p4 = bytes.concat(bytes('","sealId":"'), bytes(b.sealId),
            bytes('","shipmentId":"'), bytes(b.shipmentId));
        bytes memory p5 = bytes.concat(bytes('","timestamp":"'), bytes(b.timestamp), bytes('"}'));
        return bytes.concat(p1, p2, p3, p4, p5);
    }

    function _tamperPayload(TamperInput calldata e) private pure returns (bytes memory) {
        bytes memory p1 = bytes.concat(bytes('{"counter":'), bytes(_u(e.counter)),
            bytes(',"domain":"SMARTSEAL/TAMPER/v1","eventType":"'), bytes(e.eventType));
        bytes memory p2 = bytes.concat(bytes('","sealId":"'), bytes(e.sealId),
            bytes('","seq":'), bytes(_u(e.seq)));
        bytes memory p3 = bytes.concat(bytes(',"shipmentId":"'), bytes(e.shipmentId),
            bytes('","timestamp":"'), bytes(e.timestamp), bytes('"}'));
        return bytes.concat(p1, p2, p3);
    }

    function _u(uint256 v) private pure returns (string memory) {
        if (v == 0) return "0";
        uint256 t = v; uint256 n;
        while (t != 0) { n++; t /= 10; }
        bytes memory out = new bytes(n);
        while (v != 0) { n--; out[n] = bytes1(uint8(48 + v % 10)); v /= 10; }
        return string(out);
    }

    function _hex(bytes32 v) private pure returns (string memory) {
        bytes16 digits = "0123456789abcdef";
        bytes memory out = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            out[2 * i] = digits[uint8(v[i] >> 4)];
            out[2 * i + 1] = digits[uint8(v[i] & 0x0f)];
        }
        return string(out);
    }
}
