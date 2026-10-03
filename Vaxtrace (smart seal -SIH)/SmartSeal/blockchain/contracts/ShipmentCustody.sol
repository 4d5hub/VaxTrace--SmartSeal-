// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "./SmartSealRegistry.sol";

contract ShipmentCustody {
    SmartSealRegistry public immutable registry;
    bytes32 public constant HANDOFF_TYPEHASH = keccak256("SmartSealHandoff/v1");
    uint256 private constant HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    struct HandoffInput { string shipmentId; address from; address to; bytes32 nonce; uint64 atSeq; string timestamp; }
    struct Handoff { address from; address to; bytes32 nonce; uint64 atSeq; string timestamp; bytes sigFrom; bytes sigTo; uint64 anchoredAt; }

    mapping(string => Handoff[]) private _handoffs;
    mapping(string => mapping(bytes32 => bool)) public nonceUsed;

    event CustodyTransferred(string shipmentId, address indexed from, address indexed to, bytes32 nonce, uint64 atSeq);

    constructor(SmartSealRegistry r) { registry = r; }

    function handoffDigest(HandoffInput calldata h) public view returns (bytes32) {
        return keccak256(abi.encode(HANDOFF_TYPEHASH, block.chainid, address(this), keccak256(bytes(h.shipmentId)),
            h.from, h.to, h.nonce, h.atSeq, keccak256(bytes(h.timestamp))));
    }

    function transferCustody(HandoffInput calldata h, bytes calldata sigFrom, bytes calldata sigTo) external {
        require(registry.roleOf(msg.sender) == SmartSealRegistry.Role.GATEWAY && !registry.participantRevoked(msg.sender), "ROLE_DENIED");
        SmartSealRegistry.Shipment memory sh = registry.getShipment(h.shipmentId);
        require(sh.exists && sh.active, "WRONG_SHIPMENT");
        require(sigFrom.length == 65 && sigTo.length == 65, "NEED_BOTH_SIGNATURES");
        require(!nonceUsed[h.shipmentId][h.nonce], "NONCE_REUSED");
        Handoff[] storage list = _handoffs[h.shipmentId];
        uint256 stage = list.length;
        require(stage < 3, "ROUTE_COMPLETE");
        address current = stage == 0 ? sh.initialCustodian : list[stage - 1].to;
        require(h.from == current, "NOT_CURRENT_CUSTODIAN");
        require(registry.roleOf(h.from) == _routeRole(stage) && registry.roleOf(h.to) == _routeRole(stage + 1), "ROUTE_VIOLATION");
        require(!registry.participantRevoked(h.from) && !registry.participantRevoked(h.to), "PARTICIPANT_REVOKED");
        bytes32 digest = handoffDigest(h);
        require(_signer(digest, sigFrom) == h.from, "BAD_SIGNATURE_FROM");
        require(_signer(digest, sigTo) == h.to, "BAD_SIGNATURE_TO");
        nonceUsed[h.shipmentId][h.nonce] = true;
        list.push(Handoff(h.from, h.to, h.nonce, h.atSeq, h.timestamp, sigFrom, sigTo, uint64(block.timestamp)));
        emit CustodyTransferred(h.shipmentId, h.from, h.to, h.nonce, h.atSeq);
    }

    function handoffCount(string calldata shipmentId) external view returns (uint256) { return _handoffs[shipmentId].length; }
    function getHandoff(string calldata shipmentId, uint256 index) external view returns (Handoff memory) { return _handoffs[shipmentId][index]; }

    function currentCustodian(string calldata shipmentId) external view returns (address) {
        Handoff[] storage list = _handoffs[shipmentId];
        return list.length == 0 ? registry.getShipment(shipmentId).initialCustodian : list[list.length - 1].to;
    }

    function _routeRole(uint256 stage) private pure returns (SmartSealRegistry.Role) {
        if (stage == 0) return SmartSealRegistry.Role.MANUFACTURER;
        if (stage == 1) return SmartSealRegistry.Role.TRANSPORTER;
        if (stage == 2) return SmartSealRegistry.Role.WAREHOUSE;
        return SmartSealRegistry.Role.PHARMACY;
    }

    function _signer(bytes32 digest, bytes calldata sig) private pure returns (address) {
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "MALFORMED_SIGNATURE");
        require(uint256(s) <= HALF_N, "MALFORMED_SIGNATURE");
        address a = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)), v, r, s);
        require(a != address(0), "MALFORMED_SIGNATURE");
        return a;
    }
}
