// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "./P256.sol";

contract SmartSealRegistry {
    enum Role { NONE, MANUFACTURER, TRANSPORTER, WAREHOUSE, PHARMACY, REGULATOR, VERIFIER, GATEWAY }

    struct Seal { bool exists; bool revoked; address manufacturer; uint256 pubX; uint256 pubY; }
    struct Shipment { bool exists; bool active; string sealId; address initialCustodian; bytes32 policyHash; }

    address public admin;
    mapping(address => Role) public roleOf;
    mapping(address => bool) public participantRevoked;
    mapping(address => bool) public isModule;
    mapping(string => Seal) private _seals;
    mapping(string => Shipment) private _shipments;

    event RoleSet(address indexed account, Role role);
    event ParticipantRevoked(address indexed account);
    event ModuleSet(address indexed module, bool allowed);
    event SealRegistered(string sealId, address indexed manufacturer, uint256 pubX, uint256 pubY);
    event SealRevoked(string sealId, address indexed by);
    event ShipmentStarted(string shipmentId, string sealId, bytes32 policyHash, address indexed initialCustodian);
    event ShipmentClosed(string shipmentId);

    constructor() { admin = msg.sender; }

    modifier onlyAdmin() { require(msg.sender == admin, "ROLE_DENIED"); _; }

    function _hasRole(address a, Role r) private view returns (bool) {
        return roleOf[a] == r && !participantRevoked[a];
    }

    function setRole(address account, Role role) external onlyAdmin { roleOf[account] = role; emit RoleSet(account, role); }
    function revokeParticipant(address account) external onlyAdmin { participantRevoked[account] = true; emit ParticipantRevoked(account); }
    function setModule(address module, bool allowed) external onlyAdmin { isModule[module] = allowed; emit ModuleSet(module, allowed); }

    function registerSeal(string calldata sealId, uint256 pubX, uint256 pubY) external {
        require(_hasRole(msg.sender, Role.MANUFACTURER), "ROLE_DENIED");
        require(!_seals[sealId].exists, "SEAL_EXISTS");
        require(P256.isOnCurve(pubX, pubY), "BAD_PUBLIC_KEY");
        _seals[sealId] = Seal(true, false, msg.sender, pubX, pubY);
        emit SealRegistered(sealId, msg.sender, pubX, pubY);
    }

    function revokeSeal(string calldata sealId) external {
        Seal storage s = _seals[sealId];
        require(s.exists, "WRONG_SEAL");
        bool allowed = _hasRole(msg.sender, Role.REGULATOR) || (_hasRole(msg.sender, Role.MANUFACTURER) && msg.sender == s.manufacturer);
        require(allowed, "ROLE_DENIED");
        require(!s.revoked, "ALREADY_REVOKED");
        s.revoked = true;
        emit SealRevoked(sealId, msg.sender);
    }

    function startShipment(string calldata shipmentId, string calldata sealId, bytes32 policyHash) external {
        require(_hasRole(msg.sender, Role.MANUFACTURER), "ROLE_DENIED");
        Seal storage s = _seals[sealId];
        require(s.exists && s.manufacturer == msg.sender, "WRONG_SEAL");
        require(!s.revoked, "SEAL_REVOKED");
        require(!_shipments[shipmentId].exists, "SHIPMENT_EXISTS");
        _shipments[shipmentId] = Shipment(true, true, sealId, msg.sender, policyHash);
        emit ShipmentStarted(shipmentId, sealId, policyHash, msg.sender);
    }

    function closeShipment(string calldata shipmentId) external {
        require(isModule[msg.sender], "ROLE_DENIED");
        require(_shipments[shipmentId].exists, "WRONG_SHIPMENT");
        _shipments[shipmentId].active = false;
        emit ShipmentClosed(shipmentId);
    }

    function getSeal(string calldata sealId) external view returns (Seal memory) { return _seals[sealId]; }
    function getShipment(string calldata shipmentId) external view returns (Shipment memory) { return _shipments[shipmentId]; }
    function isActiveParticipant(address a) external view returns (bool) { return roleOf[a] != Role.NONE && !participantRevoked[a]; }
}
