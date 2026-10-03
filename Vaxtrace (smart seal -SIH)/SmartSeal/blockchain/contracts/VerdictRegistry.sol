// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "./SmartSealRegistry.sol";

contract VerdictRegistry {
    enum Verdict { NONE, ACCEPT, QUARANTINE, REJECT }
    struct VerdictRecord { Verdict verdict; string[] reasonCodes; bytes32 reportHash; address verifier; uint64 finalizedAt; }

    SmartSealRegistry public immutable registry;
    mapping(string => VerdictRecord) private _verdicts;

    event VerdictFinalized(string shipmentId, Verdict verdict, bytes32 reportHash, address indexed verifier);

    constructor(SmartSealRegistry r) { registry = r; }

    function finalizeVerdict(string calldata shipmentId, Verdict verdict, string[] calldata reasonCodes, bytes32 reportHash) external {
        SmartSealRegistry.Role r = registry.roleOf(msg.sender);
        require(!registry.participantRevoked(msg.sender) &&
            (r == SmartSealRegistry.Role.VERIFIER || r == SmartSealRegistry.Role.PHARMACY || r == SmartSealRegistry.Role.REGULATOR), "ROLE_DENIED");
        require(registry.getShipment(shipmentId).exists, "WRONG_SHIPMENT");
        require(verdict != Verdict.NONE, "BAD_VERDICT");
        require(_verdicts[shipmentId].verdict == Verdict.NONE, "VERDICT_EXISTS");
        VerdictRecord storage v = _verdicts[shipmentId];
        v.verdict = verdict; v.reportHash = reportHash; v.verifier = msg.sender; v.finalizedAt = uint64(block.timestamp);
        for (uint256 i = 0; i < reasonCodes.length; i++) v.reasonCodes.push(reasonCodes[i]);
        registry.closeShipment(shipmentId);
        emit VerdictFinalized(shipmentId, verdict, reportHash, msg.sender);
    }

    function getVerdict(string calldata shipmentId) external view returns (VerdictRecord memory) { return _verdicts[shipmentId]; }
}
