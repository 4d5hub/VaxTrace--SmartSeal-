// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../P256.sol";

contract P256Harness {
    function verify(bytes32 digest, uint256 r, uint256 s, uint256 qx, uint256 qy) external view returns (bool) {
        return P256.verify(digest, r, s, qx, qy);
    }
    function isOnCurve(uint256 x, uint256 y) external pure returns (bool) {
        return P256.isOnCurve(x, y);
    }
}
