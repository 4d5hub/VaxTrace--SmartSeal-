// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library P256 {
    uint256 internal constant P  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 internal constant N  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant B  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;
    uint256 internal constant GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    uint256 internal constant GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;

    function isOnCurve(uint256 x, uint256 y) internal pure returns (bool) {
        if (x >= P || y >= P) return false;
        uint256 lhs = mulmod(y, y, P);
        uint256 x3 = mulmod(mulmod(x, x, P), x, P);
        uint256 rhs = addmod(addmod(x3, P - mulmod(3, x, P), P), B, P);
        return lhs == rhs;
    }

    function verify(bytes32 digest, uint256 r, uint256 s, uint256 qx, uint256 qy) internal view returns (bool) {
        if (r == 0 || r >= N || s == 0 || s >= N) return false;
        if (!isOnCurve(qx, qy)) return false;
        uint256 w = _modexp(s, N - 2, N);
        uint256 u1 = mulmod(uint256(digest), w, N);
        uint256 u2 = mulmod(r, w, N);
        (uint256 gqx, uint256 gqy, bool gqInf) = _gPlusQ(qx, qy);
        uint256 rx; uint256 ry; uint256 rz;
        for (uint256 i = 256; i > 0;) {
            unchecked { i--; }
            (rx, ry, rz) = _dbl(rx, ry, rz);
            uint256 b1 = (u1 >> i) & 1;
            uint256 b2 = (u2 >> i) & 1;
            if (b1 == 1 && b2 == 1) {
                if (!gqInf) (rx, ry, rz) = _addAff(rx, ry, rz, gqx, gqy);
            } else if (b1 == 1) {
                (rx, ry, rz) = _addAff(rx, ry, rz, GX, GY);
            } else if (b2 == 1) {
                (rx, ry, rz) = _addAff(rx, ry, rz, qx, qy);
            }
        }
        if (rz == 0) return false;
        uint256 zi = _modexp(rz, P - 2, P);
        uint256 x = mulmod(rx, mulmod(zi, zi, P), P);
        return x % N == r;
    }

    function _gPlusQ(uint256 qx, uint256 qy) private view returns (uint256, uint256, bool) {
        (uint256 x, uint256 y, uint256 z) = _addAff(GX, GY, 1, qx, qy);
        if (z == 0) return (0, 0, true);
        uint256 zi = _modexp(z, P - 2, P);
        uint256 zi2 = mulmod(zi, zi, P);
        return (mulmod(x, zi2, P), mulmod(y, mulmod(zi2, zi, P), P), false);
    }

    function _dbl(uint256 x, uint256 y, uint256 z) private pure returns (uint256, uint256, uint256) {
        if (z == 0 || y == 0) return (0, 0, 0);
        uint256 zz = mulmod(z, z, P);
        uint256 m = mulmod(3, mulmod(addmod(x, P - zz, P), addmod(x, zz, P), P), P);
        uint256 yy = mulmod(y, y, P);
        uint256 s = mulmod(4, mulmod(x, yy, P), P);
        uint256 x3 = addmod(mulmod(m, m, P), P - mulmod(2, s, P), P);
        uint256 y3 = addmod(mulmod(m, addmod(s, P - x3, P), P), P - mulmod(8, mulmod(yy, yy, P), P), P);
        return (x3, y3, mulmod(2, mulmod(y, z, P), P));
    }

    function _addAff(uint256 x1, uint256 y1, uint256 z1, uint256 x2, uint256 y2)
        private pure returns (uint256, uint256, uint256)
    {
        if (z1 == 0) return (x2, y2, 1);
        uint256 zz = mulmod(z1, z1, P);
        uint256 h = addmod(mulmod(x2, zz, P), P - x1, P);
        uint256 r = addmod(mulmod(y2, mulmod(zz, z1, P), P), P - y1, P);
        if (h == 0) {
            if (r == 0) return _dbl(x1, y1, z1);
            return (0, 0, 0);
        }
        uint256 hh = mulmod(h, h, P);
        uint256 hhh = mulmod(h, hh, P);
        uint256 v = mulmod(x1, hh, P);
        uint256 x3 = addmod(addmod(mulmod(r, r, P), P - hhh, P), P - mulmod(2, v, P), P);
        uint256 y3 = addmod(mulmod(r, addmod(v, P - x3, P), P), P - mulmod(y1, hhh, P), P);
        return (x3, y3, mulmod(z1, h, P));
    }

    function _modexp(uint256 b, uint256 power, uint256 modulus) private view returns (uint256 result) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, 192))
            mstore(ptr, 32)
            mstore(add(ptr, 32), 32)
            mstore(add(ptr, 64), 32)
            mstore(add(ptr, 96), b)
            mstore(add(ptr, 128), power)
            mstore(add(ptr, 160), modulus)
            if iszero(staticcall(gas(), 5, ptr, 192, ptr, 32)) { revert(0, 0) }
            result := mload(ptr)
        }
    }
}
