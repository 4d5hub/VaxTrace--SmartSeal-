from __future__ import annotations

import hashlib

from hashing import HEX64


def _pair(left: str, right: str) -> str:
    return hashlib.sha256(bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def merkle_levels(leaves: list) -> list:
    if not leaves:
        raise ValueError("a Merkle tree needs at least one leaf")
    if any(not HEX64.match(x) for x in leaves):
        raise ValueError("leaves must be 64-char lowercase hex SHA-256 digests")
    level, levels = list(leaves), []
    levels.append(level)
    while len(level) > 1:
        nxt = [_pair(level[i], level[i + 1] if i + 1 < len(level) else level[i])
               for i in range(0, len(level), 2)]
        levels.append(nxt)
        level = nxt
    return levels


def merkle_root(leaves: list) -> str:
    return merkle_levels(leaves)[-1][0]


def merkle_proof(leaves: list, index: int) -> list:
    levels, proof, idx = merkle_levels(leaves), [], index
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    for level in levels[:-1]:
        sib = idx ^ 1
        if sib >= len(level):
            sib = idx
        proof.append({"hash": level[sib], "position": "right" if idx % 2 == 0 else "left"})
        idx //= 2
    return proof


def verify_proof(leaf: str, proof: list, root: str) -> bool:
    h = leaf
    for step in proof:
        h = _pair(h, step["hash"]) if step["position"] == "right" else _pair(step["hash"], h)
    return h == root
