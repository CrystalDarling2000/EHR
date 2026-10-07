"""Cryptographic building blocks used across the prototype.

Everything here is a thin, auditable wrapper over the `cryptography`
package (OpenSSL backend). No home-made primitives.
"""
import hashlib
import hmac
import json
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

RAW = serialization.Encoding.Raw
RAW_PUB = serialization.PublicFormat.Raw

LEAF, NODE = b"\x00", b"\x01"
EMPTY = hashlib.sha256(b"\x02").digest()      # padding leaf


# ---------------------------------------------------------------- hashing
def H(*parts) -> bytes:
    """SHA-256 over length-prefixed parts (no ambiguity between fields)."""
    h = hashlib.sha256()
    for p in parts:
        if isinstance(p, str):
            p = p.encode()
        elif isinstance(p, int):
            p = struct.pack(">Q", p)
        h.update(struct.pack(">I", len(p)))
        h.update(p)
    return h.digest()


def canon(obj) -> bytes:
    """Canonical JSON encoding used for signing and hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def mac(key: bytes, *parts) -> bytes:
    return hmac.new(key, H(*parts), hashlib.sha256).digest()


# ----------------------------------------------------------- Merkle tree
def _levels(leaves):
    """Bottom-up levels of a power-of-two padded Merkle tree."""
    level = [hashlib.sha256(LEAF + x).digest() for x in leaves]
    size = 1
    while size < max(1, len(level)):
        size *= 2
    level += [EMPTY] * (size - len(level))
    levels = [level]
    while len(level) > 1:
        level = [hashlib.sha256(NODE + level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
        levels.append(level)
    return levels


def merkle_root(leaves) -> bytes:
    return _levels(leaves)[-1][0]


def merkle_proof(leaves, index):
    """Sibling path for leaves[index]; the index bits give the side."""
    path = []
    for level in _levels(leaves)[:-1]:
        path.append(level[index ^ 1])
        index >>= 1
    return path


def merkle_verify(leaf: bytes, index: int, path, root: bytes) -> bool:
    node = hashlib.sha256(LEAF + leaf).digest()
    for sib in path:
        pair = sib + node if index & 1 else node + sib
        node = hashlib.sha256(NODE + pair).digest()
        index >>= 1
    return hmac.compare_digest(node, root)


# ------------------------------------------------------------ identities
class Identity:
    """A ledger participant: long-term Ed25519 signing key and a role."""

    def __init__(self, name: str, role: str):
        self.name, self.role = name, role
        self._sk = Ed25519PrivateKey.generate()
        self.pk = self._sk.public_key().public_bytes(RAW, RAW_PUB)
        self.id = H("id", self.pk).hex()[:32]     # pseudonymous identifier

    def sign(self, msg: bytes) -> bytes:
        return self._sk.sign(msg)


def verify_sig(pk: bytes, sig: bytes, msg: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except Exception:
        return False


# ---------------------------------------------------------- key exchange
def x25519_keypair():
    sk = X25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes(RAW, RAW_PUB)


def x25519_shared(sk, peer_pk: bytes) -> bytes:
    return sk.exchange(X25519PublicKey.from_public_bytes(peer_pk))


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 64) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length,
                salt=salt, info=info).derive(ikm)


# ----------------------------------------------------- record encryption
CHUNK = 256 * 1024          # 256 KiB chunks


def encrypt_record(rec_id: str, data: bytes, chunk: int = CHUNK):
    """Encrypt a record at rest under a fresh per-record DEK.

    Returns (dek, chunks, cid) where cid is the Merkle root over the
    ciphertext chunks. The counter nonce is safe because a DEK is never
    reused for another record or another version of the record.
    """
    dek = AESGCM.generate_key(bit_length=256)
    aead = AESGCM(dek)
    n = max(1, -(-len(data) // chunk))
    out = []
    for i in range(n):
        aad = H("chunk", rec_id, i, n)
        nonce = struct.pack(">IQ", 0, i)
        out.append(aead.encrypt(nonce, data[i * chunk:(i + 1) * chunk], aad))
    return dek, out, merkle_root(out)


def decrypt_record(rec_id: str, dek: bytes, chunks) -> bytes:
    aead = AESGCM(dek)
    n = len(chunks)
    return b"".join(
        aead.decrypt(struct.pack(">IQ", 0, i), c, H("chunk", rec_id, i, n))
        for i, c in enumerate(chunks))


def wrap(key: bytes, secret: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, secret, aad)


def unwrap(key: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)
