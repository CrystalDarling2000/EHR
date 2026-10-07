"""Off-chain encrypted store, addressed by the Merkle root of the chunks."""
from .crypto_utils import merkle_proof, merkle_verify


class OffChainStore:
    """Honest-but-curious blob store: sees only ciphertext."""

    def __init__(self):
        self._blobs: dict[bytes, list[bytes]] = {}

    def put(self, cid: bytes, chunks: list[bytes]):
        self._blobs[cid] = list(chunks)

    def get(self, cid: bytes) -> list[bytes]:
        return list(self._blobs[cid])

    def get_chunk(self, cid: bytes, i: int):
        """One chunk plus the Merkle path that ties it to the on-chain CID."""
        chunks = self._blobs[cid]
        return chunks[i], merkle_proof(chunks, i)

    def tamper(self, cid: bytes, i: int = 0):
        """Flip one bit of a stored chunk (used by the security tests)."""
        c = bytearray(self._blobs[cid][i])
        c[len(c) // 2] ^= 0x01
        self._blobs[cid][i] = bytes(c)


def verify_chunk(chunk: bytes, i: int, path, cid: bytes) -> bool:
    return merkle_verify(chunk, i, path, cid)
