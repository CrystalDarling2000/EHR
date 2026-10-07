"""E7a -- write test vectors (roots and Merkle paths) for the Solidity contract."""
import json
import os

from common import RESULTS
from hylehr.crypto_utils import H, merkle_proof, merkle_root

vectors = []
height = 0
for n_blocks in (1, 16, 128, 1024):
    hashes = [H("blk", height + i) for i in range(n_blocks)]
    idx = n_blocks // 3
    vectors.append({"first": height, "last": height + n_blocks - 1,
                    "ledgerRoot": merkle_root(hashes).hex(),
                    "consentRoot": H("consent-root", n_blocks).hex(),
                    "blockHash": hashes[idx].hex(), "index": idx,
                    "path": [p.hex() for p in merkle_proof(hashes, idx)]})
    height += n_blocks
with open(os.path.join(RESULTS, "e7_vectors.json"), "w") as fh:
    json.dump(vectors, fh, indent=1)
print(f"wrote {len(vectors)} epochs, path lengths {[len(v['path']) for v in vectors]}")
