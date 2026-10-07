"""E5 -- dual-ledger proof (DLP): size and verification cost; on-chain footprint."""
import gc
import statistics
import time

from common import World, save
from hylehr.crypto_utils import H, canon
from hylehr.ledger import make_tx, verify_dlp

TX_PER_BLOCK = [16, 64, 256, 1024, 4096]
BLOCKS_PER_EPOCH = [1, 16, 128, 1024]


class Manual:
    """Anchor exactly when the experiment says so."""
    name, fire = "manual", False

    def decide(self, now, score, max_class, n_tx):
        fire, self.fire = self.fire, False
        return "manual" if fire else None


def proof_bytes(p):
    return (32 + 4 + 32 * len(p["tx_path"])             # tx id, index, tx path
            + 8 + 32 + 32 + 32 + 8                      # block header fields
            + 4 + 32 * len(p["blk_path"]) + 8)          # block index, path, epoch


rows = []
for nb in BLOCKS_PER_EPOCH:
    for nt in TX_PER_BLOCK:
        if nb * nt > 140_000:
            continue
        pol = Manual()
        w = World(policy=pol)
        pol.fire = True
        w.block()                                    # set-up blocks get their own epoch
        target = None
        for b in range(nb):
            for i in range(nt):
                w.nonce += 1
                t = make_tx(w.hosp_a, "RECORD_ADD",
                            {"rec_id": f"r{b}-{i}", "patient": w.patient.id, "rtype": "vitals",
                             "cls": 0, "cid": H("c", b, i).hex(), "size": 2048, "chunks": 1},
                            w.nonce, w.clock)
                w.private.submit(t, check_sig=False)
                if b == nb // 2 and i == nt // 3:
                    target = t
            w.clock += 2.0
            blk = w.private.commit_block(w.clock, revalidate=False)
            pol.fire = b == nb - 1                   # close the epoch on its last block
            w.anchorer.on_block(blk)
        t0 = time.perf_counter(); proof = w.anchorer.prove(target["id"]); gen = time.perf_counter() - t0
        gc.collect()
        for _ in range(200):                         # warm-up
            verify_dlp(proof, w.public)
        ver = []
        for _ in range(1000):
            t0 = time.perf_counter(); ok = verify_dlp(proof, w.public); ver.append(time.perf_counter() - t0)
        assert ok
        rows.append({"blocks_per_epoch": nb, "tx_per_block": nt, "tx_in_epoch": nb * nt,
                     "hashes": len(proof["tx_path"]) + len(proof["blk_path"]),
                     "proof_bytes": proof_bytes(proof), "gen_ms": gen * 1e3,
                     "verify_us": statistics.median(ver) * 1e6})

print(f"{'blk/epoch':>10s}{'tx/blk':>8s}{'tx/epoch':>10s}{'hashes':>8s}{'bytes':>7s}"
      f"{'gen ms':>9s}{'verify us':>11s}")
for r in rows:
    print(f"{r['blocks_per_epoch']:>10d}{r['tx_per_block']:>8d}{r['tx_in_epoch']:>10d}"
          f"{r['hashes']:>8d}{r['proof_bytes']:>7d}{r['gen_ms']:>9.2f}{r['verify_us']:>11.1f}")

# on-chain footprint of one record, whatever its size
w = World()
foot = []
for rtype, size in (("vitals", 2 * 1024), ("lab-report", 64 * 1024),
                    ("xray-image", 8 * 2 ** 20), ("ct-series", 48 * 2 ** 20)):
    _, t = w.add_record(f"f-{rtype}", rtype=rtype, size=size)
    foot.append({"rtype": rtype, "record_bytes": size, "private_tx_bytes": len(canon(t))})
w.grant(); g = w.private.mempool[-1]
foot.append({"rtype": "CONSENT_GRANT tx", "record_bytes": 0, "private_tx_bytes": len(canon(g))})
print("\nOn-chain footprint")
for f in foot:
    print(f"  {f['rtype']:<18s} record {f['record_bytes']:>10d} B  ->  private-ledger tx "
          f"{f['private_tx_bytes']:>4d} B")
print("  public anchor: 2 x 32-byte roots + 2 heights + trigger = 81 B of calldata per epoch")
save("e5_proofs.json", {"proofs": rows, "footprint": foot})
