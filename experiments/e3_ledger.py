"""E3 -- private-ledger commit cost versus block size and validator count.

Everything runs in one Python process, so the validators of a quorum check
the block one after another. Two figures are therefore reported:
  sequential  -- what this simulator actually achieves (a lower bound);
  per-node    -- admission + one validator's share of the block work, i.e.
                 the CPU-bound rate if each validator had its own machine.
Network delay is NOT included in either figure.
"""
import statistics
import time

from common import save
from hylehr.crypto_utils import H, Identity
from hylehr.ledger import PrivateLedger, make_tx

BLOCK_SIZES = [100, 500, 1000, 2000]
VALIDATORS = [4, 7, 10, 13, 16]
REPS = 5


def build(n_val, n_tx):
    led = PrivateLedger(n_val)
    prov = Identity("prov", "provider")
    pat = Identity("pat", "patient")
    for i, who in enumerate((prov, pat)):
        led.submit(make_tx(who, "REGISTER", {"role": who.role}, i))
    led.commit_block(0.0)
    txs = [make_tx(prov, "RECORD_ADD",
                   {"rec_id": f"r{i}", "patient": pat.id, "rtype": "lab-report", "cls": int(i % 3 == 0),
                    "cid": H("c", i).hex(), "size": 65536, "chunks": 1}, 10 + i)
           for i in range(n_tx)]
    return led, txs


rows = []
for n_val in VALIDATORS:
    for n_tx in BLOCK_SIZES:
        adm, com = [], []
        for _ in range(REPS):
            led, txs = build(n_val, n_tx)
            t0 = time.perf_counter()
            for t in txs:
                led.submit(t)
            adm.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            led.commit_block(2.0)
            com.append(time.perf_counter() - t0)
        a, c = statistics.median(adm), statistics.median(com)
        q = led.quorum
        rows.append({"validators": n_val, "f": led.f, "quorum": q, "block_tx": n_tx,
                     "admit_ms_per_tx": a / n_tx * 1e3, "commit_ms": c * 1e3,
                     "tps_sequential": n_tx / (a + c), "tps_per_node": n_tx / (a + c / q),
                     "tx_bytes": len(str(txs[0]))})

print(f"{'n':>3s}{'f':>3s}{'2f+1':>5s}{'tx/blk':>8s}{'admit ms/tx':>13s}{'commit ms':>11s}"
      f"{'tps seq':>9s}{'tps node':>10s}")
for r in rows:
    print(f"{r['validators']:>3d}{r['f']:>3d}{r['quorum']:>5d}{r['block_tx']:>8d}"
          f"{r['admit_ms_per_tx']:>13.4f}{r['commit_ms']:>11.1f}{r['tps_sequential']:>9.0f}"
          f"{r['tps_per_node']:>10.0f}")
save("e3_ledger.json", rows)
