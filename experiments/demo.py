"""End-to-end walk-through of the HyL-EHR prototype (one patient, two hospitals)."""
from common import World
from hylehr.ledger import CLASS_NAME, verify_dlp
from hylehr.transmission import TransferError, transfer

w = World(n_validators=4)
print("== HyL-EHR prototype demo ==")
print(f"consortium: {len(w.private.validators)} validators, f = {w.private.f}, "
      f"quorum = {w.private.quorum}")
print(f"patient   {w.patient.id}\ncustodian {w.hosp_a.id} (Hospital A)\n"
      f"requester {w.hosp_b.id} (Hospital B)\n")

data, add = w.add_record("LAB-2026-0001", rtype="lab-report")
blk = w.block()
rec = w.private.records["LAB-2026-0001"]
print(f"[1] RECORD_ADD  {len(data)} B encrypted off-chain, {rec['chunks']} chunk(s)")
print(f"    CID (Merkle root of ciphertext) {rec['cid'][:32]}...")
print(f"    private block #{blk.height}, {len(blk.sigs)} validator signatures, "
      f"class = {CLASS_NAME[blk.max_class]}")

try:
    transfer(w.sender, w.receiver, w.hosp_a.pk, "LAB-2026-0001", w.store, w.clock)
except TransferError as e:
    print(f"[2] Hospital B asks before any consent  ->  REFUSED ({e})")

g = w.grant(scope=("lab-report",), days=30)
blk = w.block()
cd = w.private.consent_digest(w.patient.id, w.hosp_b.id)
print(f"[3] CONSENT_GRANT by patient, scope = lab-report, 30 days (block #{blk.height})")
print(f"    consent digest v1 {cd.hex()[:32]}...")

got, log = transfer(w.sender, w.receiver, w.hosp_a.pk, "LAB-2026-0001", w.store, w.clock)
blk = w.block()
print(f"[4] CBKD transfer  ->  delivered, plaintext matches: {got == data}")
print(f"    ACCESS_LOG tx {log['id'][:24]}... in block #{blk.height}")

rv = w.revoke()
blk = w.block()
a = w.public.anchors[-1]
print(f"[5] CONSENT_REVOKE by patient (block #{blk.height}, class = critical)")
print(f"    SAAA trigger = '{a.trigger}'  ->  public anchor, epoch {a.epoch}, "
      f"private blocks {a.first}..{a.last}")
print(f"    ledger root  {a.ledger_root.hex()[:32]}...")
print(f"    consent root {a.consent_root.hex()[:32]}...")

try:
    transfer(w.sender, w.receiver, w.hosp_a.pk, "LAB-2026-0001", w.store, w.clock)
except TransferError as e:
    print(f"[6] Hospital B asks again after revocation  ->  REFUSED ({e})")

proof = w.anchorer.prove(rv["id"])
print(f"[7] Dual-ledger proof for the revocation: {len(proof['tx_path'])} + "
      f"{len(proof['blk_path'])} hashes, verified against public chain: "
      f"{verify_dlp(proof, w.public)}")
print(f"\nprivate chain height {len(w.private.chain)}, public anchors {len(w.public.anchors)}")
