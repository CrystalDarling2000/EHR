"""Attack lab: each case runs on a fresh sandbox consortium and reports what happened."""
import copy

from hylehr.crypto_utils import H, Identity, merkle_proof, merkle_root, verify_sig, x25519_keypair
from hylehr.ledger import Block, LedgerError, make_tx, verify_dlp
from hylehr.transmission import Receiver, TransferError

from world import DemoWorld


def _fresh():
    w = DemoWorld()
    rec = w.add_record("lab-report")
    w.grant(["lab-report"])
    return w, rec


def _transfer(w, rec):
    """Run the protocol; return None on delivery or the error text when refused."""
    try:
        req = w.receiver.request(rec)
        resp = w.sender.respond(req, w.clock)
        w.receiver.finish(resp, w.store, w.hosp_a.pk)
        return None
    except (TransferError, LedgerError) as exc:
        return str(exc)


def stale_custodian():
    w, rec = _fresh()
    stale = copy.deepcopy(w.private)
    w.revoke()
    w.sender.ledger = stale
    return _transfer(w, rec)


def stale_custodian_no_check():
    w, rec = _fresh()
    stale = copy.deepcopy(w.private)
    w.revoke()
    w.sender.ledger, w.sender.check_fresh = stale, False
    return _transfer(w, rec)


def lagging_requester():
    w, rec = _fresh()
    lagging = copy.deepcopy(w.private)
    w.policy.theta = 1e9                           # keep the change unanchored
    w.grant(["lab-report", "prescription"])        # re-scoped, not yet anchored
    w.receiver.ledger = lagging
    return _transfer(w, rec)


def after_revocation():
    w, rec = _fresh()
    w.revoke()
    return _transfer(w, rec)


def outside_scope():
    w, _ = _fresh()
    rec = w.add_record("psychiatric-note")
    return _transfer(w, rec)


def mitm_key_swap():
    w, rec = _fresh()
    try:
        req = w.receiver.request(rec)
        resp = w.sender.respond(req, w.clock)
        resp["epk"] = x25519_keypair()[1].hex()
        w.receiver.finish(resp, w.store, w.hosp_a.pk)
        return None
    except TransferError as exc:
        return str(exc)


def unregistered_requester():
    w, rec = _fresh()
    mallory = Receiver(Identity("Mallory", "provider"), w.private, w.public)
    try:
        w.sender.respond(mallory.request(rec), w.clock)
        return None
    except TransferError as exc:
        return str(exc)


def tampered_chunk():
    w, rec = _fresh()
    w.store.tamper(bytes.fromhex(w.private.records[rec]["cid"]))
    return _transfer(w, rec)


def forged_transaction():
    w, _ = _fresh()
    t = make_tx(w.hosp_b, "CONSENT_GRANT",
                {"patient": w.patient.id, "grantee": w.hosp_b.id, "scope": ["psychiatric-note"],
                 "purpose": "treatment", "expiry": w.clock + 1e6}, 999, w.clock)
    t["sender"], t["pk"] = w.patient.id, w.patient.pk.hex()
    try:
        w.private.submit(t)
        return None
    except LedgerError as exc:
        return str(exc)


def _forge_last_block(w, drop_tx_id):
    old = w.private.chain[-1]
    kept = [t for t in old.txs if t["id"] != drop_tx_id]
    forged = Block(old.height, old.prev, merkle_root([bytes.fromhex(t["id"]) for t in kept]),
                   w.private.chain[-2].state_digest, old.ts, kept)
    quorum = w.private.validators[:w.private.quorum]
    for v in quorum:
        forged.sigs[v.id] = v.sign(forged.header())
    signed = all(verify_sig(v.pk, forged.sigs[v.id], forged.header()) for v in quorum)
    return forged, signed


def rewrite_anchored():
    w, _ = _fresh()
    w._tx(w.patient, "CONSENT_REVOKE", {"patient": w.patient.id, "grantee": w.hosp_b.id})
    w._tx(w.hosp_a, "EMERGENCY_ACCESS", {"rec_id": "LAB-0001", "reason": "drill"})
    blk, anchor = w._block()                        # critical: anchored at once
    revoke_id = blk.txs[0]["id"]
    forged, signed = _forge_last_block(w, revoke_id)
    a = w.public.anchors[-1]
    hashes = [b.hash for b in w.private.chain[a.first:a.last]] + [forged.hash]
    proof = {"tx_id": forged.txs[0]["id"], "tx_index": 0,
             "tx_path": merkle_proof([bytes.fromhex(t["id"]) for t in forged.txs], 0),
             "header": (forged.height, forged.prev, forged.tx_root, forged.state_digest,
                        int(forged.ts * 1000)),
             "blk_index": forged.height - a.first,
             "blk_path": merkle_proof(hashes, forged.height - a.first), "epoch": a.epoch}
    accepted = verify_dlp(proof, w.public)
    if accepted:
        return None
    return (f"forged block carries {len(forged.sigs)} valid validator signatures"
            if signed else "forgery failed") + ", but its proof is rejected by the public anchor"


def rewrite_unanchored():
    w, _ = _fresh()
    epochs = len(w.public.anchors)
    w.policy.theta = 1e9                            # keep the next block pending
    w.grant(["lab-report", "prescription"])
    assert len(w.public.anchors) == epochs
    forged, signed = _forge_last_block(w, w.private.chain[-1].txs[0]["id"])
    return None if signed else "forgery failed"


CASES = [
    ("after_revocation", "Request after the patient revoked consent", "Consent check", after_revocation, True),
    ("outside_scope", "Request for a record type the consent does not cover", "Consent check", outside_scope, True),
    ("stale_custodian", "Custodian cut off from the consortium misses a revocation", "Freshness (public anchor)", stale_custodian, True),
    ("stale_custodian_no_check", "Same partition, custodian's freshness check switched off", "Consent-bound key", stale_custodian_no_check, True),
    ("lagging_requester", "Consent re-scoped in an unanchored block; requester lags one block", "Consent-bound key", lagging_requester, True),
    ("mitm_key_swap", "Man-in-the-middle swaps the custodian's ephemeral key", "Signed handshake", mitm_key_swap, True),
    ("unregistered_requester", "Request signed by an identity that is not on the ledger", "Identity registry", unregistered_requester, True),
    ("tampered_chunk", "One bit flipped in a stored ciphertext chunk", "Merkle CID on ledger", tampered_chunk, True),
    ("forged_transaction", "Hospital B forges a consent grant in the patient's name", "Transaction signature", forged_transaction, True),
    ("rewrite_anchored", "Colluding quorum rewrites an anchored block to erase a revocation", "Public anchor + proof", rewrite_anchored, True),
    ("rewrite_unanchored", "Control: the same rewrite on a block that is not yet anchored", "Exposure window", rewrite_unanchored, False),
]


def run(case_id):
    for cid, title, defence, fn, should_block in CASES:
        if cid == case_id:
            outcome = fn()
            blocked = outcome is not None
            if cid == "rewrite_unanchored":
                text = ("Not detectable in public. The forged block carries valid quorum signatures and no "
                        "anchor contradicts it yet. This is the exposure window that SAAA shortens for "
                        "critical events.")
            else:
                text = outcome if blocked else "Attack succeeded"
            return {"id": cid, "title": title, "defence": defence, "blocked": blocked,
                    "expected": blocked == should_block, "outcome": text, "control": not should_block}
    raise KeyError(case_id)


def catalogue():
    return [{"id": c[0], "title": c[1], "defence": c[2], "control": not c[4]} for c in CASES]
