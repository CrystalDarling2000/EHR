"""E6 -- security test suite: each attack must be detected or blocked."""
import copy

from common import World, save
from hylehr.crypto_utils import H, x25519_keypair
from hylehr.ledger import LedgerError, make_tx, verify_dlp
from hylehr.transmission import Receiver, TransferError, transfer

results = []


def case(name, layer, expect):
    def deco(fn):
        try:
            outcome = fn()
        except (TransferError, LedgerError) as exc:
            outcome = f"{type(exc).__name__}: {exc}"
        ok = expect in str(outcome)
        results.append({"id": f"T{len(results) + 1:02d}", "attack": name, "layer": layer,
                        "outcome": str(outcome), "pass": ok})
        print(f"{results[-1]['id']}  {'PASS' if ok else 'FAIL'}  [{layer}] {name}")
        print(f"           -> {outcome}")
        return fn
    return deco


def fresh():
    w = World()
    data, _ = w.add_record("rec-1")
    w.grant()
    w.block()
    return w, data


@case("Honest transfer with live consent (control)", "transmission", "delivered")
def t_ok():
    w, data = fresh()
    got, _ = transfer(w.sender, w.receiver, w.hosp_a.pk, "rec-1", w.store, w.clock)
    return "delivered" if got == data else "corrupted"


@case("Request with no consent on the ledger", "consent", "no active consent")
def t_no_consent():
    w = World()
    w.add_record("rec-1")
    w.block()
    return transfer(w.sender, w.receiver, w.hosp_a.pk, "rec-1", w.store, w.clock)


@case("Request after the patient revoked consent", "consent", "no active consent")
def t_revoked():
    w, _ = fresh()
    w.revoke()
    w.block()
    return transfer(w.sender, w.receiver, w.hosp_a.pk, "rec-1", w.store, w.clock)


@case("Request outside the consented scope", "consent", "no active consent")
def t_scope():
    w, _ = fresh()
    w.add_record("rec-2", rtype="psychiatric-note")
    w.block()
    return transfer(w.sender, w.receiver, w.hosp_a.pk, "rec-2", w.store, w.clock)


@case("Request after the consent expired", "consent", "no active consent")
def t_expired():
    w, _ = fresh()
    return transfer(w.sender, w.receiver, w.hosp_a.pk, "rec-1", w.store,
                    w.clock + 31 * 86400)


@case("Sender cut off from the consortium misses an anchored revocation",
      "CBKD + anchoring", "stale replica")
def t_stale_sender():
    w, _ = fresh()
    stale = copy.deepcopy(w.private)             # sender's replica stops here
    w.revoke()
    w.block()                                    # critical -> anchored at once
    w.sender.ledger = stale
    return transfer(w.sender, w.receiver, w.hosp_a.pk, "rec-1", w.store, w.clock)


@case("Same partition, sender's freshness check switched off", "CBKD", "key mismatch")
def t_stale_sender_nocheck():
    w, _ = fresh()
    stale = copy.deepcopy(w.private)
    w.revoke()
    w.block()
    w.sender.ledger, w.sender.check_fresh = stale, False
    return transfer(w.sender, w.receiver, w.hosp_a.pk, "rec-1", w.store, w.clock)


@case("Consent re-scoped in a block not yet anchored; receiver lags one block",
      "CBKD", "key mismatch")
def t_lagging_receiver():
    w, _ = fresh()
    lagging = copy.deepcopy(w.private)           # receiver has not seen the new block
    epochs = len(w.public.anchors)
    w.grant(scope=("lab-report", "prescription"))
    w.block()
    assert len(w.public.anchors) == epochs       # the change is still unanchored
    w.receiver.ledger = lagging
    return transfer(w.sender, w.receiver, w.hosp_a.pk, "rec-1", w.store, w.clock)


@case("Man-in-the-middle swaps the sender's ephemeral key", "transmission", "signature invalid")
def t_mitm():
    w, _ = fresh()
    req = w.receiver.request("rec-1")
    resp = w.sender.respond(req, w.clock)
    resp["epk"] = x25519_keypair()[1].hex()
    return w.receiver.finish(resp, w.store, w.hosp_a.pk)


@case("Request signed by an unregistered identity", "transmission", "not registered")
def t_unregistered():
    w, _ = fresh()
    from hylehr.crypto_utils import Identity
    mallory = Receiver(Identity("mallory", "provider"), w.private, w.public)
    return w.sender.respond(mallory.request("rec-1"), w.clock)


@case("Wrapped data key replayed into a new session", "transmission", "key mismatch")
def t_replay_wrapped():
    w, _ = fresh()
    first = w.sender.respond(w.receiver.request("rec-1"), w.clock)
    req2 = w.receiver.request("rec-1")
    resp2 = w.sender.respond(req2, w.clock)
    resp2["wrapped"] = first["wrapped"]
    return w.receiver.finish(resp2, w.store, w.hosp_a.pk)


@case("One bit flipped in a stored ciphertext chunk", "storage", "does not match on-chain CID")
def t_tamper_chunk():
    w, _ = fresh()
    cid = bytes.fromhex(w.private.records["rec-1"]["cid"])
    w.store.tamper(cid)
    return transfer(w.sender, w.receiver, w.hosp_a.pk, "rec-1", w.store, w.clock)


@case("Chunks of a multi-chunk record reordered", "storage", "does not match on-chain CID")
def t_reorder():
    w = World()
    w.add_record("rec-big", size=1024 * 1024)
    w.grant(); w.block()
    cid = bytes.fromhex(w.private.records["rec-big"]["cid"])
    blobs = w.store._blobs[cid]
    blobs[0], blobs[1] = blobs[1], blobs[0]
    return transfer(w.sender, w.receiver, w.hosp_a.pk, "rec-big", w.store, w.clock)


@case("Transaction with a forged signature", "private ledger", "bad signature")
def t_forged_tx():
    w, _ = fresh()
    t = make_tx(w.hosp_b, "CONSENT_REVOKE",
                {"patient": w.patient.id, "grantee": w.hosp_b.id}, 99, w.clock)
    t["sender"], t["pk"] = w.patient.id, w.patient.pk.hex()
    return w.private.submit(t)


@case("Committed transaction submitted a second time", "private ledger", "replayed")
def t_replay_tx():
    w, _ = fresh()
    t = w.grant(); w.block()
    return w.private.submit(t)


@case("Provider tries to grant consent on the patient's behalf", "private ledger",
      "only the patient")
def t_impersonate():
    w, _ = fresh()
    return w.tx(w.hosp_b, "CONSENT_GRANT",
                {"patient": w.patient.id, "grantee": w.hosp_b.id,
                 "scope": ["psychiatric-note"], "purpose": "treatment",
                 "expiry": w.clock + 1e6})


def _forge_last_block(w, drop_tx_id):
    """A colluding quorum rebuilds the last block without one transaction."""
    from hylehr.crypto_utils import merkle_root, verify_sig
    from hylehr.ledger import Block
    old = w.private.chain[-1]
    kept = [t for t in old.txs if t["id"] != drop_tx_id]
    forged = Block(old.height, old.prev, merkle_root([bytes.fromhex(t["id"]) for t in kept]),
                   w.private.chain[-2].state_digest, old.ts, kept)
    for v in w.private.validators[:w.private.quorum]:
        forged.sigs[v.id] = v.sign(forged.header())
    quorum_ok = all(verify_sig(v.pk, forged.sigs[v.id], forged.header())
                    for v in w.private.validators[:w.private.quorum])
    return forged, kept, quorum_ok


@case("Colluding quorum rewrites an ANCHORED block to erase a revocation",
      "hybrid anchoring", "quorum signatures valid, public proof rejected")
def t_rewrite_anchored():
    from hylehr.crypto_utils import merkle_proof
    w, _ = fresh()
    w.add_record("rec-2")
    rv = w.revoke()
    w.block()                                    # critical -> anchored at once
    assert verify_dlp(w.anchorer.prove(rv["id"]), w.public)
    forged, kept, quorum_ok = _forge_last_block(w, rv["id"])
    a = w.public.anchors[-1]
    hashes = [b.hash for b in w.private.chain[a.first:a.last]] + [forged.hash]
    proof = {"tx_id": kept[0]["id"], "tx_index": 0,
             "tx_path": merkle_proof([bytes.fromhex(t["id"]) for t in kept], 0),
             "header": (forged.height, forged.prev, forged.tx_root, forged.state_digest,
                        int(forged.ts * 1000)),
             "blk_index": forged.height - a.first,
             "blk_path": merkle_proof(hashes, forged.height - a.first), "epoch": a.epoch}
    public_ok = verify_dlp(proof, w.public)
    return (f"quorum signatures {'valid' if quorum_ok else 'invalid'}, "
            f"public proof {'accepted' if public_ok else 'rejected'}")


@case("Control: the same rewrite on a block that is NOT yet anchored",
      "hybrid anchoring", "no public evidence yet")
def t_rewrite_unanchored():
    w, _ = fresh()
    epochs = len(w.public.anchors)
    g = w.grant(scope=("lab-report", "prescription"))
    w.add_record("rec-2")
    w.block()                                    # sensitive only -> stays pending
    assert len(w.public.anchors) == epochs
    forged, kept, quorum_ok = _forge_last_block(w, g["id"])
    return ("quorum signatures valid, no public evidence yet (exposure window)"
            if quorum_ok else "forgery failed")


@case("Patient proves a revocation against the anchored consent root",
      "hybrid anchoring", "revoked entry proven, live entry rejected")
def t_consent_root():
    from hylehr.crypto_utils import merkle_verify
    w, _ = fresh()
    live = w.private.consent_digest(w.patient.id, w.hosp_b.id)
    w.revoke()
    w.block()
    root = w.public.anchors[-1].consent_root
    leaf, i, path = w.private.consent_proof(w.patient.id, w.hosp_b.id)
    return (f"revoked entry {'proven' if merkle_verify(leaf, i, path, root) else 'not proven'}, "
            f"live entry {'accepted' if merkle_verify(live, i, path, root) else 'rejected'}")


@case("Dual-ledger proof presented for a transaction that was never committed",
      "hybrid anchoring", "proof rejected")
def t_fake_inclusion():
    w, _ = fresh()
    rv = w.revoke(); w.block()
    proof = w.anchorer.prove(rv["id"])
    proof["tx_id"] = H("never-happened").hex()
    return "accepted" if verify_dlp(proof, w.public) else "proof rejected"


@case("Break-glass access by a clinician without the emergency role", "private ledger",
      "not an emergency-authorised")
def t_breakglass():
    w, _ = fresh()
    return w.tx(w.hosp_b, "EMERGENCY_ACCESS", {"rec_id": "rec-1", "reason": "trauma"})


passed = sum(r["pass"] for r in results)
print(f"\n{passed}/{len(results)} security tests passed")
save("e6_security.json", results)
