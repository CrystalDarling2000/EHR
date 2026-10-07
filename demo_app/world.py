"""State behind the demo console: one consortium, one patient, two hospitals.

Everything here drives the same hylehr code the experiments use. Nothing is
mocked: keys, signatures, blocks, anchors and proofs are real objects.
"""
import copy
import os
import random
import time

from hylehr.anchoring import SAAA
from hylehr.crypto_utils import H, Identity, encrypt_record, merkle_root
from hylehr.ledger import (CLASS_NAME, CRITICAL, ROUTINE, SENSITIVE, Anchorer, LedgerError,
                           PrivateLedger, PublicLedger, make_tx, verify_dlp)
from hylehr.storage import OffChainStore
from hylehr.transmission import Receiver, Sender, TransferError

RECORD_TYPES = {                      # type: (label, bytes, class)
    "vitals": ("Vital signs", 2 * 1024, ROUTINE),
    "prescription": ("Prescription", 8 * 1024, SENSITIVE),
    "lab-report": ("Laboratory report", 64 * 1024, SENSITIVE),
    "xray-image": ("X-ray image", 8 * 1024 * 1024, SENSITIVE),
    "psychiatric-note": ("Psychiatric note", 32 * 1024, CRITICAL),
}
THETA, T_MAX = 12, 900                # small threshold so the demo shows score anchors


def short(b, n=12):
    if isinstance(b, (bytes, bytearray)):
        b = b.hex()
    return b[:n]


def ms(t0):
    return round((time.perf_counter() - t0) * 1000, 3)


class DemoWorld:
    def __init__(self, n_validators=4):
        self.private = PrivateLedger(n_validators)
        self.public = PublicLedger()
        self.policy = SAAA(theta=THETA, t_max=T_MAX)
        self.anchorer = Anchorer(self.private, self.public, self.policy)
        self.store = OffChainStore()
        self.patient = Identity("Patient", "patient")
        self.hosp_a = Identity("Hospital A", "provider")
        self.hosp_b = Identity("Hospital B", "provider")
        self.keystore, self.plain_hash = {}, {}
        self.nonce, self.seq = 0, 0
        self.clock = 1_780_000_000.0
        self.log = []
        for who in (self.patient, self.hosp_a, self.hosp_b):
            self._tx(who, "REGISTER", {"role": who.role, "emergency": who is self.hosp_a})
        self._block()
        self.sender = Sender(self.hosp_a, self.private, self.public, self.keystore)
        self.receiver = Receiver(self.hosp_b, self.private, self.public)
        self._say("setup", "Consortium started",
                  f"{n_validators} validators, tolerates {self.private.f} fault, "
                  f"quorum {self.private.quorum}. Patient and two hospitals registered.")

    # ---------------------------------------------------------------- helpers
    def _say(self, kind, title, detail, ok=True, steps=None):
        self.log.append({"n": len(self.log) + 1, "kind": kind, "title": title, "detail": detail,
                         "ok": ok, "steps": steps or []})

    def _tx(self, who, tx_type, payload):
        self.nonce += 1
        t = make_tx(who, tx_type, payload, self.nonce, self.clock)
        self.private.submit(t)
        return t

    def _block(self):
        self.clock += 2.0
        blk = self.private.commit_block(self.clock)
        return blk, self.anchorer.on_block(blk)

    def _commit_note(self, blk, anchor):
        note = (f"Private block #{blk.height} committed with {len(blk.sigs)} validator signatures "
                f"(highest class: {CLASS_NAME[blk.max_class]}). ")
        if anchor:
            note += (f"SAAA trigger '{anchor.trigger}' fired: public anchor {anchor.epoch} now covers "
                     f"private blocks {anchor.first} to {anchor.last}.")
        else:
            note += (f"No anchor yet: score {self.policy.score:.0f} of {self.policy.theta:.0f}, "
                     f"so this block is protected by the consortium quorum only.")
        return note

    # ---------------------------------------------------------------- actions
    def add_record(self, rtype):
        label, size, cls = RECORD_TYPES[rtype]
        self.seq += 1
        rec_id = f"{rtype.split('-')[0].upper()}-{self.seq:04d}"
        head = (f'{{"resourceType":"DocumentReference","type":"{label}",'
                f'"subject":"Patient/{self.patient.id}"}}').encode()
        data = head + os.urandom(size - len(head))
        t0 = time.perf_counter()
        dek, chunks, cid = encrypt_record(rec_id, data)
        enc_ms = ms(t0)
        self.store.put(cid, chunks)
        self.keystore[rec_id] = dek
        self.plain_hash[rec_id] = H("plain", data).hex()
        self._tx(self.hosp_a, "RECORD_ADD",
                 {"rec_id": rec_id, "patient": self.patient.id, "rtype": rtype, "cls": cls,
                  "cid": cid.hex(), "size": len(data), "chunks": len(chunks)})
        blk, anchor = self._block()
        self._say("record", f"Hospital A added {label.lower()} {rec_id}",
                  self._commit_note(blk, anchor), steps=[
                      ["Encrypt", f"{size:,} bytes in {len(chunks)} chunk(s), AES-256-GCM, fresh data key ({enc_ms} ms)"],
                      ["Fingerprint", f"CID = Merkle root of ciphertext = {short(cid, 20)}…"],
                      ["Off-chain store", "receives ciphertext only"],
                      ["Private ledger", f"RECORD_ADD with CID, size and class '{CLASS_NAME[cls]}'"],
                      ["Public ledger", "receives nothing about this record"]])
        return rec_id

    def grant(self, scope, purpose="treatment", days=30):
        self._tx(self.patient, "CONSENT_GRANT",
                 {"patient": self.patient.id, "grantee": self.hosp_b.id, "scope": list(scope),
                  "purpose": purpose, "expiry": self.clock + days * 86400})
        blk, anchor = self._block()
        c = self.private.consents[(self.patient.id, self.hosp_b.id)]
        cd = self.private.consent_digest(self.patient.id, self.hosp_b.id)
        names = ", ".join(RECORD_TYPES[s][0].lower() for s in scope)
        self._say("consent", f"Patient granted Hospital B access to: {names}",
                  self._commit_note(blk, anchor), steps=[
                      ["Consent entry", f"version {c['version']}, purpose '{purpose}', {days} days"],
                      ["Consent digest", f"{short(cd, 20)}… (changes with every grant or revocation)"]])

    def revoke(self):
        try:
            self._tx(self.patient, "CONSENT_REVOKE",
                     {"patient": self.patient.id, "grantee": self.hosp_b.id})
        except LedgerError as exc:
            self._say("consent", "Nothing to revoke", f"The ledger rejected the request: {exc}.", ok=False)
            return
        blk, anchor = self._block()
        cd = self.private.consent_digest(self.patient.id, self.hosp_b.id)
        self._say("revoke", "Patient revoked Hospital B's consent", self._commit_note(blk, anchor), steps=[
            ["Class", "critical, so SAAA anchors it in its own block"],
            ["New consent digest", f"{short(cd, 20)}…"],
            ["Public evidence", f"anchor {anchor.epoch}: consent root {short(anchor.consent_root, 20)}…" if anchor else "pending"]])

    def emergency(self, rec_id):
        try:
            self._tx(self.hosp_a, "EMERGENCY_ACCESS", {"rec_id": rec_id, "reason": "unconscious patient"})
        except LedgerError as exc:
            self._say("emergency", "Emergency access rejected", str(exc), ok=False)
            return
        blk, anchor = self._block()
        self._say("emergency", f"Emergency (break-glass) access to {rec_id} recorded",
                  self._commit_note(blk, anchor), steps=[
                      ["Who", "Hospital A clinician holding the emergency role"],
                      ["Class", "critical: anchored publicly at once, cannot be quietly removed"],
                      ["Note", "key release by a validator threshold is Phase II work"]])

    def tick(self):
        blk, anchor = self._block()
        self._say("time", "Two seconds passed", self._commit_note(blk, anchor))

    def transfer(self, rec_id):
        """One CBKD transfer, traced message by message."""
        steps, t_all = [], time.perf_counter()
        rec = self.private.records.get(rec_id)
        if rec is None:
            self._say("transfer", "Unknown record", f"{rec_id} is not on the ledger.", ok=False)
            return
        try:
            t0 = time.perf_counter()
            req = self.receiver.request(rec_id)
            steps.append(["1 B → A", f"request: record {rec_id}, ephemeral key {short(req['epk'])}…, "
                          f"nonce {short(req['nonce'])}…, signed by B ({ms(t0)} ms)"])
            t0 = time.perf_counter()
            resp = self.sender.respond(req, self.clock)
            cd = self.private.consent_digest(rec["patient"], self.hosp_b.id)
            steps.append(["2 A checks", "B's signature valid; A's replica covers the latest public anchor; "
                          "live consent covers this record type"])
            steps.append(["3 A derives", f"K = HKDF(X25519 secret; salt = consent digest {short(cd)}…; "
                          f"info = anchor {resp['epoch']} ‖ transcript)"])
            steps.append(["4 A → B", f"ephemeral key {short(resp['epk'])}…, wrapped data key "
                          f"{short(resp['wrapped'])}… ({len(resp['wrapped']) // 2} bytes), key confirmation "
                          f"({ms(t0)} ms)"])
            t0 = time.perf_counter()
            data, receipt = self.receiver.finish(resp, self.store, self.hosp_a.pk)
            ok = H("plain", data).hex() == self.plain_hash[rec_id]
            steps.append(["5 B derives", "the same key from its own ledger replica; data key unwraps; "
                          "confirmation MAC verifies"])
            steps.append(["6 B fetches", f"{rec['chunks']} ciphertext chunk(s) by CID; Merkle root matches the "
                          f"ledger; decrypts {rec['size']:,} bytes ({ms(t0)} ms)"])
            t0 = time.perf_counter()
            self.sender.nonce = self.nonce
            self.sender.log_receipt(receipt, self.clock)
            self.nonce = self.sender.nonce
            steps.append(["7 B → A", f"signed receipt naming consent digest {short(receipt['consent'])}… ({ms(t0)} ms)"])
            total = ms(t_all)
            blk, anchor = self._block()
            steps.append(["8 Ledger", "ACCESS_LOG written by A. " + self._commit_note(blk, anchor)])
            self._say("transfer", f"{rec_id} delivered to Hospital B in {total} ms",
                      ("The plaintext hash matches the original. " if ok else "The plaintext does NOT match. ")
                      + "The custodian re-wrapped a 32-byte key; the record itself was not re-encrypted.",
                      ok=ok, steps=steps)
        except (TransferError, LedgerError) as exc:
            self.private.mempool.clear()
            steps.append(["Stopped", str(exc)])
            self._say("transfer", f"Transfer of {rec_id} refused", f"Reason: {exc}.", ok=False, steps=steps)

    def prove(self, tx_id):
        try:
            t0 = time.perf_counter()
            proof = self.anchorer.prove(tx_id)
            gen = ms(t0)
            t0 = time.perf_counter()
            ok = verify_dlp(proof, self.public)
            ver = round((time.perf_counter() - t0) * 1e6, 1)
        except LedgerError as exc:
            self._say("proof", "No public proof yet", f"{exc}. The block holding this transaction has not "
                      "been anchored; it is inside its exposure window.", ok=False)
            return
        size = 32 + 4 + 32 * len(proof["tx_path"]) + 112 + 4 + 32 * len(proof["blk_path"]) + 8
        a = self.public.anchors[proof["epoch"] - 1]
        self._say("proof", f"Dual-ledger proof verified against public anchor {proof['epoch']}",
                  f"{size} bytes, built in {gen} ms, verified in {ver} µs using public-chain data only.",
                  ok=ok, steps=[
                      ["Hop 1", f"transaction {short(tx_id)}… → transaction root of private block "
                       f"#{proof['header'][0]} ({len(proof['tx_path'])} sibling hash(es))"],
                      ["Hop 2", f"block hash → ledger root {short(a.ledger_root, 16)}… of anchor {a.epoch} "
                       f"({len(proof['blk_path'])} sibling hash(es))"],
                      ["Verdict", "accepted" if ok else "rejected"]])

    # ------------------------------------------------------------------ view
    def state(self):
        blocks = []
        for b in self.private.chain:
            blocks.append({"height": b.height, "hash": short(b.hash, 10), "n_tx": len(b.txs),
                           "cls": CLASS_NAME[b.max_class], "score": b.score,
                           "epoch": self.anchorer.block_epoch.get(b.height),
                           "txs": [{"id": t["id"], "short": short(t["id"], 10), "type": t["type"],
                                    "by": self._name(t["sender"]), "what": self._describe(t)} for t in b.txs]})
        anchors = [{"epoch": a.epoch, "first": a.first, "last": a.last, "trigger": a.trigger,
                    "ledger_root": short(a.ledger_root, 16), "consent_root": short(a.consent_root, 16)}
                   for a in self.public.anchors]
        records = [{"id": r["rec_id"], "type": RECORD_TYPES[r["rtype"]][0], "rtype": r["rtype"],
                    "size": r["size"], "chunks": r["chunks"], "cls": CLASS_NAME[r["cls"]],
                    "cid": short(r["cid"], 16)} for r in self.private.records.values()]
        consents = [{"version": c["version"], "status": c["status"], "purpose": c["purpose"],
                     "scope": [RECORD_TYPES[s][0] for s in c["scope"]],
                     "digest": short(self.private.consent_digest(p, g), 16)}
                    for (p, g), c in self.private.consents.items()]
        return {"validators": len(self.private.validators), "f": self.private.f, "quorum": self.private.quorum,
                "ids": {"patient": self.patient.id, "a": self.hosp_a.id, "b": self.hosp_b.id},
                "blocks": blocks, "anchors": anchors, "records": records, "consents": consents,
                "saaa": {"score": self.policy.score, "theta": self.policy.theta, "pending": self.policy.pending,
                         "t_max": self.policy.t_max},
                "record_types": {k: {"label": v[0], "size": v[1], "cls": CLASS_NAME[v[2]]}
                                 for k, v in RECORD_TYPES.items()},
                "log": self.log[-40:]}

    def _name(self, ident):
        return {self.patient.id: "Patient", self.hosp_a.id: "Hospital A",
                self.hosp_b.id: "Hospital B"}.get(ident, ident[:8])

    def _describe(self, t):
        p, k = t["payload"], t["type"]
        if k == "REGISTER":
            return f"registers as {p['role']}"
        if k == "RECORD_ADD":
            return f"{p['rec_id']}, {p['size']:,} bytes, CID {short(p['cid'])}…"
        if k == "CONSENT_GRANT":
            return f"to {self._name(p['grantee'])}: {', '.join(p['scope'])} for {p['purpose']}"
        if k == "CONSENT_REVOKE":
            return f"from {self._name(p['grantee'])}"
        if k == "ACCESS_LOG":
            return f"{p['rec_id']} sent to {self._name(p['grantee'])} under consent {short(p['consent'])}…"
        if k == "EMERGENCY_ACCESS":
            return f"{p['rec_id']}: {p['reason']}"
        return ""
