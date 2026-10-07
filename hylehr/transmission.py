"""Consent-Bound Key Derivation (CBKD) and the record transfer protocol.

Sender   = the provider that holds the record (custodian).
Receiver = the requester the patient has consented to.

The session key is derived from an ephemeral X25519 exchange *salted with
the digest of the consent version each party reads from its own replica of
the private ledger*. If the two parties do not see the same live consent,
they do not get the same key, and the wrapped data key cannot be opened.
"""
import os

from .crypto_utils import (H, Identity, canon, decrypt_record, hkdf, mac,
                           merkle_root, unwrap, verify_sig, wrap,
                           x25519_keypair, x25519_shared)
from .ledger import LedgerError, PrivateLedger, make_tx

LABEL = b"HyL-EHR/CBKD/v1"


class TransferError(Exception):
    pass


def _transcript(rec_id, cid, snd, rcv, epk_r, epk_s, n_r, n_s) -> bytes:
    return H("transcript", rec_id, cid, snd, rcv, epk_r, epk_s, n_r, n_s)


def _session_keys(shared, consent_digest, anchor_ref, transcript):
    """K_enc, K_conf = HKDF(ECDH secret; salt = consent digest; info = ...)."""
    okm = hkdf(shared, salt=consent_digest,
               info=LABEL + anchor_ref + transcript, length=64)
    return okm[:32], okm[32:]


def _anchor_ref(public, epoch: int) -> bytes:
    """Public-chain position both parties must agree on (zero before genesis)."""
    if epoch == 0:
        return H("anchor-ref", 0)
    return H("anchor-ref", epoch, public.anchors[epoch - 1].chain_hash)


# ------------------------------------------------------------- receiver side
class Receiver:
    def __init__(self, ident: Identity, ledger: PrivateLedger, public):
        self.ident, self.ledger, self.public = ident, ledger, public

    def request(self, rec_id: str) -> dict:
        self._esk, epk = x25519_keypair()
        self._nonce = os.urandom(16)
        msg = {"rec_id": rec_id, "rcv": self.ident.id, "epk": epk.hex(),
               "nonce": self._nonce.hex()}
        self._req = msg
        return {**msg, "sig": self.ident.sign(canon(msg)).hex()}

    def finish(self, resp: dict, store, sender_pk: bytes, verify_chunks=True):
        """Derive the key from *our own* ledger view, unwrap and decrypt."""
        rec = self.ledger.records[self._req["rec_id"]]
        body = {k: resp[k] for k in ("epk", "nonce", "snd", "epoch")}
        cid = bytes.fromhex(rec["cid"])
        th = _transcript(rec["rec_id"], cid, resp["snd"], self.ident.id,
                         bytes.fromhex(self._req["epk"]), bytes.fromhex(resp["epk"]),
                         self._nonce, bytes.fromhex(resp["nonce"]))
        if not verify_sig(sender_pk, bytes.fromhex(resp["sig"]), canon(body) + th):
            raise TransferError("sender signature invalid")
        if resp["epoch"] != len(self.public.anchors):
            raise TransferError("sender is behind the public anchor")
        if not self.ledger.covers(self.public.latest()):
            raise TransferError("stale replica: behind the public anchor")
        cd = self.ledger.consent_digest(rec["patient"], self.ident.id)
        if cd is None:
            raise TransferError("no consent on receiver's ledger view")
        shared = x25519_shared(self._esk, bytes.fromhex(resp["epk"]))
        k_enc, k_conf = _session_keys(shared, cd, _anchor_ref(self.public, resp["epoch"]), th)
        try:
            dek = unwrap(k_enc, bytes.fromhex(resp["wrapped"]), th)
        except Exception as exc:
            raise TransferError("key mismatch: session keys differ") from exc
        if mac(k_conf, "S", th).hex() != resp["conf"]:
            raise TransferError("key confirmation failed")
        chunks = store.get(cid)
        if verify_chunks and merkle_root(chunks) != cid:
            raise TransferError("ciphertext does not match on-chain CID")
        try:
            data = decrypt_record(rec["rec_id"], dek, chunks)
        except Exception as exc:
            raise TransferError("chunk authentication failed") from exc
        receipt = {"rec_id": rec["rec_id"], "cid": rec["cid"], "consent": cd.hex(),
                   "th": th.hex(), "conf": mac(k_conf, "R", th).hex()}
        receipt["sig"] = self.ident.sign(canon(receipt)).hex()
        return data, receipt


# --------------------------------------------------------------- sender side
class Sender:
    def __init__(self, ident: Identity, ledger: PrivateLedger, public, keystore: dict,
                 check_fresh: bool = True):
        self.ident, self.ledger, self.public = ident, ledger, public
        self.keystore, self.check_fresh = keystore, check_fresh
        self.nonce = 0

    def respond(self, req: dict, now: float) -> dict:
        body = {k: req[k] for k in ("rec_id", "rcv", "epk", "nonce")}
        who = self.ledger.identities.get(req["rcv"])
        if who is None or not verify_sig(bytes.fromhex(who["pk"]),
                                         bytes.fromhex(req["sig"]), canon(body)):
            raise TransferError("requester not registered or bad signature")
        rec = self.ledger.records.get(req["rec_id"])
        if rec is None or rec["custodian"] != self.ident.id:
            raise TransferError("record not held here")
        # freshness: our replica must contain what the public chain has anchored
        if self.check_fresh and not self.ledger.covers(self.public.latest()):
            raise TransferError("stale replica: behind the public anchor")
        if not self.ledger.consent_active(rec["patient"], req["rcv"], rec["rtype"], now):
            raise TransferError("no active consent on ledger")
        cd = self.ledger.consent_digest(rec["patient"], req["rcv"])
        epoch = len(self.public.anchors)
        esk, epk = x25519_keypair()
        nonce = os.urandom(16)
        cid = bytes.fromhex(rec["cid"])
        th = _transcript(rec["rec_id"], cid, self.ident.id, req["rcv"],
                         bytes.fromhex(req["epk"]), epk, bytes.fromhex(req["nonce"]), nonce)
        k_enc, k_conf = _session_keys(x25519_shared(esk, bytes.fromhex(req["epk"])), cd,
                                      _anchor_ref(self.public, epoch), th)
        self._pending = (rec, cd, th, k_conf, req["rcv"])
        out = {"epk": epk.hex(), "nonce": nonce.hex(), "snd": self.ident.id, "epoch": epoch}
        out["sig"] = self.ident.sign(canon(out) + th).hex()
        out["wrapped"] = wrap(k_enc, self.keystore[rec["rec_id"]], th).hex()
        out["conf"] = mac(k_conf, "S", th).hex()
        return out

    def log_receipt(self, receipt: dict, now: float) -> dict:
        """Check the receiver's receipt and write the access to the ledger."""
        rec, cd, th, k_conf, rcv = self._pending
        body = {k: receipt[k] for k in ("rec_id", "cid", "consent", "th", "conf")}
        pk = bytes.fromhex(self.ledger.identities[rcv]["pk"])
        if (receipt["conf"] != mac(k_conf, "R", th).hex() or receipt["consent"] != cd.hex()
                or not verify_sig(pk, bytes.fromhex(receipt["sig"]), canon(body))):
            raise TransferError("receipt invalid")
        self.nonce += 1
        tx = make_tx(self.ident, "ACCESS_LOG",
                     {"rec_id": rec["rec_id"], "grantee": rcv, "consent": cd.hex(),
                      "receipt": H("receipt", canon(receipt)).hex()}, self.nonce, now)
        self.ledger.submit(tx)
        return tx


def transfer(sender: Sender, receiver: Receiver, sender_pk: bytes, rec_id: str,
             store, now: float):
    """Run one full CBKD transfer; returns (plaintext, access-log tx)."""
    req = receiver.request(rec_id)
    resp = sender.respond(req, now)
    data, receipt = receiver.finish(resp, store, sender_pk)
    return data, sender.log_receipt(receipt, now)
