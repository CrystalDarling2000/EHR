"""E2 -- end-to-end secure transfer: cost by stage, record size and scheme."""
import os
import statistics
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from common import World, save
from hylehr.crypto_utils import (H, canon, decrypt_record, hkdf, merkle_root, unwrap,
                                 verify_sig, wrap, x25519_keypair, x25519_shared)

SIZES = [4 * 1024, 64 * 1024, 1024 * 1024, 8 * 2 ** 20, 32 * 2 ** 20, 64 * 2 ** 20]
REPS = 15


def med(xs):
    return statistics.median(xs)


def ms(t0):
    return (time.perf_counter() - t0) * 1000.0


# ---------------------------------------------------------------- proposed
def run_cbkd(w, rec_id):
    """One CBKD transfer, timed stage by stage (milliseconds)."""
    t = time.perf_counter(); req = w.receiver.request(rec_id); a = ms(t)
    t = time.perf_counter(); resp = w.sender.respond(req, w.clock); b = ms(t)
    # receiver side, split so that bulk work is visible separately
    rec = w.private.records[rec_id]
    cid = bytes.fromhex(rec["cid"])
    t = time.perf_counter(); chunks = w.store.get(cid); ok = merkle_root(chunks) == cid; c = ms(t)
    assert ok
    t = time.perf_counter()
    data, receipt = w.receiver.finish(resp, w.store, w.hosp_a.pk, verify_chunks=False)
    d = ms(t)
    t = time.perf_counter(); w.sender.log_receipt(receipt, w.clock); e = ms(t)
    w.private.mempool.clear()
    return {"request": a, "respond": b, "verify_cid": c, "unwrap_decrypt": d, "receipt": e,
            "sender_total": b + e, "total": a + b + c + d + e}, data


# ------------------------------------------------- baseline 1: plain ECDHE
def run_ecdh_only(w, rec_id):
    """Signed ephemeral ECDH + HKDF, no consent or anchor binding, no ledger checks."""
    rec = w.private.records[rec_id]; cid = bytes.fromhex(rec["cid"])
    t0 = time.perf_counter()
    esk_r, epk_r = x25519_keypair(); sig_r = w.hosp_b.sign(epk_r)
    assert verify_sig(w.hosp_b.pk, sig_r, epk_r)
    esk_s, epk_s = x25519_keypair(); sig_s = w.hosp_a.sign(epk_s + epk_r)
    k = hkdf(x25519_shared(esk_s, epk_r), b"\0" * 32, b"plain", 32)
    blob = wrap(k, w.keystore[rec_id], b"")
    assert verify_sig(w.hosp_a.pk, sig_s, epk_s + epk_r)
    k2 = hkdf(x25519_shared(esk_r, epk_s), b"\0" * 32, b"plain", 32)
    dek = unwrap(k2, blob, b"")
    hs = ms(t0)
    t = time.perf_counter(); chunks = w.store.get(cid); assert merkle_root(chunks) == cid; c = ms(t)
    t = time.perf_counter(); decrypt_record(rec_id, dek, chunks); d = ms(t)
    return {"handshake": hs, "total": hs + c + d}


# ------------------------------------------- baseline 2: RSA-2048 envelope
RSA_S = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_R = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def run_rsa_envelope(w, rec_id):
    """Static RSA: requester signs, custodian wraps the DEK to the requester's key."""
    rec = w.private.records[rec_id]; cid = bytes.fromhex(rec["cid"])
    t0 = time.perf_counter()
    req = canon({"rec_id": rec_id, "nonce": os.urandom(16).hex()})
    sig_r = RSA_R.sign(req, PSS, hashes.SHA256())
    RSA_R.public_key().verify(sig_r, req, PSS, hashes.SHA256())
    blob = RSA_R.public_key().encrypt(w.keystore[rec_id], OAEP)
    sig_s = RSA_S.sign(blob + req, PSS, hashes.SHA256())
    RSA_S.public_key().verify(sig_s, blob + req, PSS, hashes.SHA256())
    dek = RSA_R.decrypt(blob, OAEP)
    rcpt = RSA_R.sign(H("receipt", blob), PSS, hashes.SHA256())
    RSA_R.public_key().verify(rcpt, H("receipt", blob), PSS, hashes.SHA256())
    hs = ms(t0)
    t = time.perf_counter(); chunks = w.store.get(cid); assert merkle_root(chunks) == cid; c = ms(t)
    t = time.perf_counter(); decrypt_record(rec_id, dek, chunks); d = ms(t)
    return {"handshake": hs, "total": hs + c + d}


# ------------------------- baseline 3: custodian re-encrypts for transport
def run_reencrypt(w, rec_id):
    """Custodian decrypts and re-encrypts the whole record under the session key."""
    rec = w.private.records[rec_id]; cid = bytes.fromhex(rec["cid"])
    t0 = time.perf_counter()
    esk_r, epk_r = x25519_keypair(); sig_r = w.hosp_b.sign(epk_r)
    assert verify_sig(w.hosp_b.pk, sig_r, epk_r)
    esk_s, epk_s = x25519_keypair(); sig_s = w.hosp_a.sign(epk_s + epk_r)
    k = hkdf(x25519_shared(esk_s, epk_r), b"\0" * 32, b"plain", 32)
    hs = ms(t0)
    t = time.perf_counter()
    plain = decrypt_record(rec_id, w.keystore[rec_id], w.store.get(cid))
    wire = AESGCM(k).encrypt(b"\0" * 12, plain, None)
    snd = ms(t)
    t = time.perf_counter()
    assert verify_sig(w.hosp_a.pk, sig_s, epk_s + epk_r)
    k2 = hkdf(x25519_shared(esk_r, epk_s), b"\0" * 32, b"plain", 32)
    AESGCM(k2).decrypt(b"\0" * 12, wire, None)
    rcv = ms(t)
    return {"handshake": hs, "sender_total": hs / 2 + snd, "total": hs + snd + rcv}


out = []
w = World()
w.grant(scope=("xray-image",))
for size in SIZES:
    rid = f"rec-{size}"
    data, _ = w.add_record(rid, rtype="xray-image", size=size)
    w.block()
    cb, ec, rs, re_ = [], [], [], []
    for _ in range(REPS):
        r, got = run_cbkd(w, rid); assert got == data; cb.append(r)
        ec.append(run_ecdh_only(w, rid)); rs.append(run_rsa_envelope(w, rid))
        re_.append(run_reencrypt(w, rid))
    row = {"size": size, "chunks": w.private.records[rid]["chunks"],
           "cbkd": {k: med([x[k] for x in cb]) for k in cb[0]},
           "ecdh_only": {k: med([x[k] for x in ec]) for k in ec[0]},
           "rsa_envelope": {k: med([x[k] for x in rs]) for k in rs[0]},
           "reencrypt": {k: med([x[k] for x in re_]) for k in re_[0]}}
    row["cbkd"]["key_establishment"] = (row["cbkd"]["request"] + row["cbkd"]["respond"]
                                        + row["cbkd"]["receipt"])
    out.append(row)

print("CBKD transfer, median of %d runs (ms)" % REPS)
print(f"{'size':>9s}{'chunks':>7s}{'request':>9s}{'respond':>9s}{'verifyCID':>10s}"
      f"{'decrypt':>9s}{'receipt':>9s}{'total':>9s}{'MiB/s':>8s}")
for r in out:
    c = r["cbkd"]
    print(f"{r['size'] / 1024:>7.0f}KB{r['chunks']:>7d}{c['request']:>9.3f}{c['respond']:>9.3f}"
          f"{c['verify_cid']:>10.3f}{c['unwrap_decrypt']:>9.3f}{c['receipt']:>9.3f}"
          f"{c['total']:>9.3f}{r['size'] / 2 ** 20 / (c['total'] / 1000):>8.1f}")
print("\nScheme comparison: total time (ms) and sender-side time (ms)")
print(f"{'size':>9s}{'CBKD':>10s}{'ECDH-only':>11s}{'RSA-env':>10s}{'Re-encrypt':>12s}"
      f"{'| snd CBKD':>12s}{'snd Re-enc':>12s}")
for r in out:
    print(f"{r['size'] / 1024:>7.0f}KB{r['cbkd']['total']:>10.3f}{r['ecdh_only']['total']:>11.3f}"
          f"{r['rsa_envelope']['total']:>10.3f}{r['reencrypt']['total']:>12.3f}"
          f"{r['cbkd']['sender_total']:>12.3f}{r['reencrypt']['sender_total']:>12.3f}")
print("\nKey establishment only (ms): CBKD %.3f | ECDH-only %.3f | RSA envelope %.3f" % (
    med([r["cbkd"]["key_establishment"] for r in out]),
    med([r["ecdh_only"]["handshake"] for r in out]),
    med([r["rsa_envelope"]["handshake"] for r in out])))
save("e2_transfer.json", out)
