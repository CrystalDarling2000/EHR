"""E1 -- cost of the cryptographic primitives on this machine."""
import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from common import save
from hylehr.crypto_utils import (H, Identity, decrypt_record, encrypt_record, hkdf,
                                 merkle_root, verify_sig, x25519_keypair, x25519_shared)
import hashlib


def per_op(fn, n):
    best = float("inf")
    for _ in range(5):
        t0 = time.perf_counter()
        for _ in range(n):
            fn()
        best = min(best, (time.perf_counter() - t0) / n)
    return best * 1e6            # microseconds


rows = []
ident = Identity("bench", "provider")
msg = os.urandom(256)
sig = ident.sign(msg)
rows.append(("Ed25519 sign", per_op(lambda: ident.sign(msg), 2000)))
rows.append(("Ed25519 verify", per_op(lambda: verify_sig(ident.pk, sig, msg), 2000)))
rows.append(("X25519 key generation", per_op(x25519_keypair, 2000)))
sk, pk = x25519_keypair()
sk2, pk2 = x25519_keypair()
rows.append(("X25519 shared secret", per_op(lambda: x25519_shared(sk, pk2), 2000)))
ss = x25519_shared(sk, pk2)
rows.append(("HKDF-SHA256 (64-byte output)", per_op(lambda: hkdf(ss, b"s" * 32, b"info"), 2000)))
rows.append(("SHA-256 field hash H() (5 fields)", per_op(lambda: H("a", ss, 7, pk, pk2), 5000)))
leaves = [os.urandom(32) for _ in range(1024)]
rows.append(("Merkle root, 1,024 leaves", per_op(lambda: merkle_root(leaves), 20)))

rsa_sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_pk = rsa_sk.public_key()
pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
rsig = rsa_sk.sign(msg, pss, hashes.SHA256())
key = os.urandom(32)
ct = rsa_pk.encrypt(key, oaep)
rows.append(("RSA-2048 PSS sign", per_op(lambda: rsa_sk.sign(msg, pss, hashes.SHA256()), 200)))
rows.append(("RSA-2048 PSS verify", per_op(lambda: rsa_pk.verify(rsig, msg, pss, hashes.SHA256()), 2000)))
rows.append(("RSA-2048 OAEP encrypt", per_op(lambda: rsa_pk.encrypt(key, oaep), 2000)))
rows.append(("RSA-2048 OAEP decrypt", per_op(lambda: rsa_sk.decrypt(ct, oaep), 200)))
t0 = time.perf_counter()
for _ in range(5):
    rsa.generate_private_key(public_exponent=65537, key_size=2048)
rows.append(("RSA-2048 key generation", (time.perf_counter() - t0) / 5 * 1e6))

# bulk throughput on a 32 MiB buffer
buf = os.urandom(32 * 1024 * 1024)
mb = len(buf) / 2 ** 20


def best_of(fn, n=5):
    out = float("inf")
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        out = min(out, time.perf_counter() - t0)
    return out


bulk = []
bulk.append(("SHA-256", mb / best_of(lambda: hashlib.sha256(buf).digest())))
aead = AESGCM(key)
bulk.append(("AES-256-GCM encrypt (single call)", mb / best_of(lambda: aead.encrypt(b"\0" * 12, buf, None))))
dek, chunks, cid = encrypt_record("r", buf)
bulk.append(("Record encrypt, 256 KiB chunks + Merkle CID", mb / best_of(lambda: encrypt_record("r", buf))))
bulk.append(("Record decrypt, 256 KiB chunks", mb / best_of(lambda: decrypt_record("r", dek, chunks))))
bulk.append(("Merkle CID check over ciphertext", mb / best_of(lambda: merkle_root(chunks))))

print(f"{'operation':<46s}{'time per op':>14s}")
for name, us in rows:
    print(f"{name:<46s}{us:>11.1f} us")
print()
print(f"{'bulk operation (32 MiB)':<46s}{'throughput':>14s}")
for name, v in bulk:
    print(f"{name:<46s}{v:>9.0f} MiB/s")
save("e1_crypto.json", {"per_op_us": rows, "bulk_mib_s": bulk})
