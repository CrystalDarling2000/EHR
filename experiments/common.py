"""Shared set-up for the experiments: a small consortium with one patient."""
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hylehr.anchoring import SAAA                                   # noqa: E402
from hylehr.crypto_utils import Identity, encrypt_record            # noqa: E402
from hylehr.ledger import (Anchorer, PrivateLedger, PublicLedger,   # noqa: E402
                           make_tx)
from hylehr.storage import OffChainStore                            # noqa: E402
from hylehr.transmission import Receiver, Sender                    # noqa: E402
from hylehr.workload import RECORD_TYPES, fhir_like_record          # noqa: E402

RESULTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
os.makedirs(RESULTS, exist_ok=True)


def save(name, obj):
    with open(os.path.join(RESULTS, name), "w") as fh:
        json.dump(obj, fh, indent=1)


class World:
    """Validators, a patient, a custodian hospital and a requesting hospital."""

    def __init__(self, n_validators=4, policy=None):
        self.private = PrivateLedger(n_validators)
        self.public = PublicLedger()
        self.anchorer = Anchorer(self.private, self.public,
                                 policy or SAAA(theta=64, t_max=900))
        self.store = OffChainStore()
        self.patient = Identity("patient-01", "patient")
        self.hosp_a = Identity("hospital-A", "provider")
        self.hosp_b = Identity("hospital-B", "provider")
        self.keystore = {}
        self.nonce = 0
        self.clock = 1_780_000_000.0
        for who in (self.patient, self.hosp_a, self.hosp_b):
            self.tx(who, "REGISTER", {"role": who.role, "emergency": who is self.hosp_a})
        self.block()
        self.sender = Sender(self.hosp_a, self.private, self.public, self.keystore)
        self.receiver = Receiver(self.hosp_b, self.private, self.public)

    def tx(self, who, tx_type, payload):
        self.nonce += 1
        t = make_tx(who, tx_type, payload, self.nonce, self.clock)
        self.private.submit(t)
        return t

    def block(self, dt=2.0):
        self.clock += dt
        blk = self.private.commit_block(self.clock)
        self.anchorer.on_block(blk)
        return blk

    def add_record(self, rec_id, rtype="lab-report", size=None, cls=None, data=None):
        default_size, default_cls = RECORD_TYPES[rtype]
        data = data if data is not None else fhir_like_record(
            rtype, self.patient.id, size or default_size, random.Random(1))
        dek, chunks, cid = encrypt_record(rec_id, data)
        self.store.put(cid, chunks)
        self.keystore[rec_id] = dek
        t = self.tx(self.hosp_a, "RECORD_ADD",
                    {"rec_id": rec_id, "patient": self.patient.id, "rtype": rtype,
                     "cls": default_cls if cls is None else cls, "cid": cid.hex(),
                     "size": len(data), "chunks": len(chunks)})
        return data, t

    def grant(self, scope=("lab-report",), days=30, purpose="treatment"):
        return self.tx(self.patient, "CONSENT_GRANT",
                       {"patient": self.patient.id, "grantee": self.hosp_b.id,
                        "scope": list(scope), "purpose": purpose,
                        "expiry": self.clock + days * 86400})

    def revoke(self):
        return self.tx(self.patient, "CONSENT_REVOKE",
                       {"patient": self.patient.id, "grantee": self.hosp_b.id})


def timeit(fn, repeat=5, number=1):
    """Median wall time of fn() in milliseconds."""
    samples = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        for _ in range(number):
            fn()
        samples.append((time.perf_counter() - t0) * 1000.0 / number)
    samples.sort()
    return samples[len(samples) // 2]
