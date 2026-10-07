"""Synthetic workload: FHIR-style records and a day of ledger traffic.

No real patient data is used anywhere in this project. Record contents are
randomly generated; sizes are chosen to resemble common EHR artefacts.
"""
import json
import os
import random

import numpy as np

from .ledger import CRITICAL, ROUTINE, SENSITIVE

RECORD_TYPES = {                       # type: (typical size in bytes, class)
    "vitals": (2 * 1024, ROUTINE),
    "prescription": (8 * 1024, SENSITIVE),
    "lab-report": (64 * 1024, SENSITIVE),
    "discharge-summary": (256 * 1024, SENSITIVE),
    "psychiatric-note": (32 * 1024, CRITICAL),
    "xray-image": (8 * 1024 * 1024, SENSITIVE),
    "ct-series": (48 * 1024 * 1024, SENSITIVE),
}


def fhir_like_record(rtype: str, patient: str, size: int, rng: random.Random) -> bytes:
    """A JSON resource with a FHIR-like envelope, padded to `size` bytes."""
    doc = {"resourceType": "DocumentReference", "status": "current",
           "type": {"text": rtype}, "subject": {"reference": f"Patient/{patient}"},
           "date": f"2026-0{rng.randint(1, 9)}-{rng.randint(10, 28)}T0{rng.randint(0, 9)}:15:00Z",
           "content": []}
    head = json.dumps(doc).encode()
    return head + os.urandom(max(0, size - len(head)))


def diurnal_rate(t: float, mean_rate: float) -> float:
    """Arrival rate (tx/s) at second-of-day t: quiet nights, busy mid-day."""
    hour = (t % 86400) / 3600.0
    shape = 0.35 + 1.30 * np.exp(-((hour - 11.0) ** 2) / 18.0) \
        + 0.75 * np.exp(-((hour - 16.5) ** 2) / 10.0)
    return mean_rate * shape / 1.0


def day_of_traffic(mean_rate=2.0, mix=(0.949, 0.05, 0.001), block_time=2.0,
                   seconds=86400, seed=7):
    """Per-block transaction counts by class for one simulated day.

    Returns an array of shape (n_blocks, 3). Arrivals are Poisson with a
    diurnal rate; `mix` gives the routine / sensitive / critical shares.
    """
    rng = np.random.default_rng(seed)
    n_blocks = int(seconds / block_time)
    t = (np.arange(n_blocks) + 0.5) * block_time
    hours = (t % 86400) / 3600.0
    shape = 0.35 + 1.30 * np.exp(-((hours - 11.0) ** 2) / 18.0) \
        + 0.75 * np.exp(-((hours - 16.5) ** 2) / 10.0)
    shape = shape / shape.mean()                   # keep the daily mean exact
    lam = mean_rate * shape * block_time
    counts = np.stack([rng.poisson(lam * m) for m in mix], axis=1)
    return counts
