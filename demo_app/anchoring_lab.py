"""Anchoring lab: compare SAAA-B with a fixed interval on one simulated day (pure Python)."""
import math
import random

from hylehr.anchoring import SAAA, FixedInterval

BLOCK, SLOT, PROP = 2.0, 12.0, 1.0
WEIGHTS = (1, 4, 16)


def _poisson(rng, lam):
    if lam <= 0:
        return 0
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def _traffic(rng, rate, mix, days):
    n = int(days * 86400 / BLOCK)
    raw = []
    for b in range(n):
        hour = ((b + 0.5) * BLOCK % 86400) / 3600.0
        raw.append(0.35 + 1.30 * math.exp(-((hour - 11.0) ** 2) / 18.0)
                   + 0.75 * math.exp(-((hour - 16.5) ** 2) / 10.0))
    mean = sum(raw) / n
    out = []
    for s in raw:
        lam = rate * BLOCK * s / mean
        out.append(tuple(_poisson(rng, lam * m) for m in mix))
    return out


def _run(counts, policy, warm_blocks):
    start, sums, tot, worst, n_anchor = 0, [0.0] * 3, [0] * 3, [0.0] * 3, 0
    pending = []
    for b, c in enumerate(counts):
        t = (b + 1) * BLOCK
        ntx = c[0] + c[1] + c[2]
        score = c[0] * WEIGHTS[0] + c[1] * WEIGHTS[1] + c[2] * WEIGHTS[2]
        maxc = 2 if c[2] else (1 if c[1] else 0)
        if ntx:
            pending.append((b, t, c))
        if policy.decide(t, score, maxc, ntx):
            included = SLOT * math.ceil((t + PROP) / SLOT)
            if b >= warm_blocks:
                n_anchor += 1
            for pb, pt, pc in pending:
                if pb >= warm_blocks:
                    e = included - pt
                    for k in range(3):
                        if pc[k]:
                            sums[k] += e * pc[k]; tot[k] += pc[k]; worst[k] = max(worst[k], e)
            pending = []
    mean = [sums[k] / tot[k] if tot[k] else 0.0 for k in range(3)]
    return {"anchors": n_anchor, "mean": mean, "worst": worst, "tx": tot}


def compare(budget=288, critical_pct=0.1, sensitive_pct=5.0, rate=2.0, seed=1):
    rng = random.Random(seed)
    crit, sens = critical_pct / 100.0, sensitive_pct / 100.0
    mix = (max(0.0, 1.0 - crit - sens), sens, crit)
    counts = _traffic(rng, rate, mix, days=2)
    warm = int(86400 / BLOCK)
    k = max(1, round(86400 / BLOCK / budget))
    theta0 = rate * 86400 * sum(m * w for m, w in zip(mix, WEIGHTS)) / budget
    fixed = _run(counts, FixedInterval(k), warm)
    saaa = _run(counts, SAAA(theta0, t_max=1800, budget_per_day=budget), warm)
    return {"params": {"budget": budget, "critical_pct": critical_pct, "sensitive_pct": sensitive_pct,
                       "rate": rate, "interval_s": k * BLOCK,
                       "critical_per_day": round(rate * 86400 * crit)},
            "fixed": fixed, "saaa": saaa}
