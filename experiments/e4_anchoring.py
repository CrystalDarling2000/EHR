"""E4 -- anchoring policies compared on simulated days of consortium traffic.

Discrete-time simulation at private-block granularity (no cryptography is
needed here, only the policies). For every transaction we record its
*exposure window*: the time from its commit on the private ledger until
the anchor that covers it is included in a public block. During that
window the transaction is protected by the consortium quorum alone.
"""
import json
import os

import numpy as np

from common import RESULTS, save
from hylehr.anchoring import SAAA, FixedInterval, PerBlock
from hylehr.workload import day_of_traffic

BLOCK = 2.0          # private block interval (s)
SLOT = 12.0          # public chain slot time (s)
PROP = 1.0           # time for the anchor transaction to reach a proposer (s)
WEIGHTS = np.array([1, 4, 16])
DAYS, WARMUP = 3, 1  # simulate three days, score the last two
SEEDS = range(10)


def wquant(x, w, q):
    order = np.argsort(x)
    cw = np.cumsum(w[order])
    return float(x[order][np.searchsorted(cw, q * cw[-1])])


def simulate(counts, policy):
    n = len(counts)
    scores = counts @ WEIGHTS
    maxc = np.where(counts[:, 2] > 0, 2, np.where(counts[:, 1] > 0, 1, 0))
    ntx = counts.sum(axis=1)
    anchored_by = np.full(n, -1)
    start, anchors = 0, []
    for b in range(n):
        trig = policy.decide((b + 1) * BLOCK, int(scores[b]), int(maxc[b]), int(ntx[b]))
        if trig:
            anchored_by[start:b + 1] = b
            start = b + 1
            anchors.append((b, trig))
    t_blk = (np.arange(n) + 1) * BLOCK
    lo = int(WARMUP * 86400 / BLOCK)
    ok = (anchored_by >= 0) & (np.arange(n) >= lo)
    t_anchor = t_blk[anchored_by[ok]]
    included = SLOT * np.ceil((t_anchor + PROP) / SLOT)
    exposure = included - t_blk[ok]
    out = {"anchors_per_day": sum(1 for b, _ in anchors if b >= lo) / (DAYS - WARMUP)}
    for trig in ("critical", "score", "timeout", "interval", "block"):
        k = sum(1 for b, t in anchors if b >= lo and t == trig) / (DAYS - WARMUP)
        if k:
            out[f"by_{trig}"] = k
    for c, name in enumerate(("routine", "sensitive", "critical")):
        w = counts[ok, c].astype(float)
        if w.sum() == 0:
            continue
        out[f"{name}_mean"] = float((exposure * w).sum() / w.sum())
        out[f"{name}_p95"] = wquant(exposure, w, 0.95)
        out[f"{name}_max"] = float(exposure[w > 0].max())
    w = (counts[ok] @ WEIGHTS).astype(float)
    out["rwe"] = float((exposure * w).sum() / w.sum())     # risk-weighted exposure
    return out


def traffic(seed, rate=2.0, mix=(0.949, 0.05, 0.001)):
    return np.concatenate([day_of_traffic(rate, mix, BLOCK, seed=1000 * seed + d)
                           for d in range(DAYS)])


def averaged(make_policy, **kw):
    runs = [simulate(traffic(s, **kw), make_policy()) for s in SEEDS]
    keys = sorted(set().union(*runs))
    return {k: (float(np.mean([r.get(k, 0.0) for r in runs])),
                float(np.std([r.get(k, 0.0) for r in runs]))) for k in keys}


def theta0(budget, rate=2.0, mix=(0.949, 0.05, 0.001)):
    """Starting threshold: the day's expected score spread over the budget."""
    return rate * 86400 * float(np.dot(mix, WEIGHTS)) / budget


def show(label, r, gas):
    g = lambda k: r.get(k, (float("nan"),) * 2)[0]
    print(f"{label:<22s}{g('anchors_per_day'):>9.0f}{g('anchors_per_day') * gas / 1e6:>9.2f}"
          f"{g('routine_mean'):>10.1f}{g('sensitive_mean'):>10.1f}{g('critical_mean'):>10.1f}"
          f"{g('critical_p95'):>10.1f}{g('critical_max'):>10.1f}{g('rwe'):>9.1f}")


HEAD = (f"{'policy':<22s}{'anch/day':>9s}{'Mgas/day':>9s}{'routine':>10s}{'sensit.':>10s}"
        f"{'crit.mean':>10s}{'crit.p95':>10s}{'crit.max':>10s}{'RWE':>9s}")

if __name__ == "__main__":
    gas_file = os.path.join(RESULTS, "e7_gas.json")
    if os.path.exists(gas_file):                 # measured on the local EVM (E7)
        gas = float(json.load(open(gas_file))["anchor_compact"][1])
    else:
        gas = 37_372.0  # fallback: steady-state anchorCompact()
    res = {"gas_per_anchor": gas, "block_s": BLOCK, "slot_s": SLOT}
    print(f"gas per anchor (compact variant, measured in E7): {gas:.0f}\n")

    print("A. Policy sweep (2 tx/s mean, 0.1% critical, 5% sensitive); exposure in seconds")
    print(HEAD)
    sweep = {}
    sweep["PB"] = averaged(PerBlock)
    for k in (5, 15, 30, 75, 150, 300, 450, 900):
        sweep[f"FI-{k}"] = averaged(lambda k=k: FixedInterval(k))
    for th in (250, 500, 1000, 2000, 4000, 8000):
        sweep[f"SAAA(theta={th})"] = averaged(lambda th=th: SAAA(th, t_max=1800))
    for b in (96, 144, 288, 576, 1440):
        sweep[f"SAAA-B({b})"] = averaged(
            lambda b=b: SAAA(theta0(b), t_max=1800, budget_per_day=b))
    for name, r in sweep.items():
        show(name, r, gas)
    res["sweep"] = sweep

    print("\nB. Share of critical transactions varied, budget 288 anchors/day")
    print(HEAD)
    crit = {}
    for frac in (0.0001, 0.0005, 0.001, 0.002, 0.005, 0.01):
        mix = (0.95 - frac, 0.05, frac)
        crit[f"{frac}"] = {
            "FI-150": averaged(lambda: FixedInterval(150), mix=mix),
            "SAAA-B": averaged(lambda: SAAA(theta0(288, mix=mix), t_max=1800,
                                            budget_per_day=288), mix=mix)}
        show(f"crit={frac:.2%} FI-150", crit[f"{frac}"]["FI-150"], gas)
        show(f"crit={frac:.2%} SAAA-B", crit[f"{frac}"]["SAAA-B"], gas)
    res["critical_share"] = crit

    # how much more must a critical event count for SAAA-B to win on the
    # composite risk-weighted exposure (RWE)?
    f, a = sweep["FI-150"], sweep["SAAA-B(288)"]
    mix = np.array([0.949, 0.05, 0.001])
    ef = np.array([f[k][0] for k in ("routine_mean", "sensitive_mean", "critical_mean")])
    ea = np.array([a[k][0] for k in ("routine_mean", "sensitive_mean", "critical_mean")])
    base = mix[:2] * WEIGHTS[:2]
    w_star = float(((ea[:2] - ef[:2]) * base).sum() / (mix[2] * (ef[2] - ea[2])))
    res["break_even_weight"] = w_star
    print(f"\nbreak-even weight of a critical event for equal RWE at 288/day: {w_star:.0f}")

    print("\nC. Load varied, threshold tuned for 2 tx/s; budget 576 anchors/day")
    print(HEAD)
    load = {}
    for rate in (0.5, 1.0, 2.0, 4.0, 6.0):
        load[f"{rate}"] = {
            "SAAA": averaged(lambda: SAAA(400, t_max=1800), rate=rate),
            "SAAA-B": averaged(lambda: SAAA(theta0(576), t_max=1800, budget_per_day=576),
                               rate=rate),
            "FI-75": averaged(lambda: FixedInterval(75), rate=rate)}
        for nm in ("FI-75", "SAAA", "SAAA-B"):
            show(f"{rate:g} tx/s {nm}", load[f"{rate}"][nm], gas)
    res["load"] = load

    # one traced run for the figures
    counts = traffic(0)
    pol = SAAA(theta0(288), t_max=1800, budget_per_day=288)
    simulate(counts, pol)
    res["theta_trace"] = pol.theta_trace
    hourly = counts.reshape(DAYS * 24, -1, 3).sum(axis=1).tolist()
    res["hourly_tx"] = hourly
    save("e4_anchoring.json", res)
