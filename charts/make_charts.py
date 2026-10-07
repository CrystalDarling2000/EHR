"""Result charts for Chapter 7, drawn from the JSON files in proto/results."""
import json
import os

import numpy as np
from style import *

R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")
os.makedirs(OUT, exist_ok=True)
L = lambda n: json.load(open(os.path.join(R, n)))


def size_label(b):
    return f"{b // 2**20} MiB" if b >= 2**20 else f"{b // 1024} KiB"


# ------------------------------------------------ Fig 7.1 where the time goes
e2 = L("e2_transfer.json")
fig, ax = plt.subplots(figsize=(6.3, 2.9))
labels = [size_label(r["size"]) for r in e2]
ke = np.array([r["cbkd"]["request"] + r["cbkd"]["respond"] + r["cbkd"]["receipt"] for r in e2])
vc = np.array([r["cbkd"]["verify_cid"] for r in e2])
de = np.array([r["cbkd"]["unwrap_decrypt"] for r in e2])
tot = ke + vc + de
y = np.arange(len(e2))[::-1]
left = np.zeros(len(e2))
for vals, col, hatch, name in ((ke, BLUE, "", "Key establishment and receipt"),
                               (vc, ORANGE, "///", "Ciphertext check against CID"),
                               (de, AQUA, "...", "Unwrap and decrypt")):
    share = 100 * vals / tot
    ax.barh(y, share, left=left, height=0.62, color=col, edgecolor="white", linewidth=1.6,
            hatch=hatch, label=name)
    left += share
for yi, t in zip(y, tot):
    ax.text(101.5, yi, f"{t:.1f} ms" if t >= 10 else f"{t:.2f} ms", va="center", ha="left",
            color=INK, fontsize=10)
ax.set_yticks(y); ax.set_yticklabels(labels)
ax.set_xlim(0, 100); ax.set_xlabel("Share of end-to-end transfer time (%)")
ax.set_ylabel("Record size")
ax.grid(axis="y", visible=False)
ax.text(101.5, y[0] + 0.72, "Total", ha="left", va="center", color=INK2, fontsize=10)
ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.24), ncol=3, columnspacing=1.2,
          handlelength=1.4)
fig.savefig(f"{OUT}/fig7_1_stage_share.png"); plt.close(fig)

# ------------------------------------------- Fig 7.2 sender-side cost vs size
fig, ax = plt.subplots(figsize=(6.0, 3.2))
sizes = np.arange(len(e2))
a = [r["cbkd"]["sender_total"] for r in e2]
b = [r["reencrypt"]["sender_total"] for r in e2]
ax.plot(sizes, b, color=ORANGE, marker="s", label="Custodian re-encrypts the record")
ax.plot(sizes, a, color=BLUE, marker="o", label="CBKD: custodian re-wraps the 32-byte key")
ax.set_yscale("log")
ax.set_xticks(sizes); ax.set_xticklabels([size_label(r["size"]) for r in e2])
ax.set_yticks([0.1, 1, 10, 100]); ax.set_yticklabels(["0.1", "1", "10", "100"])
ax.minorticks_off(); ax.set_ylim(0.1, 400)
ax.set_xlabel("Record size"); ax.set_ylabel("Custodian CPU time per transfer (ms)")
ax.annotate(f"{b[-1]:.0f} ms", (sizes[-1], b[-1]), textcoords="offset points", xytext=(-6, 8),
            ha="right", color=INK)
ax.annotate(f"{a[-1]:.2f} ms", (sizes[-1], a[-1]), textcoords="offset points", xytext=(-6, 8),
            ha="right", color=INK)
ax.legend(loc="upper left")
fig.savefig(f"{OUT}/fig7_2_sender_cost.png"); plt.close(fig)

# --------------------------------------- Fig 7.3 ledger throughput vs validators
e3 = [r for r in L("e3_ledger.json") if r["block_tx"] == 1000]
fig, ax = plt.subplots(figsize=(6.0, 3.1))
n = [r["validators"] for r in e3]
ax.plot(n, [r["tps_per_node"] for r in e3], color=BLUE, marker="o",
        label="Per-node estimate (one validator's share of the work)")
ax.plot(n, [r["tps_sequential"] for r in e3], color=ORANGE, marker="s",
        label="Measured in the single-process simulator")
ax.set_xticks(n); ax.set_ylim(0, 4200)
ax.set_xlabel("Number of validators (quorum = 2f + 1)")
ax.set_ylabel("Transactions per second")
for r in (e3[0], e3[-1]):
    ax.annotate(f"{r['tps_sequential']:.0f}", (r["validators"], r["tps_sequential"]),
                textcoords="offset points", xytext=(0, 8), ha="center", color=INK)
    ax.annotate(f"{r['tps_per_node']:.0f}", (r["validators"], r["tps_per_node"]),
                textcoords="offset points", xytext=(0, 8), ha="center", color=INK)
ax.legend(loc="center right", bbox_to_anchor=(1.0, 0.55))
fig.savefig(f"{OUT}/fig7_3_ledger_tps.png"); plt.close(fig)

# ----------------------------------------- Fig 7.4 exposure vs anchors per day
e4 = L("e4_anchoring.json")
sw = e4["sweep"]
fi = [k for k in sw if k.startswith("FI-")]
sa = [k for k in sw if k.startswith("SAAA(")]
sb = [k for k in sw if k.startswith("SAAA-B(") and k not in ("SAAA-B(96)", "SAAA-B(144)")]
fig, axes = plt.subplots(1, 2, figsize=(6.5, 3.2), sharey=True)
for ax, key, title in ((axes[0], "critical_mean", "Critical transactions"),
                       (axes[1], "routine_mean", "Routine transactions")):
    for names, col, mk, lab in ((fi, BLUE, "o", "Fixed interval"),
                                (sa, ORANGE, "s", "SAAA, fixed threshold"),
                                (sb, AQUA, "^", "SAAA-B, budget-controlled")):
        xs = [sw[k]["anchors_per_day"][0] for k in names]
        ys = [sw[k][key][0] for k in names]
        o = np.argsort(xs)
        ax.plot(np.array(xs)[o], np.array(ys)[o], color=col, marker=mk, label=lab,
                markeredgecolor="white", markeredgewidth=1.0)
    ax.set_xscale("log"); ax.set_yscale("log"); ax.set_title(title)
    ax.set_xlabel("Public anchors per day"); ax.minorticks_off()
    ax.set_xticks([50, 150, 500, 1500, 5000]); ax.set_xticklabels(["50", "150", "500", "1,500", "5,000"])
    ax.set_yticks([10, 30, 100, 300, 900]); ax.set_yticklabels(["10", "30", "100", "300", "900"])
    ax.set_ylim(4.5, 1300)
axes[0].set_ylabel("Mean exposure window (s)")
axes[0].annotate("6.9 s at every budget", (500, 6.9), textcoords="offset points", xytext=(0, 9),
                 ha="center", color=INK, fontsize=10)
h, l = axes[0].get_legend_handles_labels()
fig.legend(h, l, loc="lower center", ncol=3, bbox_to_anchor=(0.5, -0.17), columnspacing=1.4)
fig.subplots_adjust(wspace=0.08)
fig.savefig(f"{OUT}/fig7_4_tradeoff.png"); plt.close(fig)

# ------------------------------------ Fig 7.5 equal budget: exposure per class
fig, ax = plt.subplots(figsize=(6.0, 3.2))
classes = ["routine", "sensitive", "critical"]
f = [sw["FI-150"][f"{c}_mean"][0] for c in classes]
s = [sw["SAAA-B(288)"][f"{c}_mean"][0] for c in classes]
x = np.arange(3); wd = 0.34
b1 = ax.bar(x - wd / 2 - 0.02, f, wd, color=BLUE, label="Fixed interval, every 300 s (288 anchors/day)")
b2 = ax.bar(x + wd / 2 + 0.02, s, wd, color=ORANGE, hatch="///", edgecolor="white", linewidth=0,
            label="SAAA-B, budget 288 anchors/day (298 used)")
for bars, vals in ((b1, f), (b2, s)):
    for rect, v in zip(bars, vals):
        ax.text(rect.get_x() + rect.get_width() / 2, v + 5, f"{v:.1f} s", ha="center", color=INK,
                fontsize=10)
ax.set_xticks(x); ax.set_xticklabels(["Routine", "Sensitive", "Critical"])
ax.set_ylabel("Mean exposure window (s)"); ax.set_ylim(0, 330)
ax.grid(axis="x", visible=False)
ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.0), ncol=1)
fig.savefig(f"{OUT}/fig7_5_equal_budget.png"); plt.close(fig)

# ------------------------------- Fig 7.6 share of critical events vs anchors used
cs = e4["critical_share"]
fr = sorted(cs, key=float)
fig, axes = plt.subplots(1, 2, figsize=(6.5, 3.1))
xs = [100 * float(k) for k in fr]
axes[0].plot(xs, [cs[k]["SAAA-B"]["anchors_per_day"][0] for k in fr], color=ORANGE, marker="s",
             label="SAAA-B (budget 288)")
axes[0].plot(xs, [cs[k]["FI-150"]["anchors_per_day"][0] for k in fr], color=BLUE, marker="o",
             label="Fixed interval")
axes[0].set_ylabel("Anchors used per day"); axes[0].set_title("Cost")
axes[1].plot(xs, [cs[k]["SAAA-B"]["routine_mean"][0] for k in fr], color=ORANGE, marker="s")
axes[1].plot(xs, [cs[k]["FI-150"]["routine_mean"][0] for k in fr], color=BLUE, marker="o")
axes[1].set_ylabel("Routine mean exposure (s)"); axes[1].set_title("Effect on routine traffic")
axes[1].set_ylim(0, 280)
for ax in axes:
    ax.set_xscale("log"); ax.set_xticks(xs)
    ax.set_xticklabels(["0.01", "0.05", "0.1", "0.2", "0.5", "1"]); ax.minorticks_off()
    ax.set_xlabel("Critical transactions (% of all)")
axes[0].legend(loc="upper left")
fig.subplots_adjust(wspace=0.32)
fig.savefig(f"{OUT}/fig7_6_critical_share.png"); plt.close(fig)

# ------------------------------------------------- Fig 7.7 load vs anchors used
ld = e4["load"]
rates = sorted(ld, key=float)
fig, ax = plt.subplots(figsize=(6.0, 3.1))
xs = [float(r) for r in rates]
for nm, col, mk, ms_, lab in (("SAAA", ORANGE, "s", 7, "SAAA, fixed threshold (θ = 400)"),
                              ("FI-75", BLUE, "o", 11, "Fixed interval, every 150 s"),
                              ("SAAA-B", AQUA, "^", 6, "SAAA-B, budget 576 per day")):
    ax.plot(xs, [ld[r][nm]["anchors_per_day"][0] for r in rates], color=col, marker=mk, label=lab,
            markersize=ms_, markeredgecolor="white", markeredgewidth=1.0)
ax.set_xticks(xs); ax.set_xlabel("Mean load on the private ledger (transactions per second)")
ax.set_ylabel("Anchors used per day"); ax.set_ylim(0, 1900)
ax.annotate(f"{ld['6.0']['SAAA']['anchors_per_day'][0]:.0f}", (6.0, ld["6.0"]["SAAA"]["anchors_per_day"][0]),
            textcoords="offset points", xytext=(-8, 6), ha="right", color=INK)
ax.annotate(f"SAAA-B {ld['6.0']['SAAA-B']['anchors_per_day'][0]:.0f}, fixed interval 576",
            (6.0, ld["6.0"]["SAAA-B"]["anchors_per_day"][0]),
            textcoords="offset points", xytext=(4, 11), ha="right", color=INK)
ax.legend(loc="upper left")
fig.savefig(f"{OUT}/fig7_7_load.png"); plt.close(fig)

# ---------------------------------------- Fig 7.8 threshold follows the load
tr = np.array(e4["theta_trace"])
hourly = np.array(e4["hourly_tx"]).sum(axis=1)
fig, axes = plt.subplots(2, 1, figsize=(6.3, 3.9), sharex=True)
hrs = np.arange(len(hourly)) + 0.5
axes[0].bar(hrs, hourly / 1000.0, width=0.86, color=BLUE)
axes[0].set_ylabel("Transactions per\nhour (thousands)"); axes[0].grid(axis="x", visible=False)
axes[1].plot(tr[:, 0] / 3600.0, tr[:, 1], color=ORANGE, linewidth=1.8)
axes[1].set_ylabel("Threshold θ\n(score units)"); axes[1].set_xlabel("Simulated time (hours)")
axes[1].set_xticks(np.arange(0, 73, 12)); axes[1].set_xlim(0, 72)
axes[1].set_ylim(0, None)
fig.align_ylabels(axes)
fig.subplots_adjust(hspace=0.16)
fig.savefig(f"{OUT}/fig7_8_theta_trace.png"); plt.close(fig)

# --------------------------------------------------- Fig 7.9 dual-ledger proof
e5 = L("e5_proofs.json")["proofs"]
e5 = sorted(e5, key=lambda r: (r["tx_in_epoch"], r["blocks_per_epoch"]))
seen, pts = set(), []
for r in e5:
    if r["tx_in_epoch"] not in seen:
        seen.add(r["tx_in_epoch"]); pts.append(r)
fig, axes = plt.subplots(1, 2, figsize=(6.5, 3.0))
xs = [r["tx_in_epoch"] for r in pts]
axes[0].plot(xs, [r["proof_bytes"] for r in pts], color=BLUE, marker="o")
axes[0].set_ylabel("Proof size (bytes)"); axes[0].set_title("Size"); axes[0].set_ylim(0, 800)
axes[1].plot(xs, [r["verify_us"] for r in pts], color=BLUE, marker="o")
axes[1].set_ylabel("Verification time (µs)"); axes[1].set_title("Verification"); axes[1].set_ylim(0, 18)
for ax in axes:
    ax.set_xscale("log", base=2); ax.set_xlabel("Transactions covered by one anchor")
    ax.set_xticks([16, 256, 4096, 65536]); ax.set_xticklabels(["16", "256", "4,096", "65,536"])
    ax.minorticks_off()
axes[0].annotate(f"{pts[-1]['proof_bytes']} B", (xs[-1], pts[-1]["proof_bytes"]),
                 textcoords="offset points", xytext=(-4, 8), ha="right", color=INK)
axes[1].annotate(f"{pts[-1]['verify_us']:.1f} µs", (xs[-1], pts[-1]["verify_us"]),
                 textcoords="offset points", xytext=(-4, 8), ha="right", color=INK)
fig.subplots_adjust(wspace=0.32)
fig.savefig(f"{OUT}/fig7_9_dlp.png"); plt.close(fig)
print("charts written:", sorted(os.listdir(OUT)))
