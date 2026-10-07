"""Architecture and method diagrams (Chapters 1, 4 and 5)."""
import os

from draw import *

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")
os.makedirs(OUT, exist_ok=True)


# ============================================================ Fig 1.1
def fig_1_1():
    fig, ax = canvas(9.6, 4.5, 0.72)
    cols = [(0.15, "(a) Public ledger only"), (3.35, "(b) Private ledger only"),
            (6.55, "(c) Hybrid ledger (this project)")]
    for x, title in cols:
        box(ax, x, 0.15, 2.95, 4.2, fc="white", ec=MUTED, lw=0.9)
        label(ax, x + 1.475, 4.05, title, fs=10.5, bold=True)
    # (a)
    box(ax, 0.4, 2.35, 2.45, 1.25, "Public chain\nconsent, access log,\nrecord hashes", fc=T_ORANGE, fs=9.5)
    box(ax, 0.4, 0.95, 2.45, 0.95, "Off-chain store\nencrypted records", fc=T_AQUA, fs=9.5)
    arrow(ax, 1.62, 2.35, 1.62, 1.9)
    label(ax, 1.62, 0.52, "Open audit, but metadata is\nvisible to all; slow and costly", fs=8.8, color=INK2)
    # (b)
    box(ax, 3.6, 2.35, 2.45, 1.25, "Consortium chain\nconsent, access log,\nrecord hashes", fc=T_BLUE, fs=9.5)
    box(ax, 3.6, 0.95, 2.45, 0.95, "Off-chain store\nencrypted records", fc=T_AQUA, fs=9.5)
    arrow(ax, 4.82, 2.35, 4.82, 1.9)
    label(ax, 4.82, 0.52, "Fast and private, but history is\nonly as honest as the consortium", fs=8.8, color=INK2)
    # (c)
    box(ax, 6.8, 2.75, 2.45, 0.85, "Public chain\nMerkle roots only", fc=T_ORANGE, fs=9.5)
    box(ax, 6.8, 1.45, 2.45, 0.9, "Consortium chain\nconsent, log, hashes", fc=T_BLUE, fs=9.5)
    box(ax, 6.8, 0.95, 2.45, 0.38, "Off-chain encrypted records", fc=T_AQUA, fs=9)
    arrow(ax, 8.02, 2.35, 8.02, 2.75, "anchor", toff=(0.12, 0), tpos=0.5, tha="left", tva="center")
    label(ax, 8.02, 0.52, "Private speed and privacy with\npublic, tamper-evident history", fs=8.8, color=INK2)
    fig.savefig(f"{OUT}/fig1_1_ledger_models.png"); plt.close(fig)


# ============================================================ Fig 4.1
def fig_4_1():
    fig, ax = canvas(10, 7.6, 0.66)
    # actors
    actors = [(0.2, "Patient\n(mobile wallet)"), (2.65, "Custodian hospital\n(holds the record)"),
              (5.1, "Requesting hospital\n(wants the record)"), (7.55, "Auditor / regulator\n(read-only)")]
    for x, t in actors:
        box(ax, x, 6.6, 2.25, 0.85, t, fc="white", ec=INK2, fs=9.8)
        arrow(ax, x + 1.125, 6.6, x + 1.125, 6.12, style="<|-|>")
    # application layer
    box(ax, 0.2, 4.95, 9.6, 1.17, fc=T_GREY, ec=MUTED)
    label(ax, 0.38, 5.93, "Application layer", fs=10, bold=True, ha="left")
    for i, t in enumerate(["FHIR gateway and\nrecord encryptor", "Consent manager",
                           "CBKD transfer\nservice", "Proof verifier\n(DLP)"]):
        box(ax, 0.4 + i * 2.35, 5.05, 2.15, 0.68, t, fc="white", fs=9.3)
    # private ledger
    box(ax, 0.2, 2.65, 6.3, 1.95, fc=T_BLUE, ec=BLUE, lw=1.2)
    label(ax, 0.38, 4.4, "Private consortium ledger (permissioned, BFT ordering)", fs=10, bold=True, ha="left")
    for i, t in enumerate(["Identity\nregistry", "Record\nregistry", "Consent\ncontract", "Access and\nemergency log"]):
        box(ax, 0.4 + i * 1.5, 3.45, 1.38, 0.7, t, fc="white", fs=9.2)
    for i in range(5):
        box(ax, 0.4 + i * 1.2, 2.8, 1.0, 0.45, f"block {i + 41}", fc="white", ec=BLUE, fs=8.6)
        if i:
            arrow(ax, 0.4 + i * 1.2 - 0.2, 3.025, 0.4 + i * 1.2, 3.025, lw=1.0)
    # anchoring service
    box(ax, 6.95, 3.25, 2.85, 1.35, "SAAA anchoring service\nscores each block, decides\nwhen to anchor, tunes θ",
        fc=T_YELLOW, ec=INK2, fs=9.5)
    arrow(ax, 6.5, 3.9, 6.95, 3.9)
    # public ledger
    box(ax, 6.95, 0.25, 2.85, 2.15, fc=T_ORANGE, ec=ORANGE, lw=1.2)
    label(ax, 8.375, 2.13, "Public ledger", fs=10, bold=True)
    box(ax, 7.15, 0.45, 2.45, 1.35, "AnchorRegistry contract\nledger root, consent root,\nblock range per epoch", fc="white", fs=9.2)
    arrow(ax, 8.375, 3.25, 8.375, 2.4, "Merkle roots only", toff=(0.1, 0), tha="left", tva="center")
    # off-chain store
    box(ax, 0.2, 0.25, 6.3, 2.0, fc=T_AQUA, ec=AQUA, lw=1.2)
    label(ax, 0.38, 2.03, "Off-chain encrypted store (content-addressed)", fs=10, bold=True, ha="left")
    box(ax, 0.4, 0.45, 5.9, 1.2, "AES-256-GCM ciphertext in 256 KiB chunks.\nThe address of a record is the Merkle root of its chunks (CID),\nand that CID is what the private ledger stores.", fc="white", fs=9.2)
    arrow(ax, 3.35, 2.65, 3.35, 2.25, "CID", toff=(0.1, 0), tha="left", tva="center")
    arrow(ax, 5.0, 4.95, 5.0, 4.6, style="<|-|>")
    arrow(ax, 1.6, 4.95, 1.6, 4.6, style="<|-|>")
    fig.savefig(f"{OUT}/fig4_1_architecture.png"); plt.close(fig)


# ============================================================ Fig 4.2
def fig_4_2():
    fig, ax = canvas(10, 6.2, 0.66)
    label(ax, 0.2, 5.95, "Public ledger", fs=10.5, bold=True, ha="left")
    box(ax, 2.3, 5.05, 5.4, 1.0, "Anchor, epoch e\nledgerRoot | consentRoot | firstHeight | lastHeight | trigger",
        fc=T_ORANGE, ec=ORANGE, fs=9.6, lw=1.2)
    # merkle tree over block hashes
    label(ax, 0.2, 4.45, "Epoch tree", fs=10.5, bold=True, ha="left")
    label(ax, 0.2, 4.12, "(second hop of the proof)", fs=8.8, color=INK2, ha="left", italic=True)
    box(ax, 4.35, 4.2, 1.3, 0.45, "ledger root", fc="white", fs=9)
    arrow(ax, 5.0, 4.65, 5.0, 5.05)
    for x in (2.9, 5.8):
        box(ax, x, 3.4, 1.3, 0.42, "SHA-256", fc="white", fs=8.8)
        arrow(ax, x + 0.65, 3.82, 5.0 + (-0.35 if x < 4 else 0.35), 4.2, lw=1.0)
    bx = [1.0, 3.25, 5.5, 7.75]
    for i, x in enumerate(bx):
        tgt = 3.55 if i < 2 else 6.45
        arrow(ax, x + 0.62, 2.95, tgt, 3.4, lw=1.0)
    label(ax, 0.2, 2.72, "Private\nledger", fs=10.5, bold=True, ha="left", va="center")
    for i, x in enumerate(bx):
        box(ax, x, 1.55, 1.9, 1.4, fc=T_BLUE, ec=BLUE, lw=1.1)
        label(ax, x + 0.95, 2.72, f"Block h{'+' + str(i) if i else ''}", fs=9.6, bold=True)
        label(ax, x + 0.95, 2.13, "prev hash | tx root\nstate digest | time\n2f+1 signatures", fs=8.6)
        if i:
            arrow(ax, x, 2.25, x - 0.35, 2.25, lw=1.0)
    # transactions of one block
    label(ax, 0.2, 0.9, "Transactions\nin block h+1", fs=10.5, bold=True, ha="left", va="center")
    label(ax, 0.2, 0.4, "(first hop of the proof)", fs=8.8, color=INK2, ha="left", italic=True)
    txs = ["RECORD_ADD\nCID, class", "CONSENT_GRANT\nscope, expiry", "ACCESS_LOG\nreceipt hash", "CONSENT_REVOKE\n(critical)"]
    for i, t in enumerate(txs):
        x = 2.55 + i * 1.85
        box(ax, x, 0.35, 1.75, 0.8, t, fc=T_GREY if i < 3 else T_YELLOW, fs=8.3)
        arrow(ax, x + 0.875, 1.15, 4.2, 1.55, lw=0.9)
    fig.savefig(f"{OUT}/fig4_2_structures.png"); plt.close(fig)


# ============================================================ Fig 4.3
def fig_4_3():
    fig, ax = canvas(10, 4.3, 0.68)
    box(ax, 0.2, 2.1, 1.6, 0.8, "No consent", fc=T_GREY, fs=10)
    box(ax, 3.6, 2.1, 2.0, 0.8, "ACTIVE\nversion v", fc=T_AQUA, ec=AQUA, fs=10, lw=1.2)
    box(ax, 7.9, 2.1, 1.9, 0.8, "REVOKED\nversion v+1", fc=T_ORANGE, ec=ORANGE, fs=10, lw=1.2)
    box(ax, 3.65, 0.25, 1.9, 0.7, "EXPIRED", fc=T_GREY, fs=10)
    arrow(ax, 1.8, 2.5, 3.6, 2.5, "CONSENT_GRANT\n(sensitive)", toff=(0, 0.08), bg=False)
    arrow(ax, 5.6, 2.5, 7.9, 2.5, "CONSENT_REVOKE\n(critical: anchored at once)", toff=(0, 0.08), bg=False, fs=8.8)
    arrow(ax, 8.85, 2.9, 4.6, 2.9, rad=0.38)
    label(ax, 6.72, 4.02, "CONSENT_GRANT again → version v+2", fs=9, color=INK2)
    arrow(ax, 4.6, 2.1, 4.6, 0.95, "expiry time passes\n(no transaction needed)", toff=(0.14, 0), tha="left", tva="center", bg=False)
    label(ax, 7.75, 0.62, "Each grant or revocation changes the consent digest,\nand with it every session key derived afterwards.",
          fs=9.2, color=INK2, italic=True)
    fig.savefig(f"{OUT}/fig4_3_consent_states.png"); plt.close(fig)


# ============================================================ Fig 5.1
def fig_5_1():
    fig, ax = canvas(10, 4.3, 0.66)
    box(ax, 0.15, 2.55, 1.75, 1.1, "Clinical record\nFHIR JSON,\nDICOM, PDF", fc=T_GREY, fs=9.5)
    arrow(ax, 1.9, 3.1, 2.4, 3.1)
    box(ax, 2.4, 2.55, 1.6, 1.1, "Split into\n256 KiB\nchunks", fc="white", fs=9.5)
    arrow(ax, 4.0, 3.1, 4.5, 3.1)
    box(ax, 4.5, 2.55, 2.0, 1.1, "AES-256-GCM\nper chunk, fresh\n256-bit DEK", fc="white", fs=9.5)
    arrow(ax, 6.5, 3.1, 7.0, 3.1)
    box(ax, 7.0, 2.55, 2.85, 1.1, "Merkle root over the\nciphertext chunks\n= CID", fc=T_YELLOW, fs=9.5)
    box(ax, 0.15, 0.3, 2.9, 1.25, "Custodian key store\nDEK, one per record version\n(never leaves in the clear)", fc=T_GREY, fs=9.3)
    box(ax, 3.55, 0.3, 2.9, 1.25, "Off-chain store\nciphertext chunks,\nfetched by CID", fc=T_AQUA, ec=AQUA, fs=9.3, lw=1.2)
    box(ax, 6.95, 0.3, 2.9, 1.25, "Private ledger\nRECORD_ADD: CID, size,\nclass, patient pseudonym", fc=T_BLUE, ec=BLUE, fs=9.3, lw=1.2)
    arrow(ax, 5.5, 2.55, 1.6, 1.55, "DEK", tpos=0.55, toff=(0, 0.1))
    arrow(ax, 5.9, 2.55, 5.0, 1.55, "chunks", tpos=0.5, toff=(0.5, 0.0))
    arrow(ax, 8.4, 2.55, 8.4, 1.55, "CID", toff=(0.12, 0), tha="left", tva="center")
    fig.savefig(f"{OUT}/fig5_1_ingestion.png"); plt.close(fig)


# ============================================================ Fig 5.2
def fig_5_2():
    fig, ax = canvas(10, 10.4, 0.66)
    L = {"B": 1.15, "A": 4.0, "P": 6.3, "U": 7.9, "S": 9.2}
    heads = [("B", "Requester\n(Hospital B)", "white"), ("A", "Custodian\n(Hospital A)", "white"),
             ("P", "Private\nledger", T_BLUE), ("U", "Public\nledger", T_ORANGE), ("S", "Off-chain\nstore", T_AQUA)]
    for k, t, fc in heads:
        w = 1.9 if k in "BA" else 1.25
        box(ax, L[k] - w / 2, 9.55, w, 0.75, t, fc=fc, fs=9.5, bold=True)
        ax.plot([L[k], L[k]], [0.85, 9.55], color=MUTED, lw=0.9, ls=(0, (4, 3)), zorder=1)

    def msg(y, a, b, text, n):
        arrow(ax, L[a], y, L[b], y)
        left = min(L[a], L[b])
        ax.text(left + 0.2, y + 0.2, n, fontsize=8.5, color="white", zorder=7, ha="center",
                va="center", fontweight="bold", bbox=dict(boxstyle="circle,pad=0.18", fc=INK2, ec="none"))
        ax.text(left + 0.45, y + 0.09, text, fontsize=9, color=INK, zorder=6, ha="left", va="bottom",
                linespacing=1.2, bbox=dict(fc="white", ec="none", pad=1.0))

    def note(y, x, text, w, h):
        box(ax, x, y - h / 2, w, h, text, fc=T_YELLOW, fs=8.8, ec=INK2, lw=0.8, zorder=5)

    msg(8.85, "B", "A", r"Request: rec_id, ePK$_B$, N$_B$, sig$_B$", "1")
    msg(8.15, "A", "U", "read latest anchor (epoch e, chain hash)", "2")
    msg(7.45, "A", "P", "replica covers anchor e?  consent live?", "3")
    note(6.6, 2.2, "consent digest cd read from own replica\n"
         r"K = HKDF( X25519(eSK$_A$, ePK$_B$);  salt = cd;" "\n"
         "info = anchor(e) ‖ transcript )", 3.9, 0.95)
    msg(5.45, "A", "B", r"Response: ePK$_A$, N$_A$, e, sig$_A$," "\n" r"Wrap$_K$(DEK), conf$_A$", "4")
    msg(4.75, "B", "U", "check that epoch e is the latest anchor", "5")
    msg(4.05, "B", "P", "read cd′ from own replica", "6")
    note(3.25, 0.25, r"K′ = HKDF( X25519(eSK$_B$, ePK$_A$);  salt = cd′; … )" "\n"
         "unwrap DEK: fails unless cd′ = cd", 4.3, 0.75)
    msg(2.35, "B", "S", "fetch ciphertext chunks by CID; check Merkle root = CID on ledger; decrypt", "7")
    msg(1.65, "B", "A", r"Receipt: cd, transcript hash, conf$_B$, sig$_B$", "8")
    msg(0.95, "A", "P", "ACCESS_LOG transaction", "9")
    label(ax, 5.0, 0.35, "DEK = per-record data key;  cd = consent digest;  conf = key-confirmation MAC",
          fs=8.8, color=INK2, italic=True)
    fig.savefig(f"{OUT}/fig5_2_cbkd_sequence.png"); plt.close(fig)


# ============================================================ Fig 5.3
def fig_5_3():
    fig, ax = canvas(9.8, 8.3, 0.66)
    cx = 3.1
    box(ax, cx - 1.9, 7.45, 3.8, 0.7, "New private block committed", fc=T_BLUE, ec=BLUE, fs=10, lw=1.2)
    arrow(ax, cx, 7.45, cx, 7.05)
    box(ax, cx - 1.9, 6.3, 3.8, 0.75, "S ← S + Σ w(class) over the block\nw = 1 routine, 4 sensitive, 16 critical", fc="white", fs=9.5)
    arrow(ax, cx, 6.3, cx, 5.85)
    diamond(ax, cx, 5.2, 3.9, 1.3, "Critical-class\ntransaction in block?")
    arrow(ax, cx, 4.55, cx, 4.2, "no", toff=(0.12, 0), tha="left", tva="center", bg=False)
    diamond(ax, cx, 3.55, 3.9, 1.3, "S ≥ θ ?")
    arrow(ax, cx, 2.9, cx, 2.55, "no", toff=(0.12, 0), tha="left", tva="center", bg=False)
    diamond(ax, cx, 1.9, 3.9, 1.3, "Oldest pending transaction\n" r"waited ≥ T$_{max}$ ?")
    arrow(ax, cx, 1.25, cx, 0.85, "no", toff=(0.12, 0), tha="left", tva="center", bg=False)
    box(ax, cx - 1.9, 0.15, 3.8, 0.7, "Keep pending; wait for next block", fc=T_GREY, fs=9.8)
    bx, bw = 6.55, 3.1
    vx = bx + 1.0
    box(ax, bx, 3.0, bw, 1.1, "ANCHOR\nsubmit ledger root + consent\nroot to AnchorRegistry;  S ← 0",
        fc=T_ORANGE, ec=ORANGE, fs=9.4, lw=1.2)
    for y, t in ((5.2, "yes (critical)"), (3.55, "yes (score)"), (1.9, "yes (timeout)")):
        label(ax, cx + 2.05, y + 0.12, t, fs=8.8, color=INK2, ha="left", va="bottom")
    ax.plot([cx + 1.95, vx], [5.2, 5.2], color=INK2, lw=1.2, zorder=4)
    arrow(ax, vx, 5.2, vx, 4.1)
    ax.plot([cx + 1.95, vx], [1.9, 1.9], color=INK2, lw=1.2, zorder=4)
    arrow(ax, vx, 1.9, vx, 3.0)
    arrow(ax, cx + 1.95, 3.55, bx, 3.55)
    box(ax, bx, 6.3, bw, 1.85, "Budget controller\nevery window W (10 min):\n"
        r"θ ← θ · (½·recent + ½·pace)$^{γ}$" "\nrecent = last window's spend ÷ target\n"
        "pace = total spend ÷ pro-rata budget", fc=T_YELLOW, fs=8.9)
    label(ax, bx + bw / 2, 6.03, "θ is the threshold used in the score test", fs=8.6, color=INK2, italic=True)
    fig.savefig(f"{OUT}/fig5_3_saaa_flow.png"); plt.close(fig)


# ============================================================ Fig 5.4
def fig_5_4():
    fig, ax = canvas(10, 6.6, 0.66)
    HI = dict(fc=T_YELLOW, ec=ORANGE, lw=1.4)
    SIB = dict(fc=T_AQUA, ec=AQUA, lw=1.2)
    PL = dict(fc="white", ec=MUTED, lw=0.9)

    def tree(x0, y0, leaves, target, top_label, leaf_fs=8.8):
        xs = [x0 + i * 1.12 for i in range(4)]
        sib = target ^ 1
        for i, (x, t) in enumerate(zip(xs, leaves)):
            st = HI if i == target else SIB if i == sib else PL
            box(ax, x, y0, 1.0, 0.5, t, fs=leaf_fs, **st)
        mids = [x0 + 0.56, x0 + 2.8]
        tm = target // 2
        for j, x in enumerate(mids):
            st = HI if j == tm else SIB
            box(ax, x, y0 + 0.95, 1.0, 0.45, "hash", fs=8.8, **st)
            for i in (2 * j, 2 * j + 1):
                arrow(ax, xs[i] + 0.5, y0 + 0.5, x + 0.5, y0 + 0.95, lw=0.9)
        box(ax, x0 + 1.43, y0 + 1.85, 1.6, 0.48, top_label, fs=9, bold=True, **HI)
        for x in mids:
            arrow(ax, x + 0.5, y0 + 1.4, x0 + 2.23, y0 + 1.85, lw=0.9)
        return x0 + 2.23, y0 + 2.33

    # lower tree: transactions in a block
    label(ax, 0.2, 2.75, "Hop 1: transaction → private block", fs=10.2, bold=True, ha="left")
    tx_top = tree(0.6, 0.3, ["tx 0", "tx 1", "tx 2\n(proved)", "tx 3"], 2, "tx root")
    box(ax, 5.6, 1.55, 4.1, 1.05, "Block header h\nheight | prev | tx root | state digest | time\n→ block hash = SHA-256(header)",
        fc=T_BLUE, ec=BLUE, fs=9, lw=1.2)
    arrow(ax, 3.63, 2.39, 5.6, 2.2, lw=1.2)
    # upper tree: blocks in an epoch
    label(ax, 0.2, 6.35, "Hop 2: private block → public anchor", fs=10.2, bold=True, ha="left")
    tree(0.6, 3.75, ["block h−1", "block h\n(proved)", "block h+1", "block h+2"], 1, "ledger root")
    arrow(ax, 6.2, 2.6, 2.4, 3.75, rad=0.0, lw=1.2)
    box(ax, 5.6, 5.35, 4.1, 0.95, "Public anchor, epoch e\nledgerRoot stored by AnchorRegistry", fc=T_ORANGE, ec=ORANGE, fs=9.2, lw=1.2)
    arrow(ax, 3.63, 5.84, 5.6, 5.84, "must be equal", lw=1.2, toff=(0, 0.08))
    # legend
    box(ax, 5.6, 3.55, 0.45, 0.3, **HI); label(ax, 6.15, 3.7, "recomputed by the verifier", fs=9, ha="left")
    box(ax, 5.6, 3.1, 0.45, 0.3, **SIB); label(ax, 6.15, 3.25, "sibling hashes carried in the proof", fs=9, ha="left")
    box(ax, 5.6, 4.45, 4.1, 0.55, "Proof = tx path + block header + block path", fc=T_GREY, fs=9.2)
    fig.savefig(f"{OUT}/fig5_4_dlp.png"); plt.close(fig)


for f in (fig_1_1, fig_4_1, fig_4_2, fig_4_3, fig_5_1, fig_5_2, fig_5_3, fig_5_4):
    f()
print("diagrams written")
