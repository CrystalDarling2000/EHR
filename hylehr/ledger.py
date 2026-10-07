"""Private (permissioned) ledger, public anchor ledger and consent state.

The private ledger is an in-process model of a BFT-ordered consortium
chain: n validators, f = (n-1)//3 tolerated faults, and a block is final
once 2f+1 validators have signed its header. The public ledger models a
permissionless chain that stores nothing but anchors.
"""
import time
from dataclasses import dataclass, field

from .crypto_utils import (H, Identity, canon, merkle_proof, merkle_root,
                           verify_sig)

ROUTINE, SENSITIVE, CRITICAL = 0, 1, 2
CLASS_NAME = {ROUTINE: "routine", SENSITIVE: "sensitive", CRITICAL: "critical"}

# transaction types and the sensitivity class the chaincode assigns
TX_CLASS = {
    "REGISTER": ROUTINE,
    "RECORD_ADD": None,           # taken from the record's own label
    "CONSENT_GRANT": SENSITIVE,
    "CONSENT_REVOKE": CRITICAL,
    "ACCESS_LOG": None,           # inherits the record's label
    "EMERGENCY_ACCESS": CRITICAL,
}


class LedgerError(Exception):
    pass


# ------------------------------------------------------------ transactions
def make_tx(sender: Identity, tx_type: str, payload: dict, nonce: int,
            ts: float | None = None) -> dict:
    body = {"type": tx_type, "sender": sender.id, "pk": sender.pk.hex(),
            "nonce": nonce, "ts": round(ts if ts is not None else time.time(), 3),
            "payload": payload}
    raw = canon(body)
    return {**body, "sig": sender.sign(raw).hex(), "id": H("tx", raw).hex()}


def tx_valid_sig(tx: dict) -> bool:
    body = {k: tx[k] for k in ("type", "sender", "pk", "nonce", "ts", "payload")}
    raw = canon(body)
    return (H("tx", raw).hex() == tx["id"]
            and H("id", bytes.fromhex(tx["pk"])).hex()[:32] == tx["sender"]
            and verify_sig(bytes.fromhex(tx["pk"]), bytes.fromhex(tx["sig"]), raw))


# ------------------------------------------------------------------ blocks
@dataclass
class Block:
    height: int
    prev: bytes
    tx_root: bytes
    state_digest: bytes
    ts: float
    txs: list
    max_class: int = ROUTINE
    score: int = 0
    sigs: dict = field(default_factory=dict)

    def header(self) -> bytes:
        return H("blk", self.height, self.prev, self.tx_root,
                 self.state_digest, int(self.ts * 1000))

    @property
    def hash(self) -> bytes:
        return self.header()


# ------------------------------------------------------------ private chain
class PrivateLedger:
    WEIGHT = {ROUTINE: 1, SENSITIVE: 4, CRITICAL: 16}

    def __init__(self, n_validators: int = 4):
        self.validators = [Identity(f"validator-{i}", "validator")
                           for i in range(n_validators)]
        self.f = (n_validators - 1) // 3
        self.quorum = 2 * self.f + 1
        self.chain: list[Block] = []
        self.mempool: list[dict] = []
        self.seen: set[str] = set()
        # world state
        self.identities: dict[str, dict] = {}
        self.records: dict[str, dict] = {}
        self.consents: dict[tuple, dict] = {}
        self.tx_index: dict[str, tuple] = {}
        self.state_digest = H("genesis-state")

    # -- chaincode: validation and state transition ------------------------
    def _classify(self, tx) -> int:
        cls = TX_CLASS[tx["type"]]
        if cls is not None:
            return cls
        p = tx["payload"]
        if tx["type"] == "RECORD_ADD":
            return p["cls"]
        return self.records[p["rec_id"]]["cls"]

    def _check(self, tx):
        t, p, s = tx["type"], tx["payload"], tx["sender"]
        if tx["id"] in self.seen:
            raise LedgerError("replayed transaction")
        if t == "REGISTER":
            return
        if s not in self.identities:
            raise LedgerError("unknown sender")
        role = self.identities[s]["role"]
        if t == "RECORD_ADD":
            if role != "provider":
                raise LedgerError("only providers add records")
            if p["rec_id"] in self.records:
                raise LedgerError("duplicate record")
        elif t in ("CONSENT_GRANT", "CONSENT_REVOKE"):
            if s != p["patient"]:
                raise LedgerError("only the patient changes consent")
            if t == "CONSENT_REVOKE" and (p["patient"], p["grantee"]) not in self.consents:
                raise LedgerError("nothing to revoke")
        elif t == "ACCESS_LOG":
            rec = self.records.get(p["rec_id"])
            if rec is None or rec["custodian"] != s:
                raise LedgerError("only the custodian logs access")
        elif t == "EMERGENCY_ACCESS":
            if role != "provider" or not self.identities[s].get("emergency"):
                raise LedgerError("not an emergency-authorised clinician")

    def _apply(self, tx, height):
        t, p = tx["type"], tx["payload"]
        if t == "REGISTER":
            self.identities[tx["sender"]] = {"pk": tx["pk"], "role": p["role"],
                                             "emergency": p.get("emergency", False)}
        elif t == "RECORD_ADD":
            self.records[p["rec_id"]] = {**p, "custodian": tx["sender"], "height": height}
        elif t == "CONSENT_GRANT":
            key = (p["patient"], p["grantee"])
            ver = self.consents.get(key, {"version": 0})["version"] + 1
            self.consents[key] = {"version": ver, "status": "ACTIVE", "scope": p["scope"],
                                  "purpose": p["purpose"], "expiry": p["expiry"],
                                  "tx": tx["id"], "height": height}
        elif t == "CONSENT_REVOKE":
            c = self.consents[(p["patient"], p["grantee"])]
            c.update(version=c["version"] + 1, status="REVOKED", tx=tx["id"], height=height)
        if t in ("CONSENT_GRANT", "CONSENT_REVOKE"):
            self.state_digest = H("state", self.state_digest, tx["id"])

    # -- client API ----------------------------------------------------------
    def submit(self, tx: dict, check_sig: bool = True):
        if check_sig and not tx_valid_sig(tx):
            raise LedgerError("bad signature")
        self._check(tx)
        self.seen.add(tx["id"])
        self.mempool.append(tx)

    def commit_block(self, ts: float | None = None, revalidate: bool = True) -> Block:
        """Order the mempool into a block and collect a quorum of signatures."""
        txs, self.mempool = self.mempool, []
        height = len(self.chain)
        classes = []
        for tx in txs:
            classes.append(self._classify(tx))
            self._apply(tx, height)
        prev = self.chain[-1].hash if self.chain else H("genesis")
        blk = Block(height, prev, merkle_root([bytes.fromhex(t["id"]) for t in txs]),
                    self.state_digest, ts if ts is not None else time.time(), txs,
                    max(classes, default=ROUTINE),
                    sum(self.WEIGHT[c] for c in classes))
        header = blk.header()
        for v in self.validators[:self.quorum]:
            if revalidate:                      # each validator re-checks the block
                assert all(tx_valid_sig(t) for t in txs)
                assert merkle_root([bytes.fromhex(t["id"]) for t in txs]) == blk.tx_root
            blk.sigs[v.id] = v.sign(header)
        for v in self.validators[:self.quorum]:  # anyone can verify finality
            assert verify_sig(v.pk, blk.sigs[v.id], header)
        for i, tx in enumerate(txs):
            self.tx_index[tx["id"]] = (height, i)
        self.chain.append(blk)
        return blk

    # -- consent queries ------------------------------------------------------
    def consent_digest(self, patient: str, grantee: str) -> bytes | None:
        """Digest of the *current* consent version; None if never granted."""
        c = self.consents.get((patient, grantee))
        if c is None:
            return None
        return H("consent", patient, grantee, c["version"], c["status"],
                 canon(c["scope"]), c["purpose"], int(c["expiry"]),
                 bytes.fromhex(c["tx"]), self.chain[c["height"]].hash)

    def consent_active(self, patient, grantee, rec_type, now) -> bool:
        c = self.consents.get((patient, grantee))
        return bool(c and c["status"] == "ACTIVE" and rec_type in c["scope"]
                    and now < c["expiry"])

    def consent_root(self) -> bytes:
        leaves = [self.consent_digest(p, g) for (p, g) in sorted(self.consents)]
        return merkle_root(leaves)

    def consent_proof(self, patient: str, grantee: str):
        """Merkle path of one consent entry inside the consent root."""
        keys = sorted(self.consents)
        i = keys.index((patient, grantee))
        leaves = [self.consent_digest(p, g) for (p, g) in keys]
        return leaves[i], i, merkle_proof(leaves, i)

    def covers(self, anchor) -> bool:
        """True if this replica holds exactly the blocks an anchor commits to."""
        if anchor is None:
            return True
        if len(self.chain) <= anchor.last:
            return False
        hashes = [b.hash for b in self.chain[anchor.first:anchor.last + 1]]
        return merkle_root(hashes) == anchor.ledger_root


# ------------------------------------------------------------- public chain
@dataclass
class Anchor:
    epoch: int
    ledger_root: bytes
    consent_root: bytes
    first: int
    last: int
    trigger: str
    ts: float
    chain_hash: bytes = b""


class PublicLedger:
    """Stand-in for the public chain: an append-only list of anchors.

    The Solidity contract in contracts/AnchorRegistry.sol is the real
    counterpart; evm/measure_gas.js runs it on a local EVM.
    """

    def __init__(self):
        self.anchors: list[Anchor] = []
        self.chain_hash = H("public-genesis")

    def anchor(self, ledger_root, consent_root, first, last, trigger, ts) -> Anchor:
        if self.anchors and first != self.anchors[-1].last + 1:
            raise LedgerError("anchor range must be contiguous")
        self.chain_hash = H("anchor", self.chain_hash, ledger_root, consent_root, first, last)
        a = Anchor(len(self.anchors) + 1, ledger_root, consent_root, first, last, trigger, ts,
                   self.chain_hash)
        self.anchors.append(a)
        return a

    def latest(self):
        return self.anchors[-1] if self.anchors else None


class Anchorer:
    """Couples the two ledgers through an anchoring policy."""

    def __init__(self, private: PrivateLedger, public: PublicLedger, policy):
        self.private, self.public, self.policy = private, public, policy
        self.next_height = 0
        self.block_epoch: dict[int, int] = {}

    def on_block(self, blk: Block):
        trigger = self.policy.decide(blk.ts, blk.score, blk.max_class, len(blk.txs))
        if not trigger:
            return None
        first, last = self.next_height, blk.height
        hashes = [b.hash for b in self.private.chain[first:last + 1]]
        a = self.public.anchor(merkle_root(hashes), self.private.consent_root(),
                               first, last, trigger, blk.ts)
        for h in range(first, last + 1):
            self.block_epoch[h] = a.epoch
        self.next_height = last + 1
        return a

    # -- dual-ledger proof (DLP) ------------------------------------------------
    def prove(self, tx_id: str) -> dict:
        height, idx = self.private.tx_index[tx_id]
        if height not in self.block_epoch:
            raise LedgerError("transaction not anchored yet")
        blk = self.private.chain[height]
        a = self.public.anchors[self.block_epoch[height] - 1]
        hashes = [b.hash for b in self.private.chain[a.first:a.last + 1]]
        return {"tx_id": tx_id, "tx_index": idx,
                "tx_path": merkle_proof([bytes.fromhex(t["id"]) for t in blk.txs], idx),
                "header": (blk.height, blk.prev, blk.tx_root, blk.state_digest,
                           int(blk.ts * 1000)),
                "blk_index": height - a.first,
                "blk_path": merkle_proof(hashes, height - a.first),
                "epoch": a.epoch}


def verify_dlp(proof: dict, public: PublicLedger) -> bool:
    """Verify a dual-ledger proof using only public-chain data."""
    from .crypto_utils import merkle_verify
    height, prev, tx_root, state_digest, ts_ms = proof["header"]
    if not merkle_verify(bytes.fromhex(proof["tx_id"]), proof["tx_index"],
                         proof["tx_path"], tx_root):
        return False
    blk_hash = H("blk", height, prev, tx_root, state_digest, ts_ms)
    a = public.anchors[proof["epoch"] - 1]
    return (a.first <= height <= a.last and
            merkle_verify(blk_hash, proof["blk_index"], proof["blk_path"], a.ledger_root))
