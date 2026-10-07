"""Anchoring policies: when does the private ledger commit to the public one?

Each policy exposes decide(now, block_score, block_max_class, n_tx) and
returns a trigger label (truthy) when the pending blocks must be anchored.
"""
from .ledger import CRITICAL


class PerBlock:
    """Anchor every non-empty private block (upper bound on cost)."""
    name = "PB"

    def __init__(self):
        self.pending = 0

    def decide(self, now, score, max_class, n_tx):
        return "block" if n_tx else None


class FixedInterval:
    """Anchor every k private blocks -- the usual periodic checkpoint."""

    def __init__(self, k: int):
        self.k, self.count, self.pending = k, 0, 0
        self.name = f"FI-{k}"

    def decide(self, now, score, max_class, n_tx):
        self.count += 1
        self.pending += n_tx
        if self.count >= self.k:
            fire = self.pending > 0
            self.count, self.pending = 0, 0
            return "interval" if fire else None
        return None


class SAAA:
    """Sensitivity-Aware Adaptive Anchoring.

    Fires when (1) a critical-class transaction is in the block,
    (2) the accumulated sensitivity score reaches the threshold theta, or
    (3) the oldest unanchored transaction has waited t_max seconds.

    With a daily budget, theta is retuned every `window` seconds so that
    the anchor spend follows the budget whatever the load does.
    """

    def __init__(self, theta: float, t_max: float = 900.0, budget_per_day=None,
                 window: float = 600.0, gamma: float = 0.5,
                 theta_min: float = 1.0, theta_max: float = 1e7):
        self.theta, self.t_max = float(theta), t_max
        self.budget, self.window, self.gamma = budget_per_day, window, gamma
        self.theta_min, self.theta_max = theta_min, theta_max
        self.score, self.pending, self.oldest = 0.0, 0, 0.0
        self.win_start, self.spent, self.total_spent = 0.0, 0, 0
        self.theta_trace = []
        self.name = "SAAA-B" if budget_per_day else "SAAA"

    def _retune(self, now):
        while now - self.win_start >= self.window:
            self.win_start += self.window
            target = self.budget * self.window / 86400.0     # anchors per window
            allowed = self.budget * self.win_start / 86400.0  # pro-rata so far
            recent = self.spent / target                      # last window
            pace = self.total_spent / allowed                 # since start
            ratio = max(0.1, 0.5 * recent + 0.5 * pace)
            self.theta = min(self.theta_max,
                             max(self.theta_min, self.theta * ratio ** self.gamma))
            self.theta_trace.append((self.win_start, self.theta, self.spent))
            self.spent = 0

    def decide(self, now, score, max_class, n_tx):
        if self.budget:
            self._retune(now)
        if n_tx and not self.pending:
            self.oldest = now                 # first unanchored transaction
        self.score += score
        self.pending += n_tx
        trigger = None
        if self.pending:
            if max_class >= CRITICAL:
                trigger = "critical"
            elif self.score >= self.theta:
                trigger = "score"
            elif now - self.oldest >= self.t_max:
                trigger = "timeout"
        if trigger:
            self.score, self.pending = 0.0, 0
            self.spent += 1
            self.total_spent += 1
        return trigger
