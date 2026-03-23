"""
PolicyEngine -- Hard guardrails for autonomous negotiation.

5 non-negotiable checks before any escrow commitment:
1. unit_price <= max_unit_price
2. committed_today + projected_cost <= max_daily_spend
3. provider reputation >= min_reputation (if defined) -- unknown = fail
4. quote not expired (within quote_ttl)
5. valid commerce_session_id

Daily budget ledger persisted to ``.actp/budget-ledger.json``
using atomic write pattern (write-to-tmp + os.rename).
Budget resets at UTC midnight.
"""
from __future__ import annotations

import datetime
import json
import math
import os
import re
from dataclasses import dataclass, field
from typing import List, Literal, Optional


# ============================================================================
# Types
# ============================================================================

@dataclass
class MaxUnitPrice:
    amount: float
    currency: str
    unit: str


@dataclass
class MaxDailySpend:
    amount: float
    currency: str


@dataclass
class Constraints:
    max_unit_price: MaxUnitPrice
    max_daily_spend: MaxDailySpend


@dataclass
class Negotiation:
    rounds_max: int
    quote_ttl: str  # e.g. "15m"


@dataclass
class Selection:
    prioritize: List[str]
    min_reputation: Optional[float] = None
    weights: Optional[dict] = None


@dataclass
class BuyerPolicy:
    task: str
    constraints: Constraints
    negotiation: Negotiation
    selection: Selection


@dataclass
class QuoteOffer:
    provider: str
    unit_price: float
    currency: str
    unit: str
    total_price: Optional[float] = None
    expires_at: Optional[int] = None  # unix timestamp
    reputation_score: Optional[float] = None
    commerce_session_id: Optional[str] = None


@dataclass
class PolicyViolation:
    rule: str  # 'max_unit_price' | 'max_daily_spend' | 'min_reputation' | 'quote_expired' | 'missing_session_id'
    detail: str


@dataclass
class PolicyResult:
    allowed: bool
    violations: List[PolicyViolation]


@dataclass
class BudgetEntry:
    commerce_session_id: str
    amount: float
    currency: str
    status: Literal["reserved", "committed", "released"]
    created_at: str
    actp_tx_id: Optional[str] = None


@dataclass
class BudgetLedgerFile:
    version: int  # always 1
    date: str  # YYYY-MM-DD (UTC)
    entries: List[BudgetEntry] = field(default_factory=list)


# ============================================================================
# PolicyEngine
# ============================================================================

class PolicyEngine:
    def __init__(self, policy: BuyerPolicy, actp_dir: Optional[str] = None) -> None:
        self._policy = policy
        self._actp_dir = actp_dir or os.environ.get("ACTP_DIR") or os.path.join(os.getcwd(), ".actp")
        self._ledger = self._load_ledger()

    def validate(self, offer: QuoteOffer) -> PolicyResult:
        """Validate a quote offer against all 5 policy guardrails."""
        violations: List[PolicyViolation] = []

        # 0. Sanity check -- reject NaN, negative, non-finite prices
        if not math.isfinite(offer.unit_price) or offer.unit_price < 0:
            return PolicyResult(
                allowed=False,
                violations=[PolicyViolation(
                    rule="max_unit_price",
                    detail=f"Invalid unit_price: {offer.unit_price} (must be finite and >= 0)",
                )],
            )
        if offer.total_price is not None and (not math.isfinite(offer.total_price) or offer.total_price < 0):
            return PolicyResult(
                allowed=False,
                violations=[PolicyViolation(
                    rule="max_daily_spend",
                    detail=f"Invalid total_price: {offer.total_price} (must be finite and >= 0)",
                )],
            )

        # 1. Unit price check (with currency/unit consistency enforcement)
        policy_up = self._policy.constraints.max_unit_price
        if offer.currency.upper() != policy_up.currency.upper():
            violations.append(PolicyViolation(
                rule="max_unit_price",
                detail=f"Currency mismatch: offer is {offer.currency}, policy requires {policy_up.currency}",
            ))
        elif offer.unit != policy_up.unit:
            violations.append(PolicyViolation(
                rule="max_unit_price",
                detail=f"Unit mismatch: offer is per-{offer.unit}, policy requires per-{policy_up.unit}",
            ))
        elif offer.unit_price > policy_up.amount:
            violations.append(PolicyViolation(
                rule="max_unit_price",
                detail=(
                    f"{offer.unit_price} {offer.currency}/{offer.unit} exceeds max "
                    f"{policy_up.amount} {policy_up.currency}/{policy_up.unit}"
                ),
            ))

        # 2. Daily spend check (with currency consistency)
        projected_cost = offer.total_price if offer.total_price is not None else offer.unit_price
        policy_ds = self._policy.constraints.max_daily_spend
        if offer.currency.upper() != policy_ds.currency.upper():
            violations.append(PolicyViolation(
                rule="max_daily_spend",
                detail=f"Currency mismatch: offer is {offer.currency}, daily spend limit is {policy_ds.currency}",
            ))
        else:
            committed_today = self.get_committed_today()
            projected_total = committed_today + projected_cost
            if projected_total > policy_ds.amount:
                violations.append(PolicyViolation(
                    rule="max_daily_spend",
                    detail=(
                        f"Committed today: {committed_today}, projected: {projected_total}, "
                        f"max: {policy_ds.amount} {policy_ds.currency}"
                    ),
                ))

        # 3. Reputation check -- unknown (missing score) = fail when min_reputation is set
        if self._policy.selection.min_reputation is not None:
            if offer.reputation_score is None or offer.reputation_score < self._policy.selection.min_reputation:
                if offer.reputation_score is None:
                    detail = f"Provider reputation unknown -- min {self._policy.selection.min_reputation} required"
                else:
                    detail = (
                        f"Provider reputation {offer.reputation_score} below minimum "
                        f"{self._policy.selection.min_reputation}"
                    )
                violations.append(PolicyViolation(rule="min_reputation", detail=detail))

        # 4. Quote expiry check
        if offer.expires_at is not None:
            now_unix = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
            if offer.expires_at <= now_unix:
                expired_iso = datetime.datetime.fromtimestamp(
                    offer.expires_at, tz=datetime.timezone.utc
                ).isoformat()
                violations.append(PolicyViolation(
                    rule="quote_expired",
                    detail=f"Quote expired at {expired_iso}",
                ))

        # 5. Session ID check
        if not offer.commerce_session_id:
            violations.append(PolicyViolation(
                rule="missing_session_id",
                detail="No commerce_session_id provided",
            ))

        return PolicyResult(allowed=len(violations) == 0, violations=violations)

    def reserve(self, session_id: str, amount: float, currency: str) -> None:
        """
        Reserve budget for a pending commitment.
        Raises if the reservation would exceed max_daily_spend.
        """
        if not math.isfinite(amount) or amount < 0:
            raise ValueError(f"Invalid reserve amount: {amount} (must be finite and >= 0)")

        policy_currency = self._policy.constraints.max_daily_spend.currency
        if currency.upper() != policy_currency.upper():
            raise ValueError(
                f"Currency mismatch in reserve: {currency} does not match policy currency {policy_currency}"
            )

        self._ensure_ledger_current()

        # Enforce budget at reservation time (defense in depth -- not just in validate())
        committed_today = self.get_committed_today()
        max_daily = self._policy.constraints.max_daily_spend.amount
        if committed_today + amount > max_daily:
            raise ValueError(
                f"Budget exceeded: reserving {amount} {currency} would exceed daily limit "
                f"{max_daily} {self._policy.constraints.max_daily_spend.currency} "
                f"(already committed: {committed_today})"
            )

        self._ledger.entries.append(BudgetEntry(
            commerce_session_id=session_id,
            amount=amount,
            currency=currency,
            status="reserved",
            created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        ))
        self._save_ledger()

    def commit(self, session_id: str, actp_tx_id: str) -> None:
        """Commit a reservation (after escrow linked)."""
        for entry in self._ledger.entries:
            if entry.commerce_session_id == session_id and entry.status == "reserved":
                entry.status = "committed"
                entry.actp_tx_id = actp_tx_id
                self._save_ledger()
                return

    def release(self, session_id: str) -> None:
        """Release a reservation (after cancel/dispute)."""
        for entry in self._ledger.entries:
            if entry.commerce_session_id == session_id and entry.status in ("reserved", "committed"):
                entry.status = "released"
                self._save_ledger()
                return

    def get_committed_today(self) -> float:
        """Get total committed + reserved exposure for today."""
        self._ensure_ledger_current()
        return sum(
            e.amount for e in self._ledger.entries
            if e.status in ("reserved", "committed")
        )

    @staticmethod
    def parse_ttl(ttl: str) -> int:
        """Parse a TTL string like '15m' or '2h' into seconds."""
        match = re.match(r"^(\d+)(s|m|h)$", ttl)
        if not match:
            raise ValueError(f"Invalid TTL format: {ttl}")
        value = int(match.group(1))
        unit = match.group(2)
        if unit == "s":
            return value
        if unit == "m":
            return value * 60
        if unit == "h":
            return value * 3600
        raise ValueError(f"Invalid TTL unit: {unit}")

    def get_quote_deadline(self) -> int:
        """Get the quote TTL deadline (unix timestamp)."""
        ttl_seconds = PolicyEngine.parse_ttl(self._policy.negotiation.quote_ttl)
        return int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + ttl_seconds

    # ========================================================================
    # Budget Ledger Persistence
    # ========================================================================

    def _get_ledger_path(self) -> str:
        return os.path.join(self._actp_dir, "budget-ledger.json")

    @staticmethod
    def _today_string() -> str:
        """UTC date string -- daily budget resets at UTC midnight."""
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

    def _ensure_ledger_current(self) -> None:
        today = self._today_string()
        if self._ledger.date != today:
            self._ledger = BudgetLedgerFile(version=1, date=today, entries=[])
            self._save_ledger()

    def _load_ledger(self) -> BudgetLedgerFile:
        path = self._get_ledger_path()
        today = self._today_string()

        try:
            if not os.path.exists(path):
                return BudgetLedgerFile(version=1, date=today, entries=[])
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if raw.get("version") != 1 or raw.get("date") != today:
                return BudgetLedgerFile(version=1, date=today, entries=[])
            entries = [
                BudgetEntry(
                    commerce_session_id=e["commerce_session_id"],
                    actp_tx_id=e.get("actp_tx_id"),
                    amount=e["amount"],
                    currency=e["currency"],
                    status=e["status"],
                    created_at=e["created_at"],
                )
                for e in raw.get("entries", [])
            ]
            return BudgetLedgerFile(version=1, date=raw["date"], entries=entries)
        except Exception:
            return BudgetLedgerFile(version=1, date=today, entries=[])

    def _ensure_dir(self) -> None:
        if os.path.lexists(self._actp_dir):
            if os.path.islink(self._actp_dir) or not os.path.isdir(self._actp_dir):
                raise OSError(f"Security: {self._actp_dir} is not a real directory")
        else:
            os.makedirs(self._actp_dir, mode=0o700, exist_ok=True)

    def _save_ledger(self) -> None:
        self._ensure_dir()

        file_path = self._get_ledger_path()

        # Guard against target file being a symlink (lexists detects broken symlinks too)
        if os.path.lexists(file_path) and os.path.islink(file_path):
            raise OSError(f"Security: {file_path} is a symlink -- refusing to overwrite")

        tmp_path = file_path + ".tmp"

        # Guard against tmp file being a symlink
        if os.path.lexists(tmp_path) and os.path.islink(tmp_path):
            raise OSError(f"Security: {tmp_path} is a symlink -- refusing to write")

        # Serialize ledger to dict
        data = {
            "version": self._ledger.version,
            "date": self._ledger.date,
            "entries": [
                {
                    "commerce_session_id": e.commerce_session_id,
                    **({"actp_tx_id": e.actp_tx_id} if e.actp_tx_id is not None else {}),
                    "amount": e.amount,
                    "currency": e.currency,
                    "status": e.status,
                    "created_at": e.created_at,
                }
                for e in self._ledger.entries
            ],
        }

        # Atomic write
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            fobj = os.fdopen(fd, "w", encoding="utf-8")
        except BaseException:
            os.close(fd)
            raise
        with fobj:
            json.dump(data, fobj, indent=2)
        os.rename(tmp_path, file_path)
