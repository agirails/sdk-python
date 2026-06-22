# PARITY: sdk-js/src/dispute/EvaluatorClient.ts
# This file and its TypeScript twin MUST stay 1:1 — every public symbol here
# (EvaluatorClient + its methods, the request/result dataclasses,
# verify_ruling_signatures, select_third_evaluator, the error classes) has a TS
# twin with the SAME name (camelCase there, snake_case here) and arity, and
# vice-versa. The §4.7 signature-verification math and the two-phase handshake
# step order are anchored to the shared cross-SDK fixture
# `DISPUTE SYSTEM/test-vectors/evaluator-client-vectors.json`, which both the
# pytest and jest suites consume byte-identically and from which both recover the
# SAME signer addresses. Any change here (rename, new method, verification tweak)
# must be mirrored in the twin.
"""
EvaluatorClient — the SDK half of the off-chain dispute-evaluator handshake
(PRD P2-6). Targets the FROZEN wire contract
``services/dispute-evaluator/API-CONTRACT.md`` and the AIP-14 FINAL §4.7
2/3-signature verification spec.

It performs the two-phase x402 quote handshake against the evaluator service::

    STEP 0 DECLARE   client -> POST /quote     {bundleHash, declaredTokenCount, ...}   (no money, no LLM)
    STEP 1 QUOTE     server -> 402             {quote, x402 commit (bundleHash,payer,disputeNonce)}
    STEP 2 PAY       client -> x402 facilitator (USDC on Base, via the existing X402Adapter buyer stack)
    STEP 3 VERIFY    server: receipt valid + settled + SINGLE-USE + identity-bound -> CONSUME atomically
    STEP 4 RUN       server: 3-eval + 3-screen ensemble (service-internal)
    STEP 5 RETURN    server -> 200             signed AIRuling(s)  OR  proposeDirectly recommendation

The payment leg (STEP 2) is delegated to the EXISTING x402 buyer stack
(:class:`agirails.adapters.x402_adapter.X402Adapter`): its ``pay()`` POSTs to
``/evaluate``, transparently consumes the server's own 402, signs the
EIP-3009/Permit2 authorization, retries, and returns the settled 200 response.
This client never re-implements x402 — it passes the ``/evaluate`` body through
the adapter and parses the returned response body.

After receiving an ``outcome="signed"`` response, the client REPLICATES the
on-chain ``_verifyEvaluatorSignatures`` logic (§4.7) client-side using the FROZEN
:func:`recover_ruling_signer`: it independently recovers each signer, matches it
against ``[fixed_evaluators[0], fixed_evaluators[1], third_evaluator]``, counts
each once (duplicates ignored, unknown signers ignored), enforces freshness, and
requires ``valid_count >= 2``. It does NOT trust the server's advisory
``evaluators[]``. If the response is ``outcome="proposeDirectly"`` OR the signed
response fails §4.7, the client returns a ``proposeDirectly`` recommendation with
NO signatures — it NEVER fabricates a signature and NEVER submits on-chain
(the caller does that via :class:`BondEscalationClient`).

Reference: API-CONTRACT.md §3–§4; AIP-14 FINAL §4.7 (verification), §4.5 (domain),
§7.6 (proposeDirectly); INV-16 (2/3 valid sigs), INV-21 (AI never final).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Dict, List, Optional, Protocol, Sequence, Union

from eth_abi import encode as _abi_encode
from eth_utils import keccak as _keccak

from agirails.dispute.evidence_bundle import (
    EvidenceBundle,
    bundle_hash as compute_bundle_hash,
    count_bundle_tokens,
    serialize_bundle_to_string,
)
from agirails.types.dispute import AIRuling, Ruling, Tier, recover_ruling_signer


# ---------------------------------------------------------------------------
# Wire / config dataclasses (API-CONTRACT.md §2, §3, §4)
# ---------------------------------------------------------------------------


@dataclass
class BundleSource:
    """How the server obtains the evidence bundle (API-CONTRACT.md §3.1).

    Exactly one of ``cid`` / ``inline_bytes_b64`` should be set.
    """

    cid: Optional[str] = None
    inline_bytes_b64: Optional[str] = None

    def to_wire(self) -> Dict[str, Any]:
        """Serialize to the camelCase ``bundleSource`` wire object."""
        out: Dict[str, Any] = {}
        if self.cid is not None:
            out["cid"] = self.cid
        if self.inline_bytes_b64 is not None:
            out["inlineBytesB64"] = self.inline_bytes_b64
        return out


@dataclass
class RequestEvaluationParams:
    """Inputs to :meth:`EvaluatorClient.request_evaluation`.

    ``bundle`` is the logical :class:`EvidenceBundle`; the client derives
    ``bundleHash`` and ``tokenCount`` from the FROZEN serializer (it never trusts
    a caller-supplied hash).
    """

    bundle: EvidenceBundle
    dispute_id: str
    payer: str
    escrow_amount: str
    tier: Union[Tier, int]
    bundle_source: BundleSource
    chain_id: int
    verifying_contract: str
    fixed_evaluators: Sequence[str]
    rotating_pool: Sequence[str]
    freshness_seconds: int = 3600


@dataclass
class ProposeDirectlyRecommendation:
    """A non-binding ``proposeDirectly`` recommendation (API-CONTRACT.md §4.3b)."""

    ruling: Union[Ruling, int]
    split_bps: int
    confidence: int
    rationale: str


@dataclass
class RulingVerification:
    """Result of replicating the §4.7 ``_verifyEvaluatorSignatures`` logic client-side."""

    valid: bool
    valid_count: int
    recovered_signers: List[str]
    third_evaluator: str
    stale: bool


@dataclass
class EvaluationResult:
    """Discriminated result of :meth:`EvaluatorClient.request_evaluation`.

    - ``outcome == "signed"`` — 2/3 §4.7 verification PASSED. Carries the FROZEN
      :class:`AIRuling` + the 2–3 verified signatures the caller submits via
      ``BondEscalationClient.submit_ai_ruling``. The SDK has already re-recovered
      the signers; ``verification`` records the §4.7 result.
    - ``outcome == "proposeDirectly"`` — either the server returned a
      recommendation, OR a signed response FAILED §4.7 (insufficient valid sigs /
      stale). NO signatures are surfaced; the caller may call
      ``BondEscalationClient.propose_directly`` themselves. The SDK NEVER
      fabricates a signature here.
    """

    outcome: str  # "signed" | "proposeDirectly"
    token_count: Optional[int] = None
    reasoning: Optional[str] = None
    # signed-only
    ruling: Optional[AIRuling] = None
    signatures: Optional[List[str]] = None
    verification: Optional[RulingVerification] = None
    # proposeDirectly-only
    recommendation: Optional[ProposeDirectlyRecommendation] = None
    reason: Optional[str] = None  # "server-recommended" | "verification-failed"


class EvaluatorPaymentClient(Protocol):
    """Minimal x402 buyer surface this client REUSES for STEP 2.

    The existing :class:`agirails.adapters.x402_adapter.X402Adapter` satisfies
    this structurally — its ``pay(params)`` POSTs to the URL, transparently
    handles the server 402 (sign + retry), and returns a result whose
    ``.response`` is the settled HTTP response. Tests inject a stub exposing the
    same shape.
    """

    def pay(self, params: Any) -> Awaitable[Any]:  # pragma: no cover - protocol
        ...


@dataclass
class EvaluatorClientConfig:
    """Configuration for :class:`EvaluatorClient`."""

    base_url: str
    #: The x402 buyer used for STEP 2 — typically the SDK's ``X402Adapter``.
    payment_client: EvaluatorPaymentClient
    #: Async callable for the no-money STEP-0 ``/quote`` declare. Signature:
    #: ``async (url, *, method, headers, body) -> _HttpResponse``. Injected in
    #: tests to mock the HTTP endpoint; defaults to an httpx-backed POST.
    fetch_impl: Optional[Any] = None
    #: Body-level contract version (API-CONTRACT.md §1). Default ``"1.0.0"``.
    api_version: str = "1.0.0"


# ---------------------------------------------------------------------------
# Errors (frozen names — 1:1 with the TS twin)
# ---------------------------------------------------------------------------


class EvaluatorClientError(Exception):
    """Base class for evaluator-client errors."""


class QuoteRejectedError(EvaluatorClientError):
    """The ``/quote`` declare did not return the expected 402 quote.

    Attributes:
        status: HTTP status returned instead of 402.
        code: the frozen ``error.code`` from the §3.3 envelope, if present.
    """

    def __init__(self, status: int, code: Optional[str] = None, message: Optional[str] = None):
        self.status = status
        self.code = code
        super().__init__(
            f"Evaluator /quote rejected (HTTP {status}"
            + (f", code={code}" if code else "")
            + ")"
            + (f": {message}" if message else "")
        )


class EvaluateResponseError(EvaluatorClientError):
    """The ``/evaluate`` response was malformed or absent."""

    def __init__(self, message: str):
        super().__init__(f"Evaluator /evaluate response invalid: {message}")


# ---------------------------------------------------------------------------
# §4.7 third-evaluator selection (mirrors BondEscalation.sol + the TS twin)
# ---------------------------------------------------------------------------


def select_third_evaluator(
    dispute_id: str, rotating_pool: Sequence[str]
) -> Optional[str]:
    """Select the rotating third evaluator for a dispute (§4.7 step 4).

    ``rotatingPool[uint256(keccak256(abi.encode(disputeId))) % len]``. ``abi.encode``
    of a single ``bytes32`` is the 32-byte value itself, so we keccak the raw 32
    bytes. Returns ``None`` when the pool is empty.

    Args:
        dispute_id: bytes32hex dispute id.
        rotating_pool: the rotating evaluator addresses.
    """
    if not rotating_pool:
        return None
    encoded = _abi_encode(["bytes32"], [_to_bytes32(dispute_id)])
    idx = int.from_bytes(_keccak(encoded), "big") % len(rotating_pool)
    return rotating_pool[idx]


def verify_ruling_signatures(
    ruling: AIRuling,
    signatures: Sequence[str],
    *,
    chain_id: int,
    verifying_contract: str,
    fixed_evaluators: Sequence[str],
    rotating_pool: Sequence[str],
    now: Optional[int] = None,
    freshness_seconds: int = 3600,
) -> RulingVerification:
    """Replicate the on-chain ``_verifyEvaluatorSignatures`` logic (§4.7) client-side.

    Steps (§4.7):
      1. require ``2 <= len(signatures) <= 3``
      2. freshness: require ``now <= ruling.timestamp + freshness_seconds``
      3. require ``len(rotating_pool) >= 1`` (else only the two fixed slots count)
      4. ``third = rotating_pool[keccak(abi.encode(disputeId)) % len]``
      5–6. for each signature, recover the signer via :func:`recover_ruling_signer`;
           count it against ``[fixed0, fixed1, third]`` with a ``seen[3]`` dedupe map —
           unknown signers silently ignored, duplicates counted once.
      7. threshold: ``valid_count >= 2``.

    ``valid`` is ``True`` iff the threshold holds AND freshness holds AND the
    count gate (2–3) holds. NEVER raises — the caller maps a ``False`` result to a
    ``proposeDirectly`` recommendation.
    """
    if now is None:
        now = int(time.time())

    third_evaluator = select_third_evaluator(ruling.dispute_id, rotating_pool)

    # §4.7 step 4 — the ordered slot list the seen[] map tracks (fixed0, fixed1, third).
    slots: List[Optional[str]] = [
        fixed_evaluators[0] if len(fixed_evaluators) > 0 else None,
        fixed_evaluators[1] if len(fixed_evaluators) > 1 else None,
        third_evaluator,
    ]
    slots_lc = [s.lower() if s else None for s in slots]
    seen = [False, False, False]

    stale = now > int(ruling.timestamp) + freshness_seconds

    recovered_signers: List[str] = []
    valid_count = 0

    # §4.7 step 1 gate — count must be 2..3. A count outside this range can never
    # be valid, but we still recover signers (advisory) for diagnostics.
    count_in_range = 2 <= len(signatures) <= 3

    for sig in signatures:
        try:
            signer = recover_ruling_signer(ruling, sig, chain_id, verifying_contract)
        except Exception:
            # A malformed signature recovers nothing — silently ignored (unknown).
            continue
        signer_lc = signer.lower()
        slot_idx = next(
            (i for i, s in enumerate(slots_lc) if s is not None and s == signer_lc),
            -1,
        )
        if slot_idx == -1:
            continue  # unknown signer — silently ignored (§4.7)
        if seen[slot_idx]:
            continue  # duplicate — counted once (§4.7)
        seen[slot_idx] = True
        valid_count += 1
        recovered_signers.append(slots[slot_idx])  # type: ignore[arg-type]

    valid = count_in_range and (not stale) and valid_count >= 2
    return RulingVerification(
        valid=valid,
        valid_count=valid_count,
        recovered_signers=recovered_signers,
        third_evaluator=third_evaluator or "",
        stale=stale,
    )


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class EvaluatorClient:
    """Typed client for the off-chain dispute evaluator (PRD P2-6)."""

    def __init__(self, config: EvaluatorClientConfig) -> None:
        if not config.base_url or not isinstance(config.base_url, str):
            raise EvaluatorClientError("EvaluatorClient requires a base_url string.")
        if config.payment_client is None or not hasattr(config.payment_client, "pay"):
            raise EvaluatorClientError(
                "EvaluatorClient requires a payment_client with a pay() method "
                "(e.g. X402Adapter)."
            )
        self._base_url = config.base_url.rstrip("/")
        self._payment_client = config.payment_client
        self._fetch_impl = config.fetch_impl or _default_http_post
        self._api_version = config.api_version

    @property
    def base_url(self) -> str:
        return self._base_url

    async def request_evaluation(
        self, params: RequestEvaluationParams
    ) -> EvaluationResult:
        """Run the full STEP 0→5 evaluator handshake for an evidence bundle.

        Returns either signed-and-§4.7-verified ruling(s) or a ``proposeDirectly``
        recommendation. NEVER submits on-chain — the caller decides whether to
        call ``BondEscalationClient.submit_ai_ruling`` (on ``signed``) or
        ``BondEscalationClient.propose_directly`` (on ``proposeDirectly``).

        Raises:
            QuoteRejectedError: if ``/quote`` returns an error envelope instead of a 402.
            EvaluateResponseError: if ``/evaluate`` returns no/invalid body or a hash mismatch.
        """
        # Derive bundleHash + tokenCount from the FROZEN serializer — never trust a
        # caller-supplied hash. (The token cap is enforced here too.)
        bundle_hash_hex = compute_bundle_hash(params.bundle)
        declared_token_count = self._count_tokens(params.bundle)

        # ---- STEP 0 DECLARE → STEP 1 QUOTE (no money, no LLM) ----------------
        quote = await self._declare(params, bundle_hash_hex, declared_token_count)

        # ---- STEP 2 PAY (delegated to the existing x402 buyer stack) ---------
        # ---- STEP 3 VERIFY + STEP 4 RUN + STEP 5 RETURN (server-side) --------
        evaluate_body = {
            "apiVersion": self._api_version,
            "bundleHash": bundle_hash_hex,
            "disputeId": params.dispute_id,
            "disputeNonce": quote["disputeNonce"],
            "payer": params.payer,
            "chainId": params.chain_id,
            "verifyingContract": params.verifying_contract,
        }
        response = await self._pay_and_evaluate(evaluate_body)

        # ---- Parse the §4.3 200 body -----------------------------------------
        body = await self._parse_evaluate_response(response, bundle_hash_hex)

        outcome = body.get("outcome")
        if outcome == "proposeDirectly":
            rec = body["recommendation"]
            return EvaluationResult(
                outcome="proposeDirectly",
                recommendation=ProposeDirectlyRecommendation(
                    ruling=int(rec["ruling"]),
                    split_bps=int(rec.get("splitBps", 0)),
                    confidence=int(rec.get("confidence", 0)),
                    rationale=str(rec.get("rationale", "")),
                ),
                reason="server-recommended",
                token_count=body.get("tokenCount"),
                reasoning=body.get("reasoning"),
            )

        # §4.3a — signed. REPLICATE §4.7 client-side; never trust evaluators[].
        ruling = self._normalize_ruling(body["ruling"])
        verification = verify_ruling_signatures(
            ruling,
            body["signatures"],
            chain_id=params.chain_id,
            verifying_contract=params.verifying_contract,
            fixed_evaluators=params.fixed_evaluators,
            rotating_pool=params.rotating_pool,
            freshness_seconds=params.freshness_seconds,
        )

        if not verification.valid:
            # < 2/3 (or stale): DOWNGRADE to a proposeDirectly recommendation with
            # NO signatures (INV-21: AI never gains finality on a failed quorum).
            return EvaluationResult(
                outcome="proposeDirectly",
                recommendation=ProposeDirectlyRecommendation(
                    ruling=int(ruling.ruling),
                    split_bps=int(ruling.split_bps),
                    confidence=int(ruling.confidence),
                    rationale=(
                        "Signed response failed §4.7 verification "
                        f"(validCount={verification.valid_count}"
                        + (", stale" if verification.stale else "")
                        + "); recommend calling propose_directly() instead of "
                        "submitting the AI ruling."
                    ),
                ),
                reason="verification-failed",
                verification=verification,
                token_count=body.get("tokenCount"),
                reasoning=body.get("reasoning"),
            )

        return EvaluationResult(
            outcome="signed",
            ruling=ruling,
            signatures=list(body["signatures"]),
            verification=verification,
            token_count=body.get("tokenCount"),
            reasoning=body.get("reasoning"),
        )

    # -----------------------------------------------------------------------
    # Internals
    # -----------------------------------------------------------------------

    async def _declare(
        self,
        params: RequestEvaluationParams,
        bundle_hash_hex: str,
        declared_token_count: int,
    ) -> Dict[str, Any]:
        """STEP 0→1: POST ``/quote`` with the declaration (no money).

        A 402 carries the quote body (the normal success path); any other status
        is a §3.3 error envelope.
        """
        declare_body = {
            "apiVersion": self._api_version,
            "bundleHash": bundle_hash_hex,
            "disputeId": params.dispute_id,
            "declaredTokenCount": declared_token_count,
            "escrowAmount": params.escrow_amount,
            "tier": int(params.tier),
            "payer": params.payer,
            "bundleSource": params.bundle_source.to_wire(),
        }

        res = await self._fetch_impl(
            f"{self._base_url}/quote",
            method="POST",
            headers={"content-type": "application/json", "accept": "application/json"},
            body=json.dumps(declare_body),
        )

        status = _status_of(res)
        # §3.2 — a 402 IS the quote success. Anything else is a §3.3 error envelope.
        if status != 402:
            code = None
            message = None
            try:
                err_body = _json_of(res)
                err = err_body.get("error") if isinstance(err_body, dict) else None
                if isinstance(err, dict):
                    code = err.get("code")
                    message = err.get("message")
            except Exception:
                pass
            raise QuoteRejectedError(status, code, message)

        quote = _json_of(res)
        if not isinstance(quote, dict) or not isinstance(quote.get("disputeNonce"), str):
            raise QuoteRejectedError(402, None, "quote body missing disputeNonce")
        return quote

    async def _pay_and_evaluate(self, evaluate_body: Dict[str, Any]) -> Any:
        """STEP 2: pay the quote and POST ``/evaluate`` via the existing x402 buyer stack.

        The :class:`EvaluatorPaymentClient` ``pay()`` posts the body, transparently
        consumes the server 402, signs, retries, and returns the settled 200
        ``response``.
        """
        params = _EvaluatePayParams(
            to=f"{self._base_url}/evaluate",
            http_method="POST",
            http_body=json.dumps(evaluate_body),
            http_headers={
                "content-type": "application/json",
                "accept": "application/json",
            },
            metadata={"payment_method": "x402"},  # explicit opt-in (X402Adapter gate)
        )
        result = await self._payment_client.pay(params)
        response = getattr(result, "response", None)
        if response is None:
            raise EvaluateResponseError("payment client returned no HTTP response")
        return response

    async def _parse_evaluate_response(
        self, response: Any, expected_bundle_hash: str
    ) -> Dict[str, Any]:
        """Parse + validate the §4.3 evaluate response body."""
        try:
            body = _json_of(response)
        except Exception as exc:  # noqa: BLE001
            raise EvaluateResponseError(f"body is not valid JSON: {exc}")
        if not isinstance(body, dict) or body.get("outcome") not in (
            "signed",
            "proposeDirectly",
        ):
            raise EvaluateResponseError(
                f"missing/unknown outcome (got {body.get('outcome') if isinstance(body, dict) else None})"
            )
        # OQ-10: the returned bundleHash MUST equal the one we declared.
        resp_hash = body.get("bundleHash")
        if (
            not isinstance(resp_hash, str)
            or resp_hash.lower() != expected_bundle_hash.lower()
        ):
            raise EvaluateResponseError(
                f"bundleHash mismatch: response {resp_hash} != declared {expected_bundle_hash}"
            )
        if body["outcome"] == "signed":
            ruling = body.get("ruling")
            if (
                not isinstance(ruling, dict)
                or str(ruling.get("bundleHash", "")).lower()
                != expected_bundle_hash.lower()
            ):
                raise EvaluateResponseError(
                    "signed ruling.bundleHash != declared bundleHash"
                )
            if not isinstance(body.get("signatures"), list):
                raise EvaluateResponseError("signed response missing signatures[]")
        else:
            if not isinstance(body.get("recommendation"), dict):
                raise EvaluateResponseError(
                    "proposeDirectly response missing recommendation"
                )
        return body

    @staticmethod
    def _normalize_ruling(r: Dict[str, Any]) -> AIRuling:
        """Normalize a wire ruling object into the FROZEN :class:`AIRuling`."""
        return AIRuling(
            dispute_id=r["disputeId"],
            ruling=int(r["ruling"]),
            confidence=int(r["confidence"]),
            split_bps=int(r["splitBps"]),
            timestamp=int(r["timestamp"]),
            reasoning_hash=r["reasoningHash"],
            bundle_hash=r["bundleHash"],
        )

    @staticmethod
    def _count_tokens(bundle: EvidenceBundle) -> int:
        """Count cl100k_base tokens over the bundle's canonical bytes (advisory).

        The server re-counts authoritatively (§3.1/R3). Falls back to ``0`` when no
        tokenizer is installed — the field is advisory, so a missing tokenizer must
        not block the declare. ``compute_bundle_hash`` already enforced the hard
        100k cap when a tokenizer IS present.
        """
        try:
            text = serialize_bundle_to_string(bundle)
            return count_bundle_tokens(text)
        except Exception:
            return 0


# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------


@dataclass
class _EvaluatePayParams:
    """The pay() params shape the x402 buyer stack consumes (mirrors X402PayParams).

    Carries both the generic ``http_*`` fields and an x402 ``metadata`` opt-in.
    The real ``X402Adapter.pay`` reads ``to`` + the HTTP options; the stub in
    tests records them.
    """

    to: str
    http_method: str = "POST"
    http_body: Optional[str] = None
    http_headers: Optional[Dict[str, str]] = None
    metadata: Optional[Dict[str, Any]] = None


def _to_bytes32(value: Union[str, bytes]) -> bytes:
    """Coerce a bytes32hex string (or bytes) to exactly 32 bytes."""
    if isinstance(value, bytes):
        b = value
    else:
        s = value[2:] if value.startswith("0x") else value
        b = bytes.fromhex(s)
    if len(b) != 32:
        b = b.rjust(32, b"\x00")[:32]
    return b


def _status_of(res: Any) -> int:
    """Extract an HTTP status code from an httpx-like or dict-like response."""
    if hasattr(res, "status_code"):
        return int(res.status_code)
    if isinstance(res, dict) and "status" in res:
        return int(res["status"])
    raise EvaluateResponseError("response has no status_code/status")


def _json_of(res: Any) -> Any:
    """Decode a JSON body from an httpx-like (``.json()``) or dict-like response."""
    if hasattr(res, "json") and callable(res.json):
        return res.json()
    if isinstance(res, dict) and "body" in res:
        body = res["body"]
        return json.loads(body) if isinstance(body, (str, bytes)) else body
    raise EvaluateResponseError("response has no json()/body")


async def _default_http_post(
    url: str,
    *,
    method: str = "POST",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
) -> Any:
    """Default async HTTP POST for the no-money ``/quote`` declare (httpx-backed)."""
    import httpx  # local import — keeps httpx optional for pure-verification use

    async with httpx.AsyncClient() as client:
        return await client.request(
            method, url, headers=headers or {}, content=body
        )
