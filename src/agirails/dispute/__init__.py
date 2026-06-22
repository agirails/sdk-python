"""
AGIRAILS dispute module — evidence-bundle canonical serializer (PRD P2-3).

1:1 with the TypeScript SDK (`sdk-js/src/dispute/EvidenceBundle.ts`): same
public API names + arity, byte-identical canonical-bundle bytes + bundleHash.
"""

from agirails.dispute.bond_escalation import (
    # Constants (AIP-14 §7.4)
    ESCALATION_INITIAL_BPS,
    MIN_ESCALATION_BOND,
    MAX_ESCALATION_BOND,
    ESCALATION_MULTIPLIER,
    BPS_DENOMINATOR,
    # Client (PRD P2-4)
    BondEscalationClient,
)
from agirails.dispute.evidence_bundle import (
    # Constants
    EVIDENCE_BUNDLE_SCHEMA_VERSION,
    SUPPORTED_BUNDLE_MAJOR,
    MAX_BUNDLE_TOKENS,
    # Types
    EvidenceBundle,
    EvidenceBundleSpec,
    EvidenceBundleDelivery,
    EvidenceBundleDispute,
    EvidenceBundleTimelineEvent,
    EvidenceBundleReasoning,
    PinEvidenceBundleResult,
    EvidenceBundlePinner,
    BundleTokenizer,
    # Errors
    BundleTooLargeError,
    UnsupportedBundleVersionError,
    InvalidBundleError,
    # API
    validate_bundle,
    assert_supported_version,
    serialize_bundle,
    serialize_bundle_to_string,
    bundle_hash,
    compute_bundle_hash,
    count_bundle_tokens,
    enforce_token_cap,
    set_bundle_tokenizer,
    pin_evidence_bundle,
)
from agirails.dispute.composite_mediator import (
    # Types
    DisputeSplitRecorded,
    DecodedResolutionProof,
    # Pure decoders / metrics (1:1 with TS standalone functions)
    decode_dispute_split_recorded,
    decode_resolution_proof,
    compute_split_rate,
    # Client (PRD P2-5)
    CompositeMediator,
)
from agirails.dispute.uma_helper import (
    # Constants (AIP-14b §8.6 economics)
    UMA_BOND,
    SELF_DISPUTE_TOTAL,
    SELF_DISPUTE_RECOVER,
    SELF_DISPUTE_LOSS,
    # Types
    SelfDisputeCost,
    # Helper (PRD P2-7)
    UMAHelper,
)
from agirails.dispute.evaluator_client import (
    # Client (PRD P2-6)
    EvaluatorClient,
    # Config / params / result dataclasses
    EvaluatorClientConfig,
    EvaluatorPaymentClient,
    RequestEvaluationParams,
    EvaluationResult,
    RulingVerification,
    ProposeDirectlyRecommendation,
    BundleSource,
    # §4.7 verification (1:1 with TS standalone functions)
    verify_ruling_signatures,
    select_third_evaluator,
    # Errors
    EvaluatorClientError,
    QuoteRejectedError,
    EvaluateResponseError,
)
from agirails.dispute.dispute_client import (
    # Facade (PRD P2-9)
    DisputeClient,
    DisputeStatus,
    DisputeSubState,
    DISPUTE_SUBSTATES,
    # §9 sub-state decode (1:1 with TS standalone function)
    decode_dispute_sub_state,
)

__all__ = [
    # Dispute facade (PRD P2-9)
    "DisputeClient",
    "DisputeStatus",
    "DisputeSubState",
    "DISPUTE_SUBSTATES",
    "decode_dispute_sub_state",
    # Off-chain dispute evaluator client (PRD P2-6)
    "EvaluatorClient",
    "EvaluatorClientConfig",
    "EvaluatorPaymentClient",
    "RequestEvaluationParams",
    "EvaluationResult",
    "RulingVerification",
    "ProposeDirectlyRecommendation",
    "BundleSource",
    "verify_ruling_signatures",
    "select_third_evaluator",
    "EvaluatorClientError",
    "QuoteRejectedError",
    "EvaluateResponseError",
    # UMA self-dispute DVM helper (PRD P2-7)
    "UMA_BOND",
    "SELF_DISPUTE_TOTAL",
    "SELF_DISPUTE_RECOVER",
    "SELF_DISPUTE_LOSS",
    "SelfDisputeCost",
    "UMAHelper",
    # Composite mediator read/event client (PRD P2-5)
    "DisputeSplitRecorded",
    "DecodedResolutionProof",
    "decode_dispute_split_recorded",
    "decode_resolution_proof",
    "compute_split_rate",
    "CompositeMediator",
    # Bond escalation client (PRD P2-4)
    "ESCALATION_INITIAL_BPS",
    "MIN_ESCALATION_BOND",
    "MAX_ESCALATION_BOND",
    "ESCALATION_MULTIPLIER",
    "BPS_DENOMINATOR",
    "BondEscalationClient",
    "EVIDENCE_BUNDLE_SCHEMA_VERSION",
    "SUPPORTED_BUNDLE_MAJOR",
    "MAX_BUNDLE_TOKENS",
    "EvidenceBundle",
    "EvidenceBundleSpec",
    "EvidenceBundleDelivery",
    "EvidenceBundleDispute",
    "EvidenceBundleTimelineEvent",
    "EvidenceBundleReasoning",
    "PinEvidenceBundleResult",
    "EvidenceBundlePinner",
    "BundleTokenizer",
    "BundleTooLargeError",
    "UnsupportedBundleVersionError",
    "InvalidBundleError",
    "validate_bundle",
    "assert_supported_version",
    "serialize_bundle",
    "serialize_bundle_to_string",
    "bundle_hash",
    "compute_bundle_hash",
    "count_bundle_tokens",
    "enforce_token_cap",
    "set_bundle_tokenizer",
    "pin_evidence_bundle",
]
