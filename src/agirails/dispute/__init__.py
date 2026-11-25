"""
AGIRAILS dispute module — evidence-bundle canonical serializer (PRD P2-3).

1:1 with the TypeScript SDK (`sdk-js/src/dispute/EvidenceBundle.ts`): same
public API names + arity, byte-identical canonical-bundle bytes + bundleHash.
"""

from agirails.dispute.bond_escalation import (
    BPS_DENOMINATOR,
    # Constants (AIP-14 §7.4)
    ESCALATION_INITIAL_BPS,
    ESCALATION_MULTIPLIER,
    MAX_ESCALATION_BOND,
    MIN_ESCALATION_BOND,
    # Client (PRD P2-4)
    BondEscalationClient,
)
from agirails.dispute.composite_mediator import (
    # Client (PRD P2-5)
    CompositeMediator,
    DecodedResolutionProof,
    # Types
    DisputeSplitRecorded,
    compute_split_rate,
    # Pure decoders / metrics (1:1 with TS standalone functions)
    decode_dispute_split_recorded,
    decode_resolution_proof,
)
from agirails.dispute.dispute_client import (
    DISPUTE_SUBSTATES,
    # Facade (PRD P2-9)
    DisputeClient,
    DisputeStatus,
    DisputeSubState,
    # §9 sub-state decode (1:1 with TS standalone function)
    decode_dispute_sub_state,
)
from agirails.dispute.evaluator_client import (
    BundleSource,
    EvaluateResponseError,
    EvaluationResult,
    # Client (PRD P2-6)
    EvaluatorClient,
    # Config / params / result dataclasses
    EvaluatorClientConfig,
    # Errors
    EvaluatorClientError,
    EvaluatorPaymentClient,
    ProposeDirectlyRecommendation,
    QuoteRejectedError,
    RequestEvaluationParams,
    RulingVerification,
    select_third_evaluator,
    # §4.7 verification (1:1 with TS standalone functions)
    verify_ruling_signatures,
)
from agirails.dispute.evidence_artifact_v2 import (
    EVIDENCE_ARTIFACT_V2_SCHEMA_VERSION,
    InvalidArtifactError,
    UnsupportedArtifactVersionError,
    assert_artifact_v2_version,
    compute_artifact_v2_hash,
    count_artifact_v2_tokens,
    serialize_artifact_v2,
    serialize_artifact_v2_to_string,
    validate_evidence_artifact_v2,
)
from agirails.dispute.evidence_bundle import (
    # Constants
    EVIDENCE_BUNDLE_SCHEMA_VERSION,
    MAX_BUNDLE_TOKENS,
    SUPPORTED_BUNDLE_MAJOR,
    BundleTokenizer,
    # Errors
    BundleTooLargeError,
    # Types
    EvidenceBundle,
    EvidenceBundleDelivery,
    EvidenceBundleDispute,
    EvidenceBundlePinner,
    EvidenceBundleReasoning,
    EvidenceBundleSpec,
    EvidenceBundleTimelineEvent,
    InvalidBundleError,
    PinEvidenceBundleResult,
    UnsupportedBundleVersionError,
    assert_supported_version,
    bundle_hash,
    compute_bundle_hash,
    count_bundle_tokens,
    enforce_token_cap,
    pin_evidence_bundle,
    serialize_bundle,
    serialize_bundle_to_string,
    set_bundle_tokenizer,
    # API
    validate_bundle,
)
from agirails.dispute.uma_helper import (
    SELF_DISPUTE_LOSS,
    SELF_DISPUTE_RECOVER,
    SELF_DISPUTE_TOTAL,
    # Constants (AIP-14b §8.6 economics)
    UMA_BOND,
    # Types
    SelfDisputeCost,
    # Helper (PRD P2-7)
    UMAHelper,
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
    # Schema-2.0.0 evidence artifact (AIP-14c D5/D6)
    "EVIDENCE_ARTIFACT_V2_SCHEMA_VERSION",
    "assert_artifact_v2_version",
    "validate_evidence_artifact_v2",
    "serialize_artifact_v2",
    "serialize_artifact_v2_to_string",
    "compute_artifact_v2_hash",
    "count_artifact_v2_tokens",
    "UnsupportedArtifactVersionError",
    "InvalidArtifactError",
]

from agirails.dispute.receipt_authorization import (
    ReceiptAuthorizationInput,
    ReceiptAuthorizer,
    authorize_payment_receipt,
    post_paid_evaluation,
    receipt_authorization_typed_data,
)
