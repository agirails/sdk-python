"""AGIRAILS receipts package — Web Receipts upload helper."""

from agirails.receipts.web_receipt import (
    DEFAULT_BASE_URL,
    EIP712_DOMAIN_NAME,
    EIP712_DOMAIN_VERSION,
    ReceiptUploadFailure,
    ReceiptUploadOptions,
    ReceiptUploadPayload,
    ReceiptUploadResult,
    ReceiptUploadSuccess,
    upload_receipt,
)
from agirails.receipts.push import (
    RECEIPT_WRITE_DOMAIN_V2,
    RECEIPT_WRITE_TYPES_V2,
    ZERO_BYTES32,
    FormatSettledLineArgs,
    Network,
    ParticipantRole,
    PushReceiptArgs,
    PushReceiptResult,
    ReceiptDataV3,
    ReceiptTimingV3,
    chain_id_for_network,
    format_settled_line,
    push_receipt_on_settled,
    render_receipt_v3,
)

__all__ = [
    # V1 web receipt
    "DEFAULT_BASE_URL",
    "EIP712_DOMAIN_NAME",
    "EIP712_DOMAIN_VERSION",
    "ReceiptUploadFailure",
    "ReceiptUploadOptions",
    "ReceiptUploadPayload",
    "ReceiptUploadResult",
    "ReceiptUploadSuccess",
    "upload_receipt",
    # V2 receipt push (AIP-7 §6 — ReceiptWriteV2)
    "push_receipt_on_settled",
    "format_settled_line",
    "PushReceiptArgs",
    "PushReceiptResult",
    "FormatSettledLineArgs",
    "RECEIPT_WRITE_DOMAIN_V2",
    "RECEIPT_WRITE_TYPES_V2",
    "ZERO_BYTES32",
    "chain_id_for_network",
    "ParticipantRole",
    "Network",
    "render_receipt_v3",
    "ReceiptDataV3",
    "ReceiptTimingV3",
]
