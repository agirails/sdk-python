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

__all__ = [
    "DEFAULT_BASE_URL",
    "EIP712_DOMAIN_NAME",
    "EIP712_DOMAIN_VERSION",
    "ReceiptUploadFailure",
    "ReceiptUploadOptions",
    "ReceiptUploadPayload",
    "ReceiptUploadResult",
    "ReceiptUploadSuccess",
    "upload_receipt",
]
