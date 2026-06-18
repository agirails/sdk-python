"""
AIP-16 Delivery Surface (Python port).

Byte-exact parity with the TS delivery layer (sdk-js/src/delivery/) for the
``x25519-aes256gcm-v1`` and ``public-v1`` schemes: X25519 ECDH + HKDF-SHA256
session keys, AES-256-GCM AEAD, EIP-712 DeliverySetup/DeliveryEnvelope
signing/recovery, envelope assembly, validation, and the Mock/Relay channels.
"""

from __future__ import annotations

from agirails.delivery.keys import (
    DELIVERY_HKDF_INFO_V1,
    DELIVERY_SESSION_KEY_LENGTH,
    DeliveryCryptoError,
    EphemeralKeyPair,
    derive_session_key,
    derive_shared_secret,
    generate_ephemeral_key_pair,
    public_key_from_private,
    pubkey_from_hex,
    pubkey_to_hex,
)
from agirails.delivery.crypto import (
    AES_GCM_NONCE_LENGTH,
    AES_GCM_TAG_LENGTH,
    EncryptResult,
    body_hash,
    bytes_from_hex,
    bytes_to_hex,
    decrypt_body,
    encrypt_body,
    seal_with_nonce,
)
from agirails.delivery.eip712 import (
    DELIVERY_DOMAIN_NAME,
    DELIVERY_DOMAIN_VERSION,
    DELIVERY_ENVELOPE_TYPES_V1,
    DELIVERY_SETUP_TYPES_V1,
    DeliveryEip712Error,
    build_delivery_domain,
    chain_id_for_network,
    recover_envelope_signer,
    recover_setup_signer,
    sign_envelope,
    sign_setup,
)

# ---------------------------------------------------------------------------
# Upper-layer modules (AIP-16 port — types, nonce keys, validation, builders,
# channels). Mirrors sdk-js/src/delivery/index.ts.
# ---------------------------------------------------------------------------
from agirails.delivery.types import (
    CANONICAL_EMPTY_BYTES12,
    CANONICAL_EMPTY_BYTES16,
    CANONICAL_EMPTY_BYTES32,
    DELIVERY_ERROR_CODES,
    SCHEME_ENCRYPTED_V1,
    SCHEME_PUBLIC_V1,
    BuildEnvelopeResult,
    BuildSetupResult,
    DeliveryEnvelopeSignedV1,
    DeliveryEnvelopeWireV1,
    DeliveryError,
    DeliveryErrorCode,
    DeliveryMode,
    DeliveryNetwork,
    DeliveryPrivacy,
    DeliveryScheme,
    DeliveryServerMeta,
    DeliverySetupSignedV1,
    DeliverySetupWireV1,
    ParticipantRole,
)
from agirails.delivery.nonce_keys import (
    DELIVERY_NONCE_KEY_ENVELOPE,
    DELIVERY_NONCE_KEY_SETUP,
    DeliveryNonceKey,
)
from agirails.delivery.validate import (
    ValidationResult,
    is_canonical_empty_bytes12,
    is_canonical_empty_bytes16,
    is_canonical_empty_bytes32,
    is_valid_address,
    is_valid_bytes12,
    is_valid_bytes16,
    is_valid_bytes32,
    is_valid_privacy,
    is_valid_role,
    is_valid_scheme,
    is_valid_uint_string,
    validate_envelope_signed,
    validate_envelope_wire,
    validate_scheme_consistency,
    validate_setup_signed,
    validate_setup_wire,
)
from agirails.delivery.setup_builder import (
    DEFAULT_ACCEPTED_CHANNELS,
    DEFAULT_SETUP_EXPIRY_SEC,
    SETUP_TIMESTAMP_SKEW_SEC,
    BuildSetupParams,
    DeliverySetupBuilder,
    SetupVerifyResult,
)
from agirails.delivery.envelope_builder import (
    ENVELOPE_AAD_LENGTH,
    ENVELOPE_TIMESTAMP_SKEW_SEC,
    BuildEncryptedEnvelopeParams,
    BuildPublicEnvelopeParams,
    DeliveryEnvelopeBuilder,
    EnvelopeVerifyResult,
    VerifyAndDecryptResult,
    build_envelope_aad,
)
from agirails.delivery.channel import (
    DeliveryChannel,
    DeliverySubscription,
    EnvelopeCallback,
    SetupCallback,
)
from agirails.delivery.channel_log import LogFn, noop_log, noopLog
from agirails.delivery.mock_delivery_channel import (
    MockDeliveryChannel,
    MockDeliveryChannelOptions,
)
from agirails.delivery.relay_delivery_channel import (
    POLL_INTERVAL_MS,
    REQUEST_TIMEOUT_MS,
    RelayDeliveryChannel,
    RelayDeliveryChannelOptions,
)

__all__ = [
    # keys
    "DELIVERY_HKDF_INFO_V1",
    "DELIVERY_SESSION_KEY_LENGTH",
    "DeliveryCryptoError",
    "EphemeralKeyPair",
    "generate_ephemeral_key_pair",
    "public_key_from_private",
    "derive_shared_secret",
    "derive_session_key",
    "pubkey_to_hex",
    "pubkey_from_hex",
    # crypto
    "AES_GCM_NONCE_LENGTH",
    "AES_GCM_TAG_LENGTH",
    "EncryptResult",
    "encrypt_body",
    "decrypt_body",
    "seal_with_nonce",
    "body_hash",
    "bytes_to_hex",
    "bytes_from_hex",
    # eip712
    "DELIVERY_DOMAIN_NAME",
    "DELIVERY_DOMAIN_VERSION",
    "DELIVERY_SETUP_TYPES_V1",
    "DELIVERY_ENVELOPE_TYPES_V1",
    "DeliveryEip712Error",
    "chain_id_for_network",
    "build_delivery_domain",
    "sign_setup",
    "sign_envelope",
    "recover_setup_signer",
    "recover_envelope_signer",
    # types
    "DeliveryScheme",
    "DeliveryMode",
    "DeliveryPrivacy",
    "ParticipantRole",
    "DeliveryNetwork",
    "SCHEME_PUBLIC_V1",
    "SCHEME_ENCRYPTED_V1",
    "DeliveryServerMeta",
    "DeliverySetupSignedV1",
    "DeliverySetupWireV1",
    "DeliveryEnvelopeSignedV1",
    "DeliveryEnvelopeWireV1",
    "BuildSetupResult",
    "BuildEnvelopeResult",
    "DeliveryError",
    "DeliveryErrorCode",
    "DELIVERY_ERROR_CODES",
    "CANONICAL_EMPTY_BYTES32",
    "CANONICAL_EMPTY_BYTES12",
    "CANONICAL_EMPTY_BYTES16",
    # nonce keys
    "DELIVERY_NONCE_KEY_SETUP",
    "DELIVERY_NONCE_KEY_ENVELOPE",
    "DeliveryNonceKey",
    # validate
    "ValidationResult",
    "is_valid_bytes32",
    "is_valid_bytes12",
    "is_valid_bytes16",
    "is_valid_address",
    "is_valid_uint_string",
    "is_valid_scheme",
    "is_valid_privacy",
    "is_valid_role",
    "is_canonical_empty_bytes32",
    "is_canonical_empty_bytes12",
    "is_canonical_empty_bytes16",
    "validate_setup_signed",
    "validate_setup_wire",
    "validate_envelope_signed",
    "validate_envelope_wire",
    "validate_scheme_consistency",
    # setup builder
    "DeliverySetupBuilder",
    "BuildSetupParams",
    "SetupVerifyResult",
    "DEFAULT_SETUP_EXPIRY_SEC",
    "SETUP_TIMESTAMP_SKEW_SEC",
    "DEFAULT_ACCEPTED_CHANNELS",
    # envelope builder
    "DeliveryEnvelopeBuilder",
    "BuildPublicEnvelopeParams",
    "BuildEncryptedEnvelopeParams",
    "EnvelopeVerifyResult",
    "VerifyAndDecryptResult",
    "ENVELOPE_TIMESTAMP_SKEW_SEC",
    "ENVELOPE_AAD_LENGTH",
    "build_envelope_aad",
    # channel abstraction
    "DeliveryChannel",
    "DeliverySubscription",
    "SetupCallback",
    "EnvelopeCallback",
    # channel logger
    "LogFn",
    "noop_log",
    "noopLog",
    # channel implementations
    "MockDeliveryChannel",
    "MockDeliveryChannelOptions",
    "RelayDeliveryChannel",
    "RelayDeliveryChannelOptions",
    "POLL_INTERVAL_MS",
    "REQUEST_TIMEOUT_MS",
]
