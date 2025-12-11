"""Quote Builder - AIP-2 Price Quote Construction.

This module provides price quote building with:
- Amount validation (≥ originalAmount, ≤ maxPrice)
- EIP-712 signature
- Canonical JSON hashing
- Business rule enforcement

Reference:
- AIP-2 §6.1 (Quote Builder)
- Yellow Paper (Quote Message Schema)
- TypeScript SDK: QuoteBuilder.ts
"""

import json
import time
from typing import Any, Dict, Optional

from web3 import Web3

from .errors import ValidationError
from .message_signer import MessageSigner, AIP2_QUOTE_TYPES


# Platform minimum: $0.05 = 50000 base units (6 decimals for USDC)
PLATFORM_MINIMUM_AMOUNT = 50000

# Maximum quote expiry: 24 hours from quotedAt
MAX_QUOTE_EXPIRY_SECONDS = 86400

# Timestamp freshness tolerance: 5 minutes
TIMESTAMP_TOLERANCE_SECONDS = 300


def canonical_json_stringify(obj: Dict[str, Any]) -> str:
    """Canonicalize JSON object (sorted keys, no whitespace).

    Args:
        obj: Dictionary to canonicalize

    Returns:
        Canonical JSON string (sorted keys, compact)

    Example:
        >>> canonical_json_stringify({"b": 2, "a": 1})
        '{"a":1,"b":2}'

    Reference:
        - TypeScript SDK: canonicalJsonStringify()
    """
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))


class QuoteBuilder:
    """AIP-2 Quote Builder.

    Builds and validates price quotes with:
    - Amount validation (originalAmount ≤ quotedAmount ≤ maxPrice)
    - Platform minimum enforcement ($0.05)
    - EIP-712 signature
    - Canonical JSON hashing for on-chain storage

    Reference:
        - AIP-2 §6.1 (Quote Builder)
        - TypeScript SDK: QuoteBuilder.ts
    """

    def __init__(self, signer: MessageSigner):
        """Initialize quote builder.

        Args:
            signer: MessageSigner instance (must have domain initialized)
        """
        self.signer = signer
        self.nonce_counter: Dict[str, int] = {}  # Per-message-type nonce tracking

    def build(
        self,
        tx_id: str,
        provider: str,
        consumer: str,
        quoted_amount: str,
        original_amount: str,
        max_price: str,
        currency: str = "USDC",
        decimals: int = 6,
        expires_at: Optional[int] = None,
        justification: Optional[Dict[str, Any]] = None,
        chain_id: int = 84532,
        kernel_address: str = ""
    ) -> Dict[str, Any]:
        """Build and sign a quote message.

        Args:
            tx_id: Transaction ID (bytes32 hex string)
            provider: Provider DID (e.g., "did:ethr:0x...")
            consumer: Consumer DID
            quoted_amount: Quoted price (string, base units, e.g., "1000000" for $1.00 USDC)
            original_amount: Original offer from consumer (string, base units)
            max_price: Maximum acceptable price from consumer (string, base units)
            currency: Token symbol (default "USDC")
            decimals: Token decimals (default 6 for USDC)
            expires_at: Optional expiry timestamp (unix seconds, defaults to +1 hour)
            justification: Optional justification dict (reason, estimatedTime, etc.)
            chain_id: Chain ID (84532 for Base Sepolia, 8453 for Base Mainnet)
            kernel_address: ACTPKernel contract address (required for EIP-712 domain)

        Returns:
            Signed quote message dict:
            {
                "type": "agirails.quote.v1",
                "version": "1.0.0",
                "txId": "0x...",
                "provider": "did:ethr:0x...",
                "consumer": "did:ethr:0x...",
                "quotedAmount": "1000000",
                "originalAmount": "900000",
                "maxPrice": "1500000",
                "currency": "USDC",
                "decimals": 6,
                "quotedAt": 1234567890,
                "expiresAt": 1234571490,
                "justification": {...},
                "chainId": 84532,
                "nonce": 1,
                "signature": "0x..."
            }

        Raises:
            ValidationError: If parameters fail validation

        Example:
            >>> from agirails_sdk import QuoteBuilder, MessageSigner
            >>> signer = MessageSigner(private_key="0x...")
            >>> signer.init_domain(kernel_address="0x...")
            >>> builder = QuoteBuilder(signer)
            >>> quote = builder.build(
            ...     tx_id="0x123...",
            ...     provider="did:ethr:0xProvider...",
            ...     consumer="did:ethr:0xConsumer...",
            ...     quoted_amount="1000000",  # $1.00 USDC
            ...     original_amount="900000",  # $0.90 original offer
            ...     max_price="1500000",  # $1.50 max acceptable
            ...     chain_id=84532,
            ...     kernel_address="0xKernel..."
            ... )
            >>> print(quote["signature"])
            "0x..."

        Reference:
            - AIP-2 §4.1 (Provider workflow)
            - TypeScript SDK: QuoteBuilder.build()
        """
        # Validate parameters
        self._validate_params(
            tx_id=tx_id,
            provider=provider,
            consumer=consumer,
            quoted_amount=quoted_amount,
            original_amount=original_amount,
            max_price=max_price,
            chain_id=chain_id,
            kernel_address=kernel_address
        )

        # Calculate timestamps
        quoted_at = int(time.time())
        calculated_expires_at = expires_at or (quoted_at + 3600)  # Default 1 hour

        # Validate expiry
        if calculated_expires_at <= quoted_at:
            raise ValidationError("expiresAt must be after quotedAt")

        if calculated_expires_at > quoted_at + MAX_QUOTE_EXPIRY_SECONDS:
            raise ValidationError(f"expiresAt cannot exceed 24 hours from quotedAt")

        # Get next nonce
        nonce = self._get_next_nonce("agirails.quote.v1")

        # Compute justification hash
        justification_hash = self._compute_justification_hash(justification)

        # Build EIP-712 message (for signing)
        eip712_message = {
            "txId": tx_id,
            "provider": provider,
            "consumer": consumer,
            "quotedAmount": quoted_amount,
            "originalAmount": original_amount,
            "maxPrice": max_price,
            "currency": currency,
            "decimals": decimals,
            "quotedAt": quoted_at,
            "expiresAt": calculated_expires_at,
            "justificationHash": justification_hash,
            "chainId": chain_id,
            "nonce": nonce
        }

        # Initialize signer domain if needed
        if not self.signer.domain:
            self.signer.init_domain(
                kernel_address=kernel_address,
                chain_id=chain_id,
                name="AGIRAILS",
                version="1"
            )

        # Sign with EIP-712
        signature = self.signer.sign_quote(eip712_message)

        # Build full quote message (includes justification object, not just hash)
        quote = {
            "type": "agirails.quote.v1",
            "version": "1.0.0",
            "txId": tx_id,
            "provider": provider,
            "consumer": consumer,
            "quotedAmount": quoted_amount,
            "originalAmount": original_amount,
            "maxPrice": max_price,
            "currency": currency,
            "decimals": decimals,
            "quotedAt": quoted_at,
            "expiresAt": calculated_expires_at,
            "chainId": chain_id,
            "nonce": nonce,
            "signature": signature
        }

        # Add optional justification
        if justification:
            quote["justification"] = justification

        # Record nonce usage
        self._record_nonce("agirails.quote.v1", nonce)

        return quote

    def verify(self, quote: Dict[str, Any], kernel_address: str) -> bool:
        """Verify quote signature and business rules.

        Validates:
        1. Schema (type, version, required fields)
        2. Signature (EIP-712 recovery)
        3. Business rules (amount bounds, platform minimum)
        4. Expiry (not expired)
        5. Timestamp freshness (within 5-minute tolerance)

        Args:
            quote: Quote message dict
            kernel_address: ACTPKernel contract address

        Returns:
            True if valid

        Raises:
            ValidationError: If validation fails

        Example:
            >>> builder = QuoteBuilder(signer)
            >>> is_valid = builder.verify(quote, kernel_address="0x...")

        Reference:
            - AIP-2 §5.2, §5.3 (Verification)
            - TypeScript SDK: QuoteBuilder.verify()
        """
        # 1. Validate schema
        self._validate_quote_schema(quote)

        # 2. Verify signature
        recovered_address = self._recover_quote_signer(quote, kernel_address)
        expected_address = MessageSigner.did_to_address(quote["provider"])

        if recovered_address.lower() != expected_address.lower():
            raise ValidationError("Invalid signature: recovered address does not match provider")

        # 3. Validate business rules
        quoted_amount = int(quote["quotedAmount"])
        original_amount = int(quote["originalAmount"])
        max_price = int(quote["maxPrice"])

        if quoted_amount < original_amount:
            raise ValidationError("Quoted amount below original amount")

        if quoted_amount > max_price:
            raise ValidationError("Quoted amount exceeds maxPrice")

        # Platform minimum: $0.05 = 50000 base units (6 decimals)
        if quoted_amount < PLATFORM_MINIMUM_AMOUNT:
            raise ValidationError("Quoted amount below platform minimum ($0.05)")

        # 4. Check expiry
        now = int(time.time())
        if quote["expiresAt"] < now:
            raise ValidationError("Quote expired")

        # 5. Timestamp freshness check (within 5 minutes tolerance)
        if abs(now - quote["quotedAt"]) > TIMESTAMP_TOLERANCE_SECONDS:
            raise ValidationError("Quote timestamp outside 5-minute tolerance")

        return True

    def compute_hash(self, quote: Dict[str, Any]) -> str:
        """Compute quote hash (canonical JSON + keccak256).

        Used for on-chain storage in transaction metadata.

        Args:
            quote: Quote message dict

        Returns:
            Keccak256 hash (0x-prefixed hex string)

        Example:
            >>> builder = QuoteBuilder(signer)
            >>> quote_hash = builder.compute_hash(quote)
            >>> print(quote_hash)
            "0xabc..."

        Reference:
            - AIP-2 §4.1 (Step 6 - On-chain hash storage)
            - TypeScript SDK: QuoteBuilder.computeHash()
        """
        # Remove signature field for hashing
        quote_without_sig = {k: v for k, v in quote.items() if k != "signature"}

        # Canonicalize and hash
        canonical_json = canonical_json_stringify(quote_without_sig)
        return Web3.keccak(text=canonical_json).hex()

    # ------------------------------------------------------------------
    # Private Helper Methods
    # ------------------------------------------------------------------

    def _validate_params(
        self,
        tx_id: str,
        provider: str,
        consumer: str,
        quoted_amount: str,
        original_amount: str,
        max_price: str,
        chain_id: int,
        kernel_address: str
    ) -> None:
        """Validate quote parameters.

        Reference: AIP-2 §5.1, §5.2 (Validation Rules)
        """
        # Amount validation
        try:
            quoted_amt = int(quoted_amount)
            original_amt = int(original_amount)
            max_amt = int(max_price)
        except ValueError:
            raise ValidationError("Amounts must be numeric strings")

        if quoted_amt < original_amt:
            raise ValidationError("quotedAmount must be >= originalAmount")

        if quoted_amt > max_amt:
            raise ValidationError("quotedAmount must be <= maxPrice")

        # Platform minimum: $0.05 = 50000 base units (6 decimals)
        if quoted_amt < PLATFORM_MINIMUM_AMOUNT:
            raise ValidationError("quotedAmount must be >= $0.05 (50000 base units)")

        # DID format validation
        if not provider.startswith("did:ethr:"):
            raise ValidationError("provider must be valid did:ethr format")
        if not consumer.startswith("did:ethr:"):
            raise ValidationError("consumer must be valid did:ethr format")

        # Transaction ID format (bytes32 hex)
        if not (tx_id.startswith("0x") and len(tx_id) == 66):
            raise ValidationError("txId must be valid bytes32 hex string (0x + 64 chars)")

        # Kernel address format
        if not Web3.is_address(kernel_address):
            raise ValidationError("kernelAddress must be valid Ethereum address")

        # ChainId validation
        if chain_id not in (84532, 8453):
            raise ValidationError("chainId must be 84532 (Base Sepolia) or 8453 (Base Mainnet)")

    def _validate_quote_schema(self, quote: Dict[str, Any]) -> None:
        """Validate quote message schema.

        Reference: AIP-2 §2.1, §5.1 (Schema Validation)
        """
        # Type validation
        if quote.get("type") != "agirails.quote.v1":
            raise ValidationError("Invalid message type")

        # Version format (semver)
        version = quote.get("version", "")
        if not (version and len(version.split(".")) == 3):
            raise ValidationError("Invalid version format (must be semver)")

        # Transaction ID format
        tx_id = quote.get("txId", "")
        if not (tx_id.startswith("0x") and len(tx_id) == 66):
            raise ValidationError("Invalid txId format")

        # DID formats
        if not quote.get("provider", "").startswith("did:ethr:"):
            raise ValidationError("Invalid provider DID format")
        if not quote.get("consumer", "").startswith("did:ethr:"):
            raise ValidationError("Invalid consumer DID format")

        # Amount formats (numeric strings)
        for field in ("quotedAmount", "originalAmount", "maxPrice"):
            value = quote.get(field, "")
            if not (isinstance(value, str) and value.isdigit()):
                raise ValidationError(f"Invalid {field} format (must be numeric string)")

        # Currency validation
        if quote.get("currency") != "USDC":
            raise ValidationError("Only USDC currency is supported")

        # Decimals validation
        if quote.get("decimals") != 6:
            raise ValidationError("USDC must use 6 decimals")

        # ChainId validation
        chain_id = quote.get("chainId")
        if chain_id not in (84532, 8453):
            raise ValidationError("Invalid chainId")

        # Signature format (0x + 130 hex chars = 65 bytes)
        signature = quote.get("signature", "")
        if not (signature.startswith("0x") and len(signature) == 132):
            raise ValidationError("Invalid signature format")

    def _recover_quote_signer(self, quote: Dict[str, Any], kernel_address: str) -> str:
        """Recover signer address from quote signature.

        Reference: AIP-2 §5.3 (Signature Verification)
        """
        # Compute justification hash
        justification = quote.get("justification")
        justification_hash = self._compute_justification_hash(justification)

        # Build EIP-712 message (same as signing)
        message = {
            "txId": quote["txId"],
            "provider": quote["provider"],
            "consumer": quote["consumer"],
            "quotedAmount": quote["quotedAmount"],
            "originalAmount": quote["originalAmount"],
            "maxPrice": quote["maxPrice"],
            "currency": quote["currency"],
            "decimals": quote["decimals"],
            "quotedAt": quote["quotedAt"],
            "expiresAt": quote["expiresAt"],
            "justificationHash": justification_hash,
            "chainId": quote["chainId"],
            "nonce": quote["nonce"]
        }

        # Initialize temporary domain for verification
        temp_signer = MessageSigner(private_key="0x" + "00" * 32)  # Dummy key for verification
        temp_signer.init_domain(
            kernel_address=kernel_address,
            chain_id=quote["chainId"],
            name="AGIRAILS",
            version="1"
        )

        # Verify and recover address
        from eth_account.messages import encode_typed_data

        # Build full typed data
        typed_data = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                **AIP2_QUOTE_TYPES
            },
            "primaryType": "PriceQuote",
            "domain": temp_signer.domain,
            "message": message
        }

        try:
            signable_message = encode_typed_data(full_message=typed_data)
            from eth_account import Account
            recovered_address = Account.recover_message(signable_message, signature=quote["signature"])
            return recovered_address
        except Exception as e:
            raise ValidationError(f"Signature recovery failed: {e}")

    def _compute_justification_hash(self, justification: Optional[Dict[str, Any]]) -> str:
        """Compute justification hash for EIP-712 signature.

        Reference: AIP-2 §3.2 (Justification Hashing)
        """
        if not justification or len(justification) == 0:
            # Zero hash if omitted
            return "0x" + "00" * 32

        # Canonical JSON + keccak256
        canonical_json = canonical_json_stringify(justification)
        return Web3.keccak(text=canonical_json).hex()

    def _get_next_nonce(self, message_type: str) -> int:
        """Get next nonce for message type (timestamp-based).

        Uses millisecond-precision timestamp to prevent replay attacks.
        This ensures nonces are always increasing and unique.

        Args:
            message_type: Message type (e.g., "agirails.quote.v1")

        Returns:
            Timestamp-based nonce (milliseconds since epoch)
        """
        # Use timestamp in milliseconds for replay protection
        return int(time.time() * 1000)

    def _record_nonce(self, message_type: str, nonce: int) -> None:
        """Record nonce usage.

        Args:
            message_type: Message type
            nonce: Nonce value to record
        """
        self.nonce_counter[message_type] = nonce
