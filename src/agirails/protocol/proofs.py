"""
Proof Generator for AGIRAILS SDK.

Provides cryptographic proof generation for ACTP protocol:
- Content hashing (SHA-256)
- Input/output proof generation
- Delivery proof creation
- Merkle tree proofs (for batch operations)

Example:
    >>> from agirails.protocol import ProofGenerator
    >>> generator = ProofGenerator()
    >>> input_hash = generator.hash_input({"query": "Hello"})
    >>> output_hash = generator.hash_output({"response": "Hi there"})
    >>> proof = generator.create_delivery_proof(tx_id, output_hash, attestation_uid)
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from agirails.types.message import DeliveryProof, create_input_hash, create_output_hash
from agirails.utils.canonical_json import canonical_json_dumps as canonical_json_serialize


# ============================================================================
# URL validation (SSRF prevention) — mirrors sdk-js ProofGenerator.ts:8-53
# ============================================================================


@dataclass
class URLValidationConfig:
    """URL validation configuration for SSRF prevention.

    PARITY: mirrors ``URLValidationConfig`` in
    ``sdk-js/src/protocol/ProofGenerator.ts:8-34``.

    Attributes:
        allowed_protocols: Allowed URL schemes (default: ``("https",)``).
            Set to ``("https", "http")`` to allow HTTP in development.
        allow_localhost: Allow localhost URLs (default: False).
        max_size: Maximum response size in bytes (default: 10MB).
        timeout: Request timeout in seconds (default: 30.0).
        blocked_hosts: Blocked hostnames (e.g., internal services).
    """

    allowed_protocols: Optional[Tuple[str, ...]] = None
    allow_localhost: Optional[bool] = None
    max_size: Optional[int] = None
    timeout: Optional[float] = None
    blocked_hosts: Optional[Tuple[str, ...]] = None


# DEFAULT_URL_CONFIG — ProofGenerator.ts:39-53. SECURE by default.
# Note: TS stores protocols with a trailing colon (``'https:'``) because it reads
# ``URL.protocol``. Python's ``urlparse().scheme`` has no colon, so we store the
# bare scheme. The blocklist + private-IP logic is otherwise identical.
_DEFAULT_ALLOWED_PROTOCOLS: Tuple[str, ...] = ("https",)
_DEFAULT_MAX_SIZE: int = 10 * 1024 * 1024  # 10MB
_DEFAULT_TIMEOUT: float = 30.0  # 30 seconds
_DEFAULT_BLOCKED_HOSTS: Tuple[str, ...] = (
    "metadata.google.internal",
    "169.254.169.254",  # AWS/GCP metadata
    "metadata.aws.internal",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
)
# Localhost-class hosts removed from the blocklist when allow_localhost=True
# (ProofGenerator.ts:76-80).
_LOCALHOST_HOSTS: frozenset = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "[::1]"})


@dataclass
class ContentProof:
    """
    Proof for content authenticity.

    Attributes:
        content_hash: SHA-256 hash of the content
        content_type: Type of content (input, output, metadata)
        timestamp: When the proof was generated
        size: Size of the original content in bytes
    """

    content_hash: str
    content_type: str
    timestamp: int = field(default_factory=lambda: int(time.time()))
    size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "contentHash": self.content_hash,
            "contentType": self.content_type,
            "timestamp": self.timestamp,
            "size": self.size,
        }


@dataclass
class MerkleProof:
    """
    Merkle tree proof for batch verification.

    Attributes:
        root: Merkle root hash
        proof: List of sibling hashes for verification
        leaf: The leaf hash being proven
        leaf_index: Position of the leaf in the tree
    """

    root: str
    proof: List[str]
    leaf: str
    leaf_index: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "root": self.root,
            "proof": self.proof,
            "leaf": self.leaf,
            "leafIndex": self.leaf_index,
        }

    def verify(self) -> bool:
        """
        Verify the Merkle proof.

        Returns:
            True if the proof is valid
        """
        return verify_merkle_proof(
            leaf=self.leaf,
            proof=self.proof,
            root=self.root,
            leaf_index=self.leaf_index,
        )


class ProofGenerator:
    """
    Generates cryptographic proofs for ACTP protocol.

    Provides methods to create content hashes and proofs
    for inputs, outputs, and deliveries.

    Example:
        >>> generator = ProofGenerator()
        >>> input_hash = generator.hash_input({"query": "Hello"})
        >>> output_hash = generator.hash_output({"response": "Hi"})
    """

    def __init__(
        self,
        hash_algorithm: str = "keccak256",
        url_config: Optional[URLValidationConfig] = None,
    ) -> None:
        """
        Initialize ProofGenerator.

        Args:
            hash_algorithm: Hash algorithm to use (default: keccak256).
            url_config: Optional URL validation config for ``hash_from_url()``
                (SSRF prevention). Mirrors the ``urlConfig`` constructor arg in
                ``sdk-js/src/protocol/ProofGenerator.ts:69``.

        PARITY: defaults to keccak256 to match the TS SDK's
        ``ProofGenerator.hashContent`` (``keccak256(utf8(content))``). ``hashlib``
        has no keccak256 — its ``sha3_256`` is NIST SHA-3, not Ethereum keccak —
        so keccak256 is routed through ``eth_hash`` in ``_hash``.
        """
        if hash_algorithm != "keccak256" and hash_algorithm not in hashlib.algorithms_available:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")
        self._algorithm = hash_algorithm

        # Resolve URL validation config — merge overrides over secure defaults
        # (ProofGenerator.ts:70-80).
        cfg = url_config or URLValidationConfig()
        allowed = (
            tuple(cfg.allowed_protocols)
            if cfg.allowed_protocols is not None
            else _DEFAULT_ALLOWED_PROTOCOLS
        )
        allow_localhost = bool(cfg.allow_localhost) if cfg.allow_localhost is not None else False
        max_size = cfg.max_size if cfg.max_size is not None else _DEFAULT_MAX_SIZE
        timeout = cfg.timeout if cfg.timeout is not None else _DEFAULT_TIMEOUT
        blocked = (
            tuple(cfg.blocked_hosts)
            if cfg.blocked_hosts is not None
            else _DEFAULT_BLOCKED_HOSTS
        )

        # If localhost is explicitly allowed, drop localhost-class hosts from the
        # blocklist (ProofGenerator.ts:76-80).
        if allow_localhost:
            blocked = tuple(h for h in blocked if h not in _LOCALHOST_HOSTS)

        self._url_allowed_protocols: Tuple[str, ...] = allowed
        self._url_allow_localhost: bool = allow_localhost
        self._url_max_size: int = max_size
        self._url_timeout: float = timeout
        self._url_blocked_hosts: Tuple[str, ...] = blocked

    def _hash(self, data: bytes) -> str:
        """Compute hash of bytes and return hex string."""
        if self._algorithm == "keccak256":
            from eth_hash.auto import keccak

            return "0x" + keccak(data).hex()
        hasher = hashlib.new(self._algorithm)
        hasher.update(data)
        return "0x" + hasher.hexdigest()

    def _serialize(self, data: Any) -> bytes:
        """Serialize data to canonical JSON bytes."""
        if isinstance(data, bytes):
            return data
        if isinstance(data, str):
            return data.encode("utf-8")
        # Use canonical JSON for objects
        return canonical_json_serialize(data).encode("utf-8")

    def hash_content(self, content: Any, content_type: str = "generic") -> ContentProof:
        """
        Hash arbitrary content.

        Args:
            content: Content to hash (string, bytes, or JSON-serializable)
            content_type: Type label for the content

        Returns:
            ContentProof with hash and metadata
        """
        data = self._serialize(content)
        content_hash = self._hash(data)

        return ContentProof(
            content_hash=content_hash,
            content_type=content_type,
            size=len(data),
        )

    def hash_input(self, input_data: Any) -> str:
        """
        Hash input data for a service request.

        Args:
            input_data: Input data (string, dict, or any JSON-serializable)

        Returns:
            Hex-encoded hash (bytes32)
        """
        return create_input_hash(input_data)

    def hash_output(self, output_data: Any) -> str:
        """
        Hash output data from a service response.

        Args:
            output_data: Output data (string, dict, or any JSON-serializable)

        Returns:
            Hex-encoded hash (bytes32)
        """
        return create_output_hash(output_data)

    def hash_file(self, file_path: str) -> ContentProof:
        """
        Hash a file's contents.

        Args:
            file_path: Path to the file

        Returns:
            ContentProof with file hash

        Raises:
            FileNotFoundError: If file doesn't exist
            IOError: If file cannot be read
        """
        with open(file_path, "rb") as f:
            data = f.read()

        content_hash = self._hash(data)

        return ContentProof(
            content_hash=content_hash,
            content_type="file",
            size=len(data),
        )

    def hash_chunks(self, chunks: List[bytes], chunk_size: int = 1024 * 1024) -> str:
        """
        Hash data in chunks (for large files/streams).

        Args:
            chunks: List of data chunks
            chunk_size: Expected chunk size (for validation)

        Returns:
            Hex-encoded hash
        """
        hasher = hashlib.new(self._algorithm)
        for chunk in chunks:
            hasher.update(chunk)
        return "0x" + hasher.hexdigest()

    def create_delivery_proof(
        self,
        transaction_id: str,
        output_hash: str,
        attestation_uid: str = "",
        provider: str = "",
        timestamp: Optional[int] = None,
    ) -> DeliveryProof:
        """
        Create a delivery proof for a completed transaction.

        Args:
            transaction_id: ACTP transaction ID
            output_hash: Hash of the delivered output
            attestation_uid: EAS attestation UID (optional)
            provider: Provider address (optional)
            timestamp: Proof timestamp (defaults to now)

        Returns:
            DeliveryProof ready for signing
        """
        return DeliveryProof(
            transaction_id=transaction_id,
            output_hash=output_hash,
            attestation_uid=attestation_uid,
            provider=provider,
            timestamp=timestamp or int(time.time()),
        )

    def create_merkle_tree(self, leaves: List[str]) -> Tuple[str, List[List[str]]]:
        """
        Create a Merkle tree from leaf hashes.

        Args:
            leaves: List of leaf hashes (hex strings)

        Returns:
            Tuple of (root_hash, tree_levels)
            where tree_levels[0] = leaves, tree_levels[-1] = [root]
        """
        if not leaves:
            return "0x" + "0" * 64, [[]]

        # Normalize leaves
        normalized = [
            leaf if leaf.startswith("0x") else "0x" + leaf for leaf in leaves
        ]

        # Pad to power of 2
        while len(normalized) & (len(normalized) - 1) != 0:
            normalized.append(normalized[-1])  # Duplicate last leaf

        levels: List[List[str]] = [normalized]

        # Build tree bottom-up
        current_level = normalized
        while len(current_level) > 1:
            next_level: List[str] = []
            for i in range(0, len(current_level), 2):
                left = bytes.fromhex(current_level[i].replace("0x", ""))
                right = bytes.fromhex(current_level[i + 1].replace("0x", ""))
                # Sort to make tree consistent regardless of order
                if left > right:
                    left, right = right, left
                # Merkle node pairing uses sha256 to stay consistent with
                # verify_merkle_proof(); independent of the content-hash
                # algorithm (which is keccak256 for cross-SDK parity).
                combined = "0x" + hashlib.sha256(left + right).hexdigest()
                next_level.append(combined)
            levels.append(next_level)
            current_level = next_level

        return current_level[0], levels

    def create_merkle_proof(
        self,
        leaves: List[str],
        leaf_index: int,
    ) -> MerkleProof:
        """
        Create a Merkle proof for a specific leaf.

        Args:
            leaves: All leaf hashes
            leaf_index: Index of the leaf to prove

        Returns:
            MerkleProof for the specified leaf

        Raises:
            IndexError: If leaf_index is out of range
        """
        if leaf_index < 0 or leaf_index >= len(leaves):
            raise IndexError(f"Leaf index {leaf_index} out of range [0, {len(leaves)})")

        root, levels = self.create_merkle_tree(leaves)

        # Collect proof siblings
        proof: List[str] = []
        idx = leaf_index

        for level in levels[:-1]:  # Skip root level
            # Determine sibling index
            sibling_idx = idx ^ 1  # XOR with 1 to get sibling
            if sibling_idx < len(level):
                proof.append(level[sibling_idx])
            idx //= 2

        return MerkleProof(
            root=root,
            proof=proof,
            leaf=leaves[leaf_index],
            leaf_index=leaf_index,
        )

    # ------------------------------------------------------------------
    # AIP-4 delivery proof + on-chain encoding (1:1 with TS ProofGenerator)
    # ------------------------------------------------------------------

    def generate_delivery_proof(
        self,
        tx_id: str,
        deliverable: Union[str, bytes],
        delivery_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate an AIP-4 delivery proof.

        PARITY: mirrors ``ProofGenerator.generateDeliveryProof`` in
        ``sdk-js/src/protocol/ProofGenerator.ts:98-128``. Returns the same
        ``delivery.proof`` shape (``type``, ``txId``, ``contentHash``,
        ``timestamp``, ``deliveryUrl``, ``metadata{size, mimeType, ...}``).

        Computed fields (``size``, ``mimeType``) cannot be overwritten by the
        caller's ``metadata`` — they are spread first, then enforced
        (ProofGenerator.ts:112-127), preventing size/mimeType spoofing.

        Args:
            tx_id: ACTP transaction ID (bytes32 hex).
            deliverable: Delivered content (str or bytes).
            delivery_url: Optional IPFS/Arweave link.
            metadata: Optional user metadata (``size``/``mimeType`` are ignored).

        Returns:
            Delivery proof dict matching the TS ``DeliveryProof`` interface.
        """
        meta = dict(metadata or {})

        content_hash = self._hash_content_keccak(deliverable)
        if isinstance(deliverable, str):
            size = len(deliverable.encode("utf-8"))
        else:
            size = len(deliverable)

        # TS uses Date.now() (ms). Mirror that for cross-SDK consistency.
        timestamp = int(time.time() * 1000)

        # Spread user metadata first, then enforce computed fields
        # (ProofGenerator.ts:114-127). ``size``/``mimeType`` from the caller are
        # dropped before the enforced values are applied.
        mime_type = meta.get("mimeType") or "application/octet-stream"
        user_metadata = {k: v for k, v in meta.items() if k not in ("size", "mimeType")}

        out_metadata: Dict[str, Any] = dict(user_metadata)
        out_metadata["size"] = size
        out_metadata["mimeType"] = mime_type

        return {
            "type": "delivery.proof",  # Required per AIP-4
            "txId": tx_id,
            "contentHash": content_hash,
            "timestamp": timestamp,
            "deliveryUrl": delivery_url,
            "metadata": out_metadata,
        }

    def encode_proof(self, proof: Union[Dict[str, Any], "DeliveryProof"]) -> bytes:
        """
        ABI-encode a delivery proof for on-chain submission.

        PARITY: mirrors ``ProofGenerator.encodeProof`` in
        ``sdk-js/src/protocol/ProofGenerator.ts:140-146`` —
        ``abiCoder.encode(['bytes32','bytes32','uint256'], [txId, contentHash,
        timestamp])``. Returns the raw ABI bytes (TS returns a ``BytesLike``).

        Accepts either the dict produced by :meth:`generate_delivery_proof`
        (``txId``/``contentHash``/``timestamp`` keys) or a legacy
        ``DeliveryProof`` dataclass (``transaction_id``/``output_hash``).
        """
        from eth_abi import encode

        tx_id, content_hash, timestamp = self._extract_proof_fields(proof)
        return encode(
            ["bytes32", "bytes32", "uint256"],
            [
                self._to_bytes32(tx_id),
                self._to_bytes32(content_hash),
                int(timestamp),
            ],
        )

    def decode_proof(self, proof_data: Union[bytes, str]) -> Dict[str, Any]:
        """
        Decode a delivery proof from on-chain ABI data.

        PARITY: mirrors ``ProofGenerator.decodeProof`` in
        ``sdk-js/src/protocol/ProofGenerator.ts:151-167``. Returns a dict with
        ``txId`` (0x-prefixed bytes32), ``contentHash`` (0x-prefixed bytes32),
        and ``timestamp`` (int).

        Args:
            proof_data: ABI bytes (or 0x-prefixed hex string).
        """
        from eth_abi import decode

        if isinstance(proof_data, str):
            proof_data = bytes.fromhex(proof_data[2:] if proof_data.startswith("0x") else proof_data)

        tx_id, content_hash, timestamp = decode(
            ["bytes32", "bytes32", "uint256"], proof_data
        )

        return {
            "txId": "0x" + tx_id.hex(),
            "contentHash": "0x" + content_hash.hex(),
            "timestamp": int(timestamp),
        }

    def verify_deliverable(
        self, deliverable: Union[str, bytes], expected_hash: str
    ) -> bool:
        """
        Verify a deliverable matches an expected keccak256 content hash.

        PARITY: mirrors ``ProofGenerator.verifyDeliverable`` in
        ``sdk-js/src/protocol/ProofGenerator.ts:172-175`` — keccak256 of the
        deliverable compared case-insensitively against ``expected_hash``.

        Note: distinct from :meth:`verify_delivery`, which compares an
        ``output_hash`` on a legacy ``DeliveryProof`` using canonical-JSON
        hashing. ``verify_deliverable`` hashes raw bytes/UTF-8 content directly.
        """
        actual_hash = self._hash_content_keccak(deliverable)
        return actual_hash.lower() == expected_hash.lower()

    async def hash_from_url(self, url: str) -> str:
        """
        Fetch content from a URL and return its keccak256 hash (IPFS/Arweave).

        PARITY: mirrors ``ProofGenerator.hashFromUrl`` in
        ``sdk-js/src/protocol/ProofGenerator.ts:190-265``:
        - URL is validated BEFORE fetching (SSRF prevention).
        - HTTPS-only by default; hostname blocklist + private-IP block.
        - Redirects are rejected (following them would bypass the blocklist).
        - Content-Length and streamed-size limits enforced.
        - Request timeout enforced.

        Args:
            url: URL to fetch content from.

        Returns:
            keccak256 hash (0x-prefixed) of the fetched content.

        Raises:
            ValueError: If the URL is blocked/invalid, response too large,
                redirected, or the fetch fails.
        """
        import httpx

        # Security: validate URL before fetching (ProofGenerator.ts:192).
        self._validate_url(url)

        try:
            # follow_redirects=False mirrors TS ``redirect: 'error'``: a 3xx is
            # treated as a failure rather than followed (SSRF risk).
            async with httpx.AsyncClient(
                timeout=self._url_timeout, follow_redirects=False
            ) as client:
                async with client.stream("GET", url) as response:
                    if response.is_redirect:
                        raise ValueError(
                            f"Redirect rejected for {url}: caller must provide the "
                            f"final URL (following redirects bypasses the SSRF blocklist)."
                        )

                    if response.status_code >= 400:
                        raise ValueError(
                            f"HTTP error: {response.status_code} {response.reason_phrase}"
                        )

                    # Security: check Content-Length header first (ts:214-223).
                    content_length = response.headers.get("content-length")
                    if content_length is not None:
                        try:
                            declared = int(content_length)
                        except ValueError:
                            declared = -1
                        if declared > self._url_max_size:
                            raise ValueError(
                                f"Content too large: {declared} bytes exceeds maximum "
                                f"of {self._url_max_size} bytes"
                            )

                    # Security: read with a streaming size limit (ts:225-251).
                    chunks: List[bytes] = []
                    total_size = 0
                    async for chunk in response.aiter_bytes():
                        total_size += len(chunk)
                        if total_size > self._url_max_size:
                            raise ValueError(
                                f"Content too large: {total_size}+ bytes exceeds "
                                f"maximum of {self._url_max_size} bytes"
                            )
                        chunks.append(chunk)

                    return self._hash_content_keccak(b"".join(chunks))
        except httpx.TimeoutException as exc:
            raise ValueError(
                f"Request timed out after {self._url_timeout}s for {url}"
            ) from exc
        except ValueError:
            raise
        except Exception as exc:  # pragma: no cover - network failure modes
            raise ValueError(f"Failed to fetch content from {url}: {exc}") from exc

    def get_url_config(self) -> URLValidationConfig:
        """
        Return the resolved URL validation config (for testing/inspection).

        PARITY: mirrors ``ProofGenerator.getUrlConfig`` in
        ``sdk-js/src/protocol/ProofGenerator.ts:337-339``.
        """
        return URLValidationConfig(
            allowed_protocols=self._url_allowed_protocols,
            allow_localhost=self._url_allow_localhost,
            max_size=self._url_max_size,
            timeout=self._url_timeout,
            blocked_hosts=self._url_blocked_hosts,
        )

    # -- internal helpers for the AIP-4 / SSRF surface --------------------

    def _hash_content_keccak(self, content: Union[str, bytes]) -> str:
        """keccak256 of raw content (str→utf-8, bytes as-is).

        Mirrors TS ``hashContent`` (ProofGenerator.ts:86-90):
        ``keccak256(toUtf8Bytes(content))``. Independent of ``self._algorithm``
        so on-chain proofs always use Ethereum keccak256.
        """
        from eth_hash.auto import keccak

        data = content.encode("utf-8") if isinstance(content, str) else content
        return "0x" + keccak(data).hex()

    @staticmethod
    def _to_bytes32(value: Union[str, bytes]) -> bytes:
        """Coerce a 0x-prefixed hex string (or bytes) to 32 raw bytes."""
        if isinstance(value, bytes):
            raw = value
        else:
            raw = bytes.fromhex(value[2:] if value.startswith("0x") else value)
        if len(raw) != 32:
            raise ValueError(f"Expected bytes32, got {len(raw)} bytes")
        return raw

    @staticmethod
    def _extract_proof_fields(
        proof: Union[Dict[str, Any], "DeliveryProof"],
    ) -> Tuple[str, str, int]:
        """Pull (txId, contentHash, timestamp) from a dict or legacy dataclass."""
        if isinstance(proof, dict):
            return proof["txId"], proof["contentHash"], int(proof["timestamp"])
        # Legacy DeliveryProof dataclass (transaction_id / output_hash).
        return (
            proof.transaction_id,
            proof.output_hash,
            int(proof.timestamp),
        )

    def _validate_url(self, url: str) -> None:
        """Validate a URL against the SSRF rules.

        PARITY: mirrors ``ProofGenerator.validateUrl``
        (ProofGenerator.ts:273-306).
        """
        parsed = urlparse(url)
        # urlparse never raises for a malformed string; an absent scheme/netloc
        # is the closest analogue to ``new URL()`` throwing.
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid URL: {url}")

        # Check protocol (TS compares ``URL.protocol`` incl. colon; we compare
        # the bare scheme stored without a colon).
        if parsed.scheme.lower() not in self._url_allowed_protocols:
            raise ValueError(
                f'URL protocol "{parsed.scheme}:" not allowed. '
                f"Allowed protocols: {', '.join(p + ':' for p in self._url_allowed_protocols)}"
            )

        hostname = (parsed.hostname or "").lower()
        # urlparse strips the brackets from IPv6 hosts; re-add them so the
        # ``[::1]`` blocklist entry matches.
        host_for_block = f"[{hostname}]" if ":" in hostname else hostname

        if hostname in self._url_blocked_hosts or host_for_block in self._url_blocked_hosts:
            raise ValueError(
                f'URL hostname "{hostname}" is blocked for security reasons. '
                f"This prevents SSRF attacks to internal services."
            )

        if self._is_private_ip(hostname):
            raise ValueError(
                f'URL hostname "{hostname}" resolves to a private IP address. '
                f"This is blocked for security reasons (SSRF prevention)."
            )

    @staticmethod
    def _is_private_ip(hostname: str) -> bool:
        """Check whether a hostname is a literal private/loopback IPv4 address.

        PARITY: mirrors ``ProofGenerator.isPrivateIP``
        (ProofGenerator.ts:314-332). Pure-string range checks (no DNS).
        """
        ipv4_private_ranges = (
            r"^10\.",  # 10.0.0.0 - 10.255.255.255
            r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",  # 172.16.0.0 - 172.31.255.255
            r"^192\.168\.",  # 192.168.0.0 - 192.168.255.255
            r"^127\.",  # 127.0.0.0 - 127.255.255.255 (loopback)
            r"^169\.254\.",  # 169.254.0.0 - 169.254.255.255 (link-local)
            r"^0\.",  # 0.0.0.0/8
        )
        return any(re.match(rng, hostname) for rng in ipv4_private_ranges)

    def verify_delivery(
        self,
        expected_output: Any,
        proof: DeliveryProof,
    ) -> bool:
        """
        Verify a delivery matches the expected output.

        Args:
            expected_output: Expected output data
            proof: Delivery proof to verify

        Returns:
            True if output hash matches
        """
        computed_hash = self.hash_output(expected_output)
        return computed_hash.lower() == proof.output_hash.lower()


def verify_merkle_proof(
    leaf: str,
    proof: List[str],
    root: str,
    leaf_index: int,
) -> bool:
    """
    Verify a Merkle proof.

    Security Note (M-5): Uses consistent hash ordering with create_merkle_tree().
    Both functions sort hashes with smaller value first to ensure deterministic
    Merkle root computation regardless of leaf position.

    Args:
        leaf: Leaf hash being proven
        proof: Sibling hashes from leaf to root
        root: Expected Merkle root
        leaf_index: Position of leaf in original tree (used for sibling pairing)

    Returns:
        True if proof is valid
    """
    if not proof:
        return leaf.lower() == root.lower()

    current = bytes.fromhex(leaf.replace("0x", ""))
    idx = leaf_index

    for sibling in proof:
        sibling_bytes = bytes.fromhex(sibling.replace("0x", ""))

        # Security Note (M-5): Always sort hashes - smaller first
        # This matches the create_merkle_tree() logic for consistent roots
        if current > sibling_bytes:
            left, right = sibling_bytes, current
        else:
            left, right = current, sibling_bytes

        hasher = hashlib.sha256()
        hasher.update(left + right)
        current = hasher.digest()
        idx //= 2

    computed_root = "0x" + current.hex()
    return computed_root.lower() == root.lower()


def hash_service_input(
    service: str,
    input_data: Any,
    requester: str = "",
) -> str:
    """
    Create a deterministic hash for a service input.

    This combines service name, input data, and requester
    for unique request identification.

    PARITY: py-only utility — NO TypeScript twin. The TS SDK has no
    ``hashServiceInput``; its only service hash is ``hashServiceMetadata``
    (keccak256), which Python mirrors in ``utils.helpers.ServiceHash.hash`` /
    ``hash_service_metadata``. This helper produces a *local* (sha256)
    identifier over ``{service, input, requester?}`` and is intentionally NOT a
    cross-SDK routing key, so the sha256 here is safe and is kept for backward
    compatibility. Use ``ServiceHash.hash`` for the on-chain serviceHash.

    Args:
        service: Service name
        input_data: Input data
        requester: Requester address (optional)

    Returns:
        Hex-encoded hash (bytes32)
    """
    combined = {
        "service": service,
        "input": input_data,
    }
    if requester:
        combined["requester"] = requester.lower()

    encoded = canonical_json_serialize(combined)
    hash_bytes = hashlib.sha256(encoded.encode("utf-8")).digest()
    return "0x" + hash_bytes.hex()


def hash_service_output(
    transaction_id: str,
    output_data: Any,
    provider: str = "",
) -> str:
    """
    Create a deterministic hash for a service output.

    This combines transaction ID, output data, and provider
    for unique delivery identification.

    PARITY: py-only utility — NO TypeScript twin (see ``hash_service_input``).
    Produces a *local* (sha256) identifier over ``{transactionId, output,
    provider?}``; not a cross-SDK routing key. For the on-chain delivery hash
    use ``ProofGenerator.hash_output`` (keccak256, mirrors TS).

    Args:
        transaction_id: ACTP transaction ID
        output_data: Output data
        provider: Provider address (optional)

    Returns:
        Hex-encoded hash (bytes32)
    """
    combined = {
        "transactionId": transaction_id,
        "output": output_data,
    }
    if provider:
        combined["provider"] = provider.lower()

    encoded = canonical_json_serialize(combined)
    hash_bytes = hashlib.sha256(encoded.encode("utf-8")).digest()
    return "0x" + hash_bytes.hex()


__all__ = [
    "ProofGenerator",
    "ContentProof",
    "MerkleProof",
    "URLValidationConfig",
    "verify_merkle_proof",
    "hash_service_input",
    "hash_service_output",
]
