"""
Arweave Client - Permanent Storage (AIP-7 §4 Tier 2)

Permanent storage client using Arweave via Irys HTTP API.
Provides immutable, verifiable archival of completed transactions.

CRITICAL: Arweave-first write order!
Always write to Arweave FIRST, then anchor TX ID on-chain.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
from eth_account import Account

from agirails.errors.storage import (
    ArweaveDownloadError,
    ArweaveError,
    ArweaveUploadError,
    CircuitBreakerOpenError,
    FileSizeLimitError,
    InsufficientFundsError,
    SSRFProtectionError,
)
from agirails.storage.types import (
    ARCHIVE_BUNDLE_TYPE,
    DEFAULT_ARWEAVE_MAX_DOWNLOAD_SIZE,
    ArchiveBundle,
    ArweaveConfig,
    ArweaveUploadResult,
    CircuitBreakerConfig,
    DownloadResult,
    is_valid_arweave_tx_id,
)
from agirails.utils.circuit_breaker import CircuitBreaker
from agirails.utils.retry import RetryConfig, retry_async
from agirails.utils.validation import (
    is_gateway_allowed,
    sanitize_for_logging,
)


# Irys node URLs
IRYS_NODES = {
    "mainnet": "https://node1.irys.xyz",
    "devnet": "https://devnet.irys.xyz",
}

# Arweave gateways for retrieval
ARWEAVE_GATEWAYS = [
    "https://arweave.net",
    "https://gateway.irys.xyz",
]


class ArweaveClient:
    """
    Permanent storage client using Arweave via Irys.

    CRITICAL: Arweave-first write order!
    Always write to Arweave FIRST, then anchor TX ID on-chain.

    Features:
    - Upload to Arweave via Irys HTTP API
    - Query Irys node for balance and pricing
    - Circuit breaker for gateway health
    - Tag-based indexing for GraphQL queries

    Example:
        ```python
        from agirails.storage import ArweaveClient, ArweaveConfig

        client = await ArweaveClient.create(ArweaveConfig(
            private_key=os.environ["ARCHIVE_KEY"],
            rpc_url=os.environ["BASE_RPC"],
        ))

        # Check balance
        balance = await client.get_balance()
        print(f"Irys balance: {balance} wei")

        # Upload archive bundle
        result = await client.upload_bundle(bundle)
        print(f"Archived at: {result.tx_id}")
        ```
    """

    def __init__(self, config: ArweaveConfig) -> None:
        """
        Initialize Arweave client.

        Note: Use `ArweaveClient.create()` for async initialization.

        Args:
            config: Arweave configuration
        """
        self._config = config
        self._account = Account.from_key(config.private_key)
        self._node_url = IRYS_NODES[config.network]
        # P1-1 (DoS): max download size, mirrors TS DEFAULT_MAX_DOWNLOAD_SIZE (10MB).
        self._max_download_size = DEFAULT_ARWEAVE_MAX_DOWNLOAD_SIZE
        self._circuit_breaker = CircuitBreaker(
            config.circuit_breaker or CircuitBreakerConfig()
        )
        self._retry_config = RetryConfig(
            max_attempts=3,
            base_delay_ms=2000,
            retryable_errors=(ArweaveError, httpx.TransportError),
        )

    @classmethod
    async def create(cls, config: ArweaveConfig) -> ArweaveClient:
        """
        Factory method for creating ArweaveClient with async initialization.

        Args:
            config: Arweave configuration

        Returns:
            Initialized ArweaveClient

        Example:
            ```python
            client = await ArweaveClient.create(ArweaveConfig(
                private_key=os.environ["ARCHIVE_KEY"],
                rpc_url=os.environ["BASE_RPC"],
            ))
            ```
        """
        client = cls(config)
        # Verify connection by checking balance (will throw on error)
        await client.get_balance()
        return client

    @property
    def address(self) -> str:
        """Get the wallet address."""
        return self._account.address

    @property
    def node_url(self) -> str:
        """Get the Irys node URL."""
        return self._node_url

    @property
    def circuit_breaker_state(self) -> str:
        """Get current circuit breaker state."""
        return self._circuit_breaker.state.value

    async def get_balance(self) -> int:
        """
        Get current Irys balance in atomic units.

        Returns:
            Balance in wei (for ETH currencies)
        """
        async def do_get_balance() -> int:
            url = f"{self._node_url}/account/balance/{self._config.currency}"
            headers = {"x-address": self.address}

            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self._config.timeout / 1000)
            ) as client:
                response = await client.get(url, headers=headers)

                if response.status_code == 404:
                    # No balance found = 0
                    return 0

                if response.status_code != 200:
                    raise ArweaveError(
                        f"Failed to get balance: HTTP {response.status_code}",
                        node_url=self._node_url,
                    )

                data = response.json()
                return int(data.get("balance", 0))

        return await retry_async(do_get_balance, self._retry_config)

    async def get_upload_price(self, size_bytes: int) -> int:
        """
        Get upload price for given size.

        Args:
            size_bytes: Size of content to upload

        Returns:
            Price in atomic units (wei)
        """
        url = f"{self._node_url}/price/{self._config.currency}/{size_bytes}"

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self._config.timeout / 1000)
        ) as client:
            response = await client.get(url)

            if response.status_code != 200:
                raise ArweaveError(
                    f"Failed to get price: HTTP {response.status_code}",
                    node_url=self._node_url,
                )

            # Response is just the price as a string
            return int(response.text)

    async def fund(self, amount: int) -> str:
        """
        Fund Irys node with tokens.

        Note: This requires blockchain transaction and is not yet implemented.
        Use external wallet or Irys CLI to fund your account.

        Args:
            amount: Amount in atomic units (wei)

        Returns:
            Funding transaction hash

        Raises:
            NotImplementedError: Funding requires Web3 integration
        """
        raise NotImplementedError(
            "Funding requires Web3 integration. "
            "Use Irys CLI or external wallet to fund your account: "
            "https://docs.irys.xyz/build/d/features/funding"
        )

    async def upload(
        self,
        content: bytes,
        tags: Optional[List[Tuple[str, str]]] = None,
    ) -> ArweaveUploadResult:
        """
        Upload content to Arweave via Irys.

        FAIL-CLOSED (parity divergence, AIP-7 §4.3):
        The TypeScript SDK uses the official ``@irys/sdk`` which signs a valid
        ANS-104 DataItem (deep-hash over the item headers + tags + data, then
        the currency signer's signature) and submits it to the Irys node. A
        previous Python implementation hand-rolled an HTTP POST with an EIP-191
        ``personal_sign`` over the SHA256 hex of the content — that is NOT a
        valid ANS-104 DataItem and the real Irys node REJECTS it. Rather than
        silently produce an invalid/unanchored transaction (which would corrupt
        the Arweave-first write-order invariant and the on-chain anchor), this
        method now fails closed with an actionable error.

        Reads (balance, price, download, GraphQL queries) remain fully
        functional. Only the write path is gated until a byte-exact ANS-104
        DataItem signer (or an ``irys``/``bundlr`` client) is available.

        Args:
            content: Raw bytes to upload
            tags: Optional list of (name, value) tags

        Returns:
            ArweaveUploadResult with transaction ID

        Raises:
            InsufficientFundsError: If balance too low
            NotImplementedError: ANS-104 DataItem signing is not yet implemented
        """
        # Check balance first so funding problems surface before the gate.
        price = await self.get_upload_price(len(content))
        balance = await self.get_balance()

        if balance < price:
            raise InsufficientFundsError(
                balance=balance,
                required=price,
                currency=self._config.currency,
            )

        # FAIL-CLOSED: do not produce an invalid (non-ANS-104) transaction.
        raise NotImplementedError(
            "Arweave upload requires a valid ANS-104 DataItem signature which is "
            "not yet implemented in the Python SDK. The Irys node rejects "
            "non-ANS-104 payloads, so uploading here would silently fail to "
            "anchor on Arweave. Use the TypeScript SDK (@irys/sdk) or the Irys "
            "CLI to upload archive bundles until native ANS-104 signing lands. "
            "See: https://docs.irys.xyz/build/d/sdk/upload"
        )

    async def upload_json(
        self,
        data: Dict[str, Any],
        tags: Optional[List[Tuple[str, str]]] = None,
    ) -> ArweaveUploadResult:
        """
        Upload JSON data to Arweave.

        Args:
            data: Dictionary to serialize
            tags: Optional additional tags

        Returns:
            ArweaveUploadResult
        """
        # Canonical JSON
        content = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()

        all_tags = [("Content-Type", "application/json")]
        if tags:
            all_tags.extend(tags)

        return await self.upload(content, all_tags)

    async def upload_bundle(
        self,
        bundle: ArchiveBundle,
    ) -> ArweaveUploadResult:
        """
        Upload archive bundle with proper AGIRAILS tags.

        This is the primary method for archiving completed transactions.

        Args:
            bundle: ArchiveBundle to upload

        Returns:
            ArweaveUploadResult with permanent Arweave TX ID
        """
        tags: List[Tuple[str, str]] = [
            ("Content-Type", "application/json"),
            ("Protocol", "AGIRAILS"),
            ("Version", bundle.protocol_version),
            ("Schema", bundle.archive_schema_version),
            ("Type", ARCHIVE_BUNDLE_TYPE),
            ("ChainId", str(bundle.chain_id)),
            ("TxId", bundle.tx_id),
        ]

        # Serialize bundle using Pydantic's JSON serialization
        content = bundle.model_dump_json(by_alias=True).encode()

        return await self.upload(content, tags)

    async def download(
        self,
        tx_id: str,
        gateway_url: Optional[str] = None,
    ) -> DownloadResult:
        """
        Download content from Arweave by transaction ID.

        Security (parity with TS ArweaveClient.downloadBundle/downloadJSON):
        - P1-3: validate the TX ID format (43-char base64url) before any fetch.
        - P0-1: enforce the Arweave gateway allowlist (SSRF protection) — a
          caller-supplied ``gateway_url`` must be a whitelisted gateway.
        - P1-1: enforce a 10MB download size limit (Content-Length pre-check
          and post-read enforcement) to prevent unbounded-download DoS.

        Args:
            tx_id: Arweave transaction ID (43-char base64url)
            gateway_url: Optional custom gateway (must be whitelisted)

        Returns:
            DownloadResult with data

        Raises:
            ArweaveDownloadError: If TX ID is malformed or download fails
            SSRFProtectionError: If gateway is not in the allowlist
            FileSizeLimitError: If content exceeds the download size limit
        """
        # P1-3: TX ID validation (matches TS validateArweaveTxId).
        if not is_valid_arweave_tx_id(tx_id):
            raise ArweaveDownloadError(
                f"Invalid Arweave TX ID format: {tx_id} "
                "(expected 43-character base64url string)",
                tx_id=tx_id,
            )

        # P0-1: gateway allowlist (SSRF protection).
        gateway = gateway_url or ARWEAVE_GATEWAYS[0]
        if not is_gateway_allowed(gateway):
            raise SSRFProtectionError(
                sanitize_for_logging(gateway),
                reason="Gateway not in whitelist",
            )

        url = f"{gateway.rstrip('/')}/{tx_id}"

        async def do_download() -> DownloadResult:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self._config.timeout / 1000),
                follow_redirects=True,
            ) as client:
                # Stream so we can enforce the size limit before buffering.
                async with client.stream("GET", url) as response:
                    if response.status_code == 404:
                        raise ArweaveDownloadError(
                            f"Transaction not found: {tx_id}",
                            tx_id=tx_id,
                            gateway=gateway,
                        )

                    if response.status_code != 200:
                        raise ArweaveDownloadError(
                            f"Download failed: HTTP {response.status_code}",
                            tx_id=tx_id,
                            gateway=gateway,
                        )

                    # P1-1: Content-Length pre-check.
                    content_length = response.headers.get("Content-Length")
                    if content_length:
                        size = int(content_length)
                        if size > self._max_download_size:
                            raise FileSizeLimitError(
                                f"Content size {size} exceeds limit {self._max_download_size}",
                                file_size=size,
                                max_size=self._max_download_size,
                            )

                    # P1-1: enforce size limit during streaming.
                    chunks = []
                    total_size = 0
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        total_size += len(chunk)
                        if total_size > self._max_download_size:
                            raise FileSizeLimitError(
                                f"Content size exceeds limit {self._max_download_size}",
                                file_size=total_size,
                                max_size=self._max_download_size,
                            )
                        chunks.append(chunk)

                    data = b"".join(chunks)

                    return DownloadResult(
                        data=data,
                        size=len(data),
                        downloaded_at=datetime.now(timezone.utc),
                    )

        try:
            return await self._circuit_breaker.execute(
                lambda: retry_async(do_download, self._retry_config)
            )
        except CircuitBreakerOpenError:
            raise CircuitBreakerOpenError(
                "Arweave gateway circuit breaker is open",
                gateway=gateway,
            )

    async def download_bundle(
        self,
        tx_id: str,
    ) -> ArchiveBundle:
        """
        Download and parse archive bundle.

        Args:
            tx_id: Arweave transaction ID

        Returns:
            Parsed ArchiveBundle
        """
        result = await self.download(tx_id)
        data = json.loads(result.data.decode("utf-8"))
        return ArchiveBundle(**data)

    async def query_by_tags(
        self,
        tags: Dict[str, str],
        limit: int = 100,
    ) -> List[str]:
        """
        Query Arweave GraphQL for transactions by tags.

        Args:
            tags: Dictionary of tag name -> value
            limit: Maximum results

        Returns:
            List of transaction IDs
        """
        tag_filters = [
            {"name": name, "values": [value]}
            for name, value in tags.items()
        ]

        query = """
        query($tags: [TagFilter!]!, $limit: Int!) {
            transactions(tags: $tags, first: $limit) {
                edges {
                    node {
                        id
                    }
                }
            }
        }
        """

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self._config.timeout / 1000)
        ) as client:
            response = await client.post(
                "https://arweave.net/graphql",
                json={
                    "query": query,
                    "variables": {"tags": tag_filters, "limit": limit},
                },
                headers={"Content-Type": "application/json"},
            )

            if response.status_code != 200:
                raise ArweaveError(
                    f"GraphQL query failed: HTTP {response.status_code}",
                )

            data = response.json()

            edges = data.get("data", {}).get("transactions", {}).get("edges", [])
            return [edge["node"]["id"] for edge in edges]

    async def find_archives_by_chain(
        self,
        chain_id: int,
        limit: int = 100,
    ) -> List[str]:
        """
        Find all AGIRAILS archives for a chain.

        Args:
            chain_id: Blockchain chain ID (8453 for Base Mainnet)
            limit: Maximum results

        Returns:
            List of Arweave transaction IDs
        """
        return await self.query_by_tags(
            {
                "Protocol": "AGIRAILS",
                "Type": ARCHIVE_BUNDLE_TYPE,
                "ChainId": str(chain_id),
            },
            limit,
        )

    async def find_archive_by_tx(
        self,
        tx_id: str,
    ) -> Optional[str]:
        """
        Find archive for a specific ACTP transaction.

        Args:
            tx_id: ACTP transaction ID (bytes32)

        Returns:
            Arweave transaction ID if found, None otherwise
        """
        results = await self.query_by_tags(
            {
                "Protocol": "AGIRAILS",
                "TxId": tx_id,
            },
            1,
        )
        return results[0] if results else None

    def get_stats(self) -> dict:
        """
        Get client statistics.

        Returns:
            Dictionary with client stats and circuit breaker state
        """
        return {
            "address": self.address,
            "node_url": self._node_url,
            "currency": self._config.currency,
            "network": self._config.network,
            "circuit_breaker": self._circuit_breaker.get_stats(),
        }
