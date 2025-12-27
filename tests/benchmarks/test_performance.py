"""
Performance Benchmarks for AGIRAILS Python SDK.

Uses pytest-benchmark for measuring execution time of critical operations.

Run benchmarks:
    pip install pytest-benchmark
    pytest tests/benchmarks/ -v --benchmark-only

Compare with previous run:
    pytest tests/benchmarks/ -v --benchmark-compare

Performance Targets:
    - Transaction creation (mock): <10ms
    - keccak256 hashing: <1ms per hash
    - JSON canonicalization: <1ms per object
    - EIP-712 signing: <10ms per signature
    - State validation: <0.1ms per check

Notes:
    - Benchmarks are skipped if pytest-benchmark is not installed
    - Use --benchmark-warmup=on for more accurate results
    - Use --benchmark-min-rounds=100 for statistically significant data
"""

import json
import secrets
import time
from typing import Any, Callable, Dict, Optional

import pytest

# Try to import benchmark - skip tests if not available
try:
    import pytest_benchmark
    from pytest_benchmark.fixture import BenchmarkFixture

    HAS_BENCHMARK = True
except ImportError:
    HAS_BENCHMARK = False
    BenchmarkFixture = Any  # type: ignore

pytestmark = pytest.mark.skipif(
    not HAS_BENCHMARK,
    reason="pytest-benchmark not installed: pip install pytest-benchmark",
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_transaction_params() -> Dict[str, Any]:
    """Sample transaction parameters for benchmarking."""
    return {
        "provider": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "requester": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "amount": "1000000",  # 1 USDC
        "deadline": int(time.time()) + 3600,
        "dispute_window": 3600,
        "service_description": "test-service",
    }


@pytest.fixture
def sample_json_data() -> Dict[str, Any]:
    """Sample JSON data for canonicalization benchmarks."""
    return {
        "service": "ai-summarization",
        "input": "Long text to summarize...",
        "timestamp": 1700000000000,
        "nested": {
            "key1": "value1",
            "key2": 12345,
            "key3": True,
        },
    }


@pytest.fixture
def sample_delivery_proof_params() -> Dict[str, Any]:
    """Sample delivery proof parameters."""
    return {
        "transaction_id": "0x" + "a" * 64,
        "output_hash": "0x" + "b" * 64,
        "provider": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "consumer": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "result_cid": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
        "timestamp": int(time.time()),
        "nonce": 1,
        "chain_id": 84532,
    }


# =============================================================================
# Hashing Benchmarks
# =============================================================================


class TestHashingPerformance:
    """Benchmarks for hashing operations."""

    def test_keccak256_small_string(self, benchmark: BenchmarkFixture) -> None:
        """Benchmark keccak256 hashing of small string."""
        from agirails.types.message import compute_result_hash

        data = "Hello, World!"

        result = benchmark(compute_result_hash, data)

        assert result.startswith("0x")
        assert len(result) == 66

    def test_keccak256_large_json(self, benchmark: BenchmarkFixture) -> None:
        """Benchmark keccak256 hashing of large JSON object."""
        from agirails.types.message import compute_result_hash

        # ~1KB of data
        data = {
            "key_" + str(i): "value_" * 10 for i in range(50)
        }

        result = benchmark(compute_result_hash, data)

        assert result.startswith("0x")

    def test_keccak256_bytes(self, benchmark: BenchmarkFixture) -> None:
        """Benchmark keccak256 hashing of raw bytes."""
        from agirails.types.message import compute_result_hash

        data = secrets.token_bytes(1024)  # 1KB of random bytes

        result = benchmark(compute_result_hash, data)

        assert result.startswith("0x")

    def test_service_hash_computation(
        self, benchmark: BenchmarkFixture, sample_json_data: Dict[str, Any]
    ) -> None:
        """Benchmark ServiceHash computation."""
        from agirails.utils.helpers import ServiceHash, ServiceMetadata

        metadata = ServiceMetadata(
            service=sample_json_data["service"],
            input=json.dumps(sample_json_data),
        )

        result = benchmark(ServiceHash.hash, metadata)

        assert result.startswith("0x")
        assert len(result) == 66


# =============================================================================
# JSON Canonicalization Benchmarks
# =============================================================================


class TestCanonicalJsonPerformance:
    """Benchmarks for JSON canonicalization."""

    def test_canonical_json_small(
        self, benchmark: BenchmarkFixture, sample_json_data: Dict[str, Any]
    ) -> None:
        """Benchmark canonical JSON serialization of small object."""
        from agirails.utils.canonical_json import canonical_json_dumps

        result = benchmark(canonical_json_dumps, sample_json_data)

        assert isinstance(result, str)
        assert "service" in result

    def test_canonical_json_large(self, benchmark: BenchmarkFixture) -> None:
        """Benchmark canonical JSON serialization of large object."""
        from agirails.utils.canonical_json import canonical_json_dumps

        # ~10KB of data
        data = {
            "items": [{"id": i, "name": f"item_{i}", "value": i * 1.5} for i in range(500)]
        }

        result = benchmark(canonical_json_dumps, data)

        assert isinstance(result, str)

    def test_canonical_json_deeply_nested(self, benchmark: BenchmarkFixture) -> None:
        """Benchmark canonical JSON with deeply nested structure."""
        from agirails.utils.canonical_json import canonical_json_dumps

        # Nested 10 levels deep
        data: Dict[str, Any] = {"value": "leaf"}
        for i in range(10):
            data = {"level": i, "child": data}

        result = benchmark(canonical_json_dumps, data)

        assert isinstance(result, str)


# =============================================================================
# State Machine Benchmarks
# =============================================================================


class TestStateMachinePerformance:
    """Benchmarks for state machine operations."""

    def test_state_transition_validation(self, benchmark: BenchmarkFixture) -> None:
        """Benchmark is_valid_transition check."""
        from agirails.runtime.types import State, is_valid_transition

        def check_all_transitions() -> int:
            """Check all possible state transitions."""
            valid_count = 0
            for from_state in State:
                for to_state in State:
                    if is_valid_transition(from_state, to_state):
                        valid_count += 1
            return valid_count

        result = benchmark(check_all_transitions)

        # Should have some valid transitions
        assert result > 0

    def test_terminal_state_check(self, benchmark: BenchmarkFixture) -> None:
        """Benchmark is_terminal_state check."""
        from agirails.runtime.types import State, is_terminal_state

        states = list(State)

        def check_all_terminal() -> int:
            return sum(1 for s in states if is_terminal_state(s))

        result = benchmark(check_all_terminal)

        # SETTLED and CANCELLED are terminal
        assert result == 2


# =============================================================================
# Builder Pattern Benchmarks
# =============================================================================


class TestBuilderPerformance:
    """Benchmarks for builder patterns."""

    def test_delivery_proof_builder(
        self, benchmark: BenchmarkFixture, sample_delivery_proof_params: Dict[str, Any]
    ) -> None:
        """Benchmark DeliveryProofBuilder.build()."""
        from agirails.builders.delivery_proof import DeliveryProofBuilder

        def build_proof() -> Any:
            return (
                DeliveryProofBuilder()
                .for_transaction(sample_delivery_proof_params["transaction_id"])
                .from_provider(sample_delivery_proof_params["provider"])
                .with_output({"result": "success"})
                .for_consumer(sample_delivery_proof_params["consumer"])
                .with_result_cid(sample_delivery_proof_params["result_cid"])
                .with_nonce(sample_delivery_proof_params["nonce"])
                .on_chain(sample_delivery_proof_params["chain_id"])
                .build()
            )

        result = benchmark(build_proof)

        assert result is not None
        assert result.transaction_id == sample_delivery_proof_params["transaction_id"]

    def test_delivery_proof_builder_message(
        self, benchmark: BenchmarkFixture, sample_delivery_proof_params: Dict[str, Any]
    ) -> None:
        """Benchmark DeliveryProofBuilder.build_message()."""
        from agirails.builders.delivery_proof import DeliveryProofBuilder

        def build_message() -> Any:
            return (
                DeliveryProofBuilder()
                .for_transaction(sample_delivery_proof_params["transaction_id"])
                .from_provider(sample_delivery_proof_params["provider"])
                .with_output({"result": "success"})
                .for_consumer(sample_delivery_proof_params["consumer"])
                .with_result_cid(sample_delivery_proof_params["result_cid"])
                .with_nonce(sample_delivery_proof_params["nonce"])
                .on_chain(sample_delivery_proof_params["chain_id"])
                .build_message()
            )

        result = benchmark(build_message)

        assert result is not None
        assert result.tx_id == sample_delivery_proof_params["transaction_id"]

    def test_quote_builder(self, benchmark: BenchmarkFixture) -> None:
        """Benchmark QuoteBuilder.build()."""
        from agirails.builders.quote import QuoteBuilder

        def build_quote() -> Any:
            return (
                QuoteBuilder()
                .for_transaction("0x" + "a" * 64)
                .from_provider("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
                .with_price(1000000)
                .with_estimated_time(300)
                .build()
            )

        result = benchmark(build_quote)

        assert result is not None
        assert result.price == 1000000


# =============================================================================
# Mock Runtime Benchmarks
# =============================================================================


class TestMockRuntimePerformance:
    """Benchmarks for MockRuntime operations."""

    @pytest.fixture
    def mock_runtime(self) -> Any:
        """Create MockRuntime for benchmarking."""
        from agirails.runtime.mock_runtime import MockRuntime

        return MockRuntime(
            address="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            initial_balance=1000000000,  # 1000 USDC
        )

    def test_create_transaction(
        self, benchmark: BenchmarkFixture, mock_runtime: Any
    ) -> None:
        """Benchmark transaction creation in MockRuntime."""
        from agirails.runtime.base import CreateTransactionParams

        params = CreateTransactionParams(
            provider="0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            requester="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            amount="1000000",
            deadline=int(time.time()) + 3600,
            dispute_window=3600,
        )

        result = benchmark(mock_runtime.create_transaction, params)

        assert result.startswith("0x")
        assert len(result) == 66

    def test_get_transaction(
        self, benchmark: BenchmarkFixture, mock_runtime: Any
    ) -> None:
        """Benchmark transaction retrieval."""
        from agirails.runtime.base import CreateTransactionParams

        # Create a transaction first
        params = CreateTransactionParams(
            provider="0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            requester="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            amount="1000000",
            deadline=int(time.time()) + 3600,
            dispute_window=3600,
        )
        tx_id = mock_runtime.create_transaction(params)

        result = benchmark(mock_runtime.get_transaction, tx_id)

        assert result is not None
        assert result.id == tx_id

    def test_state_transition(
        self, benchmark: BenchmarkFixture, mock_runtime: Any
    ) -> None:
        """Benchmark state transition."""
        from agirails.runtime.base import CreateTransactionParams
        from agirails.runtime.types import State

        # Create and commit a transaction
        params = CreateTransactionParams(
            provider="0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            requester="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            amount="1000000",
            deadline=int(time.time()) + 3600,
            dispute_window=3600,
        )
        tx_id = mock_runtime.create_transaction(params)
        mock_runtime.link_escrow(tx_id, "1000000")

        def do_transition() -> None:
            mock_runtime.transition_state(tx_id, State.IN_PROGRESS)
            mock_runtime.transition_state(tx_id, State.COMMITTED)  # Reset

        # This benchmark may have side effects, so we just measure one transition
        # and create a fresh transaction each time
        @benchmark
        def measure() -> None:
            p = CreateTransactionParams(
                provider="0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
                requester="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
                amount="1000000",
                deadline=int(time.time()) + 3600,
                dispute_window=3600,
            )
            tid = mock_runtime.create_transaction(p)
            mock_runtime.link_escrow(tid, "1000000")
            mock_runtime.transition_state(tid, State.IN_PROGRESS)


# =============================================================================
# Security Utility Benchmarks
# =============================================================================


class TestSecurityPerformance:
    """Benchmarks for security utilities."""

    def test_timing_safe_equal(self, benchmark: BenchmarkFixture) -> None:
        """Benchmark timing-safe string comparison."""
        from agirails.utils.security import timing_safe_equal

        a = "0x" + "a" * 64
        b = "0x" + "a" * 64

        result = benchmark(timing_safe_equal, a, b)

        assert result is True

    def test_validate_path(self, benchmark: BenchmarkFixture) -> None:
        """Benchmark path validation."""
        from agirails.utils.security import validate_path

        base_path = "/home/user/data"
        user_path = "files/document.json"

        result = benchmark(validate_path, user_path, base_path)

        assert "/document.json" in result

    def test_validate_service_name(self, benchmark: BenchmarkFixture) -> None:
        """Benchmark service name validation."""
        from agirails.utils.security import validate_service_name

        name = "ai-summarization-v2"

        result = benchmark(validate_service_name, name)

        assert result is True

    def test_is_valid_address(self, benchmark: BenchmarkFixture) -> None:
        """Benchmark Ethereum address validation."""
        from agirails.utils.security import is_valid_address

        address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

        result = benchmark(is_valid_address, address)

        assert result is True

    def test_safe_json_parse(self, benchmark: BenchmarkFixture) -> None:
        """Benchmark safe JSON parsing."""
        from agirails.utils.security import safe_json_parse

        json_str = json.dumps({
            "key": "value",
            "nested": {"a": 1, "b": 2},
            "array": [1, 2, 3],
        })

        result = benchmark(safe_json_parse, json_str)

        assert result["key"] == "value"


# =============================================================================
# Rate Limiter Benchmarks
# =============================================================================


class TestRateLimiterPerformance:
    """Benchmarks for rate limiter."""

    def test_token_bucket_acquire(self, benchmark: BenchmarkFixture) -> None:
        """Benchmark token bucket acquire operation."""
        from agirails.utils.security import TokenBucketRateLimiter

        limiter = TokenBucketRateLimiter(max_rate=1000.0, burst_size=100)

        def try_acquire() -> bool:
            return limiter.try_acquire()

        result = benchmark(try_acquire)

        # Should be able to acquire with high rate limit
        assert result is True

    def test_lru_cache_operations(self, benchmark: BenchmarkFixture) -> None:
        """Benchmark LRU cache get/set operations."""
        from agirails.utils.security import LRUCache

        cache: LRUCache[str, str] = LRUCache(max_size=1000)

        # Pre-populate
        for i in range(500):
            cache.set(f"key_{i}", f"value_{i}")

        def cache_ops() -> Optional[str]:
            # Mix of get and set
            key = f"key_{secrets.randbelow(1000)}"
            result = cache.get(key)
            cache.set(key, f"new_value")
            return result

        benchmark(cache_ops)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--benchmark-only"])
