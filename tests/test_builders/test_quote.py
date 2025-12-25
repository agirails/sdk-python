"""Tests for QuoteBuilder."""

import time

import pytest

from agirails.builders.quote import (
    Quote,
    QuoteBuilder,
    create_quote,
)


class TestQuote:
    """Tests for Quote dataclass."""

    def test_create_quote(self) -> None:
        """Test creating a quote."""
        quote = Quote(
            transaction_id="0x" + "1" * 64,
            provider="0x" + "a" * 40,
            price=1_000_000,  # $1.00
            estimated_time=60,
            valid_until=int(time.time()) + 3600,
        )

        assert quote.transaction_id == "0x" + "1" * 64
        assert quote.provider == "0x" + "a" * 40
        assert quote.price == 1_000_000
        assert quote.estimated_time == 60

    def test_price_usdc(self) -> None:
        """Test price conversion to USDC."""
        quote = Quote(
            transaction_id="0x" + "1" * 64,
            provider="0x" + "a" * 40,
            price=1_500_000,  # $1.50
            estimated_time=60,
            valid_until=int(time.time()) + 3600,
        )

        assert quote.price_usdc == 1.5

    def test_is_valid(self) -> None:
        """Test validity check."""
        # Valid quote
        valid_quote = Quote(
            transaction_id="0x" + "1" * 64,
            provider="0x" + "a" * 40,
            price=1_000_000,
            estimated_time=60,
            valid_until=int(time.time()) + 3600,
        )
        assert valid_quote.is_valid is True

        # Expired quote
        expired_quote = Quote(
            transaction_id="0x" + "1" * 64,
            provider="0x" + "a" * 40,
            price=1_000_000,
            estimated_time=60,
            valid_until=int(time.time()) - 1,  # Already expired
        )
        assert expired_quote.is_valid is False

    def test_estimated_time_formatted(self) -> None:
        """Test formatted estimated time."""
        # Seconds
        quote1 = Quote(
            transaction_id="0x" + "1" * 64,
            provider="0x" + "a" * 40,
            price=1_000_000,
            estimated_time=30,
            valid_until=int(time.time()) + 3600,
        )
        assert quote1.estimated_time_formatted == "30s"

        # Minutes
        quote2 = Quote(
            transaction_id="0x" + "1" * 64,
            provider="0x" + "a" * 40,
            price=1_000_000,
            estimated_time=90,  # 1m 30s
            valid_until=int(time.time()) + 3600,
        )
        assert quote2.estimated_time_formatted == "1m 30s"

        # Hours
        quote3 = Quote(
            transaction_id="0x" + "1" * 64,
            provider="0x" + "a" * 40,
            price=1_000_000,
            estimated_time=3660,  # 1h 1m
            valid_until=int(time.time()) + 7200,
        )
        assert quote3.estimated_time_formatted == "1h 1m"

    def test_to_dict(self) -> None:
        """Test converting to dictionary."""
        quote = Quote(
            transaction_id="0x" + "1" * 64,
            provider="0x" + "a" * 40,
            price=1_000_000,
            estimated_time=60,
            valid_until=int(time.time()) + 3600,
        )

        d = quote.to_dict()
        assert d["transactionId"] == "0x" + "1" * 64
        assert d["provider"] == "0x" + "a" * 40
        assert d["price"] == 1_000_000
        assert d["priceUSDC"] == 1.0
        assert "isValid" in d

    def test_compute_hash(self) -> None:
        """Test computing quote hash."""
        quote = Quote(
            transaction_id="0x" + "1" * 64,
            provider="0x" + "a" * 40,
            price=1_000_000,
            estimated_time=60,
            valid_until=1000000,
        )

        hash1 = quote.compute_hash()
        hash2 = quote.compute_hash()

        assert hash1 == hash2  # Deterministic
        assert hash1.startswith("0x")
        assert len(hash1) == 66


class TestQuoteBuilder:
    """Tests for QuoteBuilder class."""

    def test_build_quote(self) -> None:
        """Test building a quote with all fields."""
        quote = (
            QuoteBuilder()
            .for_transaction("0x" + "1" * 64)
            .from_provider("0x" + "a" * 40)
            .with_price(1_000_000)
            .with_estimated_time(60)
            .valid_for(3600)
            .build()
        )

        assert quote.transaction_id == "0x" + "1" * 64
        assert quote.provider == "0x" + "a" * 40
        assert quote.price == 1_000_000
        assert quote.estimated_time == 60

    def test_with_price_usdc(self) -> None:
        """Test setting price in USDC."""
        quote = (
            QuoteBuilder()
            .for_transaction("0x" + "1" * 64)
            .from_provider("0x" + "a" * 40)
            .with_price_usdc(1.50)
            .build()
        )

        assert quote.price == 1_500_000
        assert quote.price_usdc == 1.5

    def test_with_estimated_time_minutes(self) -> None:
        """Test setting estimated time in minutes."""
        quote = (
            QuoteBuilder()
            .for_transaction("0x" + "1" * 64)
            .from_provider("0x" + "a" * 40)
            .with_price(1_000_000)
            .with_estimated_time_minutes(5)
            .build()
        )

        assert quote.estimated_time == 300  # 5 minutes = 300 seconds

    def test_valid_until(self) -> None:
        """Test setting explicit valid_until."""
        deadline = int(time.time()) + 7200

        quote = (
            QuoteBuilder()
            .for_transaction("0x" + "1" * 64)
            .from_provider("0x" + "a" * 40)
            .with_price(1_000_000)
            .valid_until(deadline)
            .build()
        )

        assert quote.valid_until == deadline

    def test_with_terms(self) -> None:
        """Test adding terms."""
        quote = (
            QuoteBuilder()
            .for_transaction("0x" + "1" * 64)
            .from_provider("0x" + "a" * 40)
            .with_price(1_000_000)
            .with_terms("No refunds after completion")
            .build()
        )

        assert quote.terms == "No refunds after completion"

    def test_with_metadata(self) -> None:
        """Test adding metadata."""
        quote = (
            QuoteBuilder()
            .for_transaction("0x" + "1" * 64)
            .from_provider("0x" + "a" * 40)
            .with_price(1_000_000)
            .with_metadata("priority", "high")
            .with_metadata("version", 2)
            .build()
        )

        assert quote.metadata["priority"] == "high"
        assert quote.metadata["version"] == 2

    def test_missing_transaction_id_raises(self) -> None:
        """Test that missing transaction_id raises error."""
        with pytest.raises(ValueError) as exc_info:
            QuoteBuilder().from_provider("0x" + "a" * 40).with_price(1_000_000).build()

        assert "transaction_id" in str(exc_info.value)

    def test_missing_provider_raises(self) -> None:
        """Test that missing provider raises error."""
        with pytest.raises(ValueError) as exc_info:
            QuoteBuilder().for_transaction("0x" + "1" * 64).with_price(1_000_000).build()

        assert "provider" in str(exc_info.value)

    def test_missing_price_raises(self) -> None:
        """Test that missing price raises error."""
        with pytest.raises(ValueError) as exc_info:
            (
                QuoteBuilder()
                .for_transaction("0x" + "1" * 64)
                .from_provider("0x" + "a" * 40)
                .build()
            )

        assert "price" in str(exc_info.value)

    def test_reset(self) -> None:
        """Test resetting builder."""
        builder = (
            QuoteBuilder()
            .for_transaction("0x" + "1" * 64)
            .from_provider("0x" + "a" * 40)
            .with_price(1_000_000)
        )

        builder.reset()

        with pytest.raises(ValueError):
            builder.build()


class TestCreateQuote:
    """Tests for create_quote helper function."""

    def test_create_quote_minimal(self) -> None:
        """Test creating quote with minimal parameters."""
        quote = create_quote(
            transaction_id="0x" + "1" * 64,
            provider="0x" + "a" * 40,
            price=1_000_000,
        )

        assert quote.transaction_id == "0x" + "1" * 64
        assert quote.provider == "0x" + "a" * 40
        assert quote.price == 1_000_000
        assert quote.estimated_time == 60  # Default

    def test_create_quote_full(self) -> None:
        """Test creating quote with all parameters."""
        quote = create_quote(
            transaction_id="0x" + "1" * 64,
            provider="0x" + "a" * 40,
            price=2_000_000,
            estimated_time=120,
            validity_seconds=7200,
        )

        assert quote.price == 2_000_000
        assert quote.estimated_time == 120
        assert quote.is_valid is True
