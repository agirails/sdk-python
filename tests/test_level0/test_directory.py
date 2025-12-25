"""Tests for ServiceDirectory and related types."""

import pytest
from agirails.level0.directory import (
    ServiceDirectory,
    ServiceEntry,
    ServiceQuery,
    get_global_directory,
    reset_global_directory,
)


class TestServiceEntry:
    """Tests for ServiceEntry dataclass."""

    def test_basic_creation(self):
        """Test creating a ServiceEntry."""
        entry = ServiceEntry(
            name="echo",
            description="Echo service",
            capabilities=["text", "json"],
        )
        assert entry.name == "echo"
        assert entry.description == "Echo service"
        assert entry.capabilities == ["text", "json"]

    def test_has_capability(self):
        """Test capability checking."""
        entry = ServiceEntry(name="test", capabilities=["gpt-4", "streaming"])
        assert entry.has_capability("gpt-4")
        assert entry.has_capability("GPT-4")  # Case insensitive
        assert not entry.has_capability("gpt-3")

    def test_has_all_capabilities(self):
        """Test checking multiple capabilities."""
        entry = ServiceEntry(name="test", capabilities=["a", "b", "c"])
        assert entry.has_all_capabilities(["a", "b"])
        assert entry.has_all_capabilities(["a"])
        assert not entry.has_all_capabilities(["a", "d"])

    def test_has_any_capability(self):
        """Test checking any capability."""
        entry = ServiceEntry(name="test", capabilities=["a", "b"])
        assert entry.has_any_capability(["a", "z"])
        assert entry.has_any_capability(["z", "b"])
        assert not entry.has_any_capability(["x", "y"])


class TestServiceQuery:
    """Tests for ServiceQuery matching."""

    def test_name_match(self):
        """Test exact name matching."""
        entry = ServiceEntry(name="echo")
        query = ServiceQuery(name="echo")
        assert query.matches(entry)

        query_no_match = ServiceQuery(name="other")
        assert not query_no_match.matches(entry)

    def test_name_pattern_match(self):
        """Test pattern matching."""
        entry = ServiceEntry(name="text-generation")

        assert ServiceQuery(name_pattern="text-*").matches(entry)
        assert ServiceQuery(name_pattern="*generation").matches(entry)
        assert ServiceQuery(name_pattern="*-*").matches(entry)
        assert not ServiceQuery(name_pattern="audio-*").matches(entry)

    def test_capabilities_match(self):
        """Test capability filtering."""
        entry = ServiceEntry(name="test", capabilities=["gpt-4", "streaming"])

        assert ServiceQuery(capabilities=["gpt-4"]).matches(entry)
        assert ServiceQuery(capabilities=["gpt-4", "streaming"]).matches(entry)
        assert not ServiceQuery(capabilities=["gpt-4", "batch"]).matches(entry)

    def test_any_capabilities_match(self):
        """Test any capability filtering."""
        entry = ServiceEntry(name="test", capabilities=["gpt-4"])

        assert ServiceQuery(any_capabilities=["gpt-4", "gpt-3"]).matches(entry)
        assert not ServiceQuery(any_capabilities=["gpt-3", "gpt-3.5"]).matches(entry)

    def test_provider_address_match(self):
        """Test provider address filtering."""
        entry = ServiceEntry(name="test", provider_address="0x123")

        assert ServiceQuery(provider_address="0x123").matches(entry)
        assert not ServiceQuery(provider_address="0x456").matches(entry)

    def test_custom_filter(self):
        """Test custom filter function."""
        entry = ServiceEntry(name="test", metadata={"priority": True})

        query = ServiceQuery(custom=lambda e: e.metadata.get("priority", False))
        assert query.matches(entry)

        entry_no_priority = ServiceEntry(name="test2")
        assert not query.matches(entry_no_priority)

    def test_combined_filters(self):
        """Test multiple filters combined."""
        entry = ServiceEntry(
            name="text-gen",
            capabilities=["gpt-4"],
            provider_address="0x123",
        )

        # All conditions must match
        query = ServiceQuery(
            name_pattern="text-*",
            capabilities=["gpt-4"],
            provider_address="0x123",
        )
        assert query.matches(entry)

        # One condition fails
        query_fail = ServiceQuery(
            name_pattern="text-*",
            capabilities=["gpt-4"],
            provider_address="0x456",  # Wrong address
        )
        assert not query_fail.matches(entry)


class TestServiceDirectory:
    """Tests for ServiceDirectory."""

    def test_register_and_get(self):
        """Test registering and retrieving a service."""
        directory = ServiceDirectory()
        entry = directory.register("echo", description="Echo service")

        assert entry.name == "echo"
        assert entry.description == "Echo service"

        retrieved = directory.get("echo")
        assert retrieved is not None
        assert retrieved.name == "echo"

    def test_register_with_capabilities(self):
        """Test registering with capabilities."""
        directory = ServiceDirectory()
        entry = directory.register(
            "text-gen",
            capabilities=["gpt-4", "streaming"],
        )

        assert entry.capabilities == ["gpt-4", "streaming"]

    def test_register_duplicate_raises(self):
        """Test that duplicate registration raises."""
        directory = ServiceDirectory()
        directory.register("echo")

        with pytest.raises(ValueError, match="already registered"):
            directory.register("echo")

    def test_register_empty_name_raises(self):
        """Test that empty name raises."""
        directory = ServiceDirectory()

        with pytest.raises(ValueError, match="cannot be empty"):
            directory.register("")

    def test_unregister(self):
        """Test unregistering a service."""
        directory = ServiceDirectory()
        directory.register("echo")

        assert directory.has("echo")
        result = directory.unregister("echo")
        assert result is True
        assert not directory.has("echo")

        # Unregistering non-existent returns False
        assert directory.unregister("nonexistent") is False

    def test_has(self):
        """Test has method."""
        directory = ServiceDirectory()
        directory.register("echo")

        assert directory.has("echo")
        assert not directory.has("other")

    def test_find(self):
        """Test finding services with query."""
        directory = ServiceDirectory()
        directory.register("text-gen", capabilities=["gpt-4"])
        directory.register("text-summary", capabilities=["gpt-4"])
        directory.register("audio-gen", capabilities=["whisper"])

        # Find by capability
        results = directory.find(ServiceQuery(capabilities=["gpt-4"]))
        assert len(results) == 2

        # Find by pattern
        results = directory.find(ServiceQuery(name_pattern="text-*"))
        assert len(results) == 2

    def test_find_by_capability(self):
        """Test convenience find_by_capability."""
        directory = ServiceDirectory()
        directory.register("a", capabilities=["x"])
        directory.register("b", capabilities=["x", "y"])
        directory.register("c", capabilities=["z"])

        results = directory.find_by_capability("x")
        assert len(results) == 2

    def test_find_by_pattern(self):
        """Test convenience find_by_pattern."""
        directory = ServiceDirectory()
        directory.register("text-gen")
        directory.register("text-summary")
        directory.register("audio-gen")

        results = directory.find_by_pattern("text-*")
        assert len(results) == 2

    def test_list_all(self):
        """Test listing all services."""
        directory = ServiceDirectory()
        directory.register("a")
        directory.register("b")
        directory.register("c")

        all_services = directory.list_all()
        assert len(all_services) == 3

    def test_list_names(self):
        """Test listing service names."""
        directory = ServiceDirectory()
        directory.register("a")
        directory.register("b")

        names = directory.list_names()
        assert set(names) == {"a", "b"}

    def test_count(self):
        """Test counting services."""
        directory = ServiceDirectory()
        assert directory.count() == 0

        directory.register("a")
        assert directory.count() == 1

        directory.register("b")
        assert directory.count() == 2

    def test_clear(self):
        """Test clearing all services."""
        directory = ServiceDirectory()
        directory.register("a")
        directory.register("b")

        directory.clear()
        assert directory.count() == 0

    def test_update(self):
        """Test updating a service."""
        directory = ServiceDirectory()
        directory.register("echo", description="Old")

        updated = directory.update("echo", description="New")
        assert updated is not None
        assert updated.description == "New"

        # Update non-existent returns None
        assert directory.update("nonexistent", description="X") is None

    def test_contains_operator(self):
        """Test 'in' operator."""
        directory = ServiceDirectory()
        directory.register("echo")

        assert "echo" in directory
        assert "other" not in directory

    def test_len_operator(self):
        """Test len() function."""
        directory = ServiceDirectory()
        assert len(directory) == 0

        directory.register("a")
        assert len(directory) == 1

    def test_iter(self):
        """Test iteration."""
        directory = ServiceDirectory()
        directory.register("a")
        directory.register("b")

        names = [entry.name for entry in directory]
        assert set(names) == {"a", "b"}


class TestGlobalDirectory:
    """Tests for global directory functions."""

    def test_get_global_directory(self):
        """Test getting global directory."""
        reset_global_directory()

        dir1 = get_global_directory()
        dir2 = get_global_directory()

        assert dir1 is dir2  # Same instance

    def test_reset_global_directory(self):
        """Test resetting global directory."""
        reset_global_directory()

        directory = get_global_directory()
        directory.register("test")
        assert directory.has("test")

        reset_global_directory()

        new_directory = get_global_directory()
        assert not new_directory.has("test")
