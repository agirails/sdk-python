"""
GOLDEN VECTOR test for the AIRuling EIP-712 signer (AIP-14b §4.4).

This is the cross-language anchor: the Python SDK MUST reproduce the exact same
EIP-712 digest as the TypeScript SDK and the on-chain contract path. The frozen
constants below come from:

    Protocol/actp-kernel/test/EncodingCanonical.t.sol

If RULING_TYPEHASH, the AIRuling field order, the domain name/version, the
chainId binding, or the verifyingContract binding ever drifts, this test breaks
loudly.
"""

from eth_utils import keccak

from agirails.types.dispute import (
    AIRuling,
    DisputeEIP712Domain,
    Ruling,
    Tier,
    compute_ruling_digest,
    compute_ruling_domain_separator,
    compute_ruling_struct_hash,
    recover_ruling_signer,
    sign_ruling,
)


# ---- FIXED golden inputs (every byte hardcoded) ----
GOLDEN_CHAIN_ID = 8453  # Base mainnet
GOLDEN_VERIFYING_CONTRACT = "0x3c68CC8dFe901c7e89eC9f738F9a81709E6e7737"

GOLDEN_DISPUTE_ID = "0x" + keccak(text="ACTP_GOLDEN_VECTOR_DISPUTE").hex()
GOLDEN_RULING = 1  # requester wins
GOLDEN_CONFIDENCE = 9500  # 95%
GOLDEN_SPLIT_BPS = 0
GOLDEN_TIMESTAMP = 1_700_000_000
GOLDEN_REASONING_HASH = "0x" + keccak(text="golden-reasoning").hex()
GOLDEN_BUNDLE_HASH = "0x" + keccak(text="golden-bundle").hex()
GOLDEN_EVIDENCE_REF_HASH = "0x" + keccak(text="golden-evidence-ref").hex()
GOLDEN_REASONING_REF_HASH = "0x" + keccak(text="golden-reasoning-ref").hex()

# ---- FROZEN EXPECTED VALUES (the canonical anchor, AIP-14c 9-field type) ----
GOLDEN_DOMAIN_SEPARATOR = (
    "0x49c919619319169442e048297d8b8dc2f0c6a78b8601c78a39656bc2b3b25db8"
)
GOLDEN_STRUCT_HASH = (
    "0x2b30b25ad0258f200a315a68b1a7ebffc4040679fca1a4bbdf1cae0b57c589b4"
)
GOLDEN_DIGEST = (
    "0xc14778f377cd385dd4686b798cb2a010c8ff95e8a35a4f170af7e05bc8c2d8a0"
)


def _golden_ruling() -> AIRuling:
    return AIRuling(
        dispute_id=GOLDEN_DISPUTE_ID,
        ruling=GOLDEN_RULING,
        confidence=GOLDEN_CONFIDENCE,
        split_bps=GOLDEN_SPLIT_BPS,
        timestamp=GOLDEN_TIMESTAMP,
        reasoning_hash=GOLDEN_REASONING_HASH,
        bundle_hash=GOLDEN_BUNDLE_HASH,
        evidence_ref_hash=GOLDEN_EVIDENCE_REF_HASH,
        reasoning_ref_hash=GOLDEN_REASONING_REF_HASH,
    )


def _golden_domain() -> DisputeEIP712Domain:
    return DisputeEIP712Domain(
        chain_id=GOLDEN_CHAIN_ID,
        verifying_contract=GOLDEN_VERIFYING_CONTRACT,
    )


def test_golden_domain_separator():
    """The EIP-712 domain separator must equal the frozen golden constant."""
    sep = _golden_domain().separator()
    assert "0x" + sep.hex() == GOLDEN_DOMAIN_SEPARATOR


def test_golden_struct_hash():
    """The AIRuling struct hash must equal the frozen golden constant."""
    sh = _golden_ruling().struct_hash()
    assert "0x" + sh.hex() == GOLDEN_STRUCT_HASH


def test_golden_digest():
    """The full EIP-712 digest must equal the frozen golden constant."""
    digest = compute_ruling_digest(
        _golden_ruling(), GOLDEN_CHAIN_ID, GOLDEN_VERIFYING_CONTRACT
    )
    assert "0x" + digest.hex() == GOLDEN_DIGEST


def test_golden_all_three_at_once():
    """domain_separator == GOLDEN, struct_hash == GOLDEN, digest == GOLDEN."""
    domain = _golden_domain()
    ruling = _golden_ruling()

    domain_separator = "0x" + domain.separator().hex()
    struct_hash = "0x" + ruling.struct_hash().hex()
    digest = (
        "0x"
        + compute_ruling_digest(
            ruling, GOLDEN_CHAIN_ID, GOLDEN_VERIFYING_CONTRACT
        ).hex()
    )

    assert domain_separator == GOLDEN_DOMAIN_SEPARATOR
    assert struct_hash == GOLDEN_STRUCT_HASH
    assert digest == GOLDEN_DIGEST


def test_ruling_enum_value():
    """INV-1 canonical mapping: requester wins == 1."""
    assert int(Ruling.REQUESTER_WINS) == GOLDEN_RULING
    assert int(Ruling.PROVIDER_WINS) == 0
    assert int(Ruling.SPLIT) == 2


def test_tier_enum_is_zero_based_matches_chain():
    """
    Negative control: Tier MUST be 0-based to match BondEscalation.sol's d.tier
    field (opened=0 -> proposal=1 -> UMA=2). TIER1 == on-chain value 1, NOT 2.
    A 1-based enum would misclassify every tier the moment a disputes()/d.tier
    reader is wired. TS twin asserts the identical mapping.
    """
    assert int(Tier.TIER0) == 0
    assert int(Tier.TIER1) == 1
    assert int(Tier.TIER2) == 2


def test_standalone_digest_helpers_match_methods():
    """
    Module-level compute_ruling_struct_hash / compute_ruling_domain_separator
    (added for TS parity) delegate to the methods and reproduce the golden values.
    """
    ruling = _golden_ruling()
    assert "0x" + compute_ruling_struct_hash(ruling).hex() == GOLDEN_STRUCT_HASH
    sep = compute_ruling_domain_separator(GOLDEN_CHAIN_ID, GOLDEN_VERIFYING_CONTRACT)
    assert "0x" + sep.hex() == GOLDEN_DOMAIN_SEPARATOR


def test_sign_and_recover_round_trip():
    """sign_ruling then recover_ruling_signer recovers the signing address."""
    private_key = "0x" + "11" * 32
    from eth_account import Account

    expected_signer = Account.from_key(private_key).address

    ruling = _golden_ruling()
    signature = sign_ruling(
        ruling, private_key, GOLDEN_CHAIN_ID, GOLDEN_VERIFYING_CONTRACT
    )
    recovered = recover_ruling_signer(
        ruling, signature, GOLDEN_CHAIN_ID, GOLDEN_VERIFYING_CONTRACT
    )
    assert recovered == expected_signer


def test_bytes32_inputs_accepted():
    """AIRuling accepts raw bytes for bytes32 fields and reproduces the digest."""
    ruling = AIRuling(
        dispute_id=keccak(text="ACTP_GOLDEN_VECTOR_DISPUTE"),
        ruling=GOLDEN_RULING,
        confidence=GOLDEN_CONFIDENCE,
        split_bps=GOLDEN_SPLIT_BPS,
        timestamp=GOLDEN_TIMESTAMP,
        reasoning_hash=keccak(text="golden-reasoning"),
        bundle_hash=keccak(text="golden-bundle"),
        evidence_ref_hash=keccak(text="golden-evidence-ref"),
        reasoning_ref_hash=keccak(text="golden-reasoning-ref"),
    )
    digest = compute_ruling_digest(
        ruling, GOLDEN_CHAIN_ID, GOLDEN_VERIFYING_CONTRACT
    )
    assert "0x" + digest.hex() == GOLDEN_DIGEST


def test_ref_hashes_load_bearing_default_zero():
    """
    AIP-14c: evidence_ref_hash / reasoning_ref_hash default to bytes32(0) when
    omitted (pre-D7 / direct-proposal path), and are load-bearing — supplying
    the golden refs yields the golden digest, omitting them does NOT.
    """
    zero_ref = AIRuling(
        dispute_id=GOLDEN_DISPUTE_ID,
        ruling=GOLDEN_RULING,
        confidence=GOLDEN_CONFIDENCE,
        split_bps=GOLDEN_SPLIT_BPS,
        timestamp=GOLDEN_TIMESTAMP,
        reasoning_hash=GOLDEN_REASONING_HASH,
        bundle_hash=GOLDEN_BUNDLE_HASH,
    )
    digest_zero = compute_ruling_digest(
        zero_ref, GOLDEN_CHAIN_ID, GOLDEN_VERIFYING_CONTRACT
    )
    assert "0x" + digest_zero.hex() != GOLDEN_DIGEST


def test_typehash_frozen_literal():
    """RULING_TYPEHASH equals the frozen AIP-14c literal (byte-for-byte)."""
    from agirails.types.dispute import RULING_TYPEHASH

    assert (
        "0x" + RULING_TYPEHASH.hex()
        == "0x00e11bf3b34994a6bc6e216b116cbdaddee1227d0c97d46416f8d994ba8420ae"
    )
