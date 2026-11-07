import pytest
from eth_abi import encode

from agirails.dispute.composite_mediator import decode_resolution_proof
from agirails.reputation.dispute_split_indexer import DisputeOutcome, DisputeSplitIndexer


@pytest.fixture(params=[False, True])
def proof(request):
    return (
        "0x"
        + (
            encode(["uint256", "uint256", "bool"], [1, 0, True])
            if request.param
            else encode(["uint256", "uint256"], [1, 0])
        ).hex()
    )


@pytest.mark.parametrize("entry", ["decoder", "indexer"])
def test_unknown_principal_never_becomes_a_one_wei_payout(proof, entry):
    with pytest.raises(ValueError, match="principal"):
        if entry == "decoder":
            decode_resolution_proof(proof, remaining=None)
        else:
            DisputeSplitIndexer().classify_payout(
                DisputeOutcome(
                    provider="p", requester="r", kind="settled", remaining=None, proof=proof
                )
            )


@pytest.mark.parametrize("principal", [0, 50000])
def test_explicit_principal_is_authoritative_even_when_legacy_alias_is_missing(proof, principal):
    direct = decode_resolution_proof(proof, remaining=None, escrow_principal=principal)
    indexed = DisputeSplitIndexer().classify_payout(
        DisputeOutcome(
            provider="p",
            requester="r",
            kind="settled",
            remaining=None,
            escrow_principal=principal,
            proof=proof,
        )
    )
    assert direct == indexed
    assert direct.requester_amount == (0 if principal == 0 else 1)
    assert direct.provider_amount == 0 and direct.phantom_sentinel == (principal == 0)


def test_no_proof_does_not_attempt_to_classify_unknown_principal():
    assert (
        DisputeSplitIndexer().classify_payout(
            DisputeOutcome(provider="p", requester="r", kind="settled", remaining=None)
        )
        is None
    )


def test_default_zero_principal_still_suppresses_sentinel(proof):
    result = DisputeSplitIndexer().classify_payout(
        DisputeOutcome(provider="p", requester="r", kind="settled", proof=proof)
    )
    assert result.phantom_sentinel and result.requester_amount == result.provider_amount == 0
