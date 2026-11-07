"""Release validation through real ABI decoding and the real replay tracker."""

import time
from eth_abi import encode
import pytest

from tests.test_protocol.test_local_contract_io import eas, ledger, TX, UID, OTHER, ACCOUNT

OTHER_TX = '0x' + '44' * 32


def reply_attestation(rpc, *, uid=UID, schema=UID, expiration=0, revocation=0, tx=TX, data=None):
    payload = data if data is not None else encode(
        ['bytes32','string','bytes32','uint256'],
        [bytes.fromhex(tx[2:]), 'bafy-result', bytes.fromhex(TX[2:]), 1700000000],
    )
    rpc.reply('getAttestation', (
        bytes.fromhex(uid[2:]), bytes.fromhex(schema[2:]), 1700000000,
        expiration, revocation, bytes(32), OTHER, ACCOUNT.address, True, payload,
    ))


@pytest.mark.asyncio
async def test_release_verifies_actual_attestation_and_records_idempotent_usage(eas):
    rpc, helper = eas
    reply_attestation(rpc)
    result = await helper.get_delivery_attestation(UID)
    assert result.transaction_id == TX and result.result_cid == 'bafy-result'
    assert await helper.verify_delivery_attestation(TX, UID) is True
    assert helper.attestation_tracker.get_usage_for_attestation(UID).lower() == TX.lower()
    assert await helper.verify_and_record_for_release(TX, UID) is None
    assert rpc.sent == []
    attestation = await helper.get_attestation(UID)
    assert attestation.is_valid and not attestation.is_expired and not attestation.is_revoked
    assert attestation.to_dict()['isValid'] is True


@pytest.mark.asyncio
@pytest.mark.parametrize('fields,message', [
    ({'uid':OTHER_TX}, 'not found'),
    ({'schema':OTHER_TX}, 'Schema UID mismatch'),
    ({'revocation':1}, 'revoked'),
    ({'expiration':1}, 'expired'),
    ({'tx':OTHER_TX}, 'txId mismatch'),
    ({'data':b'bad'}, 'data format mismatch'),
])
async def test_release_rejects_invalid_attestation_without_recording_or_sending(eas, fields, message):
    rpc, helper = eas
    reply_attestation(rpc, **fields)
    with pytest.raises(ValueError, match=message):
        await helper.verify_and_record_for_release(TX, UID)
    assert helper.attestation_tracker.get_usage_for_attestation(UID) is None
    assert rpc.sent == []


@pytest.mark.asyncio
async def test_release_rejects_previously_recorded_other_transaction(eas):
    rpc, helper = eas
    reply_attestation(rpc)
    await helper.attestation_tracker.record_usage(UID, OTHER_TX)
    with pytest.raises(ValueError, match='replay'):
        await helper.verify_delivery_attestation(TX, UID)
    assert helper.attestation_tracker.get_usage_for_attestation(UID) == OTHER_TX
    assert rpc.sent == []


@pytest.mark.asyncio
async def test_release_rechecks_atomic_record_result(eas, monkeypatch):
    rpc, helper = eas
    reply_attestation(rpc)
    async def lose_race(uid, tx):
        await original(uid, OTHER_TX)
        return False
    original = helper.attestation_tracker.record_usage
    monkeypatch.setattr(helper.attestation_tracker, 'record_usage', lose_race)
    with pytest.raises(ValueError, match='replay'):
        await helper.verify_delivery_attestation(TX, UID)
    assert helper.attestation_tracker.get_usage_for_attestation(UID) == OTHER_TX


@pytest.mark.asyncio
@pytest.mark.parametrize('tx,uid', [('bad',UID), (TX,'bad'), ('',UID), (TX,'')])
async def test_release_validates_identifiers_before_rpc(eas, tx, uid):
    rpc, helper = eas
    before = len(rpc.calls)
    with pytest.raises(ValueError, match='format'):
        await helper.verify_delivery_attestation(tx, uid)
    assert len(rpc.calls) == before


@pytest.mark.asyncio
@pytest.mark.parametrize('expiration,revocation,valid', [(0,1,False), (1,0,False), (0,0,True)])
async def test_attestation_lifetime_properties(eas, expiration, revocation, valid):
    rpc, helper = eas
    reply_attestation(rpc, expiration=expiration, revocation=revocation)
    attestation = await helper.get_attestation(UID)
    assert attestation.is_valid is valid
    assert attestation.is_revoked is (revocation > 0)
    assert attestation.is_expired is (0 < expiration < time.time())
