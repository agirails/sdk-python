import secrets

import pytest

from agirails_sdk import ACTPClient, Network, State
from agirails_sdk.errors import DeadlineError, InvalidStateTransitionError, RpcError


class StubFunc:
    def __init__(self, fn_name, callback=None):
        self.fn_name = fn_name
        self._callback = callback or (lambda *a, **k: None)

    def estimate_gas(self, *_args, **_kwargs):
        return 100_000

    def build_transaction(self, tx_meta):
        # Return both the meta and name so assertions can inspect calls
        return {"fn": self.fn_name, "meta": tx_meta}

    def __call__(self, *args, **kwargs):
        return self._callback(*args, **kwargs)


class StubEvents:
    def __init__(self, tx_id):
        self.tx_id = tx_id

    def TransactionCreated(self):
        class _Event:
            def __init__(self, tx_id):
                self.tx_id = tx_id

            def process_receipt(self, _receipt):
                return [{"args": {"transactionId": self.tx_id}}]

        return _Event(self.tx_id)

    def StateTransitioned(self):
        class _Event:
            def process_receipt(self, _receipt):
                return [{"args": {"transactionId": "0xstate", "newState": State.COMMITTED}}]

        return _Event()

    def EscrowLinked(self):
        class _Event:
            def process_receipt(self, _receipt):
                return [{"args": {"transactionId": "0xescr", "escrowId": "0xescrow"}}]

        return _Event()


class StubKernel:
    def __init__(self, tx_id_hex, tx_view_tuple):
        self._tx_id_hex = tx_id_hex
        self._tx_view_tuple = tx_view_tuple
        self.functions = self
        self.events = StubEvents(tx_id_hex)
        self.link_calls = []
        self.transition_calls = []
        self.anchor_calls = []

    # Function stubs
    def createTransaction(self, *args):
        return StubFunc("createTransaction")

    def linkEscrow(self, tx_id, escrow_contract, escrow_id):
        self.link_calls.append((tx_id, escrow_contract, escrow_id))
        return StubFunc("linkEscrow")

    def transitionState(self, *_args):
        self.transition_calls.append(_args)
        return StubFunc("transitionState")

    def getTransaction(self, *_args):
        class _GetTx(StubFunc):
            def call(self_inner):
                return self._tx_view_tuple

        return _GetTx("getTransaction")

    def anchorAttestation(self, *args):
        self.anchor_calls.append(args)
        return StubFunc("anchorAttestation")


class StubEAS:
    def __init__(self, attestation):
        self.attestation = attestation
        self.functions = self

    def getAttestation(self, uid):
        class _GetAtt(StubFunc):
            def call(self_inner):
                return self.attestation

        return _GetAtt("getAttestation")


class StubUSDC:
    def __init__(self):
        self.approve_calls = []
        self.functions = self

    def approve(self, escrow_contract, amount):
        self.approve_calls.append((escrow_contract, amount))
        return StubFunc("approve")


@pytest.fixture()
def client(monkeypatch):
    # Private key for tests (DO NOT USE IN PRODUCTION)
    pk = "0x" + "11" * 32
    c = ACTPClient(network=Network.BASE_SEPOLIA, private_key=pk)

    # Patch gas estimator to avoid RPC calls
    monkeypatch.setattr(c, "_estimate_gas", lambda *_, **__: 123_456)
    # Patch tx meta to avoid RPC nonce
    monkeypatch.setattr(
        c,
        "_tx_meta",
        lambda gas=None, overrides=None: {
            "from": c.address,
            "nonce": 0,
            "chainId": c.config.chain_id,
            "gas": gas or 450_000,
            "maxFeePerGas": 1,
            "maxPriorityFeePerGas": 1,
        },
    )
    monkeypatch.setattr(c, "now", lambda: 0)

    # Stub kernel/usdc contracts and send
    tx_id_hex = "0x" + "aa" * 32
    tx_view_tuple = (
        bytes.fromhex(tx_id_hex[2:]),
        "0xreq",
        "0xprov",
        State.INITIATED,  # default state for funding/quote tests
        1_000_000,
        111,
        222,
        10_000_000,  # deadline in the future relative to tests
        b"\x00" * 32,
        "0xescrow",
        b"\x01" * 32,
        b"\x02" * 32,
        444,
        b"\x03" * 32,
        100,
    )
    c.kernel = StubKernel(tx_id_hex, tx_view_tuple)
    c.usdc = StubUSDC()
    att = (
        bytes.fromhex("ff" * 32),  # uid
        bytes.fromhex("00" * 32),  # schema
        bytes.fromhex(tx_id_hex[2:]),  # refUID ties to tx
        0,  # time
        0,  # expirationTime
        0,  # revocationTime
        "0xprov",  # recipient
        "0xattester",
        b"",  # data
    )
    c.eas = StubEAS(att)
    c.agent_registry = type(
        "AR",
        (),
        {
            "functions": type(
                "F",
                (),
                {
                    "registerAgent": lambda *args, **kwargs: StubFunc("registerAgent"),
                    "updateEndpoint": lambda *args, **kwargs: StubFunc("updateEndpoint"),
                    "addServiceType": lambda *args, **kwargs: StubFunc("addServiceType"),
                    "removeServiceType": lambda *args, **kwargs: StubFunc("removeServiceType"),
                    "setActiveStatus": lambda *args, **kwargs: StubFunc("setActiveStatus"),
                    "getAgent": lambda *_: type("G", (), {"call": lambda *_: {"agent": "ok"}})(),
                    "getServiceDescriptors": lambda *_: type("D", (), {"call": lambda *_: [{"svc": "ok"}]})(),
                },
            )()
        },
    )()

    def _fake_send(tx):
        # Simply return a stub receipt to unlock event parsing
        return {"status": 1}

    monkeypatch.setattr(c, "_build_and_send", _fake_send)
    return c


def _set_kernel_state(client: ACTPClient, state: State):
    tup = list(client.kernel._tx_view_tuple)
    tup[3] = state  # state index
    client.kernel._tx_view_tuple = tuple(tup)


def test_create_transaction_parses_event_txid(client):
    tx_id = client.create_transaction(
        provider="0xProvider",
        requester=client.address,
        amount=1,
        deadline=10,
        dispute_window=5,
        service_hash="0x" + "00" * 32,
    )
    assert tx_id == client.kernel._tx_id_hex


def test_get_transaction_decodes_full_struct(client):
    tx = client.get_transaction(client.kernel._tx_id_hex)
    assert tx.transaction_id == bytes.fromhex(client.kernel._tx_id_hex[2:])
    assert tx.amount == 1_000_000
    assert tx.state == State.INITIATED
    assert tx.platform_fee_bps_locked == 100


def test_link_escrow_approves_and_links(client):
    escrow_id = client.link_escrow(client.kernel._tx_id_hex, amount=123, escrow_id="0x" + "ab" * 32)
    assert client.usdc.approve_calls == [(client.config.escrow_vault, 123)]
    assert client.kernel.link_calls  # called once
    called_tx, called_vault, called_escrow = client.kernel.link_calls[0]
    assert called_vault == client.config.escrow_vault
    assert escrow_id == "0x" + called_escrow.hex()


def test_transition_state_accepts_hex_proof(client):
    # Should not raise and should build/send once
    _set_kernel_state(client, State.DELIVERED)
    proof = "0x" + "ff" * 32
    client.transition_state(client.kernel._tx_id_hex, State.SETTLED, proof=proof)


def test_fund_transaction_validates_and_links(client):
    escrow_id = client.fund_transaction(client.kernel._tx_id_hex)
    assert client.usdc.approve_calls  # approve called
    assert client.kernel.link_calls  # linkEscrow called
    # Returned escrow_id should be hex string
    assert escrow_id.startswith("0x")


def test_submit_quote_encodes_proof(client):
    quote_hash = "0x" + "ab" * 32
    client.submit_quote(client.kernel._tx_id_hex, quote_hash)
    assert client.kernel.transition_calls
    tx_bytes, new_state, proof_bytes = client.kernel.transition_calls[0]
    assert new_state == State.QUOTED
    assert proof_bytes == bytes.fromhex(quote_hash[2:])


def test_release_escrow_with_verification(client):
    att_uid = "0x" + "ff" * 32
    _set_kernel_state(client, State.DELIVERED)
    client.release_escrow_with_verification(client.kernel._tx_id_hex, att_uid)
    # Should record transition call with proof = att_uid
    tx_bytes, new_state, proof_bytes = client.kernel.transition_calls[-1]
    assert new_state == State.SETTLED
    assert proof_bytes == bytes.fromhex(att_uid[2:])


def test_invalid_transition_raises(client):
    # INITIATED -> SETTLED should be invalid per client-side state machine
    with pytest.raises(InvalidStateTransitionError):
        client.transition_state(client.kernel._tx_id_hex, State.SETTLED)


def test_build_and_send_decodes_revert(monkeypatch):
    pk = "0x" + "11" * 32
    c = ACTPClient(network=Network.BASE_SEPOLIA, private_key=pk)

    # stub sign/send to raise ValueError with encoded revert data
    def _raise(*_args, **_kwargs):
        selector = "08c379a0"
        offset = "0000000000000000000000000000000000000000000000000000000000000020"
        length = "0000000000000000000000000000000000000000000000000000000000000005"
        text = "68656c6c6f" + ("00" * 27)
        data = "0x" + selector + offset + length + text  # "hello"
        raise ValueError({"data": data})

    monkeypatch.setattr(
        c,
        "account",
        type("A", (), {"sign_transaction": _raise, "address": c.address})(),
    )
    monkeypatch.setattr(c.w3.eth, "send_raw_transaction", lambda *_: None)
    monkeypatch.setattr(c.w3.eth, "wait_for_transaction_receipt", lambda *_: {"status": 1})

    with pytest.raises(RpcError) as exc:
        c._build_and_send({"from": c.address, "nonce": 0})
    assert "hello" in str(exc.value)


def test_deadline_error_on_fund(monkeypatch, client):
    # set deadline in past
    tup = list(client.kernel._tx_view_tuple)
    tup[7] = -1
    client.kernel._tx_view_tuple = tuple(tup)
    with pytest.raises(DeadlineError):
        client.fund_transaction(client.kernel._tx_id_hex)


def test_anchor_attestation(client):
    uid = "0x" + "11" * 32
    client.anchor_attestation(client.kernel._tx_id_hex, uid)
    assert client.kernel.anchor_calls


def test_deliver_sets_dispute_window(client):
    _set_kernel_state(client, State.IN_PROGRESS)
    client.deliver(client.kernel._tx_id_hex, dispute_window_seconds=3600)
    tx_bytes, new_state, proof_bytes = client.kernel.transition_calls[-1]
    assert new_state == State.DELIVERED
    assert int.from_bytes(proof_bytes, "big") == 3600


def test_dispute_and_cancel(client):
    _set_kernel_state(client, State.IN_PROGRESS)
    client.dispute(client.kernel._tx_id_hex)
    assert client.kernel.transition_calls[-1][1] == State.DISPUTED
    _set_kernel_state(client, State.QUOTED)
    client.cancel(client.kernel._tx_id_hex)
    assert client.kernel.transition_calls[-1][1] == State.CANCELLED


def test_parse_events(client):
    receipt = {"status": 1}
    parsed = client.parse_events(receipt)
    assert "transaction_created" in parsed and "state_transitioned" in parsed and "escrow_linked" in parsed


def test_agent_registry_calls(client):
    client.register_agent("https://endpoint", [])
    client.update_endpoint("https://new")
    client.add_service_type("text-generation")
    client.remove_service_type("0x" + "00" * 32)
    client.set_active_status(True)
    assert client.get_agent("0x123")["agent"] == "ok"
    assert client.get_service_descriptors("0x123")[0]["svc"] == "ok"
