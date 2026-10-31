import hashlib
import os
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization

from enginir_opcua import Client, ua
from enginir_opcua.common.connection import (
    FrameReader,
    OpenRequestError,
    SecureChannel,
    TransportError,
    TransportLimits,
)
from enginir_opcua.common.utils import Buffer
from enginir_opcua.crypto import uacrypto
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256, SecurityPolicyNone
from tests.harness import PKI_FILES


def test_srv25_channel_exposes_its_security_properties() -> None:
    """Part 6, 6.7.7: sessions read the channel's identity from the channel, not from the policy object."""
    channel = SecureChannel(SecurityPolicyNone(), TransportLimits())
    channel.security_token.ChannelId = 7
    assert channel.channel_id == 7
    assert channel.policy_uri == SecurityPolicyNone.URI
    assert channel.security_mode == ua.MessageSecurityMode.None_
    assert not channel.peer_certificate
    assert not channel.local_certificate
    assert channel.last_used > 0


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class ChannelPair:
    def __init__(self, client: SecureChannel, server: SecureChannel, clock: FakeClock) -> None:
        self.client = client
        self.server = server
        self.clock = clock
        self.request_id = 0
        self._ids = SimpleNamespace(get_new_channel_id=lambda: 77)

    def renew(self, lifetime: int = 3_600_000) -> None:
        self._open(ua.SecurityTokenRequestType.Renew, lifetime)

    def _open(self, request_type: ua.SecurityTokenRequestType, lifetime: int) -> None:
        nonce_length = self.client.security_policy.secure_channel_nonce_length
        client_nonce = os.urandom(nonce_length)
        params = ua.OpenSecureChannelParameters(
            RequestType=request_type, ClientNonce=client_nonce, RequestedLifetime=lifetime
        )
        result = self.server.open(params, self._ids)
        self.client.set_channel(result, request_type, client_nonce)

    def send(self, sender: SecureChannel, receiver: SecureChannel, tamper_token: int | None = None) -> object:
        self.request_id += 1
        data = bytearray(sender.message_to_binary(b"payload", request_id=self.request_id))
        if tamper_token is not None:
            data[12:16] = tamper_token.to_bytes(4, "little")
        reader = FrameReader(lambda: 65535)
        reader.feed(bytes(data))
        ((header, body),) = list(reader.frames())
        return receiver.receive_from_header_and_body(header, Buffer(bytes(body)))


def accept_any_certificate(_chain: bytes) -> None:
    return None


def open_pair(policy: bool = False) -> ChannelPair:
    clock = FakeClock()
    if policy:
        certificate = PKI_FILES / "certificate-example.der"
        key = PKI_FILES / "private-key-example.pem"
        peer_certificate = PKI_FILES / "certificates" / "peer-certificate-example-1.der"
        peer_key = PKI_FILES / "certificates" / "peer-private-key-example-1.pem"
        client_policy = SecurityPolicyBasic256Sha256(
            uacrypto.x509_from_der(certificate.read_bytes()),
            uacrypto.x509_from_der(peer_certificate.read_bytes()),
            serialization.load_pem_private_key(peer_key.read_bytes(), None),
            ua.MessageSecurityMode.Sign,
        )
        server_policy = SecurityPolicyBasic256Sha256(
            uacrypto.x509_from_der(peer_certificate.read_bytes()),
            uacrypto.x509_from_der(certificate.read_bytes()),
            serialization.load_pem_private_key(key.read_bytes(), None),
            ua.MessageSecurityMode.Sign,
        )
    else:
        client_policy, server_policy = SecurityPolicyNone(), SecurityPolicyNone()
    client = SecureChannel(client_policy, TransportLimits())
    server = SecureChannel(server_policy, TransportLimits())
    for channel in (client, server):
        channel._clock = clock
        channel.peer_certificate_check = accept_any_certificate
    pair = ChannelPair(client, server, clock)
    pair._open(ua.SecurityTokenRequestType.Issue, 3_600_000)
    return pair


@pytest.mark.parametrize(
    ("requested", "revised"),
    [(0, 3_600_000), (1, 10_000), (50_000, 50_000), (2**32 - 1, 3_600_000)],
)
@pytest.mark.parametrize("request_type", [ua.SecurityTokenRequestType.Issue, ua.SecurityTokenRequestType.Renew])
def test_com37_requested_lifetime_is_revised(
    requested: int, revised: int, request_type: ua.SecurityTokenRequestType
) -> None:
    """Part 4, 5.6.2.2: the server returns a lifetime it chose within its limits, never 0."""
    pair = open_pair()
    params = ua.OpenSecureChannelParameters(RequestType=request_type, RequestedLifetime=requested)
    result = pair.server.open(params, pair._ids)
    assert result.SecurityToken.RevisedLifetime == revised


def test_com38_token_ids_are_random_nonzero_and_not_repeated() -> None:
    """Part 4, 5.6.2.2: a new SecurityToken has its own TokenId; 13 for every channel is not random."""
    ids = set()
    for _ in range(5):
        ids.add(open_pair().server.security_token.TokenId)
    pair = open_pair()
    ids.add(pair.server.security_token.TokenId)
    for _ in range(20):
        params = ua.OpenSecureChannelParameters(RequestType=ua.SecurityTokenRequestType.Renew)
        token = pair.server.open(params, pair._ids).SecurityToken
        assert token.TokenId not in ids
        ids.add(token.TokenId)
    assert 0 not in ids
    assert 13 not in ids


def test_com59_token_id_zero_does_not_replace_the_current_token() -> None:
    """Part 6, 6.7.7: the empty token slot has id 0; a chunk with that id must not rotate anything."""
    pair = open_pair()
    token_id = pair.server.security_token.TokenId
    with pytest.raises(TransportError) as error:
        pair.send(pair.client, pair.server, tamper_token=0)
    assert error.value.status == ua.StatusCodes.BadSecureChannelTokenUnknown
    assert pair.server.security_token.TokenId == token_id


@pytest.mark.parametrize("policy", [False, True], ids=["none", "basic256sha256"])
def test_cry7_unknown_token_id_is_token_unknown(policy: bool) -> None:
    """Part 6, 6.7.7: the key is selected by the TokenId; an id nobody issued selects none."""
    pair = open_pair(policy)
    with pytest.raises(TransportError) as error:
        pair.send(pair.client, pair.server, tamper_token=12345)
    assert error.value.status == ua.StatusCodes.BadSecureChannelTokenUnknown


@pytest.mark.parametrize("policy", [False, True], ids=["none", "basic256sha256"])
def test_cry7_old_and_new_tokens_both_work_during_a_renewal(policy: bool) -> None:
    """Part 4, 5.6.2.1: the server sends under the old token until the new one is used, and both are accepted."""
    pair = open_pair(policy)
    pair.send(pair.client, pair.server)
    pair.renew()
    assert pair.send(pair.server, pair.client) is not None
    assert pair.server._next is not None
    assert pair.send(pair.client, pair.server) is not None
    assert pair.server._next is None
    assert pair.send(pair.server, pair.client) is not None


@pytest.mark.parametrize("policy", [False, True], ids=["none", "basic256sha256"])
def test_a_sequence_number_out_of_order_is_a_transport_error(policy: bool) -> None:
    """Part 6, 6.7.2.4 and 6.7.7: the peer is told Bad_SecurityChecksFailed and the stored number stays."""
    pair = open_pair(policy)
    pair.send(pair.client, pair.server)
    expected = pair.server._peer_sequence_number
    pair.client._sequence_number += 5
    with pytest.raises(TransportError) as error:
        pair.send(pair.client, pair.server)
    assert error.value.status == ua.StatusCodes.BadSecurityChecksFailed
    assert pair.server._peer_sequence_number == expected


@pytest.mark.parametrize("policy", [False, True], ids=["none", "basic256sha256"])
def test_com62_a_token_is_accepted_until_125_percent_of_its_lifetime(policy: bool) -> None:
    """Part 4, 5.6.2.1: expired tokens are refused, also the current one, for every policy."""
    pair = open_pair(policy)
    lifetime = pair.server.security_token.RevisedLifetime / 1000
    pair.clock.now += lifetime * 1.2
    assert pair.send(pair.client, pair.server) is not None
    pair.clock.now += lifetime * 0.1
    with pytest.raises(TransportError) as error:
        pair.send(pair.client, pair.server)
    assert error.value.status == ua.StatusCodes.BadSecureChannelTokenUnknown
    assert pair.server.expires_in() == 0


def test_com62_expires_in_counts_down_to_the_end_of_the_last_window() -> None:
    """Part 4, 5.6.2.1: the channel is closed when no token is inside its window any more."""
    pair = open_pair()
    lifetime = pair.server.security_token.RevisedLifetime / 1000
    assert pair.server.expires_in() == pytest.approx(lifetime * 1.25)
    pair.clock.now += lifetime
    assert pair.server.expires_in() == pytest.approx(lifetime * 0.25)
    pair.renew()
    pair.server.open(ua.OpenSecureChannelParameters(RequestType=ua.SecurityTokenRequestType.Renew), pair._ids)
    assert pair.server.expires_in() == pytest.approx(lifetime * 1.25)


def open_params(
    request_type: ua.SecurityTokenRequestType = ua.SecurityTokenRequestType.Issue,
    nonce: bytes = b"",
    mode: ua.MessageSecurityMode = ua.MessageSecurityMode.None_,
    version: int = 0,
) -> ua.OpenSecureChannelParameters:
    return ua.OpenSecureChannelParameters(
        ClientProtocolVersion=version, RequestType=request_type, SecurityMode=mode, ClientNonce=nonce
    )


def signed_header(channel: SecureChannel, certificate: bytes | None = None) -> ua.AsymmetricAlgorithmHeader:
    policy = channel.security_policy
    return ua.AsymmetricAlgorithmHeader(
        SecurityPolicyURI=policy.URI,
        SenderCertificate=certificate if certificate is not None else policy.peer_certificate,
        ReceiverCertificateThumbPrint=hashlib.sha1(policy.host_certificate or b"", usedforsecurity=False).digest(),
    )


def test_com63_renew_on_an_unopened_channel_is_request_type_invalid() -> None:
    """Part 4, 5.6.2.3: Renew needs an open channel."""
    server = SecureChannel(SecurityPolicyNone(), TransportLimits())
    params = open_params(ua.SecurityTokenRequestType.Renew)
    with pytest.raises(OpenRequestError) as error:
        server.validate_open_request(0, ua.AsymmetricAlgorithmHeader(), params, 0)
    assert error.value.status == ua.StatusCodes.BadRequestTypeInvalid


def test_com63_issue_on_an_open_channel_is_request_type_invalid() -> None:
    """Part 4, 5.6.2.3: a second Issue must not replace the channel id and keys."""
    pair = open_pair()
    with pytest.raises(OpenRequestError) as error:
        pair.server.validate_open_request(0, ua.AsymmetricAlgorithmHeader(), open_params(), 0)
    assert error.value.status == ua.StatusCodes.BadRequestTypeInvalid


def test_com63_renew_must_name_the_channel() -> None:
    """Part 6, 6.7.4: a Renew carries the SecureChannelId of the channel."""
    pair = open_pair()
    params = open_params(ua.SecurityTokenRequestType.Renew)
    with pytest.raises(TransportError) as error:
        pair.server.validate_open_request(pair.server.channel_id + 1, ua.AsymmetricAlgorithmHeader(), params, 0)
    assert error.value.status == ua.StatusCodes.BadTcpSecureChannelUnknown


def test_com63_issue_must_use_channel_id_zero() -> None:
    """Part 6, 6.7.7: Issue uses channel id 0."""
    server = SecureChannel(SecurityPolicyNone(), TransportLimits())
    with pytest.raises(TransportError) as error:
        server.validate_open_request(5, ua.AsymmetricAlgorithmHeader(), open_params(), 0)
    assert error.value.status == ua.StatusCodes.BadTcpSecureChannelUnknown


def test_com63_protocol_version_must_match_the_hello() -> None:
    """Part 6, 6.7.4: ClientProtocolVersion equals the Hello's ProtocolVersion."""
    server = SecureChannel(SecurityPolicyNone(), TransportLimits())
    with pytest.raises(OpenRequestError) as error:
        server.validate_open_request(0, ua.AsymmetricAlgorithmHeader(), open_params(version=3), 0)
    assert error.value.status == ua.StatusCodes.BadProtocolVersionUnsupported


def test_com63_nonce_of_the_wrong_length_is_nonce_invalid() -> None:
    """Part 6, 6.7.4: the ClientNonce has the length of the policy."""
    pair = open_pair(policy=True)
    server = SecureChannel(pair.server.security_policy, TransportLimits())
    server.peer_certificate_check = accept_any_certificate
    header = signed_header(server)
    mode = ua.MessageSecurityMode.Sign
    for nonce in (b"", os.urandom(16), os.urandom(33)):
        with pytest.raises(OpenRequestError) as error:
            server.validate_open_request(0, header, open_params(nonce=nonce, mode=mode), 0)
        assert error.value.status == ua.StatusCodes.BadNonceInvalid
    server.validate_open_request(0, header, open_params(nonce=os.urandom(32), mode=mode), 0)


def test_com63_renew_nonce_must_not_repeat() -> None:
    """Part 6, 6.7.4: a nonce is never reused."""
    pair = open_pair(policy=True)
    header = signed_header(pair.server)
    params = open_params(
        ua.SecurityTokenRequestType.Renew, nonce=pair.server.remote_nonce, mode=ua.MessageSecurityMode.Sign
    )
    with pytest.raises(OpenRequestError) as error:
        pair.server.validate_open_request(pair.server.channel_id, header, params, 0)
    assert error.value.status == ua.StatusCodes.BadNonceInvalid


def test_com63_thumbprint_must_name_our_certificate() -> None:
    """Part 6, 6.7.2.3: ReceiverCertificateThumbprint is compared with our certificate."""
    pair = open_pair(policy=True)
    server = SecureChannel(pair.server.security_policy, TransportLimits())
    header = signed_header(server)
    header.ReceiverCertificateThumbPrint = bytes(20)
    with pytest.raises(TransportError) as error:
        server.validate_open_request(0, header, open_params(nonce=os.urandom(32), mode=ua.MessageSecurityMode.Sign), 0)
    assert error.value.status == ua.StatusCodes.BadSecurityChecksFailed


@pytest.mark.parametrize("change", ["certificate", "policy", "mode"])
def test_com63_renew_must_keep_certificate_policy_and_mode(change: str) -> None:
    """Part 6, 6.7.4: a Renew comes from the same certificate with the same policy and mode."""
    pair = open_pair(policy=True)
    header = signed_header(pair.server)
    mode = ua.MessageSecurityMode.Sign
    if change == "certificate":
        header.SenderCertificate = (PKI_FILES / "certificate-example.der").read_bytes()
    elif change == "policy":
        header.SecurityPolicyURI = SecurityPolicyNone.URI
    else:
        mode = ua.MessageSecurityMode.SignAndEncrypt
    params = open_params(ua.SecurityTokenRequestType.Renew, os.urandom(32), mode)
    with pytest.raises(TransportError) as error:
        pair.server.validate_open_request(pair.server.channel_id, header, params, 0)
    assert error.value.status == ua.StatusCodes.BadSecurityChecksFailed


def test_com63_a_valid_renew_passes() -> None:
    """Part 6, 6.7.4: the checks do not refuse a proper Renew."""
    pair = open_pair(policy=True)
    header = signed_header(pair.server)
    params = open_params(ua.SecurityTokenRequestType.Renew, os.urandom(32), ua.MessageSecurityMode.Sign)
    pair.server.validate_open_request(pair.server.channel_id, header, params, 0)


@pytest.mark.parametrize("mutation", ["lifetime", "token", "channel", "version", "nonce"])
def test_com63_client_rejects_an_invalid_open_response(mutation: str) -> None:
    """Part 6, 6.7.4: the client checks ids, lifetime, versions and nonce of the response."""
    pair = open_pair(policy=True)
    nonce = os.urandom(32)
    params = open_params(ua.SecurityTokenRequestType.Renew, nonce, ua.MessageSecurityMode.Sign)
    result = pair.server.open(params, pair._ids)
    pair.client.check_open_response(result, params, 0)
    if mutation == "lifetime":
        result.SecurityToken.RevisedLifetime = 0
    elif mutation == "token":
        result.SecurityToken.TokenId = 0
    elif mutation == "channel":
        result.SecurityToken.ChannelId = 0
    elif mutation == "version":
        result.ServerProtocolVersion = 1
    else:
        result.ServerNonce = nonce
    with pytest.raises(ua.UaStatusCodeError):
        pair.client.check_open_response(result, params, 0)


async def test_cli8_renewal_interval_follows_every_revised_lifetime(monkeypatch: pytest.MonkeyPatch) -> None:
    """Part 4, 5.6.2.1: the client renews at 75 % of the lifetime of the token it holds now, never below 1 s."""
    client = Client("opc.tcp://127.0.0.1:1")
    client.secure_channel_timeout = 40_000
    sleeps: list[float] = []
    lifetimes = iter([8_000, 0, 20_000])

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    async def fake_open(renew: bool = False) -> None:
        client.secure_channel_timeout = next(lifetimes)
        if len(sleeps) == 3:
            client.uaclient._disconnect_requested = True

    monkeypatch.setattr("enginir_opcua.client.client.asyncio.sleep", fake_sleep)
    monkeypatch.setattr(client, "open_secure_channel", fake_open)
    await client._renew_channel_loop()
    assert sleeps == [30.0, 6.0, 1.0]


def test_srv3_channel_without_a_certificate_check_refuses_the_peer_certificate_on_issue_and_renew() -> None:
    """Part 4, 6.1.3 and Part 6, 6.7.4: with a policy other than None and no check set, nothing is trusted."""
    pair = open_pair(policy=True)
    bare = SecureChannel(pair.server.security_policy, TransportLimits())
    header = signed_header(bare)
    params = open_params(ua.SecurityTokenRequestType.Issue, os.urandom(32), ua.MessageSecurityMode.Sign)
    with pytest.raises(TransportError) as error:
        bare.validate_open_request(0, header, params, 0)
    assert error.value.status == ua.StatusCodes.BadSecurityChecksFailed
    pair.server.peer_certificate_check = bare.peer_certificate_check
    renew = open_params(ua.SecurityTokenRequestType.Renew, os.urandom(32), ua.MessageSecurityMode.Sign)
    with pytest.raises(TransportError) as error:
        pair.server.validate_open_request(pair.server.channel_id, signed_header(pair.server), renew, 0)
    assert error.value.status == ua.StatusCodes.BadSecurityChecksFailed


def test_srv3_client_channel_without_a_certificate_check_refuses_the_open_response() -> None:
    """Part 4, 6.1.3: the client side fails closed as well."""
    pair = open_pair(policy=True)
    params = open_params(ua.SecurityTokenRequestType.Renew, os.urandom(32), ua.MessageSecurityMode.Sign)
    result = pair.server.open(params, pair._ids)
    bare = SecureChannel(pair.client.security_policy, TransportLimits())
    with pytest.raises(ua.UaError):
        bare.check_open_response(result, params, 0)
