import asyncio
import hmac
import struct
from collections.abc import AsyncIterator, Callable
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ua_client import UaClient
from enginir_opcua.crypto import uacrypto
from enginir_opcua.crypto.permission_rules import User, UserRole
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256, SecurityPolicyNone
from enginir_opcua.server import identity
from enginir_opcua.server.identity import IdentityGuard, peer_key
from enginir_opcua.server.internal_session import ChannelSecurity
from enginir_opcua.server.user_managers import (
    AnonymousReadOnlyUserManager,
    CertificateUserManager,
    PermissiveUserManager,
    UserManager,
)
from tests.conftest import find_free_port
from tests.harness import PKI_FILES, TWO_SESSION_USERS, SessionProbe, TwoUserManager, make_certificate, signing_client
from tests.pki import CLIENT_APPLICATION_URI, make_identity

PASSWORD = TWO_SESSION_USERS["alice"]
RSA_15 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"


def _rewrite_user_token(
    monkeypatch: pytest.MonkeyPatch, rewrite: Callable[[ua.UserNameIdentityToken, bytes], None]
) -> None:
    activate_session = UaClient.activate_session

    async def rewritten(self: UaClient, params: ua.ActivateSessionParameters) -> ua.ActivateSessionResult:
        rewrite(params.UserIdentityToken, self.security_policy.peer_certificate)
        return await activate_session(self, params)

    monkeypatch.setattr(UaClient, "activate_session", rewritten)


def _public_key(der: bytes) -> rsa.RSAPublicKey:
    certificate = uacrypto.x509_from_der(der)
    assert certificate is not None
    public_key = certificate.public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)
    return public_key


def _secret(password: str, nonce: bytes) -> bytes:
    return ua.ua_binary.Primitives.Bytes.pack(password.encode("utf8") + nonce)


async def test_signing_server_accepts_correct_token(shared_signing_server: Server) -> None:
    client = await signing_client(shared_signing_server)
    async with client:
        assert await client.nodes.server_state.read_value() == ua.ServerState.Running


async def test_srv6_password_bound_to_another_nonce_is_rejected(
    shared_signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.2.2: the encrypted secret ends with the current server nonce; any other nonce is a replay."""

    def replay(token: ua.UserNameIdentityToken, server_certificate: bytes) -> None:
        public_key = _public_key(server_certificate)
        token.Password = uacrypto.encrypt_rsa_oaep(public_key, _secret(PASSWORD, b"\x00" * 32))

    _rewrite_user_token(monkeypatch, replay)
    client = await signing_client(shared_signing_server)
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await client.connect()
    await client.disconnect()


async def test_cry8_rsa15_password_is_rejected_on_basic256sha256(
    shared_signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.2: the secret is encrypted with the algorithm of the UserTokenPolicy's SecurityPolicy."""

    def encrypt_with_rsa15(client: Client, password: str, policy_uri: str) -> tuple[bytes, str]:
        public_key = _public_key(client.security_policy.peer_certificate)
        return uacrypto.encrypt_rsa15(public_key, _secret(password, client._server_nonce or b"")), RSA_15

    monkeypatch.setattr(Client, "_encrypt_password", encrypt_with_rsa15)
    client = await signing_client(shared_signing_server)
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await client.connect()
    await client.disconnect()


async def test_srv6_plaintext_password_is_rejected_when_policy_requires_encryption(
    shared_signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.4: a UserTokenPolicy with a SecurityPolicy other than None requires an encrypted password."""

    def plaintext(token: ua.UserNameIdentityToken, server_certificate: bytes) -> None:
        token.Password = PASSWORD.encode("utf8")
        token.EncryptionAlgorithm = None

    _rewrite_user_token(monkeypatch, plaintext)
    client = await signing_client(shared_signing_server)
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await client.connect()
    await client.disconnect()


async def test_srv6_unknown_policy_id_is_rejected(
    shared_signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.1: the PolicyId has to name one of the endpoint's UserTokenPolicies."""

    def unknown_policy(token: ua.UserNameIdentityToken, server_certificate: bytes) -> None:
        token.PolicyId = "no-such-policy"

    _rewrite_user_token(monkeypatch, unknown_policy)
    client = await signing_client(shared_signing_server)
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await client.connect()
    await client.disconnect()


@pytest.mark.parametrize(
    "password",
    [
        pytest.param("", id="srv6_token_without_a_password_goes_to_the_user_manager"),
        pytest.param("wrong", id="srv6_wrong_password"),
    ],
)
async def test_srv6_bad_password_is_user_access_denied(shared_signing_server: Server, password: str) -> None:
    """Part 4, 5.7.3.3: a valid token with a wrong or empty password is Bad_UserAccessDenied."""
    client = await signing_client(shared_signing_server)
    client.set_password(password)
    with pytest.raises(ua.uaerrors.BadUserAccessDenied):
        await client.connect()
    await client.disconnect()


RSA_OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"


def _craft_secret(monkeypatch: pytest.MonkeyPatch, build: Callable[[bytes, bytes], bytes]) -> None:
    def crafted(client: Client, password: str, policy_uri: str) -> tuple[bytes, str]:
        public_key = _public_key(client.security_policy.peer_certificate)
        plaintext = build(password.encode("utf8"), client._server_nonce or b"")
        return uacrypto.encrypt_rsa_oaep(public_key, plaintext), RSA_OAEP

    monkeypatch.setattr(Client, "_encrypt_password", crafted)


def _with_length(body: bytes, length: int, padding: bytes = b"") -> bytes:
    return struct.pack("<I", length) + body + padding


SECRET_FAILURES: dict[str, Callable[[bytes, bytes], bytes]] = {
    "nonzero_padding": lambda pw, nonce: _with_length(pw + nonce, len(pw + nonce), b"\x07\x07junk"),
    "length_beyond_plaintext": lambda pw, nonce: _with_length(pw + nonce, 9999),
    "length_shorter_than_nonce": lambda pw, nonce: _with_length(pw + nonce, len(nonce) - 1),
    "plaintext_shorter_than_length_field": lambda pw, nonce: b"\x01\x00",
    "wrong_nonce": lambda pw, nonce: _with_length(pw + bytes(len(nonce)), len(pw + nonce)),
    "invalid_utf8": lambda pw, nonce: _with_length(b"\xff\xfe" + nonce, 2 + len(nonce)),
}


@pytest.mark.parametrize("failure", sorted(SECRET_FAILURES))
async def test_srv48_all_secret_failures_give_identity_token_invalid(
    failure: str, shared_signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.2.1 and 7.40.2.2: every defect of the secret is Bad_IdentityTokenInvalid."""
    _craft_secret(monkeypatch, SECRET_FAILURES[failure])
    client = await signing_client(shared_signing_server)
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await client.connect()
    await client.disconnect()


@pytest.mark.parametrize("failure", sorted(SECRET_FAILURES))
async def test_srv48_every_check_runs_whichever_one_fails(
    failure: str, shared_signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.2.1: validation takes the same work whichever check fails; the nonce is always compared."""
    comparisons: list[int] = []
    compare_digest = hmac.compare_digest

    def counting(left: bytes, right: bytes) -> bool:
        comparisons.append(1)
        return compare_digest(left, right)

    monkeypatch.setattr(identity, "hmac", SimpleNamespace(compare_digest=counting))
    _craft_secret(monkeypatch, SECRET_FAILURES[failure])
    client = await signing_client(shared_signing_server)
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await client.connect()
    await client.disconnect()
    assert comparisons == [1]


async def test_srv48_secret_with_zero_padding_is_accepted(
    shared_signing_server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.40.2.2: bytes after the data are zero padding and are fine."""
    _craft_secret(monkeypatch, lambda pw, nonce: _with_length(pw + nonce, len(pw + nonce), bytes(16)))
    client = await signing_client(shared_signing_server)
    async with client:
        assert await client.nodes.server_state.read_value() == ua.ServerState.Running


port_num = find_free_port()
uri = f"opc.tcp://127.0.0.1:{port_num}/baz/server"
uri_creds = f"opc.tcp://foobar:hR%26yjjGhP%246%40nQ4e@127.0.0.1:{port_num}/baz/server"
uri_wrong_creds = f"opc.tcp://foobar:wrong@127.0.0.1:{port_num}/baz/server"


class FoobarUserManager:
    def get_user(self, iserver, username=None, password=None, certificate=None):
        if username == "foobar" and password == "hR&yjjGhP$6@nQ4e":
            return User(role=UserRole.User)
        return None


@pytest.fixture()
async def srv_user():
    srv = Server(allow_no_security=True, user_manager=FoobarUserManager())
    srv.set_endpoint(uri)
    srv.set_identity_tokens([ua.UserNameIdentityToken])
    srv.allow_plaintext_password = True

    await srv.init()
    await srv.start()
    yield srv
    await srv.stop()


async def test_creds(srv_user):
    clt = Client(uri)
    clt.set_user("foobar")
    clt.set_password("hR&yjjGhP$6@nQ4e")
    await clt.connect()
    await clt.disconnect()


async def test_wrong_creds(srv_user):
    clt = Client(uri)
    clt.set_user("foobar")
    clt.set_password("wrong")
    with pytest.raises(ua.uaerrors.BadUserAccessDenied):
        await clt.connect()
    await clt.disconnect()


async def test_creds_in_uri(srv_user):
    clt = Client(uri_creds)
    # check if credentials got removed
    assert clt.server_url.geturl() == uri
    await clt.connect()
    await clt.disconnect()


async def test_wrong_creds_in_uri(srv_user):
    clt = Client(uri_wrong_creds)
    with pytest.raises(ua.uaerrors.BadUserAccessDenied):
        await clt.connect()
    await clt.disconnect()


async def _started(**server_arguments: Any) -> Server:
    srv = Server(**server_arguments)
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    srv.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    await srv.start()
    return srv


@pytest.fixture
async def default_server() -> AsyncIterator[Server]:
    srv = await _started()
    variable = await srv.nodes.objects.add_variable(2, "Setpoint", 1.0)
    await variable.set_writable()
    yield srv
    await srv.stop()


def test_srv7_default_user_manager_is_anonymous_read_only() -> None:
    """Part 4, 7.40.1: a server without a configured user manager accepts Anonymous only."""
    srv = Server()
    assert isinstance(srv.iserver.user_manager, AnonymousReadOnlyUserManager)
    assert not isinstance(srv.iserver.user_manager, PermissiveUserManager)


def test_srv7_remote_admin_switch_is_gone() -> None:
    """Part 4, 7.40.1: there is no built-in Admin user to switch on or off."""
    assert not hasattr(Server, "allow_remote_admin")
    assert not hasattr(Server().iserver, "allow_remote_admin")


async def test_srv7_default_server_offers_only_anonymous(default_server: Server) -> None:
    """Part 4, 7.41: the endpoints list only the UserTokenPolicies the server can accept."""
    for endpoint in await default_server.get_endpoints():
        assert {policy.TokenType for policy in endpoint.UserIdentityTokens} == {ua.UserTokenType.Anonymous}


@pytest.mark.parametrize("user", ["admin", "Admin", "alice"])
async def test_srv7_default_server_rejects_username_tokens(default_server: Server, user: str) -> None:
    """Part 4, 5.7.3.2: without a user manager no UserName policy is offered, so the client does not try one."""
    client = Client(default_server.endpoint.geturl())
    client.set_user(user)
    client.set_password("anything")
    with pytest.raises(ua.uaerrors.ConfigurationError):
        await client.connect()
    await client.disconnect()


async def test_srv7_default_server_anonymous_reads_but_does_not_write(default_server: Server) -> None:
    """Part 4, 5.7.3.1: the default user is Anonymous, which reads and cannot write."""
    async with Client(default_server.endpoint.geturl()) as client:
        variable = client.get_node(await default_server.nodes.objects.get_child("2:Setpoint"))
        assert await variable.read_value() == 1.0
        with pytest.raises(ua.uaerrors.BadUserAccessDenied):
            await variable.write_value(2.0)


async def test_srv7_permissive_manager_is_an_explicit_opt_in() -> None:
    """Part 4, 7.40.1: an application that wants every login accepted has to ask for it."""
    srv = Server(user_manager=PermissiveUserManager())
    srv.allow_plaintext_password = True
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    srv.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    await srv.start()
    try:
        async with Client(srv.endpoint.geturl().replace("//", "//admin@")) as client:
            assert await client.nodes.server_state.read_value() == ua.ServerState.Running
    finally:
        await srv.stop()


async def test_srv7_certificate_manager_refuses_anonymous_by_default() -> None:
    """Part 4, 5.7.3.2: with a CertificateUserManager an Anonymous login without a registered certificate is refused."""
    srv = await _started(user_manager=CertificateUserManager())
    try:
        client = Client(srv.endpoint.geturl())
        with pytest.raises(ua.uaerrors.BadUserAccessDenied):
            await client.connect()
        await client.disconnect()
    finally:
        await srv.stop()


async def test_srv7_certificate_manager_accepts_anonymous_when_allowed() -> None:
    """Part 4, 5.7.3.2: allow_anonymous lets Anonymous in, as the read-only role."""
    srv = await _started(user_manager=CertificateUserManager(allow_anonymous=True))
    try:
        async with Client(srv.endpoint.geturl()) as client:
            assert await client.nodes.server_state.read_value() == ua.ServerState.Running
            with pytest.raises(ua.uaerrors.BadUserAccessDenied):
                await client.nodes.server_state.write_value(1)
    finally:
        await srv.stop()


async def test_srv7_custom_manager_without_token_types_keeps_all_configured_tokens() -> None:
    """Part 4, 7.41: a manager that doesn't list token types is offered every token class the server supports."""

    class Duck:
        def get_user(self, iserver: Any, username: Any = None, password: Any = None, certificate: Any = None) -> None:
            return None

    srv = Server(user_manager=Duck())  # type: ignore[arg-type]
    assert set(srv.iserver.offered_token_classes()) == set(srv.iserver.supported_tokens)
    assert UserManager.accepted_token_types == {
        ua.UserTokenType.Anonymous,
        ua.UserTokenType.UserName,
        ua.UserTokenType.Certificate,
    }


USER_CERTIFICATE = (PKI_FILES / "certificates" / "peer-certificate-example-1.der").read_bytes()


@pytest.fixture
async def unsecured_server() -> AsyncIterator[Server]:
    srv = Server(user_manager=PermissiveUserManager())
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    srv.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    await srv.start()
    yield srv
    await srv.stop()


async def _activate(server: Server, token: object) -> ua.ActivateSessionResult:
    probe = await SessionProbe.open(server.endpoint.geturl())
    try:
        session = await probe.create_session()
        probe.use(session.AuthenticationToken)
        params = ua.ActivateSessionParameters()
        params.UserIdentityToken = token
        params.ClientSignature = ua.SignatureData()
        return await probe.client.uaclient.activate_session(params)
    finally:
        probe.client.disconnect_socket()


async def test_srv6_anonymous_policy_id_is_matched(unsecured_server: Server) -> None:
    """Part 4, 7.41 and 7.40.3: the PolicyId names one of the endpoint's UserTokenPolicies."""
    with pytest.raises(ua.uaerrors.BadIdentityTokenInvalid):
        await _activate(unsecured_server, ua.AnonymousIdentityToken(PolicyId="no-such-policy"))


async def test_srv6_matching_anonymous_policy_id_is_accepted(unsecured_server: Server) -> None:
    """Part 4, 7.41 and 7.40.3: the PolicyId of an offered Anonymous policy is accepted."""
    await _activate(unsecured_server, ua.AnonymousIdentityToken(PolicyId="anonymous"))


async def test_srv6_empty_token_is_anonymous_without_policy_id(unsecured_server: Server) -> None:
    """Part 4, 5.7.3.2: an empty UserIdentityToken is Anonymous and carries no PolicyId."""
    await _activate(unsecured_server, ua.ExtensionObject())


async def test_srv6_token_class_not_offered_by_the_endpoint_is_identity_token_rejected(
    unsecured_server: Server,
) -> None:
    """Part 4, 5.7.3.2 and 7.40.1: the None endpoint offers no Certificate policy without a signing policy."""
    token = ua.X509IdentityToken(PolicyId="certificate", CertificateData=USER_CERTIFICATE)
    with pytest.raises(ua.uaerrors.BadIdentityTokenRejected):
        await _activate(unsecured_server, token)


async def test_srv6_user_name_token_without_user_name_policy_is_identity_token_rejected() -> None:
    """Part 4, 5.7.3.2 and 7.40.1: a UserName token needs a UserName policy on the endpoint."""
    srv = Server(user_manager=PermissiveUserManager())
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    srv.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    await srv.start()
    try:
        token = ua.UserNameIdentityToken(PolicyId="username", UserName="alice", Password=b"secret")
        with pytest.raises(ua.uaerrors.BadIdentityTokenRejected):
            await _activate(srv, token)
    finally:
        await srv.stop()


async def test_srv49_no_username_policy_on_unsecured_endpoint_without_encryption(unsecured_server: Server) -> None:
    """Part 4, 7.40.4: a password must not be advertised in clear on an endpoint that cannot protect it."""
    endpoints = await unsecured_server.get_endpoints()
    assert endpoints
    for endpoint in endpoints:
        assert all(policy.TokenType != ua.UserTokenType.UserName for policy in endpoint.UserIdentityTokens)


async def test_srv49_plaintext_password_policy_can_be_enabled_explicitly() -> None:
    """Part 4, 7.40.4: the administrator may opt in to a password in clear."""
    srv = Server(user_manager=PermissiveUserManager())
    srv.allow_plaintext_password = True
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    srv.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    await srv.start()
    try:
        endpoints = await srv.get_endpoints()
        assert any(policy.TokenType == ua.UserTokenType.UserName for policy in endpoints[0].UserIdentityTokens)
    finally:
        await srv.stop()


class Delays:
    def __init__(self) -> None:
        self.slept: list[float] = []

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def delays(shared_signing_server: Server) -> Delays:
    recorded = Delays()
    shared_signing_server.iserver.identity_guard.sleep = recorded.sleep
    return recorded


async def _login(server: Server, password: str | None = None) -> None:
    client = await signing_client(server)
    if password is not None:
        client.set_password(password)
    try:
        await client.connect()
    finally:
        await client.disconnect()


async def _fail(server: Server, times: int) -> None:
    for _ in range(times):
        with pytest.raises(ua.uaerrors.BadUserAccessDenied):
            await _login(server, "wrong")


async def test_srv39_repeated_bad_passwords_are_delayed(shared_signing_server: Server, delays: Delays) -> None:
    """Part 4, 5.7.3.1: from the sixth attempt of a peer on, every answer waits 1 s, doubling."""
    await _fail(shared_signing_server, 5)
    assert delays.slept == []
    await _fail(shared_signing_server, 3)
    assert delays.slept == [1.0, 2.0, 4.0]


async def test_srv39_valid_token_is_delayed_after_five_failures(shared_signing_server: Server, delays: Delays) -> None:
    """Part 4, 5.7.3.1: the delay applies to a correct password too, which is not answered at once."""
    await _fail(shared_signing_server, 5)
    await _login(shared_signing_server)
    assert delays.slept == [1.0]


async def test_srv39_success_resets_the_counter(shared_signing_server: Server, delays: Delays) -> None:
    """Part 4, 5.7.3.1: a successful login clears the failures of the peer."""
    await _fail(shared_signing_server, 5)
    await _login(shared_signing_server)
    await _login(shared_signing_server)
    await _fail(shared_signing_server, 5)
    assert delays.slept == [1.0]


async def test_srv39_secured_login_is_recorded_under_the_application_uri(
    shared_signing_server: Server, delays: Delays
) -> None:
    """Part 4, 5.7.3.1: a failed secured login is recorded under the ApplicationUri of the client certificate."""
    await _fail(shared_signing_server, 1)
    assert list(shared_signing_server.iserver.identity_guard.records) == [f"uri:{CLIENT_APPLICATION_URI}"]


async def test_srv39_key_is_the_ip_address_when_unsecured() -> None:
    """Part 4, 5.7.3.1: unsecured channels are told apart by the IP address."""
    srv = Server(user_manager=TwoUserManager())
    srv.allow_plaintext_password = True
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    srv.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    await srv.start()
    try:
        client = Client(srv.endpoint.geturl())
        client.set_user("alice")
        client.set_password("wrong")
        with pytest.raises(ua.uaerrors.BadUserAccessDenied):
            await client.connect()
        await client.disconnect()
        assert list(srv.iserver.identity_guard.records) == ["ip:127.0.0.1"]
        assert TWO_SESSION_USERS["alice"] != "wrong"
    finally:
        await srv.stop()


@pytest.fixture
def guard() -> IdentityGuard:
    return IdentityGuard()


def test_srv39_parallel_attempts_count_in_flight(guard: IdentityGuard) -> None:
    """Part 4, 5.7.3.1: attempts still waiting count as failures, so a burst cannot beat the counter."""
    delays = [guard.begin("uri:burst") for _ in range(8)]
    assert delays == [0.0] * 5 + [1.0, 2.0, 4.0]


def test_srv39_delay_is_capped(guard: IdentityGuard) -> None:
    """Part 4, 5.7.3.1: the delay doubles up to 30 s."""
    for _ in range(40):
        guard.begin("uri:flood")
    assert guard.begin("uri:flood") == 30.0


def test_srv39_other_peers_are_not_delayed(guard: IdentityGuard) -> None:
    """Part 4, 5.7.3.1: failures of one peer do not slow down another."""
    for _ in range(10):
        guard.begin("uri:noisy")
    assert guard.begin("uri:quiet") == 0.0


def test_srv39_table_is_bounded() -> None:
    """Part 4, 5.7.3.1: the memory for failure counters has a limit; the oldest entry goes first."""
    guard = IdentityGuard(max_keys=3)
    for number in range(5):
        guard.begin(f"uri:{number}")
        guard.record_failure(f"uri:{number}")
        guard.end(f"uri:{number}")
    assert list(guard.records) == ["uri:2", "uri:3", "uri:4"]


def test_srv39_failures_expire_after_ten_minutes() -> None:
    """Part 4, 5.7.3.1: a peer without failures for ten minutes starts afresh."""
    clock = Clock()
    guard = IdentityGuard(clock=clock)
    for _ in range(5):
        guard.begin("uri:old")
        guard.record_failure("uri:old")
        guard.end("uri:old")
    clock.now += 601
    assert guard.begin("uri:old") == 0.0


async def test_srv39_wait_is_an_await_that_leaves_other_requests_alone(shared_signing_server: Server) -> None:
    """Part 4, 5.7.3.1: the delay is a wait on the request's own task, other Sessions keep working."""
    release = asyncio.Event()
    waiting = asyncio.Event()

    async def hold(seconds: float) -> None:
        waiting.set()
        await release.wait()

    working = await signing_client(shared_signing_server, "bob")
    async with working:
        await _fail(shared_signing_server, 5)
        shared_signing_server.iserver.identity_guard.sleep = hold
        delayed = asyncio.create_task(_login(shared_signing_server))
        await asyncio.wait_for(waiting.wait(), 10)
        assert await working.nodes.server_state.read_value() == ua.ServerState.Running
        assert not delayed.done()
        release.set()
        await asyncio.wait_for(delayed, 10)


def test_srv39_key_is_the_application_uri_of_the_certificate() -> None:
    """Part 4, 5.7.3.1: a secured channel is identified by the ApplicationUri in the client certificate."""
    uri = "urn:example:backoff-client"
    security = ChannelSecurity(make_certificate(uri)[0], SecurityPolicyBasic256Sha256.URI, ua.MessageSecurityMode.Sign)
    assert peer_key(security, "10.1.2.3") == f"uri:{uri}"


def test_srv39_key_falls_back_to_the_address_without_a_uri() -> None:
    """Part 4, 5.7.3.1: a certificate without an ApplicationUri leaves the address as the key."""
    certificate = make_identity("without-uri", uri=None).der
    security = ChannelSecurity(certificate, SecurityPolicyBasic256Sha256.URI, ua.MessageSecurityMode.Sign)
    assert peer_key(security, "10.1.2.3") == "ip:10.1.2.3"


def test_srv39_key_of_an_unsecured_channel_is_the_address_only() -> None:
    """Part 4, 5.7.3.1: with mode None the key is the IP address, whatever the client claims."""
    security = ChannelSecurity(
        make_certificate("urn:example:claimed")[0], SecurityPolicyNone.URI, ua.MessageSecurityMode.None_
    )
    assert peer_key(security, "10.1.2.3") == "ip:10.1.2.3"


class _AsyncOnlyManager:
    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.entered = asyncio.Event()

    async def authenticate(
        self,
        iserver: Any,
        username: str | None = None,
        password: str | None = None,
        certificate: Any = None,
    ) -> User | None:
        self.entered.set()
        await self.release.wait()
        return User(role=UserRole.User, name=username)


async def test_srv101_a_manager_with_async_authenticate_does_not_block_the_loop(signing_server: Server) -> None:
    manager = _AsyncOnlyManager()
    signing_server.iserver.user_manager = manager
    client = await signing_client(signing_server)
    login = asyncio.create_task(client.connect())
    await asyncio.wait_for(manager.entered.wait(), 5)
    assert await signing_server.nodes.server_state.read_value() == ua.ServerState.Running
    manager.release.set()
    await asyncio.wait_for(login, 5)
    await client.disconnect()


async def test_srv101_the_default_authenticate_calls_get_user() -> None:
    class Manager(UserManager):
        def get_user(
            self,
            iserver: Any,
            username: str | None = None,
            password: str | None = None,
            certificate: Any = None,
        ) -> User | None:
            return User(role=UserRole.Admin, name=username)

    assert await Manager().authenticate(None, username="x") == User(role=UserRole.Admin, name="x")


def test_a_user_certificate_needs_an_rsa_private_key() -> None:
    """The RSA security policies sign the user token with RSA; another key is a configuration error, not a TypeError."""
    client = Client("opc.tcp://127.0.0.1:4840")
    client.user_private_key = ec.generate_private_key(ec.SECP256R1())
    client._policy_ids = [
        ua.UserTokenPolicy(
            PolicyId="cert", TokenType=ua.UserTokenType.Certificate, SecurityPolicyUri=SecurityPolicyBasic256Sha256.URI
        )
    ]
    certificate = uacrypto.x509_from_der((PKI_FILES / "certificate-example.der").read_bytes())
    assert certificate is not None
    with pytest.raises(ua.uaerrors.ConfigurationError, match="RSA private key"):
        client._add_certificate_auth(ua.ActivateSessionParameters(), certificate, b"challenge")
