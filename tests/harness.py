"""Building blocks for tests that act as a misbehaving peer.

The fixtures that use them are in conftest.py: raw_peer, tampered_responses and two_sessions.
"""

from __future__ import annotations

import asyncio
import struct
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ua_client import UaClient
from enginir_opcua.common.connection import FrameReader, SecureChannel, TransportLimits
from enginir_opcua.common.utils import Buffer
from enginir_opcua.crypto.permission_rules import User, UserRole
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256, SecurityPolicyNone
from enginir_opcua.server.internal_server import InternalServer
from enginir_opcua.ua.ua_binary import nodeid_from_binary, struct_from_binary, struct_to_binary, uatcp_to_binary
from tests.pki import generated_pki

CONNECTION_PROTOCOL_HEADER = struct.Struct("<3scI")
PKI = generated_pki()
PKI_FILES = PKI.fixed


class RawPeer:
    """A UA-TCP peer that sends hand-made bytes and reads raw replies (Part 6, 7.1)."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer

    @classmethod
    async def connect(cls, host: str, port: int) -> RawPeer:
        reader, writer = await asyncio.open_connection(host, port)
        return cls(reader, writer)

    async def send(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def send_hello(self, hello: ua.Hello) -> None:
        await self.send(uatcp_to_binary(ua.MessageType.Hello, hello))

    async def send_message(
        self, message_type: bytes, body: bytes, chunk_type: bytes = b"F", size: int | None = None
    ) -> None:
        announced = CONNECTION_PROTOCOL_HEADER.size + len(body) if size is None else size
        await self.send(CONNECTION_PROTOCOL_HEADER.pack(message_type, chunk_type, announced) + body)

    async def receive(self, timeout: float = 5.0) -> tuple[bytes, bytes]:
        header = await asyncio.wait_for(self._reader.readexactly(CONNECTION_PROTOCOL_HEADER.size), timeout)
        message_type, _, message_size = CONNECTION_PROTOCOL_HEADER.unpack(header)
        body = await asyncio.wait_for(self._reader.readexactly(message_size - CONNECTION_PROTOCOL_HEADER.size), timeout)
        return message_type, body

    async def receive_acknowledge(self, timeout: float = 5.0) -> ua.Acknowledge:
        message_type, body = await self.receive(timeout)
        if message_type != ua.MessageType.Acknowledge:
            raise AssertionError(f"expected an Acknowledge, got {message_type!r}")
        return struct_from_binary(ua.Acknowledge, Buffer(body))

    async def receive_error(self, timeout: float = 5.0) -> ua.ErrorMessage:
        message_type, body = await self.receive(timeout)
        if message_type != ua.MessageType.Error:
            raise AssertionError(f"expected an Error, got {message_type!r}")
        return struct_from_binary(ua.ErrorMessage, Buffer(body))

    async def receive_hello(self, timeout: float = 5.0) -> ua.Hello:
        message_type, body = await self.receive(timeout)
        if message_type != ua.MessageType.Hello:
            raise AssertionError(f"expected a Hello, got {message_type!r}")
        return struct_from_binary(ua.Hello, Buffer(body))

    async def send_acknowledge(self, acknowledge: ua.Acknowledge) -> None:
        await self.send(uatcp_to_binary(ua.MessageType.Acknowledge, acknowledge))

    async def is_closed_by_peer(self, timeout: float = 5.0) -> bool:
        try:
            return await asyncio.wait_for(self._reader.read(1), timeout) == b""
        except (ConnectionResetError, TimeoutError):
            return False

    async def close(self) -> None:
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except ConnectionResetError:
            pass


class RawServer:
    """A listening socket that hands the first connection of a client under test to the test as a RawPeer."""

    def __init__(self, server: asyncio.Server, connected: asyncio.Future[RawPeer], port: int) -> None:
        self._server = server
        self._connected = connected
        self.host = "127.0.0.1"
        self.port = port

    @classmethod
    async def start(cls) -> RawServer:
        connected: asyncio.Future[RawPeer] = asyncio.get_running_loop().create_future()

        def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            if not connected.done():
                connected.set_result(RawPeer(reader, writer))

        server = await asyncio.start_server(accept, "127.0.0.1", 0)
        return cls(server, connected, server.sockets[0].getsockname()[1])

    @property
    def url(self) -> str:
        return f"opc.tcp://{self.host}:{self.port}"

    async def accept(self, timeout: float = 5.0) -> RawPeer:
        return await asyncio.wait_for(self._connected, timeout)

    async def close(self) -> None:
        if self._connected.done():
            await self._connected.result().close()
        self._server.close()


def secure_chunk(
    chunk_type: bytes,
    request_id: int,
    sequence_number: int,
    body: bytes,
    message_type: bytes = b"MSG",
    channel_id: int = 0,
    token_id: int = 0,
) -> bytes:
    """A chunk of the None policy: header, channel id, token id, sequence header and body (Part 6, 6.7.2)."""
    content = struct.pack("<IIII", channel_id, token_id, sequence_number, request_id) + body
    return (
        CONNECTION_PROTOCOL_HEADER.pack(message_type, chunk_type, CONNECTION_PROTOCOL_HEADER.size + len(content))
        + content
    )


class _ChannelIds:
    @staticmethod
    def get_new_channel_id() -> int:
        return 4242


def _frames(data: bytes) -> list[tuple[ua.Header, Buffer]]:
    reader = FrameReader(lambda: 2**31)
    reader.feed(data)
    return list(reader.frames())


async def send_open_request(
    peer: RawPeer,
    channel: SecureChannel,
    params: ua.OpenSecureChannelParameters,
    message_channel_id: int | None = None,
) -> None:
    saved = channel.security_token.ChannelId
    if message_channel_id is not None:
        channel.security_token.ChannelId = message_channel_id
    request = ua.OpenSecureChannelRequest(Parameters=params)
    data = channel.message_to_binary(struct_to_binary(request), ua.MessageType.SecureOpen, request_id=99)
    channel.security_token.ChannelId = saved
    await peer.send(data)


async def receive_message(peer: RawPeer, channel: SecureChannel) -> ua.Message:
    """Reads one single-chunk secure message from the peer and decodes it with the channel."""
    message_type, body = await peer.receive()
    data = CONNECTION_PROTOCOL_HEADER.pack(message_type, b"F", CONNECTION_PROTOCOL_HEADER.size + len(body)) + body
    ((header, chunk_body),) = _frames(data)
    message = channel.receive_from_header_and_body(header, chunk_body)
    assert isinstance(message, ua.Message)
    return message


async def receive_service_status(peer: RawPeer, channel: SecureChannel) -> int:
    """Reads one OPN reply (a ServiceFault or a response) and returns its ServiceResult."""
    message = await receive_message(peer, channel)
    reply = message.body()
    nodeid_from_binary(reply)
    return struct_from_binary(ua.ResponseHeader, reply).ServiceResult.value


async def open_channel_as_client(peer: RawPeer, lifetime: int = 3_600_000) -> SecureChannel:
    """Runs Hello and an OpenSecureChannel Issue with the None policy against the real server; returns the client side."""
    await peer.send_hello(ua.Hello())
    await peer.receive_acknowledge()
    channel = SecureChannel(SecurityPolicyNone(), TransportLimits())
    params = ua.OpenSecureChannelParameters(
        RequestType=ua.SecurityTokenRequestType.Issue,
        SecurityMode=ua.MessageSecurityMode.None_,
        RequestedLifetime=lifetime,
    )
    request = ua.OpenSecureChannelRequest(Parameters=params)
    await peer.send(channel.message_to_binary(struct_to_binary(request), ua.MessageType.SecureOpen, request_id=1))
    message = await receive_message(peer, channel)
    response = struct_from_binary(ua.OpenSecureChannelResponse, message.body())
    channel.set_channel(response.Parameters, params.RequestType, params.ClientNonce)
    return channel


async def open_channel_as_server(
    uaclient: UaClient, peer: RawPeer, tamper: Callable[[ua.OpenSecureChannelResult], None] | None = None
) -> SecureChannel:
    """Answers the OpenSecureChannel Issue of a client under test with the None policy; returns the server side."""
    channel = SecureChannel(SecurityPolicyNone(), TransportLimits())
    opening = asyncio.create_task(
        uaclient.open_secure_channel(
            ua.OpenSecureChannelParameters(
                RequestType=ua.SecurityTokenRequestType.Issue,
                SecurityMode=ua.MessageSecurityMode.None_,
                RequestedLifetime=3_600_000,
            )
        )
    )
    message = await receive_message(peer, channel)
    request = struct_from_binary(ua.OpenSecureChannelRequest, message.body())
    result = channel.open(request.Parameters, _ChannelIds())
    if tamper is not None:
        tamper(result)
    response = ua.OpenSecureChannelResponse(Parameters=result)
    await peer.send(
        channel.message_to_binary(
            struct_to_binary(response), ua.MessageType.SecureOpen, request_id=message.request_id()
        )
    )
    if tamper is None:
        await opening
    return channel


async def connect_client(raw_server: RawServer, acknowledge: ua.Acknowledge | None = None) -> tuple[UaClient, RawPeer]:
    """Connects a UaClient to the raw_server and completes the handshake with the given Acknowledge."""
    uaclient = UaClient(timeout=1)
    await uaclient.connect_socket(raw_server.host, raw_server.port)
    hello_task = asyncio.create_task(uaclient.send_hello(raw_server.url))
    peer = await raw_server.accept()
    await peer.receive_hello()
    await peer.send_acknowledge(acknowledge or ua.Acknowledge(ReceiveBufferSize=65535, SendBufferSize=65535))
    await hello_task
    return uaclient, peer


ResponseTamper = Callable[[Any], None]


class ResponseTampering:
    """Changes server responses of a given type just before they are encoded."""

    def __init__(self) -> None:
        self._tampers: dict[type, ResponseTamper] = {}

    def on(self, response_type: type, tamper: ResponseTamper) -> None:
        self._tampers[response_type] = tamper

    def apply(self, response: Any) -> None:
        tamper = self._tampers.get(type(response))
        if tamper is not None:
            tamper(response)


TWO_SESSION_USERS = {"alice": "alice-password", "bob": "bob-password"}


class TwoUserManager:
    def get_user(
        self,
        iserver: InternalServer,
        username: str | None = None,
        password: str | None = None,
        certificate: Any = None,
    ) -> User | None:
        if username is not None and TWO_SESSION_USERS.get(username) == password:
            return User(role=UserRole.User, name=username)
        return None


class SessionProbe:
    """A client with an open None-policy channel that creates, activates, uses and closes sessions by token."""

    def __init__(self, url: str) -> None:
        self.client = Client(url)

    @classmethod
    async def open(cls, url: str) -> SessionProbe:
        probe = cls(url)
        await probe.client.connect_socket()
        await probe.client.send_hello()
        await probe.client.open_secure_channel()
        return probe

    def use(self, token: ua.NodeId) -> None:
        self.client.uaclient.session.restore_authentication_token(token)

    async def create_session(
        self, client_nonce: bytes | None = None, timeout_ms: float = 60_000, use_new_token: bool = True
    ) -> ua.CreateSessionResult:
        params = ua.CreateSessionParameters()
        params.ClientDescription = ua.ApplicationDescription(
            ApplicationUri=self.client.application_uri, ApplicationType=ua.ApplicationType.Client
        )
        params.EndpointUrl = self.client.server_url.geturl()
        params.SessionName = "probe"
        params.ClientNonce = bytes(32) if client_nonce is None else client_nonce
        params.RequestedSessionTimeout = timeout_ms
        previous = self.client.uaclient.session.authentication_token
        result = await self.client.uaclient.create_session(params)
        if not use_new_token:
            self.use(previous)
        return result

    async def activate(self, token: ua.NodeId) -> ua.ActivateSessionResult:
        self.use(token)
        params = ua.ActivateSessionParameters()
        params.UserIdentityToken = ua.AnonymousIdentityToken(PolicyId="anonymous")
        params.ClientSignature = ua.SignatureData()
        return await self.client.uaclient.activate_session(params)

    async def read_server_state(self, token: ua.NodeId) -> int:
        self.use(token)
        params = ua.ReadParameters()
        params.NodesToRead = [
            ua.ReadValueId(NodeId=ua.NodeId(ua.ObjectIds.Server_ServerStatus_State), AttributeId=ua.AttributeIds.Value)
        ]
        variant = (await self.client.uaclient.read(params))[0].Value
        assert variant is not None
        return int(variant.Value)

    async def send(self, token: ua.NodeId, request: Any, response_type: type) -> Any:
        self.use(token)
        data = await self.client.uaclient._send_request(request)
        response = struct_from_binary(response_type, data)
        response.ResponseHeader.ServiceResult.check()
        return response

    async def send_edited(
        self, token: ua.NodeId, request: Any, response_type: type, edit: Callable[[bytes], bytes]
    ) -> Any:
        """Sends the encoded request after `edit` changed its bytes, for malformed bodies."""
        self.use(token)
        protocol = self.client.uaclient.protocol
        assert protocol is not None
        protocol._setup_request_header(request.RequestHeader, 1)
        message = protocol._channel.message_to_binary(
            edit(struct_to_binary(request)),
            message_type=ua.MessageType.SecureMessage,
            request_id=protocol._request_id + 1,
        )
        protocol._request_id += 1
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        protocol._callbackmap[protocol._request_id] = future
        assert protocol.transport is not None
        protocol.transport.write(message)
        protocol.check_answer(await asyncio.wait_for(future, 5), "")
        response = struct_from_binary(response_type, await future)
        response.ResponseHeader.ServiceResult.check()
        return response

    async def close_session(self, token: ua.NodeId, delete_subscriptions: bool = True) -> None:
        request = ua.CloseSessionRequest(DeleteSubscriptions=delete_subscriptions)
        await self.send(token, request, ua.CloseSessionResponse)

    def close(self) -> None:
        self.client.disconnect_socket()


@dataclass
class TwoSessions:
    server: Server
    alice: Client
    bob: Client


async def signing_client(server: Server, user: str = "alice") -> Client:
    """A client for the signing_server fixture: Basic256Sha256, Sign, logged in as one of TWO_SESSION_USERS."""
    client = Client(server.endpoint.geturl())
    await client.set_security(
        SecurityPolicyBasic256Sha256,
        PKI.peer1.certificate,
        PKI.peer1.key,
        None,
        PKI.server.certificate,
        ua.MessageSecurityMode.Sign,
    )
    client.set_user(user)
    client.set_password(TWO_SESSION_USERS[user])
    return client


def make_certificate(application_uri: str) -> tuple[bytes, bytes]:
    """A self-signed certificate (DER) with the ApplicationUri, and its private key (PEM), made for one test."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test application")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(application_uri)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return certificate.public_bytes(serialization.Encoding.DER), pem


async def start_discovery_server(port: int) -> Server:
    """A discovery server that accepts registrations on a None and a SignAndEncrypt endpoint."""
    srv = Server(allow_no_security=True)
    await srv.init()
    await srv.set_application_uri("urn:enginir:opcua:discovery")
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    srv.set_security_policy([ua.SecurityPolicyType.NoSecurity, ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    await srv.load_certificate(PKI.server.certificate)
    await srv.load_private_key(PKI.server.key)
    srv.set_trust_store(PKI.trust_store())
    srv.accept_server_registrations()
    await srv.start()
    return srv


async def give_identity(srv: Server, application_uri: str, discovery: Server | None = None) -> None:
    """Gives the server an ApplicationUri and a generated certificate that carries it.

    The server trusts the certificates of PKI; the discovery server, when given, trusts the new certificate.
    """
    peer = PKI.issue(f"identity-{abs(hash(application_uri))}", application_uri)
    await srv.load_certificate(peer.certificate)
    await srv.load_private_key(peer.key)
    await srv.set_application_uri(application_uri)
    srv.set_trust_store(PKI.trust_store())
    if discovery is not None and discovery.iserver.trust_store is not None:
        discovery.iserver.trust_store.pin(peer.identity.certificate)
