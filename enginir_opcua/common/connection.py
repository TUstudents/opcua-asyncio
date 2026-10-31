from __future__ import annotations

import logging
import secrets
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol

from enginir_opcua import ua
from enginir_opcua.ua.uaerrors import UaError, UaStatusCodeError

from ..crypto.security_policies import SecurityPolicyNone
from ..crypto.uacrypto import certificate_thumbprint, split_certificate_chain
from ..ua.ua_binary import header_from_binary, header_to_binary, struct_from_binary, struct_to_binary, uatcp_to_binary
from .utils import Buffer, NotEnoughData

if TYPE_CHECKING:
    from ..crypto.security_policies import CryptographyNone, SecurityPolicy, SecurityPolicyFactory

_logger = logging.getLogger("enginir_opcua.uaprotocol")

HELLO_MAX_CHUNK_SIZE = 8192
MIN_BUFFER_SIZE = 8192
MAX_ENDPOINT_URL_BYTES = 4096
MAX_ERROR_REASON_BYTES = 4096
KNOWN_MESSAGE_TYPES = frozenset(
    {
        ua.MessageType.Hello,
        ua.MessageType.Acknowledge,
        ua.MessageType.Error,
        ua.MessageType.SecureOpen,
        ua.MessageType.SecureMessage,
        ua.MessageType.SecureClose,
    }
)


REVERSE_HELLO_TYPES = frozenset({ua.MessageType.ReverseHello, ua.MessageType.Error})
MAX_REVERSE_HELLO_SIZE = 8 + 2 * (4 + MAX_ENDPOINT_URL_BYTES)


def _refuse_unchecked_certificate(_chain: bytes) -> None:
    raise TransportError(
        ua.StatusCodes.BadSecurityChecksFailed,
        "No certificate check is set on the channel, so no peer certificate is trusted",
    )


class TransportError(UaError):
    """A failure that ends the connection and is reported to the peer as an Error message."""

    def __init__(self, status: int, reason: str = "") -> None:
        super().__init__(status, reason)
        self.status = status
        self.reason = reason


class MessageSizeExceeded(TransportError):
    """A Message above the MaxMessageSize or MaxChunkCount this side announced."""

    def __init__(self, reason: str) -> None:
        super().__init__(ua.StatusCodes.BadTcpMessageTooLarge, reason)


@dataclass
class AbortedMessage:
    """An Abort chunk (OPC 10000-6 v1.05, 6.7.3): the Message of request_id is discarded and the channel stays open."""

    request_id: int
    error: ua.ErrorMessage

    @staticmethod
    def from_chunk(chunk: MessageChunk) -> AbortedMessage:
        try:
            error = struct_from_binary(ua.ErrorMessage, Buffer(chunk.Body))
            if len((error.Reason or "").encode()) > MAX_ERROR_REASON_BYTES:
                raise UaError("Reason is too long")
        except Exception:
            error = ua.ErrorMessage(ua.StatusCode(ua.StatusCodes.BadUnexpectedError), "")
        return AbortedMessage(chunk.SequenceHeader.RequestId, error)


class OpenRequestError(UaError):
    """A verified OpenSecureChannel request with an invalid parameter; answered with a ServiceFault."""

    def __init__(self, status: int, reason: str = "") -> None:
        super().__init__(status, reason)
        self.status = status
        self.reason = reason


class MessageTooLarge(UaError):
    """A Message above the MaxMessageSize or MaxChunkCount the peer announced; nothing was written."""


class MessageAborted(UaError):
    """Encoding failed after the first chunk; written holds the chunks encoded so far and the Abort chunk."""

    def __init__(self, written: bytes) -> None:
        super().__init__("Message aborted")
        self.written = written


def reverse_hello_to_binary(server_uri: str, endpoint_url: str) -> bytes:
    """A ReverseHello message (OPC 10000-6 v1.05, 7.1.2.6); both strings encode to fewer than 4096 bytes."""
    for name, value in (("ServerUri", server_uri), ("EndpointUrl", endpoint_url)):
        if len(value.encode()) >= MAX_ENDPOINT_URL_BYTES:
            raise ValueError(f"{name} must encode to fewer than {MAX_ENDPOINT_URL_BYTES} bytes")
    return uatcp_to_binary(ua.MessageType.ReverseHello, ua.ReverseHello(server_uri, endpoint_url))


def error_message_to_binary(status: int, reason: str = "") -> bytes:
    """An Error message (OPC 10000-6 v1.05, 7.1.2.5); the Reason is cut to 4096 bytes."""
    reason = reason.encode()[:MAX_ERROR_REASON_BYTES].decode(errors="ignore")
    return uatcp_to_binary(ua.MessageType.Error, ua.ErrorMessage(ua.StatusCode(status), reason))


class FrameReader:
    """
    Cuts the byte stream of a UA-TCP connection into whole messages (OPC 10000-6 v1.05, 7.1.2.2).
    The size of a message is checked against the limit before any of its body is waited for.
    """

    def __init__(self, max_frame_size: Callable[[], int], known_types: frozenset[bytes] = KNOWN_MESSAGE_TYPES) -> None:
        self.buffer = bytearray()
        self._max_frame_size = max_frame_size
        self._known_types = known_types

    def feed(self, data: bytes) -> None:
        self.buffer += data

    def frames(self) -> Iterator[tuple[ua.Header, Buffer]]:
        """The whole messages in the buffer, each as its header and its body; a partial message stays buffered."""
        pos = 0
        try:
            while True:
                if len(self.buffer) - pos < 3:
                    return
                if bytes(self.buffer[pos : pos + 3]) not in self._known_types:
                    raise TransportError(ua.StatusCodes.BadTcpMessageTypeInvalid, "Unknown message type")
                try:
                    header = header_from_binary(Buffer(bytes(self.buffer[pos : pos + ua.Header.max_size()])))
                except NotEnoughData:
                    return
                except UaStatusCodeError as e:
                    raise TransportError(e.code, "Malformed message header") from e
                limit = self._max_frame_size()
                if header.packet_size > limit:
                    raise TransportError(
                        ua.StatusCodes.BadTcpMessageTooLarge, f"Message size {header.packet_size} exceeds {limit}"
                    )
                end = pos + header.packet_size
                if len(self.buffer) < end:
                    return
                yield header, Buffer(bytes(self.buffer[pos + header.header_size : end]))
                pos = end
        except TransportError:
            pos = len(self.buffer)
            raise
        finally:
            del self.buffer[:pos]


DEFAULT_MAX_MESSAGE_SIZE = 100 * 1024 * 1024
DEFAULT_MAX_CHUNK_COUNT = DEFAULT_MAX_MESSAGE_SIZE // 65535 + 1


@dataclass
class TransportLimits:
    """
    Limits of the tcp transport layer to prevent excessive resource usage.

    max_recv_buffer, max_message_size and max_chunk_count are what this side enforces on incoming data and
    tells the peer. max_send_buffer, send_max_message_size and send_max_chunk_count are what the peer
    told us and what this side obeys when sending (0 means the peer has no limit).
    """

    max_recv_buffer: int = 65535
    max_send_buffer: int = 65535
    max_chunk_count: int = DEFAULT_MAX_CHUNK_COUNT
    max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE
    send_max_message_size: int = 0
    send_max_chunk_count: int = 0

    def __post_init__(self) -> None:
        if self.max_message_size == 0:
            self.max_message_size = DEFAULT_MAX_MESSAGE_SIZE
        if self.max_chunk_count == 0:
            self.max_chunk_count = DEFAULT_MAX_CHUNK_COUNT

    def is_msg_size_within_limit(self, sz: int) -> bool:
        """Whether a received Message of sz bytes is within max_message_size; logs when it is not."""
        if self.max_message_size == 0:
            return True
        within_limit = sz <= self.max_message_size
        if not within_limit:
            _logger.error("Message size: %s is > configured max message size: %s", sz, self.max_message_size)
        return within_limit

    def is_chunk_count_within_limit(self, sz: int) -> bool:
        """Whether a received Message of sz chunks is within max_chunk_count; logs when it is not."""
        if self.max_chunk_count == 0:
            return True
        within_limit = sz <= self.max_chunk_count
        if not within_limit:
            _logger.error("Number of message chunks: %s is > configured max chunk count: %s", sz, self.max_chunk_count)
        return within_limit

    @staticmethod
    def check_hello(msg: ua.Hello) -> None:
        """Refuse a Hello with a buffer below 8192 bytes or an EndpointUrl above 4096 bytes (7.1.2.3)."""
        for name in ("ReceiveBufferSize", "SendBufferSize"):
            size = getattr(msg, name)
            if size < MIN_BUFFER_SIZE:
                raise TransportError(
                    ua.StatusCodes.BadInvalidArgument, f"{name} {size} is below the minimum of {MIN_BUFFER_SIZE}"
                )
        if len((msg.EndpointUrl or "").encode()) > MAX_ENDPOINT_URL_BYTES:
            raise TransportError(ua.StatusCodes.BadTcpEndpointUrlInvalid, "EndpointUrl is too long")

    def create_acknowledge_and_set_limits(self, msg: ua.Hello) -> ua.Acknowledge:
        """Server side: check the Hello, revise the buffer sizes down to both sides' limits and answer them."""
        self.check_hello(msg)
        ack = ua.Acknowledge()
        ack.ReceiveBufferSize = min(msg.SendBufferSize, self.max_recv_buffer)
        ack.SendBufferSize = min(msg.ReceiveBufferSize, self.max_send_buffer)
        ack.MaxChunkCount = self.max_chunk_count
        ack.MaxMessageSize = self.max_message_size
        self.max_recv_buffer = ack.ReceiveBufferSize
        self.max_send_buffer = ack.SendBufferSize
        self.send_max_message_size = msg.MaxMessageSize
        self.send_max_chunk_count = msg.MaxChunkCount
        _logger.info("updated server limits to: %s", self)
        return ack

    def create_hello_limits(self, msg: ua.Hello) -> ua.Hello:
        """Client side: write this side's limits into the Hello."""
        msg.ReceiveBufferSize = self.max_recv_buffer
        msg.SendBufferSize = self.max_send_buffer
        msg.MaxChunkCount = self.max_chunk_count
        msg.MaxMessageSize = self.max_message_size
        return msg

    def update_client_limits(self, msg: ua.Acknowledge) -> None:
        """Client side: check the Acknowledge against the Hello that was sent and adopt its limits (7.1.2.4)."""
        if msg.ProtocolVersion > 0:
            raise TransportError(ua.StatusCodes.BadProtocolVersionUnsupported, "Acknowledge version is too high")
        for name, size, sent in (
            ("ReceiveBufferSize", msg.ReceiveBufferSize, self.max_send_buffer),
            ("SendBufferSize", msg.SendBufferSize, self.max_recv_buffer),
        ):
            if size < MIN_BUFFER_SIZE or size > sent:
                raise TransportError(
                    ua.StatusCodes.BadInvalidArgument, f"Acknowledge {name} {size} is outside {MIN_BUFFER_SIZE}..{sent}"
                )
        self.max_send_buffer = msg.ReceiveBufferSize
        self.max_recv_buffer = msg.SendBufferSize
        self.send_max_message_size = msg.MaxMessageSize
        self.send_max_chunk_count = msg.MaxChunkCount
        _logger.info("updated client limits to: %s", self)


class MessageChunk:
    """
    Message Chunk, as described in OPC 10000-6 v1.05, 6.7.2.
    """

    def __init__(
        self,
        crypto: CryptographyNone,
        body: bytes = b"",
        msg_type: bytes = ua.MessageType.SecureMessage,
        chunk_type: bytes = ua.ChunkType.Single,
    ) -> None:
        self.MessageHeader = ua.Header(msg_type, chunk_type)
        self.SecurityHeader: ua.SymmetricAlgorithmHeader | ua.AsymmetricAlgorithmHeader
        if msg_type in (ua.MessageType.SecureMessage, ua.MessageType.SecureClose):
            self.SecurityHeader = ua.SymmetricAlgorithmHeader()
        elif msg_type == ua.MessageType.SecureOpen:
            self.SecurityHeader = ua.AsymmetricAlgorithmHeader()
        else:
            raise ua.UaError(f"Unsupported message type: {msg_type!r}")
        self.SequenceHeader = ua.SequenceHeader()
        self.Body = body
        self.crypto = crypto

    @staticmethod
    def from_binary(security_policy: SecurityPolicy, data: Buffer) -> MessageChunk:
        """Decode, verify and decrypt one whole chunk, header included."""
        return MessageChunk.from_header_and_body(security_policy, header_from_binary(data), data)

    @staticmethod
    def from_header_and_body(
        security_policy: SecurityPolicy,
        header: ua.Header,
        buf: Buffer,
        symmetric_cryptography: CryptographyNone | None = None,
    ) -> MessageChunk:
        """
        Verify and decrypt the body of one chunk whose header was already read. symmetric_cryptography selects the
        keys of a token other than the current one; OPN chunks always use the asymmetric keys.
        """
        if len(buf) < header.body_size:
            raise ValueError("Full body expected here")
        data = buf.copy(header.body_size)
        buf.skip(header.body_size)
        security_header: ua.SymmetricAlgorithmHeader | ua.AsymmetricAlgorithmHeader
        if header.MessageType in (ua.MessageType.SecureMessage, ua.MessageType.SecureClose):
            security_header = struct_from_binary(ua.SymmetricAlgorithmHeader, data)
            crypto = symmetric_cryptography or security_policy.symmetric_cryptography
        elif header.MessageType == ua.MessageType.SecureOpen:
            security_header = struct_from_binary(ua.AsymmetricAlgorithmHeader, data)
            crypto = security_policy.asymmetric_cryptography
        else:
            raise ua.UaError(f"Unsupported message type: {header.MessageType!r}")
        obj = MessageChunk(crypto)
        obj.MessageHeader = header
        obj.SecurityHeader = security_header
        decrypted = crypto.decrypt(data.read(len(data)))
        signature_size = crypto.vsignature_size()
        if signature_size > 0:
            signature = decrypted[-signature_size:]
            decrypted = decrypted[:-signature_size]
            crypto.verify(
                header_to_binary(obj.MessageHeader) + struct_to_binary(obj.SecurityHeader) + decrypted, signature
            )
        data = Buffer(crypto.remove_padding(decrypted))
        obj.SequenceHeader = struct_from_binary(ua.SequenceHeader, data)
        obj.Body = data.read(len(data))
        return obj

    def encrypted_size(self, plain_size: int) -> int:
        """Size on the wire of a padded plain part of plain_size bytes once signed and encrypted."""
        size = plain_size + self.crypto.signature_size()
        pbs = self.crypto.plain_block_size()
        if size % pbs != 0:
            raise ua.UaError(f"Padded size {size} is not a multiple of the block size {pbs}")
        return size // pbs * self.crypto.encrypted_block_size()

    def to_binary(self) -> bytes:
        """Pad, sign and encrypt the chunk; the SequenceNumber must be set."""
        security = struct_to_binary(self.SecurityHeader)
        encrypted_part = struct_to_binary(self.SequenceHeader) + self.Body
        encrypted_part += self.crypto.padding(len(encrypted_part))
        self.MessageHeader.body_size = len(security) + self.encrypted_size(len(encrypted_part))
        header = header_to_binary(self.MessageHeader)
        encrypted_part += self.crypto.signature(header + security + encrypted_part)
        return header + security + self.crypto.encrypt(encrypted_part)

    @staticmethod
    def max_body_size(crypto: CryptographyNone, max_chunk_size: int) -> int:
        """The most body bytes a symmetric chunk of max_chunk_size bytes can carry with these keys."""
        max_encrypted_size = max_chunk_size - ua.Header.max_size() - ua.SymmetricAlgorithmHeader.max_size()
        max_plain_size = (max_encrypted_size // crypto.encrypted_block_size()) * crypto.plain_block_size()
        return max_plain_size - ua.SequenceHeader.max_size() - crypto.signature_size() - crypto.min_padding_size()

    @staticmethod
    def message_to_chunks(
        security_policy: SecurityPolicy,
        body: bytes,
        max_chunk_size: int,
        message_type: bytes = ua.MessageType.SecureMessage,
        channel_id: int = 1,
        request_id: int = 1,
        token_id: int = 1,
    ) -> list[MessageChunk]:
        """
        Split a message body into chunks of at most max_chunk_size bytes. An OPN body is always one chunk
        (OPC 10000-6 v1.05, 6.7.2). The SequenceNumber is left for the SecureChannel to set.
        """
        if message_type == ua.MessageType.SecureOpen:
            asymmetric_header = ua.AsymmetricAlgorithmHeader(SecurityPolicyURI=security_policy.URI)
            if security_policy.host_certificate and security_policy.Mode != ua.MessageSecurityMode.None_:
                asymmetric_header.SenderCertificate = security_policy.host_certificate + b"".join(
                    security_policy.host_certificate_chain
                )
            if security_policy.peer_certificate:
                asymmetric_header.ReceiverCertificateThumbPrint = certificate_thumbprint(
                    security_policy.peer_certificate
                )
            chunk = MessageChunk(security_policy.asymmetric_cryptography, body, message_type, ua.ChunkType.Single)
            chunk.SecurityHeader = asymmetric_header
            chunk.MessageHeader.ChannelId = channel_id
            chunk.SequenceHeader.RequestId = request_id
            return [chunk]

        crypto = security_policy.symmetric_cryptography
        max_size = MessageChunk.max_body_size(crypto, max_chunk_size)
        if max_size < 1:
            raise ua.UaError(f"A chunk of {max_chunk_size} bytes cannot carry any data")

        chunks = []
        for i in range(0, len(body), max_size):
            part = body[i : i + max_size]
            chunk_type = ua.ChunkType.Single if i + max_size >= len(body) else ua.ChunkType.Intermediate
            chunk = MessageChunk(crypto, part, message_type, chunk_type)
            chunk.SecurityHeader = ua.SymmetricAlgorithmHeader(TokenId=token_id)
            chunk.MessageHeader.ChannelId = channel_id
            chunk.SequenceHeader.RequestId = request_id
            chunks.append(chunk)
        return chunks

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__}({self.MessageHeader}, {self.SequenceHeader},"
            f" {self.SecurityHeader}, {len(self.Body)} bytes)"
        )

    __repr__ = __str__


class ChannelIdSource(Protocol):
    """What the server-side SecureChannel needs from the server: unique SecureChannelIds."""

    def get_new_channel_id(self) -> int: ...


@dataclass
class ChannelSettings:
    """Bounds in milliseconds for the token lifetime a server grants; 0 requested means the default."""

    min_lifetime: int = 10_000
    max_lifetime: int = 3_600_000
    default_lifetime: int = 3_600_000

    def revise(self, requested: int) -> int:
        """The RevisedLifetime for a RequestedLifetime (OPC 10000-4 v1.05, 5.6.2.2)."""
        if requested == 0:
            return self.default_lifetime
        return min(max(requested, self.min_lifetime), self.max_lifetime)


@dataclass
class TokenSlot:
    """A SecurityToken with its keys and the monotonic time it was issued at."""

    token: ua.ChannelSecurityToken
    cryptography: CryptographyNone
    issued_at: float

    @property
    def window_end(self) -> float:
        """The token is accepted until 125 % of its lifetime has passed (OPC 10000-4 v1.05, 5.6.2.1)."""
        return self.issued_at + self.token.RevisedLifetime * 5 / 4000


type ReceivedMessage = ua.Message | AbortedMessage | ua.Acknowledge | ua.ErrorMessage | None


class SecureChannel:
    """
    One end of an OPC UA Secure Conversation channel (OPC 10000-6 v1.05, 6.7), for client and server: the security
    policy, the tokens with their keys, the sequence numbers and the reassembly of received chunks into Messages.
    """

    def __init__(self, security_policy: SecurityPolicy, limits: TransportLimits) -> None:
        self._sequence_number = 0
        self._peer_sequence_number: int | None = None
        self._incoming_parts: list[MessageChunk] = []
        self._incoming_size = 0
        self.security_policy = security_policy
        self._policies: list[SecurityPolicyFactory] = []
        self.peer_certificate_check: Callable[[bytes], None] = _refuse_unchecked_certificate
        self._open = False
        self.security_token = ua.ChannelSecurityToken()
        self._current: TokenSlot | None = None
        self._next: TokenSlot | None = None
        self._previous: TokenSlot | None = None
        self.local_nonce = b""
        self.remote_nonce = b""
        self._limits = limits
        self.last_used = time.monotonic()
        self._clock: Callable[[], float] = time.monotonic
        self.types: ua.TypeRegistry | None = None

    @property
    def channel_id(self) -> int:
        return self.security_token.ChannelId

    @property
    def policy_uri(self) -> str:
        return self.security_policy.URI

    @property
    def security_mode(self) -> ua.MessageSecurityMode:
        return self.security_policy.Mode

    @property
    def peer_certificate(self) -> bytes | None:
        return self.security_policy.peer_certificate

    @property
    def local_certificate(self) -> bytes | None:
        return self.security_policy.host_certificate

    @property
    def limits(self) -> TransportLimits:
        return self._limits

    def _new_token_id(self) -> int:
        used = {slot.token.TokenId for slot in (self._current, self._next, self._previous) if slot is not None}
        while True:
            token_id = secrets.randbelow(0xFFFFFFFF) + 1
            if token_id not in used:
                return token_id

    def _slot(self, token: ua.ChannelSecurityToken, local_nonce: bytes, remote_nonce: bytes) -> TokenSlot:
        cryptography = self.security_policy.make_symmetric_cryptography(local_nonce, remote_nonce)
        return TokenSlot(token, cryptography, self._clock())

    def _make_current(self, slot: TokenSlot) -> None:
        self._current = slot
        self.security_token = slot.token
        self.security_policy.symmetric_cryptography = slot.cryptography

    def _purge_expired(self) -> None:
        now = self._clock()
        if self._previous is not None and now > self._previous.window_end:
            self._previous = None
        if self._next is not None and now > self._next.window_end:
            self._next = None
        if self._current is not None and now > self._current.window_end:
            self._current = None

    def expires_in(self) -> float:
        """Seconds until the last token's window ends; 0 when no token is valid any more."""
        windows = [slot.window_end for slot in (self._current, self._next, self._previous) if slot is not None]
        if not windows:
            return 0.0
        return max(0.0, max(windows) - self._clock())

    def _select_slot(self, token_id: int) -> TokenSlot:
        self._purge_expired()
        for slot in (self._current, self._next, self._previous):
            if slot is not None and slot.token.TokenId == token_id:
                return slot
        raise TransportError(ua.StatusCodes.BadSecureChannelTokenUnknown, f"Unknown token id {token_id}")

    def set_channel(
        self, params: ua.OpenSecureChannelResult, request_type: ua.SecurityTokenRequestType, client_nonce: bytes
    ) -> None:
        """Client side: take the token and keys of a checked OpenSecureChannel response; a Renew keeps the old token."""
        self.local_nonce = client_nonce
        self.remote_nonce = params.ServerNonce
        slot = self._slot(params.SecurityToken, client_nonce, params.ServerNonce)
        if request_type == ua.SecurityTokenRequestType.Renew and self._current is not None:
            self._previous = self._current
        self._make_current(slot)
        self._open = True

    def open(
        self,
        params: ua.OpenSecureChannelParameters,
        server: ChannelIdSource,
        settings: ChannelSettings | None = None,
    ) -> ua.OpenSecureChannelResult:
        """
        Server side: answer a validated OpenSecureChannel request. An Issue opens the channel with a new channel id;
        a Renew keeps the id and holds the new token back until the client first uses it.
        """
        settings = settings or ChannelSettings()
        local_nonce = ua.utils.create_nonce(self.security_policy.secure_channel_nonce_length)
        response = ua.OpenSecureChannelResult()
        response.ServerNonce = local_nonce
        token = ua.ChannelSecurityToken()
        token.TokenId = self._new_token_id()
        token.RevisedLifetime = settings.revise(params.RequestedLifetime)
        token.CreatedAt = datetime.now(UTC)
        issue = not self._open or params.RequestType == ua.SecurityTokenRequestType.Issue
        token.ChannelId = server.get_new_channel_id() if issue else self.security_token.ChannelId
        slot = self._slot(token, local_nonce, params.ClientNonce)
        self.local_nonce = local_nonce
        self.remote_nonce = params.ClientNonce
        if issue:
            self._open = True
            self._next = None
            self._previous = None
            self._make_current(slot)
        else:
            self._next = slot
        response.SecurityToken = token
        return response

    def _rotate(self) -> None:
        assert self._next is not None
        self._previous = self._current
        self._make_current(self._next)
        self._next = None

    def close(self) -> None:
        self._open = False
        self._current = self._next = self._previous = None

    def is_open(self) -> bool:
        return self._open

    def set_policy_factories(self, policies: list[SecurityPolicyFactory]) -> None:
        """Server side: the security policies of the server's endpoints, one of which an Issue request selects."""
        self._policies = policies

    def _uses_policy(self, uri: str, mode: ua.MessageSecurityMode | None = None) -> bool:
        return self.security_policy.URI == uri and (mode is None or self.security_policy.Mode == mode)

    def select_policy(
        self, uri: str, peer_certificate: bytes | None, mode: ua.MessageSecurityMode | None = None
    ) -> None:
        """
        Server side: switch to the endpoint policy for this SecurityPolicyUri and, if given, mode. Raises
        OpenRequestError with Bad_SecurityModeRejected when only the mode differs, else Bad_SecurityPolicyRejected.
        """
        for factory in self._policies:
            if factory.matches(uri, mode):
                self.security_policy = factory.create(peer_certificate)
                return
        if self._uses_policy(uri, mode):
            return
        if any(factory.matches(uri) for factory in self._policies) or self._uses_policy(uri):
            raise OpenRequestError(ua.StatusCodes.BadSecurityModeRejected, f"Mode {mode} is not configured for {uri}")
        raise OpenRequestError(ua.StatusCodes.BadSecurityPolicyRejected, f"No matching policy: {uri}")

    def validate_open_request(
        self,
        message_channel_id: int,
        security_header: ua.AsymmetricAlgorithmHeader,
        params: ua.OpenSecureChannelParameters,
        protocol_version: int,
    ) -> None:
        """
        Server side: check a decrypted OpenSecureChannel request (OPC 10000-6 v1.05, 6.7.4 and 6.7.7). Raises
        TransportError for what closes the connection and OpenRequestError for what a ServiceFault answers.
        """
        renew = params.RequestType == ua.SecurityTokenRequestType.Renew
        if renew and self._open:
            self._check_renew_identity(message_channel_id, security_header, params)
        elif not self._open and message_channel_id != 0:
            raise TransportError(ua.StatusCodes.BadTcpSecureChannelUnknown, "Issue must use channel id 0")
        policy = self.security_policy
        if policy.URI != SecurityPolicyNone.URI:
            if not security_header.SenderCertificate or not security_header.ReceiverCertificateThumbPrint:
                raise TransportError(ua.StatusCodes.BadSecurityChecksFailed, "Certificate or thumbprint is missing")
            thumbprint = certificate_thumbprint(policy.host_certificate or b"")
            if security_header.ReceiverCertificateThumbPrint != thumbprint:
                raise TransportError(ua.StatusCodes.BadSecurityChecksFailed, "Thumbprint is not ours")
            self.peer_certificate_check(security_header.SenderCertificate)
        if params.ClientProtocolVersion != protocol_version:
            raise OpenRequestError(ua.StatusCodes.BadProtocolVersionUnsupported, "Protocol version differs from Hello")
        if renew != self._open:
            raise OpenRequestError(ua.StatusCodes.BadRequestTypeInvalid, "Request type does not fit the channel state")
        if policy.URI != SecurityPolicyNone.URI:
            nonce = params.ClientNonce or b""
            if len(nonce) != policy.secure_channel_nonce_length or (renew and nonce == self.remote_nonce):
                raise OpenRequestError(ua.StatusCodes.BadNonceInvalid, "Client nonce is not valid")

    def _check_renew_identity(
        self,
        message_channel_id: int,
        security_header: ua.AsymmetricAlgorithmHeader,
        params: ua.OpenSecureChannelParameters,
    ) -> None:
        if message_channel_id != self.channel_id:
            raise TransportError(ua.StatusCodes.BadTcpSecureChannelUnknown, "Renew names another channel")
        sender = security_header.SenderCertificate or b""
        peer = self.security_policy.peer_certificate or b""
        if (
            security_header.SecurityPolicyURI != self.security_policy.URI
            or params.SecurityMode != self.security_policy.Mode
            or (peer and not sender.startswith(peer))
        ):
            raise TransportError(ua.StatusCodes.BadSecurityChecksFailed, "Renew changes policy, mode or certificate")

    def check_open_response(
        self,
        response: ua.OpenSecureChannelResult,
        params: ua.OpenSecureChannelParameters,
        protocol_version: int,
        sender_certificate: bytes | None = None,
    ) -> None:
        """Client side: check the server's certificate chain, protocol version, token and nonce in the response."""
        if self.security_policy.URI != SecurityPolicyNone.URI:
            self.peer_certificate_check(self._server_chain(sender_certificate))
        token = response.SecurityToken
        if response.ServerProtocolVersion != protocol_version:
            raise ua.uaerrors.BadProtocolVersionUnsupported()
        if token.ChannelId == 0 or token.TokenId == 0 or token.RevisedLifetime == 0:
            raise ua.uaerrors.BadSecureChannelIdInvalid()
        if self.security_policy.URI != SecurityPolicyNone.URI:
            nonce = response.ServerNonce or b""
            if len(nonce) != self.security_policy.secure_channel_nonce_length or nonce == params.ClientNonce:
                raise ua.uaerrors.BadNonceInvalid()

    def _server_chain(self, sender_certificate: bytes | None) -> bytes:
        leaf = self.security_policy.peer_certificate or b""
        try:
            pieces = split_certificate_chain(sender_certificate) if sender_certificate else []
        except UaError:
            return leaf
        if pieces and pieces[0] == leaf:
            return leaf + b"".join(pieces[1:])
        return leaf

    def message_to_binary(
        self, message: bytes, message_type: bytes = ua.MessageType.SecureMessage, request_id: int = 0
    ) -> bytes:
        """
        Encode a message body of type OPN, MSG or CLO as signed and encrypted chunks. A MSG above the peer's limits
        raises MessageTooLarge before anything is encoded; a failure after the first chunk raises MessageAborted.
        """
        if message_type == ua.MessageType.SecureMessage:
            self._check_send_limits(message)
        chunks = MessageChunk.message_to_chunks(
            self.security_policy,
            message,
            self._limits.max_send_buffer,
            message_type=message_type,
            channel_id=self.security_token.ChannelId,
            request_id=request_id,
            token_id=self.security_token.TokenId,
        )
        encoded: list[bytes] = []
        first_sequence_number = self._sequence_number
        for chunk in chunks:
            chunk.SequenceHeader.SequenceNumber = self._next_sequence_number()
            try:
                encoded.append(chunk.to_binary())
            except Exception:
                if not encoded:
                    self._sequence_number = first_sequence_number
                    raise
                self._sequence_number -= 1
                encoded.append(self._abort_chunk(chunk))
                raise MessageAborted(b"".join(encoded)) from None
        return b"".join(encoded)

    def _next_sequence_number(self) -> int:
        self._sequence_number += 1
        if self._sequence_number >= (1 << 32):
            _logger.debug("Wrapping sequence number: %d -> 1", self._sequence_number)
            self._sequence_number = 1
        return self._sequence_number

    def _check_send_limits(self, message: bytes) -> None:
        capacity = MessageChunk.max_body_size(self.security_policy.symmetric_cryptography, self._limits.max_send_buffer)
        if capacity < 1:
            raise ua.UaError(f"A chunk of {self._limits.max_send_buffer} bytes cannot carry any data")
        chunk_count = -(-len(message) // capacity)
        if self._limits.send_max_message_size and len(message) > self._limits.send_max_message_size:
            raise MessageTooLarge(f"Message of {len(message)} bytes exceeds {self._limits.send_max_message_size}")
        if self._limits.send_max_chunk_count and chunk_count > self._limits.send_max_chunk_count:
            raise MessageTooLarge(f"Message of {chunk_count} chunks exceeds {self._limits.send_max_chunk_count}")

    def _abort_chunk(self, failed: MessageChunk) -> bytes:
        error = ua.ErrorMessage(ua.StatusCode(ua.StatusCodes.BadUnexpectedError), "")
        abort = MessageChunk(
            failed.crypto, struct_to_binary(error), failed.MessageHeader.MessageType, ua.ChunkType.Abort
        )
        abort.SecurityHeader = failed.SecurityHeader
        abort.MessageHeader.ChannelId = failed.MessageHeader.ChannelId
        abort.SequenceHeader.RequestId = failed.SequenceHeader.RequestId
        abort.SequenceHeader.SequenceNumber = self._next_sequence_number()
        return abort.to_binary()

    def _check_incoming_chunk(self, chunk: MessageChunk) -> None:
        if self._incoming_parts:
            if self._incoming_parts[0].SequenceHeader.RequestId != chunk.SequenceHeader.RequestId:
                raise self._reject_chunk(
                    ua.StatusCodes.BadSecurityChecksFailed,
                    f"Wrong request id {chunk.SequenceHeader.RequestId},"
                    f" expected {self._incoming_parts[0].SequenceHeader.RequestId}",
                )
        seq_num = chunk.SequenceHeader.SequenceNumber
        previous = self._peer_sequence_number
        if previous is not None and seq_num != previous + 1:
            if seq_num < 1024 and previous >= (1 << 32) - 1024:
                _logger.debug("Sequence number wrapped: %d -> %d", previous, seq_num)
            else:
                raise self._reject_chunk(
                    ua.StatusCodes.BadSecurityChecksFailed,
                    f"Bad_SequenceNumberInvalid: expected {previous + 1}, received {seq_num}",
                )
        self._peer_sequence_number = seq_num

    def receive_from_header_and_body(self, header: ua.Header, body: Buffer) -> ReceivedMessage:
        """
        Process one whole received frame. OPN, MSG and CLO chunks are verified and decrypted and give a Message once
        the final chunk is in, None for an intermediate chunk and an AbortedMessage for an Abort chunk. ACK and ERR
        give the Acknowledge or ErrorMessage (OPC 10000-6 v1.05, 7.1.2). Anything else raises TransportError.
        """
        if header.MessageType == ua.MessageType.SecureOpen:
            data = body.copy(header.body_size)
            security_header = struct_from_binary(ua.AsymmetricAlgorithmHeader, data)

            if not self.is_open():
                try:
                    self.select_policy(security_header.SecurityPolicyURI, security_header.SenderCertificate)
                except OpenRequestError as e:
                    raise TransportError(e.status, e.reason) from e

        slot: TokenSlot | None = None
        if header.MessageType in (ua.MessageType.SecureMessage, ua.MessageType.SecureClose):
            if not self.is_open() or header.ChannelId != self.channel_id:
                raise TransportError(ua.StatusCodes.BadTcpSecureChannelUnknown, "Unknown channel id")
            data = body.copy(header.body_size)
            symmetric_header = struct_from_binary(ua.SymmetricAlgorithmHeader, data)
            slot = self._select_slot(symmetric_header.TokenId)

        if header.MessageType in (ua.MessageType.SecureMessage, ua.MessageType.SecureOpen, ua.MessageType.SecureClose):
            chunk = MessageChunk.from_header_and_body(
                self.security_policy, header, body, slot.cryptography if slot is not None else None
            )
            msg = self._receive(chunk)
            if slot is not None and slot is self._next:
                self._rotate()
            return msg
        if header.MessageType == ua.MessageType.Acknowledge:
            ack = struct_from_binary(ua.Acknowledge, body)
            self._limits.update_client_limits(ack)
            return ack
        if header.MessageType == ua.MessageType.Error:
            error = struct_from_binary(ua.ErrorMessage, body)
            if len((error.Reason or "").encode()) > MAX_ERROR_REASON_BYTES:
                error.Reason = ""
            _logger.warning("Received an error: %s", error)
            return error
        raise TransportError(ua.StatusCodes.BadTcpMessageTypeInvalid, f"Unexpected message type {header.MessageType!r}")

    def _drop_incoming_parts(self) -> None:
        self._incoming_parts = []
        self._incoming_size = 0

    def _reject_chunk(self, status: int, reason: str) -> TransportError:
        self._drop_incoming_parts()
        return TransportError(status, reason)

    def _receive(self, msg: MessageChunk) -> ua.Message | AbortedMessage | None:
        header = msg.MessageHeader
        self._check_incoming_chunk(msg)
        self.last_used = time.monotonic()
        if header.ChunkType not in (ua.ChunkType.Single, ua.ChunkType.Intermediate, ua.ChunkType.Abort):
            raise self._reject_chunk(ua.StatusCodes.BadTcpMessageTypeInvalid, "Unsupported chunk type")
        if header.MessageType != ua.MessageType.SecureMessage and header.ChunkType != ua.ChunkType.Single:
            raise self._reject_chunk(ua.StatusCodes.BadSecurityChecksFailed, "Only MSG can have several chunks")
        if self._incoming_parts and self._incoming_parts[0].MessageHeader.MessageType != header.MessageType:
            raise self._reject_chunk(ua.StatusCodes.BadSecurityChecksFailed, "Chunks of different message types")
        if header.ChunkType == ua.ChunkType.Abort:
            aborted = AbortedMessage.from_chunk(msg)
            _logger.warning("Message %s aborted: %s", msg, aborted.error)
            self._drop_incoming_parts()
            return aborted
        if not self._limits.is_msg_size_within_limit(self._incoming_size + len(msg.Body)):
            self._drop_incoming_parts()
            raise MessageSizeExceeded("Message size exceeds the limit")
        self._incoming_parts.append(msg)
        self._incoming_size += len(msg.Body)
        if not self._limits.is_chunk_count_within_limit(len(self._incoming_parts)):
            self._drop_incoming_parts()
            raise MessageSizeExceeded("Chunk count exceeds the limit")
        if header.ChunkType == ua.ChunkType.Intermediate:
            return None
        message = ua.Message(self._incoming_parts, self.types)
        self._drop_incoming_parts()
        return message
