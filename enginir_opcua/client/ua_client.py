"""
Low level binary client.

`UaClient` provides:

- transport: socket and secure channel via `UASocketProtocol`,
- sessionless services (Discovery, Register/Unregister Server),
- a default `UaSession` accessible via `session`, plus back-compat delegating
  methods so code that used to call session services on `UaClient` keeps working.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import logging
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from enginir_opcua import ua
from enginir_opcua.common.utils import Buffer
from enginir_opcua.ua.uaerrors._base import UaError

from ..common.connection import (
    MAX_ENDPOINT_URL_BYTES,
    MAX_REVERSE_HELLO_SIZE,
    REVERSE_HELLO_TYPES,
    AbortedMessage,
    FrameReader,
    MessageAborted,
    MessageSizeExceeded,
    MessageTooLarge,
    ReceivedMessage,
    SecureChannel,
    TransportError,
    TransportLimits,
    error_message_to_binary,
)
from ..common.utils import wait_for
from ..crypto import security_policies
from ..crypto.validator import (
    CertificateValidator,
    PeerRole,
    ValidationContext,
    check_application_uri,
    untrusted_hint,
)
from ..observer import NULL_OBSERVER, Observer
from ..ua.ua_binary import nodeid_from_binary, struct_from_binary, struct_to_binary, uatcp_to_binary
from ..ua.uaprotocol_auto import OpenSecureChannelResult
from .ua_session import SessionState, UaSession

MAX_ABANDONED_REQUESTS = 10000


def _timeout(timeout: float | None) -> dict[str, float]:
    return {} if timeout is None else {"timeout": timeout}


class UaClientState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    SOCKET_OPEN = "socket_open"
    CHANNEL_OPEN = "channel_open"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    DISCONNECTING = "disconnecting"


class UASocketState(Enum):
    INITIALIZED = "initialized"
    OPEN = "open"
    CLOSED = "closed"


class UASocketProtocol(asyncio.Protocol):
    """
    Handle socket connection and send ua messages.
    Timeout is the timeout used while waiting for an ua answer from server.
    """

    def __init__(
        self,
        timeout: float = 1,
        security_policy: security_policies.SecurityPolicy = security_policies.SecurityPolicyNone(),
        limits: TransportLimits | None = None,
    ) -> None:
        """
        :param timeout: Timeout in seconds
        :param security_policy: Security policy (optional)
        """
        self.logger = logging.getLogger(f"{__name__}.UASocketProtocol")
        self.transport: asyncio.Transport | None = None
        self.timeout = timeout
        self.authentication_token = ua.NodeId()
        self._request_id = 0
        self._request_handle = 0
        self._callbackmap: dict[int, asyncio.Future[Any]] = {}
        self._abandoned_requests: dict[int, None] = {}
        if limits is None:
            limits = TransportLimits()
        else:
            limits = copy.deepcopy(limits)  # Make a copy because the limits can change in the session
        self._channel = SecureChannel(security_policy, limits)
        self._channel.peer_certificate_check = self._check_server_certificate
        self.certificate_validator: CertificateValidator | None = None
        self.validation_host_name: str | None = None
        self.expected_application_uri: str | None = None
        self._acknowledged_version = 0
        self._reader = FrameReader(lambda: self._channel.limits.max_recv_buffer)

        self.state: UASocketState = UASocketState.INITIALIZED
        # needed to pass params from asynchronous request to synchronous data receive callback, as well as
        # passing back the processed response to the request so that it can return it.
        self._open_secure_channel_exchange: ua.OpenSecureChannelResponse | ua.OpenSecureChannelParameters | None = None
        self.pre_request_hook: Callable[[], Awaitable[None]] | None = None
        # Synchronous callback fired from connection_lost — used by the supervisor to detect transport loss.
        self.on_connection_lost: Callable[[Exception | None], None] | None = None
        self._types: ua.TypeRegistry | None = None
        # Predicate telling whether the owning session is closing, so late responses
        # to cancelled requests are logged as expected teardown rather than warnings.
        self.is_session_closing: Callable[[], bool] | None = None

    @property
    def types(self) -> ua.TypeRegistry | None:
        return self._types

    @types.setter
    def types(self, registry: ua.TypeRegistry | None) -> None:
        self._types = registry
        self._channel.types = registry

    def _check_server_certificate(self, chain: bytes) -> None:
        if self.certificate_validator is None:
            raise ua.UaStatusCodeError(
                ua.StatusCodes.BadCertificateUntrusted,
                "No certificate validator is configured, so no server certificate is trusted; "
                "configure the trust store of the client (set_trust_store)",
            )
        context = ValidationContext(
            PeerRole.SERVER, self._channel.security_policy.URI, host_name=self.validation_host_name
        )
        outcome = self.certificate_validator.validate_application_certificate(chain, context)
        if not outcome.accepted:
            self.certificate_validator.keep_rejected(outcome, self.validation_host_name)
            hint = untrusted_hint("server", outcome, self.certificate_validator.trust_store)
            if hint is not None:
                raise ua.UaStatusCodeError(outcome.status, f"{hint} ({outcome.detail})")
        outcome.raise_for_status()
        if self.expected_application_uri is not None and outcome.leaf is not None:
            check_application_uri(outcome.leaf, self.expected_application_uri).raise_for_status()

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        self.state = UASocketState.OPEN
        self.transport = transport

    def connection_lost(self, exc: Exception | None) -> None:
        self.logger.info("Socket has closed connection")
        self.state = UASocketState.CLOSED
        self.transport = None
        self._fail_all_pending(exc or ConnectionError("connection lost"))
        if self.on_connection_lost is not None:
            try:
                self.on_connection_lost(exc)
            except Exception:
                self.logger.exception("on_connection_lost callback raised")

    def data_received(self, data: bytes) -> None:
        self._reader.feed(data)
        try:
            for header, body in self._reader.frames():
                self._process_frame(header, body)
        except TransportError as e:
            self.logger.error("Closing connection to server: %s (%s)", e.reason, ua.StatusCode(e.status))
            status = ua.StatusCodes.BadResponseTooLarge if isinstance(e, MessageSizeExceeded) else e.status
            self._fail_all_pending(ua.UaStatusCodeError(status))
            self.disconnect_socket()
        except ua.UaStatusCodeError as e:
            self.logger.error("Got error status from server: %s", e)
            self._fail_all_pending(e)
            self.disconnect_socket()
        except Exception:
            self.logger.exception("Exception raised while parsing message from server")
            self.disconnect_socket()

    def _process_frame(self, header: ua.Header, body: Buffer) -> None:
        msg = self._channel.receive_from_header_and_body(header, body)
        if (
            header.MessageType == ua.MessageType.SecureOpen
            and isinstance(msg, ua.Message)
            and isinstance(self._open_secure_channel_exchange, ua.OpenSecureChannelParameters)
        ):
            params = self._open_secure_channel_exchange
            security_header = msg.security_header()
            assert isinstance(security_header, ua.AsymmetricAlgorithmHeader)
            self.check_answer(msg.body(), " in response to OpenSecureChannelRequest")
            response: ua.OpenSecureChannelResponse = struct_from_binary(ua.OpenSecureChannelResponse, msg.body())
            response.ResponseHeader.ServiceResult.check()
            self._channel.check_open_response(
                response.Parameters, params, self._acknowledged_version, security_header.SenderCertificate
            )
            self._open_secure_channel_exchange = response
            self._channel.set_channel(response.Parameters, params.RequestType, params.ClientNonce)
        self._process_received_message(msg)

    def _process_received_message(self, msg: ReceivedMessage) -> None:
        if msg is None:
            pass
        elif isinstance(msg, ua.Message):
            self._call_callback(msg.request_id(), msg.body())
        elif isinstance(msg, AbortedMessage):
            self._fail_request(msg)
        elif isinstance(msg, ua.Acknowledge):
            self._call_callback(0, msg)
        elif isinstance(msg, ua.ErrorMessage):
            self.logger.fatal("Received an error: %r", msg)
            self.disconnect_socket()
            if msg.Error is not None:
                msg.Error.check()
        else:
            raise ua.UaError(f"Unsupported message type: {msg}")

    def _fail_request(self, aborted: AbortedMessage) -> None:
        future = self._callbackmap.pop(aborted.request_id, None)
        if future is not None and not future.done():
            future.set_exception(ua.UaStatusCodeError(aborted.error.Error.value))

    def _send_request(
        self,
        request: Any,
        timeout: float = 1,
        message_type: bytes = ua.MessageType.SecureMessage,
        timeout_hint: float | None = None,
    ) -> asyncio.Future[Any]:
        """
        Send request to server, lower-level method.
        Timeout is the timeout written in ua header, unless timeout_hint is given.
        :param request: Request
        :param timeout: Timeout in seconds
        :param message_type: UA Message Type (optional)
        :param timeout_hint: Timeout in seconds written in the ua header instead of the timeout
        :return: Future that resolves with the Response
        """
        if self.transport is None:
            raise ConnectionError("Connection is not open")
        self._setup_request_header(request.RequestHeader, timeout if timeout_hint is None else timeout_hint)
        self.logger.debug("Sending: %s", request)
        next_request_id = self._request_id + 1
        try:
            with self._types.encoding() if self._types is not None else contextlib.nullcontext():
                binreq = struct_to_binary(request)
            msg = self._channel.message_to_binary(binreq, message_type=message_type, request_id=next_request_id)
        except MessageTooLarge as e:
            self._request_handle -= 1
            raise ua.uaerrors.BadRequestTooLarge() from e
        except MessageAborted as e:
            self._request_handle -= 1
            if self.transport is not None:
                self.transport.write(e.written)
            raise
        except Exception:
            # reset request handle if any error
            # see self._setup_request_header
            self._request_handle -= 1
            raise
        self._request_id = next_request_id
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        self._callbackmap[self._request_id] = future
        self.transport.write(msg)
        return future

    async def send_request(
        self,
        request: Any,
        timeout: float | None = None,
        message_type: bytes = ua.MessageType.SecureMessage,
        timeout_hint: float | None = None,
    ) -> Buffer:
        """
        Send a request to the server.
        Timeout is the time to wait for the answer and the timeout written in ua header, unless timeout_hint is given.
        Returns response object if no callback is provided.
        """
        timeout = self.timeout if timeout is None else timeout
        if self.pre_request_hook:
            # This will propagate exceptions from background tasks to the library user before calling a request which will
            # time out then.
            await self.pre_request_hook()
        try:
            pending = self._send_request(request, timeout, message_type, timeout_hint)
            data = await self._wait_for_response(pending, self._request_id, timeout if timeout else None)
        except UaError:
            raise
        except TimeoutError:
            raise
        except Exception as ex:
            if self.state is not UASocketState.OPEN:
                raise ConnectionError("Connection is closed") from None
            ex.add_note("Unhandled exception while sending request to OPC UA server")
            raise
        self.check_answer(data, f" in response to {request.__class__.__name__}")
        return data

    async def _wait_for_response(self, pending: asyncio.Future[Any], request_id: int, timeout: float | None) -> Any:
        try:
            return await wait_for(pending, timeout)
        except BaseException:
            self._abandon_request(request_id, pending)
            raise

    def _abandon_request(self, request_id: int, pending: asyncio.Future[Any]) -> None:
        if self._callbackmap.get(request_id) is not pending:
            return
        del self._callbackmap[request_id]
        self._abandoned_requests[request_id] = None
        while len(self._abandoned_requests) > MAX_ABANDONED_REQUESTS:
            del self._abandoned_requests[next(iter(self._abandoned_requests))]

    def check_answer(self, data: Buffer, context: str) -> bool:
        data = data.copy()
        typeid = nodeid_from_binary(data)
        if typeid == ua.FourByteNodeId(ua.ObjectIds.ServiceFault_Encoding_DefaultBinary):
            hdr = struct_from_binary(ua.ResponseHeader, data)
            self.logger.debug(
                "ServiceFault (%s, diagnostics: %s) from server received %s",
                hdr.ServiceResult.name,
                hdr.ServiceDiagnostics,
                context,
            )
            hdr.ServiceResult.check()
            return False
        return True

    def _fail_all_pending(self, exc: Exception) -> None:
        for fut in self._callbackmap.values():
            if not fut.done():
                fut.set_exception(exc)
        self._callbackmap.clear()
        self._abandoned_requests.clear()

    def _call_callback(self, request_id: int, body: Buffer | ua.Acknowledge) -> None:
        future = self._callbackmap.pop(request_id, None)
        if future is None:
            if request_id in self._abandoned_requests:
                del self._abandoned_requests[request_id]
                self.logger.debug("Dropped the late response to abandoned request id %s", request_id)
                return
            raise ua.UaStatusCodeError(
                ua.StatusCodes.BadSecurityChecksFailed,
                f"Response for request id {request_id}, which was never sent; pending are {list(self._callbackmap)}",
            )
        try:
            future.set_result(body)
        except asyncio.InvalidStateError:
            if self.is_session_closing is not None and self.is_session_closing():
                self.logger.debug("Future for request id %s not handled due to disconnect", request_id)
            else:
                self.logger.warning("Future for request id %s is already done", request_id)

    def _setup_request_header(self, hdr: ua.RequestHeader, timeout: float = 1) -> None:
        """
        :param hdr: Request header
        :param timeout: Timeout in seconds
        """
        hdr.AuthenticationToken = self.authentication_token
        self._request_handle += 1
        hdr.RequestHandle = self._request_handle
        hdr.TimeoutHint = int(timeout * 1000)

    @property
    def is_closed(self) -> bool:
        return self.state is UASocketState.CLOSED

    def disconnect_socket(self) -> None:
        self.logger.info("Request to close socket received")
        if self.transport:
            self.transport.close()
        else:
            self.logger.warning("disconnect_socket was called but transport is None")

    async def send_hello(self, url: str, max_messagesize: int = 0, max_chunkcount: int = 0) -> ua.Acknowledge:
        limits = self._channel.limits
        if max_messagesize:
            limits.max_message_size = max_messagesize
        if max_chunkcount:
            limits.max_chunk_count = max_chunkcount
        hello = limits.create_hello_limits(ua.Hello(EndpointUrl=url))
        ack: asyncio.Future[ua.Acknowledge] = asyncio.Future()
        self._callbackmap[0] = ack
        if self.transport is not None:
            self.transport.write(uatcp_to_binary(ua.MessageType.Hello, hello))
        acknowledge = await wait_for(ack, self.timeout)
        self._acknowledged_version = acknowledge.ProtocolVersion
        return acknowledge

    async def open_secure_channel(self, params: ua.OpenSecureChannelParameters) -> OpenSecureChannelResult:
        self.logger.info("open_secure_channel")
        request = ua.OpenSecureChannelRequest()
        request.Parameters = params
        if self._open_secure_channel_exchange is not None:
            raise UaError(
                "Two Open Secure Channel requests can not happen too close to each other. "
                "The response must be processed and returned before the next request can be sent."
            )
        self._open_secure_channel_exchange = params
        try:
            pending = self._send_request(request, message_type=ua.MessageType.SecureOpen)
            await self._wait_for_response(pending, self._request_id, self.timeout)
            exchange = self._open_secure_channel_exchange
            assert isinstance(exchange, ua.OpenSecureChannelResponse)
            return exchange.Parameters
        finally:
            self._open_secure_channel_exchange = None

    async def close_secure_channel(self) -> None:
        """
        Close secure channel.
        It seems to trigger a shutdown of socket in most servers, so be prepared to reconnect.
        OPC 10000-6 v1.05, 7.1.4 say that Server does not send a CloseSecureChannel response
        and should just close socket.
        """
        self.logger.info("close_secure_channel")
        request = ua.CloseSecureChannelRequest()
        future = self._send_request(request, message_type=ua.MessageType.SecureClose)
        future.cancel()
        # Fail any in-flight RPC futures with ConnectionError so awaiters can clean up,
        # rather than leaving them as silently cancelled.
        for pending in self._callbackmap.values():
            if not pending.done():
                pending.set_exception(ConnectionError("Secure channel closed"))
        self._callbackmap.clear()


def normalize_endpoint_url(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    return f"{parsed.scheme.lower()}://{host}:{parsed.port or 4840}{parsed.path}"


class _ReverseAcceptor(asyncio.Protocol):
    """A socket accepted for reverse connect: waits for the ReverseHello, checks it, then parks or hands it over."""

    def __init__(self, listener: ReverseConnectListener) -> None:
        self.listener = listener
        self.transport: asyncio.Transport | None = None
        self.target: ReverseTarget | None = None
        self.endpoint_url = ""
        self.server_uri = ""
        self._reader = FrameReader(lambda: MAX_REVERSE_HELLO_SIZE, REVERSE_HELLO_TYPES)
        self._timer: asyncio.TimerHandle | None = None
        self._done = False

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        self._timer = asyncio.get_running_loop().call_later(self.listener.rhe_deadline, self._expired)

    def _expired(self) -> None:
        if self.transport is not None and self.target is None:
            self.transport.close()

    def _refuse(self, status: int, reason: str) -> None:
        self._done = True
        if self.transport is not None:
            self.transport.write(error_message_to_binary(status, reason))
            self.transport.close()

    def data_received(self, data: bytes) -> None:
        if self._done:
            return
        if self.target is not None:
            self._refuse(ua.StatusCodes.BadTcpMessageTypeInvalid, "No message is expected before the Hello")
            return
        self._reader.feed(data)
        try:
            for header, body in self._reader.frames():
                if header.MessageType != ua.MessageType.ReverseHello:
                    self._refuse(ua.StatusCodes.BadTcpMessageTypeInvalid, "ReverseHello expected first")
                    return
                self._reverse_hello(struct_from_binary(ua.ReverseHello, body))
                return
        except TransportError as e:
            self._refuse(e.status, e.reason)
        except Exception:
            self._refuse(ua.StatusCodes.BadTcpMessageTypeInvalid, "Malformed ReverseHello")

    def _reverse_hello(self, hello: ua.ReverseHello) -> None:
        uri, endpoint = hello.ServerUri or "", hello.EndpointUrl or ""
        if len(uri.encode()) >= MAX_ENDPOINT_URL_BYTES or len(endpoint.encode()) >= MAX_ENDPOINT_URL_BYTES:
            self._refuse(ua.StatusCodes.BadTcpEndpointUrlInvalid, "ServerUri or EndpointUrl too long")
            return
        target = self.listener.find_target(uri, endpoint)
        if target is None:
            self._refuse(ua.StatusCodes.BadTcpEndpointUrlInvalid, "Unknown server")
            return
        self.server_uri, self.endpoint_url = uri, endpoint
        if not target.offer(self):
            self._refuse(ua.StatusCodes.BadServerTooBusy, "A socket of this server is already kept")
            return
        self.target = target
        if self._timer is not None:
            self._timer.cancel()

    def connection_lost(self, exc: Exception | None) -> None:
        self._done = True
        if self._timer is not None:
            self._timer.cancel()
        if self.target is not None:
            self.target.dropped(self)
        self.listener.forget(self)


class ReverseTarget:
    """The sockets of one server (ServerUri and EndpointUrl) that a reverse connect listener keeps for a client."""

    def __init__(self, listener: ReverseConnectListener, server_uri: str, endpoint_url: str) -> None:
        self.listener = listener
        self.server_uri = server_uri
        self.endpoint_url = endpoint_url
        self._parked: _ReverseAcceptor | None = None
        self._waiter: asyncio.Future[_ReverseAcceptor] | None = None

    def offer(self, acceptor: _ReverseAcceptor) -> bool:
        if self._waiter is not None and not self._waiter.done():
            self._waiter.set_result(acceptor)
            return True
        if self._parked is not None or self.listener.parked_count() >= self.listener.max_parked:
            return False
        self._parked = acceptor
        return True

    def dropped(self, acceptor: _ReverseAcceptor) -> None:
        if self._parked is acceptor:
            self._parked = None

    def has_parked(self) -> bool:
        return self._parked is not None

    async def accept(self, timeout: float) -> tuple[asyncio.Transport, str]:
        """The transport of the next ReverseHello of this server and the EndpointUrl it announced."""
        acceptor, self._parked = self._parked, None
        if acceptor is None:
            self._waiter = asyncio.get_running_loop().create_future()
            try:
                acceptor = await asyncio.wait_for(self._waiter, timeout)
            finally:
                self._waiter = None
        assert acceptor.transport is not None
        acceptor.target = None
        acceptor.listener.forget(acceptor)
        return acceptor.transport, acceptor.endpoint_url


class ReverseConnectListener:
    """
    Listens for servers that connect out (reverse connect, OPC 10000-6 v1.05, 7.1.2.6 and 7.1.3). One listener
    serves any number of clients, each waiting for its own server (ServerUri and EndpointUrl). A socket of an
    unknown server is refused with Bad_TcpEndpointUrlInvalid, a second socket of a server whose first one is parked
    with Bad_ServerTooBusy.
    """

    def __init__(self, listen_url: str, rhe_deadline: float = 30.0, max_parked: int = 8) -> None:
        parsed = urlparse(listen_url)
        if parsed.scheme != "opc.tcp" or not parsed.hostname or parsed.port is None:
            raise ValueError(f"The listen URL must be opc.tcp://host:port, not {listen_url!r}")
        self.host: str = parsed.hostname
        self.port: int = parsed.port
        self.rhe_deadline = rhe_deadline
        self.max_parked = max_parked
        self._server: asyncio.Server | None = None
        self._targets: list[ReverseTarget] = []
        self._acceptors: set[_ReverseAcceptor] = set()

    def target(self, server_uri: str, endpoint_url: str) -> ReverseTarget:
        endpoint = normalize_endpoint_url(endpoint_url)
        for existing in self._targets:
            if existing.server_uri == server_uri and existing.endpoint_url == endpoint:
                return existing
        created = ReverseTarget(self, server_uri, endpoint)
        self._targets.append(created)
        return created

    def find_target(self, server_uri: str, endpoint_url: str) -> ReverseTarget | None:
        endpoint = normalize_endpoint_url(endpoint_url)
        return next((t for t in self._targets if t.server_uri == server_uri and t.endpoint_url == endpoint), None)

    def parked_count(self) -> int:
        return sum(1 for t in self._targets if t.has_parked())

    def forget(self, acceptor: _ReverseAcceptor) -> None:
        self._acceptors.discard(acceptor)

    def _make_acceptor(self) -> _ReverseAcceptor:
        acceptor = _ReverseAcceptor(self)
        self._acceptors.add(acceptor)
        return acceptor

    @property
    def is_listening(self) -> bool:
        return self._server is not None

    async def start(self) -> None:
        if self._server is not None:
            return
        self._server = await asyncio.get_running_loop().create_server(self._make_acceptor, self.host, self.port)
        if self.port == 0:
            self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.close()
        for acceptor in list(self._acceptors):
            if acceptor.transport is not None:
                acceptor.transport.close()
        self._acceptors.clear()
        if server is not None:
            await server.wait_closed()

    async def __aenter__(self) -> ReverseConnectListener:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()


class StateSubscription:
    """Async context manager that buffers `UaClient` state transitions.

    Created via `UaClient.subscribe_state()`. The buffer is filled by a sync
    listener installed in `__aenter__`, so any transition that happens between
    entering the block and calling `wait_for_state` / `next_change` is captured
    rather than lost to a race.
    """

    def __init__(self, client: UaClient) -> None:
        self._client = client
        self._queue: asyncio.Queue[UaClientState] = asyncio.Queue()
        self._unsubscribe: Callable[[], None] | None = None

    async def __aenter__(self) -> StateSubscription:
        self._unsubscribe = self._client.add_state_listener(self._queue.put_nowait)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> None:
        if self._unsubscribe is not None:
            self._unsubscribe()
            self._unsubscribe = None

    async def wait_for_state(self, target: UaClientState, timeout: float | None = None) -> None:
        """Wait until state == `target`. Considers current state and any buffered changes."""
        if self._client.state is target:
            return

        async def _consume() -> None:
            while True:
                state = await self._queue.get()
                if state is target:
                    return

        if timeout is None:
            await _consume()
        else:
            await asyncio.wait_for(_consume(), timeout)

    async def next_change(self, timeout: float | None = None) -> UaClientState:
        """Return the next buffered state change."""
        if timeout is None:
            return await self._queue.get()
        return await asyncio.wait_for(self._queue.get(), timeout)


class UaClient:
    """
    Low level OPC-UA client (transport).

    Owns the transport (`UASocketProtocol`) and a default `UaSession`.
    Sessionless services (Discovery, Register/Unregister Server) live here.
    Session-scoped service calls delegate to `self.session` for back-compat
    with code that used to call them on `UaClient` directly.
    """

    _max_concurrent_requests = 100

    def __init__(self, timeout: float = 1.0) -> None:
        """
        :param timeout: Timout in seconds
        """
        self.logger = logging.getLogger(f"{__name__}.UaClient")
        self._timeout = timeout
        self._request_semaphore = asyncio.Semaphore(self._max_concurrent_requests)
        self.security_policy: security_policies.SecurityPolicy = security_policies.SecurityPolicyNone()
        self.certificate_validator: CertificateValidator | None = None
        self.validation_host_name: str | None = None
        self.protocol: UASocketProtocol | None = None
        self._pre_request_hook: Callable[[], Awaitable[None]] | None = None
        self._state: UaClientState = UaClientState.DISCONNECTED
        self._state_listeners: list[Callable[[UaClientState], None]] = []
        self._disconnect_requested: bool = False
        self._reconnect_hold = False
        self.reconnect_on_loss = False
        self.observer: Observer = NULL_OBSERVER
        self.session: UaSession = UaSession(self)
        self.types: ua.TypeRegistry | None = None

    @property
    def state(self) -> UaClientState:
        return self._state

    @property
    def is_disconnect_requested(self) -> bool:
        """Has the owner requested an orderly shutdown? Set via request_disconnect()."""
        return self._disconnect_requested

    def request_disconnect(self) -> None:
        """Mark this client as shutting down; observed by the supervisor loops."""
        self._disconnect_requested = True

    def clear_disconnect_request(self) -> None:
        """Clear the shutdown flag ahead of a fresh connect()."""
        self._disconnect_requested = False

    def _observe(self, hook: Callable[[], None]) -> None:
        try:
            hook()
        except Exception:
            self.logger.exception("observer raised")

    def _set_state(self, target: UaClientState) -> None:
        """Set state and notify listeners. Same-state assignments are no-ops."""
        if target is self._state:
            return
        if self._reconnect_hold and target is not UaClientState.RECONNECTING:
            return
        self._state = target
        self._observe(lambda: self.observer.on_state_change(target))
        # Iterate a copy so listeners can safely unsubscribe themselves.
        for listener in list(self._state_listeners):
            try:
                listener(target)
            except Exception:
                self.logger.exception("state listener raised")

    def add_state_listener(self, callback: Callable[[UaClientState], None]) -> Callable[[], None]:
        """Register a raw state-change callback; returns an unsubscribe callable.

        Internal helper. External code should use the `subscribe_state()`
        context manager, which buffers transitions in a queue and is race-free
        between subscription and trigger.
        """
        self._state_listeners.append(callback)

        def unsubscribe() -> None:
            try:
                self._state_listeners.remove(callback)
            except ValueError:
                pass

        return unsubscribe

    def remove_state_listener(self, callback: Callable[[UaClientState], None]) -> None:
        try:
            self._state_listeners.remove(callback)
        except ValueError:
            pass

    def subscribe_state(self) -> StateSubscription:
        """Subscribe to state transitions; use as an async context manager.

        Inside the `async with` block every transition is captured into a queue,
        even ones that happen before `wait_for_state` is called. That makes the
        common pattern race-free:

            async with client.subscribe_state() as sub:
                trigger_something_that_changes_state()
                await sub.wait_for_state(UaClientState.CONNECTED)
        """
        return StateSubscription(self)

    def _on_transport_lost(self, _exc: Exception | None) -> None:
        """Called from UASocketProtocol.connection_lost.

        Surface the loss as a state change so that subscribers (the supervisor,
        tests, user code) can react. Skip if we're already tearing down or reconnecting.
        """
        if self._reconnect_hold or self._state in (UaClientState.DISCONNECTED, UaClientState.DISCONNECTING):
            return
        if self.reconnect_on_loss and self._state is UaClientState.CONNECTED:
            self.enter_reconnecting()
        else:
            self._set_state(UaClientState.DISCONNECTED)

    def notify_transport_lost(self) -> None:
        """Surface a transport loss detected by a higher-level watchdog, driving the
        same state change as a dropped socket so the supervisor reacts."""
        self._on_transport_lost(None)

    def enter_reconnecting(self) -> None:
        """Mark the client as reconnecting. Until complete_reconnect or mark_disconnected the state stays
        RECONNECTING, whatever the attempts do to the socket and the channel."""
        self._reconnect_hold = True
        self._set_state(UaClientState.RECONNECTING)

    def complete_reconnect(self) -> None:
        self._reconnect_hold = False
        self._set_state(UaClientState.CONNECTED)

    def mark_disconnected(self) -> None:
        """Mark the client as disconnected; the supervisor calls this when it gives up."""
        self._reconnect_hold = False
        self._set_state(UaClientState.DISCONNECTED)

    @property
    def has_transport(self) -> bool:
        """True while a socket/secure-channel transport is attached."""
        return self.protocol is not None

    @property
    def has_session(self) -> bool:
        """True when a server-side session exists that ActivateSession could reuse."""
        return self.session.has_session

    def ensure_publish_loop(self) -> None:
        self.session.ensure_publish_loop()

    # --- transport helpers ---

    def set_security(self, policy: security_policies.SecurityPolicy) -> None:
        self.security_policy = policy

    def set_max_concurrent_requests(self, max_concurrent_requests: int) -> None:
        """Set the maximum number of requests sent concurrently."""
        self._max_concurrent_requests = max_concurrent_requests
        self._request_semaphore = asyncio.Semaphore(max_concurrent_requests)

    def _make_protocol(self) -> UASocketProtocol:
        self.protocol = UASocketProtocol(self._timeout, security_policy=self.security_policy)
        self.protocol.certificate_validator = self.certificate_validator
        self.protocol.validation_host_name = self.validation_host_name
        self.protocol.pre_request_hook = self._pre_request_hook
        self.protocol.on_connection_lost = self._on_transport_lost
        self.protocol.types = self.types
        self.protocol.is_session_closing = self._is_session_closing
        return self.protocol

    def _is_session_closing(self) -> bool:
        return self.session.state in (SessionState.CLOSING, SessionState.CLOSED)

    @property
    def pre_request_hook(self) -> Callable[[], Awaitable[None]] | None:
        return self._pre_request_hook

    @pre_request_hook.setter
    def pre_request_hook(self, hook: Callable[[], Awaitable[None]] | None) -> None:
        self._pre_request_hook = hook
        if self.protocol:
            self.protocol.pre_request_hook = self._pre_request_hook

    async def connect_socket(self, host: str, port: int) -> None:
        """Connect to server socket."""
        self.logger.info("opening connection")
        self.validation_host_name = host
        self._set_state(UaClientState.CONNECTING)
        try:
            await asyncio.wait_for(
                asyncio.get_running_loop().create_connection(self._make_protocol, host, port), self._timeout
            )
        except BaseException:
            self._set_state(UaClientState.DISCONNECTED)
            raise
        self._set_state(UaClientState.SOCKET_OPEN)

    def attach_socket(self, transport: asyncio.Transport, host: str, expected_application_uri: str | None) -> None:
        """Use a socket that the server opened (reverse connect, OPC 10000-6 v1.05, 7.1.3) like one that was dialled."""
        self.validation_host_name = host
        self._set_state(UaClientState.CONNECTING)
        protocol = self._make_protocol()
        protocol.expected_application_uri = expected_application_uri
        transport.set_protocol(protocol)
        protocol.connection_made(transport)
        self._set_state(UaClientState.SOCKET_OPEN)

    def disconnect_socket(self) -> None:
        if self._state is UaClientState.DISCONNECTED:
            return
        if self._state is UaClientState.DISCONNECTING:
            # already tearing down; let the in-flight call complete
            return
        self._set_state(UaClientState.DISCONNECTING)
        if self.protocol is not None and self.protocol.state is not UASocketState.CLOSED:
            self.protocol.disconnect_socket()
        self.protocol = None
        self._set_state(UaClientState.DISCONNECTED)

    async def send_hello(self, url: str, max_messagesize: int = 0, max_chunkcount: int = 0) -> ua.Acknowledge:
        if self.protocol is None:
            raise ConnectionError("Connection is not open")
        return await self.protocol.send_hello(url, max_messagesize, max_chunkcount)

    async def open_secure_channel(self, params: ua.OpenSecureChannelParameters) -> OpenSecureChannelResult:
        if self.protocol is None:
            raise ConnectionError("Connection is not open")
        is_renew = params.RequestType == ua.SecurityTokenRequestType.Renew
        result = await self.protocol.open_secure_channel(params)
        if not is_renew:
            self._set_state(UaClientState.CHANNEL_OPEN)
        return result

    async def close_secure_channel(self) -> None:
        if not self.protocol or self.protocol.state is UASocketState.CLOSED:
            self.logger.warning("close_secure_channel was called but connection is closed")
            return
        await self.protocol.close_secure_channel()
        if self._state is UaClientState.CHANNEL_OPEN:
            self._set_state(UaClientState.SOCKET_OPEN)

    async def _send_request(
        self,
        request: Any,
        timeout: float | None = None,
        message_type: bytes = ua.MessageType.SecureMessage,
        *,
        timeout_hint: float | None = None,
        limited: bool = True,
    ) -> Buffer:
        with self.observer.observe_request(request):
            if not limited:
                return await self._send_unlimited(request, timeout, message_type, timeout_hint)
            async with self._request_semaphore:
                return await self._send_unlimited(request, timeout, message_type, timeout_hint)

    async def _send_unlimited(
        self, request: Any, timeout: float | None, message_type: bytes, timeout_hint: float | None
    ) -> Buffer:
        if self.protocol is None:
            raise ConnectionError("Connection is not open")
        if timeout_hint is None:
            return await self.protocol.send_request(request, timeout, message_type)
        return await self.protocol.send_request(request, timeout, message_type, timeout_hint)

    # --- back-compat: properties that previously lived on UaClient ---

    @property
    def _subscription_callbacks(self) -> dict[int, Callable[..., Any]]:
        return self.session._subscription_callbacks

    @property
    def _publish_task(self) -> asyncio.Task[None] | None:
        return self.session._publish_task

    # --- session lifecycle: delegate to default session ---

    async def create_session(self, parameters: ua.CreateSessionParameters) -> ua.CreateSessionResult:
        return await self.session.create_session(parameters)

    async def activate_session(self, parameters: ua.ActivateSessionParameters) -> ua.ActivateSessionResult:
        result = await self.session.activate_session(parameters)
        # Only transition on the first activation; re-activate of an already-ACTIVATED
        # session leaves UaClient in CONNECTED.
        if self._state is UaClientState.CHANNEL_OPEN:
            self._set_state(UaClientState.CONNECTED)
        return result

    async def close_session(self, delete_subscriptions: bool) -> None:
        await self.session.close_session(delete_subscriptions)
        if self._state is UaClientState.CONNECTED:
            self._set_state(UaClientState.CHANNEL_OPEN)

    # --- sessionless services ---

    async def get_endpoints(self, params: ua.GetEndpointsParameters) -> list[ua.EndpointDescription]:
        self.logger.debug("get_endpoint")
        request = ua.GetEndpointsRequest()
        request.Parameters = params
        data = await self._send_request(request)
        response = struct_from_binary(ua.GetEndpointsResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Endpoints

    async def find_servers(self, params: ua.FindServersParameters) -> list[ua.ApplicationDescription]:
        self.logger.debug("find_servers")
        request = ua.FindServersRequest()
        request.Parameters = params
        data = await self._send_request(request)
        response = struct_from_binary(ua.FindServersResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Servers

    async def find_servers_on_network(self, params: ua.FindServersOnNetworkParameters) -> ua.FindServersOnNetworkResult:
        self.logger.debug("find_servers_on_network")
        request = ua.FindServersOnNetworkRequest()
        request.Parameters = params
        data = await self._send_request(request)
        response = struct_from_binary(ua.FindServersOnNetworkResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Parameters

    async def register_server(self, registered_server: ua.RegisteredServer) -> None:
        self.logger.debug("register_server")
        request = ua.RegisterServerRequest()
        request.Server = registered_server
        data = await self._send_request(request)
        response = struct_from_binary(ua.RegisterServerResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()

    async def unregister_server(self, registered_server: ua.RegisteredServer) -> None:
        """Same request as register_server; the caller's RegisteredServer.IsOnline = False makes it an unregistration."""
        self.logger.debug("unregister_server")
        request = ua.RegisterServerRequest()
        request.Server = registered_server
        data = await self._send_request(request)
        response = struct_from_binary(ua.RegisterServerResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()

    async def register_server2(self, params: ua.RegisterServer2Parameters) -> list[ua.StatusCode]:
        self.logger.debug("register_server2")
        request = ua.RegisterServer2Request()
        request.Parameters = params
        data = await self._send_request(request)
        response = struct_from_binary(ua.RegisterServer2Response, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.ConfigurationResults

    async def unregister_server2(self, params: ua.RegisterServer2Parameters) -> list[ua.StatusCode]:
        """Same request as register_server2; the caller's RegisteredServer.IsOnline = False makes it an unregistration."""
        self.logger.debug("unregister_server2")
        request = ua.RegisterServer2Request()
        request.Parameters = params
        data = await self._send_request(request)
        response = struct_from_binary(ua.RegisterServer2Response, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.ConfigurationResults

    # --- AbstractSession: delegate to default session ---

    async def browse(self, parameters: ua.BrowseParameters, timeout: float | None = None) -> list[ua.BrowseResult]:
        return await self.session.browse(parameters, **_timeout(timeout))

    async def browse_next(
        self, parameters: ua.BrowseNextParameters, timeout: float | None = None
    ) -> list[ua.BrowseResult]:
        return await self.session.browse_next(parameters, **_timeout(timeout))

    async def translate_browsepaths_to_nodeids(
        self, browse_paths: list[ua.BrowsePath], timeout: float | None = None
    ) -> list[ua.BrowsePathResult]:
        return await self.session.translate_browsepaths_to_nodeids(browse_paths, **_timeout(timeout))

    async def register_nodes(self, nodes: list[ua.NodeId], timeout: float | None = None) -> list[ua.NodeId]:
        return await self.session.register_nodes(nodes, **_timeout(timeout))

    async def unregister_nodes(self, nodes: list[ua.NodeId], timeout: float | None = None) -> None:
        return await self.session.unregister_nodes(nodes, **_timeout(timeout))

    async def read(self, parameters: ua.ReadParameters, timeout: float | None = None) -> list[ua.DataValue]:
        return await self.session.read(parameters, **_timeout(timeout))

    async def write(self, params: ua.WriteParameters, timeout: float | None = None) -> list[ua.StatusCode]:
        return await self.session.write(params, **_timeout(timeout))

    async def history_read(
        self, params: ua.HistoryReadParameters, timeout: float | None = None
    ) -> list[ua.HistoryReadResult]:
        return await self.session.history_read(params, **_timeout(timeout))

    async def history_update(
        self, params: ua.HistoryUpdateParameters, timeout: float | None = None
    ) -> list[ua.HistoryUpdateResult]:
        return await self.session.history_update(params, **_timeout(timeout))

    async def read_attributes(
        self, nodeids: list[ua.NodeId], attr: ua.AttributeIds, timeout: float | None = None
    ) -> list[ua.DataValue]:
        return await self.session.read_attributes(nodeids, attr, **_timeout(timeout))

    async def write_attributes(
        self,
        nodeids: list[ua.NodeId],
        datavalues: list[ua.DataValue],
        attributeid: ua.AttributeIds = ua.AttributeIds.Value,
        timeout: float | None = None,
    ) -> list[ua.StatusCode]:
        return await self.session.write_attributes(nodeids, datavalues, attributeid, **_timeout(timeout))

    async def add_nodes(
        self, nodestoadd: list[ua.AddNodesItem], timeout: float | None = None
    ) -> list[ua.AddNodesResult]:
        return await self.session.add_nodes(nodestoadd, **_timeout(timeout))

    async def add_references(
        self, refs: list[ua.AddReferencesItem], timeout: float | None = None
    ) -> list[ua.StatusCode]:
        return await self.session.add_references(refs, **_timeout(timeout))

    async def delete_references(
        self, refs: list[ua.DeleteReferencesItem], timeout: float | None = None
    ) -> list[ua.StatusCode]:
        return await self.session.delete_references(refs, **_timeout(timeout))

    async def delete_nodes(self, params: ua.DeleteNodesParameters, timeout: float | None = None) -> list[ua.StatusCode]:
        return await self.session.delete_nodes(params, **_timeout(timeout))

    async def call(
        self, methodstocall: list[ua.CallMethodRequest], timeout: float | None = None
    ) -> list[ua.CallMethodResult]:
        return await self.session.call(methodstocall, **_timeout(timeout))

    async def create_subscription(
        self,
        params: ua.CreateSubscriptionParameters,
        callback: Callable[..., Any],
        timeout: float | None = None,
    ) -> ua.CreateSubscriptionResult:
        return await self.session.create_subscription(params, callback, **_timeout(timeout))

    async def update_subscription(
        self, params: ua.ModifySubscriptionParameters, timeout: float | None = None
    ) -> ua.ModifySubscriptionResult:
        return await self.session.update_subscription(params, **_timeout(timeout))

    modify_subscription = update_subscription  # legacy support

    async def delete_subscriptions(
        self, subscription_ids: list[int], timeout: float | None = None
    ) -> list[ua.StatusCode]:
        return await self.session.delete_subscriptions(subscription_ids, **_timeout(timeout))

    async def transfer_subscriptions(
        self, params: ua.TransferSubscriptionsParameters, timeout: float | None = None
    ) -> list[ua.TransferResult]:
        return await self.session.transfer_subscriptions(params, **_timeout(timeout))

    async def inform_subscriptions(self, status: ua.StatusCode) -> None:
        return await self.session.inform_subscriptions(status)

    async def publish(self, acks: list[ua.SubscriptionAcknowledgement]) -> ua.PublishResponse:
        return await self.session.publish(acks)

    async def create_monitored_items(
        self,
        params: ua.CreateMonitoredItemsParameters,
        timeout: float | None = None,
    ) -> list[ua.MonitoredItemCreateResult]:
        return await self.session.create_monitored_items(params, **_timeout(timeout))

    async def delete_monitored_items(
        self, params: ua.DeleteMonitoredItemsParameters, timeout: float | None = None
    ) -> list[ua.StatusCode]:
        return await self.session.delete_monitored_items(params, **_timeout(timeout))

    async def modify_monitored_items(
        self,
        params: ua.ModifyMonitoredItemsParameters,
        timeout: float | None = None,
    ) -> list[ua.MonitoredItemModifyResult]:
        return await self.session.modify_monitored_items(params, **_timeout(timeout))

    async def set_monitoring_mode(
        self, params: ua.SetMonitoringModeParameters, timeout: float | None = None
    ) -> list[ua.uatypes.StatusCode]:
        return await self.session.set_monitoring_mode(params, **_timeout(timeout))

    async def set_publishing_mode(
        self, params: ua.SetPublishingModeParameters, timeout: float | None = None
    ) -> list[ua.uatypes.StatusCode]:
        return await self.session.set_publishing_mode(params, **_timeout(timeout))
