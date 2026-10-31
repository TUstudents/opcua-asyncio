"""
High level interface to pure python OPC-UA server
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import socket
from collections.abc import Awaitable, Callable, Iterable
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import ParseResult, urlparse

import anyio
from cryptography import x509

from enginir_opcua import ua

from ..client import Client
from ..common.callback import CallbackType
from ..common.connection import TransportLimits
from ..common.event_objects import BaseEvent
from ..common.manage_nodes import delete_nodes
from ..common.node import Node
from ..common.shortcuts import Shortcuts
from ..common.structures import load_enums, load_type_definitions
from ..common.structures104 import load_data_type_definitions
from ..common.subscription import Subscription
from ..common.ua_utils import get_nodes_of_namespace
from ..common.xmlexporter import XmlExporter
from ..common.xmlimporter import XmlImporter
from ..config import (
    ServerConfig,
    check_certificate_uri,
    is_loopback,
    parse_opc_tcp_url,
    password_from_environment,
    quickstart_server_config,
    server_user_manager,
    with_default_port,
)
from ..crypto import pki, security_policies, uacrypto, validator
from ..crypto.permission_rules import SimpleRoleRuleset, UserRole
from ..crypto.truststore import TrustStore
from ..crypto.validator import CertificateValidator
from ..pubsub.pubsub import PubSub
from ..ua.uaerrors import ConfigurationError
from .address_space import NodeData
from .binary_server_asyncio import BinaryServer, ReverseConnection
from .certificate_manager import CertificateManager
from .conditions import Condition
from .diagnostics import DiagnosticsCollector
from .event_generator import EventGenerator
from .file_transfer import FileProvider
from .internal_server import InternalServer
from .user_managers import UserManager

if TYPE_CHECKING:
    from .internal_session import InternalSession

_logger = logging.getLogger(__name__)

MAX_DISCOVERY_PERIOD_SECONDS = 600
DISCOVERY_UNREGISTER_TIMEOUT_SECONDS = 5.0


def _get_node(isession: InternalSession, whatever: Node | ua.NodeId | int) -> Node:
    if isinstance(whatever, Node):
        return whatever
    if isinstance(whatever, ua.NodeId):
        return Node(isession, whatever)
    return Node(isession, ua.NodeId(whatever))


class Server:
    """
    High level Server class

    This class creates an enginir_opcua server with default values

    Create your own namespace and then populate your server address space
    using the nodes of ``server.nodes`` (``root``, ``objects``, ...) or ``get_node()``,
    and ``get_event_generator()`` to fire events. Then start the server.

    The server is not thread-safe. It runs on the event loop that started it, and the address space and the
    services have no locks: use it from tasks of that loop only. From other threads use ``enginir_opcua.sync.Server``
    or ``asyncio.run_coroutine_threadsafe``. Method callbacks that are plain functions run in a thread pool,
    so they must not touch the server objects directly; ``async def`` callbacks run on the loop.

    If you need more flexibility you call directly the Ua Service methods
    on the iserver or iserver.isession object members.

    During startup the standard address space will be constructed, which may be
    time-consuming when running a server on a less powerful device (e.g. a
    Raspberry Pi). In order to improve startup performance, an optional path to a
    cache file can be passed to the server constructor.
    If the parameter is defined, the address space will be loaded from the
    cache file or the file will be created if it does not exist yet.
    As a result the first startup will be even slower due to the cache file
    generation but all further start ups will be significantly faster.
    ┌────────┐
    │ Server │ ── BinaryServer ── OPCUAProtocol ── UaProcessor
    │        │ ── InternalServer ── InternalSession
    └────────┘                   ── SubscriptionService

    :ivar product_uri:
    :ivar name:
    :ivar iserver: `InternalServer` instance
    :ivar bserver: binary protocol server `BinaryServer`
    :ivar nodes: shortcuts to common nodes - `Shortcuts` instance
    :ivar socket_address:
        A tuple of IP address and port describing the server socket address. Used when the IP address of the network
        interface is different from the endpoint IP offered to the client during discovery. Helpful when the server
        is running behind NAT or inside a Docker container, where the client connects to an external IP, while the
        server listens on some internal IP.
    """

    def __init__(
        self,
        iserver: InternalServer | None = None,
        user_manager: UserManager | None = None,
        *,
        allow_no_security: bool = False,
        allow_deprecated_policies: bool = False,
        config: ServerConfig | None = None,
    ) -> None:
        """
        :param config: a ServerConfig (see Server.quickstart). It replaces `iserver`, `user_manager`,
            `allow_no_security` and `allow_deprecated_policies`; the PKI directory it names is read or created in
            `init()`.
        """
        self._config: ServerConfig | None = config
        if config is not None:
            if iserver is not None or user_manager is not None or allow_no_security or allow_deprecated_policies:
                raise ConfigurationError(
                    "server: config replaces iserver, user_manager, allow_no_security and allow_deprecated_policies; "
                    "put the user manager in the config"
                )
            config.validate()
            user_manager = server_user_manager(config)
        self.endpoint: ParseResult = urlparse("opc.tcp://0.0.0.0:4840/enginir-opcua/server/")
        self._application_uri: str = "urn:enginir:opcua:server"
        self.product_uri: str = "urn:enginir:opcua"
        self.name: str = "engiNIR OPC UA Server"
        self.manufacturer_name: str = "engiNIR"
        self.application_type: ua.ApplicationType = ua.ApplicationType.ClientAndServer
        self.iserver: InternalServer = iserver if iserver else InternalServer(user_manager=user_manager)
        self.bserver: BinaryServer | None = None
        self._reverse_connections: list[ReverseConnection] = []
        self.socket_address: tuple[str, int] | None = None
        self._discovery_clients: dict[str, Client] = {}
        self._discovery_configurations: dict[str, ua.DiscoveryConfiguration | None] = {}
        self._discovery_period: int = 60
        self._discovery_handle: asyncio.Task[None] | None = None
        self._policies: list[security_policies.SecurityPolicyFactory] = []
        self._default_validator: CertificateValidator | None = None
        self._certificate_manager: CertificateManager | None = None
        self.nodes: Shortcuts = Shortcuts(self.iserver.isession)
        self.allow_deprecated_policies: bool = allow_deprecated_policies
        # the secure endpoints are enabled by default, the None endpoint only when asked for
        self._security_policy: list[ua.SecurityPolicyType] = [
            *([ua.SecurityPolicyType.NoSecurity] if allow_no_security else []),
            ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
            ua.SecurityPolicyType.Basic256Sha256_Sign,
            ua.SecurityPolicyType.Aes128Sha256RsaOaep_SignAndEncrypt,
            ua.SecurityPolicyType.Aes128Sha256RsaOaep_Sign,
            ua.SecurityPolicyType.Aes256Sha256RsaPss_Sign,
            ua.SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt,
        ]
        # allow all certificates by default
        self._permission_ruleset: SimpleRoleRuleset = SimpleRoleRuleset()
        # Use acceptable limits
        buffer_sz = 65535
        max_msg_sz = 100 * 1024 * 1024  # 100mb
        self.limits: TransportLimits = TransportLimits(
            max_recv_buffer=buffer_sz,
            max_send_buffer=buffer_sz,
            max_chunk_count=math.ceil(max_msg_sz / buffer_sz),  # Round up to allow max msg size
            max_message_size=max_msg_sz,
        )
        self._pubsub: PubSub | None = None
        if config is not None:
            self._apply_config(config)

    @classmethod
    def quickstart(
        cls,
        endpoint: str,
        profile: str = "secure",
        pki: str | Path | None = "./pki",
        users: str | Path | UserManager | None = None,
        **overrides: Any,
    ) -> Server:
        """
        A server for one of the two profiles, not initialised and not started. "secure": Basic256Sha256,
        Aes128Sha256RsaOaep and Aes256Sha256RsaPss with SignAndEncrypt, any network. "development": loopback only,
        also without security. `pki` is the PKI directory (created at `init()` with a self-signed certificate, and
        nothing is trusted); `users` a users file or a user manager; `overrides` any other ServerConfig field.
        """
        return cls(config=quickstart_server_config(endpoint, profile, pki, users, overrides))

    def _apply_config(self, config: ServerConfig) -> None:
        self.endpoint = with_default_port(parse_opc_tcp_url(config.endpoint, "server.endpoint"))
        self.name = config.name
        self._application_uri = config.application_uri
        self.product_uri = config.product_uri
        self.manufacturer_name = config.manufacturer_name
        self._security_policy = config.policy_types()
        limits = config.limits
        iserver = self.iserver
        iserver.session_manager.max_sessions = limits.max_sessions
        iserver.max_connections = limits.max_connections
        iserver.min_session_timeout_ms = limits.min_session_timeout_ms
        iserver.max_session_timeout_ms = limits.max_session_timeout_ms
        iserver.max_subscriptions = limits.max_subscriptions
        iserver.max_subscriptions_per_session = limits.max_subscriptions_per_session
        iserver.min_publishing_interval_ms = limits.min_publishing_interval_ms
        iserver.max_publishing_interval_ms = limits.max_publishing_interval_ms
        iserver.max_monitored_items = limits.max_monitored_items
        iserver.max_monitored_items_per_subscription = limits.max_monitored_items_per_subscription
        iserver.hello_timeout_seconds = limits.hello_timeout_seconds
        iserver.max_string_length = limits.max_string_length
        iserver.max_byte_string_length = limits.max_byte_string_length
        iserver.max_array_length = limits.max_array_length
        self.limits = TransportLimits(
            max_recv_buffer=limits.max_buffer_size,
            max_send_buffer=limits.max_buffer_size,
            max_chunk_count=math.ceil(limits.max_message_size / limits.max_buffer_size),
            max_message_size=limits.max_message_size,
        )
        if config.profile == "development":
            self.socket_address = (self.endpoint.hostname or "127.0.0.1", self.endpoint.port or 4840)

    async def _apply_pki(self, config: ServerConfig) -> None:
        if config.pki is None:
            return
        password = password_from_environment("server.private_key_password_env", config.private_key_password_env)
        try:
            await self.set_pki_directory(config.pki, create=config.create_pki, private_key_password=password)
        except ConfigurationError as error:
            raise ConfigurationError(f"server.pki: {error}") from None
        assert self.iserver.certificate is not None
        check_certificate_uri(self.iserver.certificate, self._application_uri, "server", config.pki)

    async def init_pki(self) -> x509.Certificate:
        """
        Create the PKI directory of the configuration (Server.quickstart, `pki=`) and its self-signed application
        certificate now, and return the certificate. init() does the same; call this first to hand the certificate
        to a client before the server starts. Calling it again returns the same certificate.
        """
        config = self._config
        if config is None or config.pki is None:
            raise ConfigurationError(
                "server.pki: init_pki needs a PKI directory; create the server with Server.quickstart"
            )
        await self._apply_pki(config)
        assert self.iserver.certificate is not None
        return cast("x509.Certificate", self.iserver.certificate)

    async def init(self, shelf_file: Path | None = None) -> None:
        await self.iserver.init(shelf_file)
        await self.set_application_uri(self._application_uri)
        if self._config is not None:
            await self._apply_pki(self._config)
        sa_node = self.get_node(ua.NodeId(ua.ObjectIds.Server_ServerArray))
        await sa_node.write_value([self._application_uri])
        # TODO: ServiceLevel is 255 default, should be calculated in later Versions
        sl_node = self.get_node(ua.NodeId(ua.ObjectIds.Server_ServiceLevel))
        await sl_node.write_value(ua.Variant(255, ua.VariantType.Byte))

        await self.set_build_info(self.product_uri, self.manufacturer_name, self.name, "1.0pre", "0", datetime.now())

    def set_match_discovery_endpoint_url(self, match_discovery_endpoint_url: bool) -> None:
        """
        Enables or disables the matching of the EndpointUrl request parameter during discovery.

        When True (default), the host/port of endpoints sent during the discovery is modified to the host/port
        which is specified in the EndpointUrl request parameter.
        """
        self.iserver.match_discovery_endpoint_url = match_discovery_endpoint_url

    def accept_server_registrations(self, enabled: bool = True) -> None:
        """
        Let other servers register with this server through RegisterServer and RegisterServer2,
        so that this server acts as a discovery server. Off by default.
        Registrations are not authenticated yet, so only enable this on trusted networks.
        """
        self.iserver.accept_server_registrations = enabled

    def set_match_discovery_client_ip(self, match_discovery_client_ip: bool) -> None:
        """
        Enables or disables the matching of an endpoint IP to a client IP during discovery.

        When True (default), the IP address of endpoints sent during the discovery is modified to an IP address
        of the server network interface used to communicate with the client. Disabling comes handy when the real
        client IP is different from the client IP that the server sees (e.g., behind NAT or inside Docker container).
        Do not call unless you know what you are doing.
        """
        self.iserver.match_discovery_source_ip = match_discovery_client_ip

    def set_force_server_timestamp(self, force_server_timestamp: bool) -> None:
        """
        Enables or disables automatically setting ServerTimestamp on Value attributes
        """
        self.iserver.aspace.force_server_timestamp = force_server_timestamp

    async def set_build_info(
        self,
        product_uri: str,
        manufacturer_name: str,
        product_name: str,
        software_version: str,
        build_number: str,
        build_date: datetime,
    ) -> None:
        if not all(
            isinstance(arg, str)
            for arg in [product_uri, manufacturer_name, product_name, software_version, build_number]
        ):
            raise TypeError(f"""Expected all str got
                product_uri: {type(product_uri)},
                manufacturer_name: {type(manufacturer_name)},
                product_name: {type(product_name)},
                software_version: {type(software_version)},
                build_number: {type(build_number)}
                instead!""")

        if not isinstance(build_date, datetime):
            raise TypeError(f"Expected datetime got {type(build_date)} instead!")

        status_node = self.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus))
        build_node = self.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_BuildInfo))

        status_dv = await status_node.read_data_value(raise_on_bad_status=False)
        status = status_dv.Value.Value if status_dv.Value is not None else None
        if status is None:
            status = ua.ServerStatusDataType()
            status.SecondsTillShutdown = 0

        status.BuildInfo.ProductUri = product_uri
        status.BuildInfo.ManufacturerName = manufacturer_name
        status.BuildInfo.ProductName = product_name
        status.BuildInfo.SoftwareVersion = software_version
        status.BuildInfo.BuildNumber = build_number
        status.BuildInfo.BuildDate = build_date

        await status_node.write_value(status)
        await build_node.write_value(status.BuildInfo)

        # we also need to update all individual nodes :/
        product_uri_node = self.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_BuildInfo_ProductUri))
        product_name_node = self.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_BuildInfo_ProductName))
        product_manufacturer_name_node = self.get_node(
            ua.NodeId(ua.ObjectIds.Server_ServerStatus_BuildInfo_ManufacturerName)
        )
        product_software_version_node = self.get_node(
            ua.NodeId(ua.ObjectIds.Server_ServerStatus_BuildInfo_SoftwareVersion)
        )
        product_build_number_node = self.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_BuildInfo_BuildNumber))
        product_build_date_node = self.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_BuildInfo_BuildDate))

        await product_uri_node.write_value(status.BuildInfo.ProductUri)
        await product_name_node.write_value(status.BuildInfo.ProductName)
        await product_manufacturer_name_node.write_value(status.BuildInfo.ManufacturerName)
        await product_software_version_node.write_value(status.BuildInfo.SoftwareVersion)
        await product_build_number_node.write_value(status.BuildInfo.BuildNumber)
        await product_build_date_node.write_value(status.BuildInfo.BuildDate)

    async def __aenter__(self) -> Server:
        await self.start()
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: Any
    ) -> None:
        await self.stop()

    def __str__(self) -> str:
        return f"OPC UA Server({self.endpoint.geturl()})"

    __repr__ = __str__

    async def load_certificate(self, path_or_content: str | bytes | Path, format: str | None = None) -> None:
        """
        load server certificate from file, either pem or der
        """
        self.iserver.certificate = await uacrypto.load_certificate(path_or_content, format)

    async def load_certificate_chain(self, chain: Iterable[str | bytes | Path]) -> None:
        """
        load the intermediate CA certificates between the server certificate and its root, leaf side first.
        Each item is a DER or PEM file (a PEM file may hold several certificates) or the bytes of one.
        The server sends the chain after its certificate wherever it sends its certificate.
        """
        certificates: list[x509.Certificate] = []
        for item in chain:
            certificates.extend(await uacrypto.load_certificates(item))
        self.iserver.certificate_chain = certificates

    async def load_private_key(
        self, path_or_content: str | Path | bytes, password: str | bytes | None = None, format: str | None = None
    ) -> None:
        self.iserver.private_key = await uacrypto.load_private_key(path_or_content, password, format)

    def disable_clock(self, val: bool = True) -> None:
        """
        for debugging you may want to disable clock that write every second
        to address space
        """
        self.iserver.disabled_clock = val

    def get_application_uri(self) -> str:
        return self._application_uri

    async def set_application_uri(self, uri: str) -> None:
        """
        Set application/server URI.
        This uri is supposed to be unique. If you intend to register
        your server to a discovery server, it really should be unique in
        your system!
        default is : "urn:enginir:opcua:server"

        Per OPC 10000-5 v1.05, 6.3.1, both NamespaceArray[1] and ServerArray[0]
        shall equal the ApplicationUri.
        """
        self._application_uri = uri
        ns_node = self.get_node(ua.NodeId(ua.ObjectIds.Server_NamespaceArray))
        uries = await ns_node.read_value()
        if len(uries) > 1:
            uries[1] = uri  # application uri is always namespace 1
        else:
            uries.append(uri)
        await ns_node.write_value(uries)

        # Keep ServerArray in sync (OPC 10000-5 v1.05, 6.3.1)
        sa_node = self.get_node(ua.NodeId(ua.ObjectIds.Server_ServerArray))
        server_array = await sa_node.read_value()
        if server_array:
            server_array[0] = uri
        else:
            server_array = [uri]
        await sa_node.write_value(server_array)

    async def find_servers(self, uris: list[str] | None = None) -> list[ua.ApplicationDescription]:
        """
        find_servers. mainly implemented for symmetry with client
        """
        if uris is None:
            uris = []
        params = ua.FindServersParameters()
        params.EndpointUrl = self.endpoint.geturl()
        params.ServerUris = uris
        return self.iserver.find_servers(params)

    async def _secure_discovery_client(self, client: Client) -> None:
        if self.iserver.certificate is None or self.iserver.private_key is None:
            return
        if self.iserver.trust_store is not None:
            client.set_trust_store(self.iserver.trust_store)
        await client.set_security(
            security_policies.SecurityPolicyBasic256Sha256,
            uacrypto.CertProperties(uacrypto.der_from_x509(self.iserver.certificate), "DER"),
            uacrypto.CertProperties(uacrypto.pem_from_key(self.iserver.private_key), "PEM"),
        )

    async def register_to_discovery(
        self,
        url: str = "opc.tcp://localhost:4840",
        period: int = 60,
        discovery_configuration: ua.DiscoveryConfiguration | None = None,
    ) -> None:
        """
        Register to an OPC-UA Discovery server. Registering must be renewed at
        least every 10 minutes, so this method will use our asyncio thread to
        re-register every period seconds
        if period is 0 registration is not automatically renewed

        The discovery server accepts the registration only on a secure channel, so the server needs its
        certificate and private key, and an application URI (set_application_uri) equal to the ApplicationUri of
        its certificate. The certificate of the discovery server is validated against the trust store of this
        server (set_trust_store).
        """
        if not 0 <= period <= MAX_DISCOVERY_PERIOD_SECONDS:
            raise ValueError(f"period must be between 0 and {MAX_DISCOVERY_PERIOD_SECONDS} seconds")
        client = Client(url)
        await self._secure_discovery_client(client)
        await client.connect_sessionless()
        try:
            await client.register_server(self, discovery_configuration)
        finally:
            await client.disconnect_sessionless()
        self._discovery_clients[url] = client
        self._discovery_configurations[url] = discovery_configuration
        self._discovery_period = period
        if period and (self._discovery_handle is None or self._discovery_handle.done()):
            self._discovery_handle = asyncio.create_task(self._run_renewal_loop())

    async def _run_renewal_loop(self) -> None:
        while True:
            try:
                await self._renew_registration()
            except Exception as e:
                _logger.warning("Error during registration renewal: %s", e)
            await asyncio.sleep(self._discovery_period)

    async def unregister_from_discovery(
        self, url: str = "opc.tcp://localhost:4840", discovery_configuration: ua.DiscoveryConfiguration | None = None
    ) -> None:
        """
        stop registration thread
        """
        client = self._discovery_clients.get(url)
        if client is None:
            raise ua.UaError(f"The server is not registered to {url}")
        del self._discovery_clients[url]
        configuration = self._discovery_configurations.pop(url, None)
        if not self._discovery_clients:
            self._cancel_discovery_renewal()
        await client.connect_sessionless()
        try:
            await client.unregister_server(self, discovery_configuration or configuration)
        finally:
            await client.disconnect_sessionless()

    def _cancel_discovery_renewal(self) -> None:
        if self._discovery_handle is not None:
            self._discovery_handle.cancel()
            self._discovery_handle = None

    async def _renew_registration(self) -> None:
        for url, client in list(self._discovery_clients.items()):
            await client.connect_sessionless()
            try:
                await client.register_server(self, self._discovery_configurations.get(url))
            finally:
                await client.disconnect_sessionless()

    async def _withdraw_discovery_registrations(self) -> None:
        self._cancel_discovery_renewal()
        for url in list(self._discovery_clients):
            try:
                await asyncio.wait_for(self.unregister_from_discovery(url), DISCOVERY_UNREGISTER_TIMEOUT_SECONDS)
            except Exception as e:
                _logger.warning("Could not withdraw the registration from %s: %s", url, e)

    @property
    def allow_plaintext_password(self) -> bool:
        return self.iserver.allow_plaintext_password

    @allow_plaintext_password.setter
    def allow_plaintext_password(self, allow: bool) -> None:
        self.iserver.allow_plaintext_password = allow

    @property
    def max_string_length(self) -> int:
        """Longest String in a request from a client, in bytes (MaxStringLength); set before `init()`."""
        return self.iserver.max_string_length

    @max_string_length.setter
    def max_string_length(self, value: int) -> None:
        self.iserver.max_string_length = value

    @property
    def max_byte_string_length(self) -> int:
        """Longest ByteString in a request from a client, in bytes (MaxByteStringLength); set before `init()`."""
        return self.iserver.max_byte_string_length

    @max_byte_string_length.setter
    def max_byte_string_length(self, value: int) -> None:
        self.iserver.max_byte_string_length = value

    @property
    def max_array_length(self) -> int:
        """Most elements in an array value of a request from a client (MaxArrayLength); set before `init()`."""
        return self.iserver.max_array_length

    @max_array_length.setter
    def max_array_length(self, value: int) -> None:
        self.iserver.max_array_length = value

    def set_endpoint(self, url: str) -> None:
        """Set the endpoint URL: opc.tcp://host[:port][/path]. A URL without scheme or host is refused."""
        self.endpoint = parse_opc_tcp_url(url, "endpoint")

    async def get_endpoints(self) -> list[ua.EndpointDescription]:
        return await self.iserver.get_endpoints()

    def set_security_policy(
        self,
        security_policy: list[ua.SecurityPolicyType],
        permission_ruleset: SimpleRoleRuleset | None = None,
    ) -> None:
        """
        Method setting up the security policies for connections
        to the server, where security_policy is a list of integers.
        During server initialization, all secure endpoints are enabled. The None endpoint is only
        enabled with Server(allow_no_security=True) or by listing ua.SecurityPolicyType.NoSecurity here.
        The deprecated Basic128Rsa15 and Basic256 policies need Server(allow_deprecated_policies=True).

        E.g. to limit the number of endpoints:

                set_security_policy([
                            ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])

        """
        deprecated = [
            policy_type.name
            for policy_type in security_policy
            if getattr(security_policies.SECURITY_POLICY_TYPE_MAP[policy_type][0], "deprecated", False)
        ]
        if deprecated and not self.allow_deprecated_policies:
            raise ConfigurationError(
                f"The deprecated policies {', '.join(deprecated)} are only available with "
                "Server(allow_deprecated_policies=True)"
            )
        if not security_policy:
            raise ConfigurationError("security_policy: the list is empty; name at least one policy")
        self._security_policy = security_policy
        if permission_ruleset is not None:
            self._permission_ruleset = permission_ruleset

    def set_security_IDs(self, policy_ids: list[str]) -> None:
        """
        DEPRECATED!
        Only available for backwards compatibility.
        Use set_identity_tokens instead.
        """
        _logger.warning("set_security_IDs is deprecated, use set_identity_tokens instead!")
        tokens = []
        if "Anonymous" in policy_ids:
            tokens.append(ua.AnonymousIdentityToken)
        if "Basic256Sha256" in policy_ids:
            tokens.append(ua.X509IdentityToken)
        if "Username" in policy_ids:
            tokens.append(ua.UserNameIdentityToken)
        self.set_identity_tokens(tokens)

    def set_identity_tokens(self, tokens: list[type]) -> None:
        """
        Method setting up allowed identity token types for authentication.

        E.g. to disable anonymous clients:

            set_identity_tokens([ua.X509IdentityToken, ua.UserNameIdentityToken])
        """
        if not tokens:
            raise ConfigurationError("identity_tokens: the list is empty; name at least one token type")
        self.iserver.supported_tokens = tuple(tokens)

    async def _setup_server_nodes(self) -> None:
        self.iserver.endpoints = []
        self._policies = []
        no_cert = False
        for policy_type in self._security_policy:
            policy, mode, level = security_policies.SECURITY_POLICY_TYPE_MAP[policy_type]
            if policy is not security_policies.SecurityPolicyNone and not (
                self.iserver.certificate and self.iserver.private_key
            ):
                no_cert = True
                continue
            if getattr(policy, "deprecated", False):
                _logger.warning("The deprecated policy %s is offered, do not use it anymore", policy_type.name)
            self._set_endpoints(policy, mode, level)
            self._policies.append(
                security_policies.SecurityPolicyFactory(
                    policy,
                    mode,
                    self.iserver.certificate,
                    self.iserver.private_key,
                    permission_ruleset=self._permission_ruleset,
                    certificate_chain=self.iserver.certificate_chain,
                )
            )

        if no_cert:
            _logger.warning("Endpoints other than open requested but private key and certificate are not set.")
        if not self.iserver.endpoints:
            raise ConfigurationError(
                "The server has no endpoint: load a certificate and a private key for the secure policies, or "
                "enable the None policy with Server(allow_no_security=True)"
            )

    def _password_policy_uri(
        self, policy: type[security_policies.SecurityPolicy], mode: ua.MessageSecurityMode
    ) -> str | None:
        if mode == ua.MessageSecurityMode.SignAndEncrypt:
            return security_policies.SecurityPolicyNone.URI
        if mode == ua.MessageSecurityMode.Sign:
            return policy.URI
        if self.iserver.certificate and self.iserver.private_key:
            for token_policy_type in self._security_policy:
                token_policy, token_mode, _ = security_policies.SECURITY_POLICY_TYPE_MAP[token_policy_type]
                if token_mode == ua.MessageSecurityMode.SignAndEncrypt:
                    return token_policy.URI  # type: ignore[attr-defined,no-any-return]
        if self.allow_plaintext_password:
            _logger.warning("No encrypting policy available, the password is advertised for transfer in plaintext")
            return security_policies.SecurityPolicyNone.URI
        _logger.info("No UserName token policy on an unsecured endpoint without an encrypting policy")
        return None

    def _set_endpoints(
        self, policy: type[security_policies.SecurityPolicy], mode: ua.MessageSecurityMode, level: int
    ) -> None:
        idtokens = []
        tokens = self.iserver.offered_token_classes()
        if ua.AnonymousIdentityToken in tokens:
            idtoken = ua.UserTokenPolicy()
            idtoken.PolicyId = "anonymous"
            idtoken.TokenType = ua.UserTokenType.Anonymous
            idtoken.SecurityPolicyUri = security_policies.SecurityPolicyNone.URI
            idtokens.append(idtoken)

        if ua.X509IdentityToken in tokens:
            idtoken = ua.UserTokenPolicy()
            idtoken.PolicyId = "certificate"
            idtoken.TokenType = ua.UserTokenType.Certificate
            # always request signing
            if mode == ua.MessageSecurityMode.None_:
                # find first policy with signing
                for token_policy_type in self._security_policy:
                    token_policy, token_mode, _ = security_policies.SECURITY_POLICY_TYPE_MAP[token_policy_type]
                    if token_mode == ua.MessageSecurityMode.None_:
                        continue
                    idtoken.SecurityPolicyUri = token_policy.URI  # type: ignore[attr-defined]
                    idtokens.append(idtoken)
                    break
                else:
                    _logger.warning("No signing policy available, user certificate cannot get verified")
            else:
                idtoken.SecurityPolicyUri = policy.URI
                idtokens.append(idtoken)

        if ua.UserNameIdentityToken in tokens:
            password_policy_uri = self._password_policy_uri(policy, mode)
            if password_policy_uri is not None:
                idtoken = ua.UserTokenPolicy()
                idtoken.PolicyId = "username"
                idtoken.TokenType = ua.UserTokenType.UserName
                idtoken.SecurityPolicyUri = password_policy_uri
                idtokens.append(idtoken)

        appdesc = ua.ApplicationDescription()
        appdesc.ApplicationName = ua.LocalizedText(self.name)
        appdesc.ApplicationUri = self._application_uri
        appdesc.ApplicationType = self.application_type
        appdesc.ProductUri = self.product_uri
        appdesc.DiscoveryUrls.append(self.endpoint.geturl())

        edp = ua.EndpointDescription()
        edp.EndpointUrl = self.endpoint.geturl()
        edp.Server = appdesc
        if self.iserver.certificate:
            edp.ServerCertificate = b"".join(
                uacrypto.der_from_x509(certificate)
                for certificate in (self.iserver.certificate, *self.iserver.certificate_chain)
            )
        edp.SecurityMode = mode
        edp.SecurityPolicyUri = policy.URI
        edp.UserIdentityTokens = idtokens
        edp.TransportProfileUri = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"
        edp.SecurityLevel = level
        self.iserver.add_endpoint(edp)

    def set_server_name(self, name: str) -> None:
        self.name = name

    async def start(self) -> None:
        """
        Start to listen on network
        """
        self._check_development_bind()
        if self.iserver.certificate is not None:
            # Log warnings about the certificate
            uacrypto.check_certificate(self.iserver.certificate, self._application_uri, socket.gethostname())
        await self._prepare_certificate_validation()
        if self.iserver.user_trust_store is not None:
            await self.iserver.user_trust_store.load()
        await self._setup_server_nodes()
        await self.iserver.start()
        try:
            ipaddress, port = self._get_bind_socket_info()
            self.bserver = BinaryServer(self.iserver, ipaddress, port, self.limits)
            self.bserver.set_policies(self._policies)
            for connection in self._reverse_connections:
                self.bserver.add_reverse_connection(connection)
            await self.bserver.start()
        except Exception as exp:
            _logger.exception("%s error starting server", self)
            await self.iserver.stop()
            raise exp
        else:
            _logger.debug("%s server started", self)

    async def _prepare_certificate_validation(self) -> None:
        current = self.iserver.certificate_validator
        if current is not None and current is not self._default_validator:
            _logger.warning(
                "A custom certificate validator is in use; it decides which client certificates are trusted"
            )
            return
        trust_store = self.iserver.trust_store or TrustStore()
        await trust_store.load()
        self._default_validator = CertificateValidator(trust_store)
        self.iserver.certificate_validator = self._default_validator
        has_secure_policy = any(
            security_policies.SECURITY_POLICY_TYPE_MAP[policy_type][0] is not security_policies.SecurityPolicyNone
            for policy_type in self._security_policy
        )
        snapshot = trust_store.snapshot
        if has_secure_policy and not (snapshot.trusted or snapshot.pinned):
            _logger.warning(
                "No client certificate is trusted, so no client can connect with security: "
                "configure the trusted certificates with set_trust_store"
            )

    def _check_development_bind(self) -> None:
        config = self._config
        if config is None or config.profile != "development":
            return
        host = self._get_bind_socket_info()[0]
        if host is None or not is_loopback(host):
            raise ConfigurationError(
                f"server.endpoint: the development profile only listens on loopback addresses, but socket_address "
                f"is {self.socket_address}"
            )
        _logger.warning(
            "development profile: %s offers a connection without security; it is meant for this machine only",
            self.endpoint.geturl(),
        )

    def _get_bind_socket_info(self) -> tuple[str | None, int | None]:
        if self.socket_address is not None:
            return self.socket_address
        return self.endpoint.hostname, self.endpoint.port

    async def stop(self) -> None:
        """
        Stop server
        """
        try:
            await self.iserver.set_server_state(ua.ServerState.Shutdown)
        except Exception:
            _logger.warning("Could not set the server state to Shutdown", exc_info=True)
        await self._withdraw_discovery_registrations()
        if self.bserver is not None:
            await self.bserver.stop()
        await self.iserver.stop()
        if self._pubsub is not None:
            await self._pubsub.stop()
        _logger.debug("%s Internal server stopped, everything closed", self)

    def get_root_node(self) -> Node:
        """
        Get Root node of server. Returns a Node object.
        """
        return self.get_node(ua.TwoByteNodeId(ua.ObjectIds.RootFolder))

    def get_objects_node(self) -> Node:
        """
        Get Objects node of server. Returns a Node object.
        """
        return self.get_node(ua.TwoByteNodeId(ua.ObjectIds.ObjectsFolder))

    def get_node(self, nodeid: Node | ua.NodeId | str | int) -> Node:
        """
        Get a specific node using NodeId object or a string representing a NodeId
        """
        return Node(self.iserver.isession, nodeid)

    async def create_subscription(
        self,
        period: float,
        handler: Any = None,
        *,
        queue_maxsize: int = 1000,
    ) -> Subscription:
        params = ua.CreateSubscriptionParameters()
        params.RequestedPublishingInterval = period
        params.RequestedLifetimeCount = 3000
        params.RequestedMaxKeepAliveCount = 10000
        params.MaxNotificationsPerPublish = 0
        params.PublishingEnabled = True
        params.Priority = 0
        subscription = Subscription(
            self.iserver.isession,
            params,
            handler,
            queue_maxsize=queue_maxsize,
        )
        await subscription.init()
        return subscription

    @property
    def types(self) -> ua.TypeRegistry:
        return self.iserver.types

    async def get_namespace_array(self) -> list[str]:
        """
        get all namespace defined in server
        """
        return await self.nodes.namespace_array.read_value()

    async def register_namespace(self, uri: str) -> int:
        """
        Register a new namespace. Nodes should in custom namespace, not 0.
        """
        uries = await self.nodes.namespace_array.read_value()
        if uri in uries:
            return uries.index(uri)
        uries.append(uri)
        await self.nodes.namespace_array.write_value(uries)
        return len(uries) - 1

    async def get_namespace_index(self, uri: str) -> int:
        """
        get index of a namespace using its uri
        """
        uries = await self.get_namespace_array()
        return uries.index(uri)

    async def get_event_generator(
        self,
        etype: BaseEvent | Node | ua.NodeId | int | None = None,
        emitting_node: Node | ua.NodeId | int = ua.ObjectIds.Server,
    ) -> EventGenerator:
        """
        Returns an event object using an event type from address space.
        Use this object to fire events
        """
        if not etype:
            etype = BaseEvent()
        ev_gen = EventGenerator(self.iserver.isession)
        await ev_gen.init(etype, emitting_node=emitting_node)
        return ev_gen

    async def create_custom_data_type(
        self,
        idx: int | ua.NodeId,
        name: str | ua.QualifiedName,
        basetype: ua.NodeId | int = ua.ObjectIds.BaseDataType,
        properties: list[tuple] | None = None,
        description: str | None = None,
    ) -> Node:
        if properties is None:
            properties = []
        base_t = _get_node(self.iserver.isession, basetype)

        custom_t = await base_t.add_data_type(idx, name, description)
        for prop in properties:
            datatype = None
            if len(prop) > 2:
                datatype = prop[2]
            await custom_t.add_property(
                idx, prop[0], ua.get_default_value(prop[1]), varianttype=prop[1], datatype=datatype
            )
        return custom_t

    async def create_custom_event_type(
        self,
        idx: int | ua.NodeId,
        name: str | ua.QualifiedName,
        basetype: ua.NodeId | int = ua.ObjectIds.BaseEventType,
        properties: list[tuple] | None = None,
    ) -> Node:
        if properties is None:
            properties = []
        return await self._create_custom_type(idx, name, basetype, properties, [], [])

    async def create_custom_object_type(
        self,
        idx: int | ua.NodeId,
        name: str | ua.QualifiedName,
        basetype: ua.NodeId | int = ua.ObjectIds.BaseObjectType,
        properties: list[tuple] | None = None,
        variables: list[tuple] | None = None,
        methods: list[tuple] | None = None,
    ) -> Node:
        if properties is None:
            properties = []
        if variables is None:
            variables = []
        if methods is None:
            methods = []
        return await self._create_custom_type(idx, name, basetype, properties, variables, methods)

    # def create_custom_reference_type(self, idx, name, basetype=ua.ObjectIds.BaseReferenceType, properties=[]):
    # return self._create_custom_type(idx, name, basetype, properties)

    async def create_custom_variable_type(
        self,
        idx: int | ua.NodeId,
        name: str | ua.QualifiedName,
        basetype: ua.NodeId | int = ua.ObjectIds.BaseVariableType,
        properties: list[tuple] | None = None,
        variables: list[tuple] | None = None,
        methods: list[tuple] | None = None,
    ) -> Node:
        if properties is None:
            properties = []
        if variables is None:
            variables = []
        if methods is None:
            methods = []
        return await self._create_custom_type(idx, name, basetype, properties, variables, methods)

    async def _create_custom_type(
        self,
        idx: int | ua.NodeId,
        name: str | ua.QualifiedName,
        basetype: ua.NodeId | int,
        properties: list[tuple],
        variables: list[tuple],
        methods: list[tuple],
    ) -> Node:
        base_t = _get_node(self.iserver.isession, basetype)
        custom_t = await base_t.add_object_type(idx, name)
        for prop in properties:
            datatype = None
            if len(prop) > 2:
                datatype = prop[2]
            await custom_t.add_property(
                idx, prop[0], ua.get_default_value(prop[1]), varianttype=prop[1], datatype=datatype
            )
        for variable in variables:
            datatype = None
            if len(variable) > 2:
                datatype = variable[2]
            await custom_t.add_variable(
                idx, variable[0], ua.get_default_value(variable[1]), varianttype=variable[1], datatype=datatype
            )
        for method in methods:
            await custom_t.add_method(idx, method[0], method[1], method[2], method[3])
        return custom_t

    async def import_xml(
        self,
        path: str | None = None,
        xmlstring: str | None = None,
        strict_mode: bool = True,
        auto_load_definitions: bool = True,
    ) -> list[ua.NodeId]:
        """
        Import nodes defined in xml
        """
        importer = XmlImporter(self, strict_mode, auto_load_definitions)
        return await importer.import_xml(path, xmlstring)

    async def export_xml(
        self, nodes: Iterable[Node], path: str, export_values: bool = False, model_uris: list[str] | None = None
    ) -> None:
        """
        Export defined nodes to xml
        :param export_value: export values from variants
        :param model_uris: namespaces that are written as models, with their version and required models
        """
        exp = XmlExporter(self, export_values=export_values)
        await exp.build_etree(nodes, model_uris=model_uris)
        await exp.write_xml(path)

    async def export_xml_by_ns(
        self, path: str, namespaces: list[str | int] | None = None, export_values: bool = False
    ) -> None:
        """
        Export nodes of one or more namespaces to an XML file.
        Namespaces used by nodes are always exported for consistency.

        :param path: name of the xml file to write
        :param namespaces: list of string uris or int indexes of the namespace to export;
            if not provided all ns are used except 0
        :param export_values: export values from variants
        """
        if namespaces is None:
            namespaces = []
        nodes = await get_nodes_of_namespace(self, namespaces)
        ns_array = await self.get_namespace_array()
        uris = [ns if isinstance(ns, str) else ns_array[ns] for ns in namespaces] or ns_array[1:]
        await self.export_xml(nodes, path, export_values=export_values, model_uris=uris)

    async def delete_nodes(
        self, nodes: Iterable[Node], recursive: bool = False
    ) -> tuple[list[Node], list[ua.StatusCode]]:
        return await delete_nodes(self.iserver.isession, nodes, recursive)

    async def historize_node_data_change(
        self, node: Node | list[Node] | tuple[Node, ...], period: timedelta = timedelta(days=7), count: int = 0
    ) -> None:
        """
        Start historizing supplied nodes; see history module
        :param node: node or list of nodes that can be historized (variables/properties)
        :param period: time delta to store the history; older data will be deleted from the storage
        :param count: number of changes to store in the history
        """
        nodes = node if isinstance(node, list | tuple) else [node]
        for n in nodes:
            await self.iserver.enable_history_data_change(n, period, count)

    async def dehistorize_node_data_change(self, node: Node | list[Node] | tuple[Node, ...]) -> None:
        """
        Stop historizing supplied nodes; see history module
        :param node: node or list of nodes that can be historized (UA variables/properties)
        """
        nodes = node if isinstance(node, list | tuple) else [node]
        for n in nodes:
            await self.iserver.disable_history_data_change(n)

    async def historize_node_event(
        self, node: Node | list[Node] | tuple[Node, ...], period: timedelta = timedelta(days=7), count: int = 0
    ) -> None:
        """
        Start historizing events from node (typically a UA object); see history module
        :param node: node or list of nodes that can be historized (UA objects)
        :param period: time delta to store the history; older data will be deleted from the storage
        :param count: number of events to store in the history
        """
        nodes = node if isinstance(node, list | tuple) else [node]
        for n in nodes:
            await self.iserver.enable_history_event(n, period, count)

    async def dehistorize_node_event(self, node: Node | list[Node] | tuple[Node, ...]) -> None:
        """
        Stop historizing events from node (typically a UA object); see history module
        :param node: node or list of nodes that can be historized (UA objects)
        """
        nodes = node if isinstance(node, list | tuple) else [node]
        for n in nodes:
            await self.iserver.disable_history_event(n)

    def subscribe_server_callback(self, event: CallbackType, handle: Callable[..., Any]) -> None:
        self.iserver.subscribe_server_callback(event, handle)

    def unsubscribe_server_callback(self, event: CallbackType, handle: Callable[..., Any]) -> None:
        self.iserver.unsubscribe_server_callback(event, handle)

    def link_method(self, node: Node, callback: Callable[..., Any]) -> None:
        """
        Link a python function to a UA method in the address space; required when a UA method has been imported
        to the address space via XML; the python executable must be linked manually
        :param node: UA method node
        :param callback: python function that the UA method will call
        """
        self.iserver.isession.add_method_callback(node.nodeid, callback)

    async def load_type_definitions(self, nodes: Iterable[Node] | None = None) -> Any:
        """
        load custom structures from our server.
        Server side this can be used to create python objects from custom structures
        imported through xml into server
        """
        _logger.warning("Deprecated since spec 1.04, call load_data_type_definitions")
        return await load_type_definitions(self, nodes)

    async def load_data_type_definitions(
        self, node: Node | None = None, overwrite_existing: bool = False
    ) -> dict[str, type]:
        """
        Load custom types (custom structures/extension objects) definition from server
        Generate Python classes for custom structures/extension objects defined in server
        These classes will be available in ua module
        """
        return await load_data_type_definitions(self, node, overwrite_existing=overwrite_existing)

    async def load_enums(self) -> dict[str, type]:
        """
        load UA structures and generate python Enums in ua module for custom enums in server
        """
        _logger.warning("Deprecated since spec 1.04, call load_data_type_definitions")
        return await load_enums(self)

    async def write_attribute_value(
        self, nodeid: ua.NodeId, datavalue: ua.DataValue, attr: ua.AttributeIds = ua.AttributeIds.Value
    ) -> None:
        """
        write datavalue to the Attribute as the application itself: the access bits are not checked, the type,
        shape and index range are. Raises the error of a bad result
        """
        return await self.iserver.write_attribute_value(nodeid, datavalue, attr)

    def set_attribute_value_callback(
        self,
        nodeid: ua.NodeId,
        callback: Callable[[ua.NodeId, ua.AttributeIds], ua.DataValue],
        attr: ua.AttributeIds = ua.AttributeIds.Value,
    ) -> None:
        """
        Set a callback function to the Attribute that returns a value for read_attribute_value() instead of the
        written value. Note that it does not trigger the datachange_callbacks unlike write_attribute_value().
        A client cannot write the Attribute (Bad_NotWritable); a write by the application replaces the callback.
        """
        self.iserver.set_attribute_value_callback(nodeid, callback, attr)

    def set_attribute_value_setter(
        self,
        nodeid: ua.NodeId,
        setter: Callable[[NodeData, ua.AttributeIds, ua.DataValue], ua.StatusCode | Awaitable[Any] | None],
        attr: ua.AttributeIds = ua.AttributeIds.Value,
    ) -> None:
        """
        Set a setter function for the Attribute. This setter will be called when a new value is written, instead of
        storing it, and has to store the value itself. Its returned StatusCode is the result of the write (nothing
        returned is Good); a bad result, or a raised status-coded error, means nothing was written and the data change
        callbacks are not called.
        """
        self.iserver.set_attribute_value_setter(nodeid, setter, attr)

    def read_attribute_value(self, nodeid: ua.NodeId, attr: ua.AttributeIds = ua.AttributeIds.Value) -> ua.DataValue:
        """
        directly read datavalue of the Attribute
        """
        return self.iserver.read_attribute_value(nodeid, attr)

    async def read_attributes(
        self, nodes: Iterable[Node], attr: ua.AttributeIds = ua.AttributeIds.Value
    ) -> list[ua.DataValue]:
        """
        directly read the attributes of multiple nodes.
        async for compatibility with client API
        """
        nodeids = [node.nodeid for node in nodes]
        return [self.iserver.read_attribute_value(nodeid, attr) for nodeid in nodeids]

    # --- File transfer and certificate management (Part 20, Part 12) ---
    async def add_file(
        self,
        parent: Node | ua.NodeId,
        name: str,
        provider: FileProvider | str | Path,
        *,
        writable: bool = False,
        max_size: int | None = None,
        mime_type: str | None = None,
        max_byte_string_length: int | None = None,
        write_role: UserRole = UserRole.User,
        namespace: int | None = None,
    ) -> Node:
        """
        Make a file visible to clients as a FileType Object below `parent`. `provider` is a path to a regular file
        or an object with the FileProvider operations (MemoryFile keeps the content in memory). Clients open it
        with Open and move the content with Read and Write; a handle belongs to one Session. With `writable` a
        client whose role is at least `write_role` may open it for writing, up to `max_size` bytes.
        """
        return await self.iserver.file_service.add_file(
            _get_node(self.iserver.isession, parent),
            name,
            provider,
            writable=writable,
            max_size=max_size,
            mime_type=mime_type,
            max_byte_string_length=max_byte_string_length,
            write_role=write_role,
            namespace=namespace,
        )

    async def add_directory(
        self,
        parent: Node | ua.NodeId,
        name: str,
        root: str | Path,
        *,
        writable: bool = False,
        max_file_size: int | None = None,
        max_entries: int = 10_000,
        write_role: UserRole = UserRole.User,
        namespace: int | None = None,
    ) -> Node:
        """
        Make the directory `root` visible as a FileDirectoryType Object below `parent` (name it "FileSystem" for the
        root of a tree). Clients can create, delete, move and copy files and directories below `root` when `writable`
        is set and their role is at least `write_role`. No path from a client can leave `root`.
        """
        return await self.iserver.file_service.add_directory(
            _get_node(self.iserver.isession, parent),
            name,
            root,
            writable=writable,
            max_file_size=max_file_size,
            max_entries=max_entries,
            write_role=write_role,
            namespace=namespace,
        )

    async def refresh_directory(self, directory: Node | ua.NodeId) -> None:
        """Bring the Objects of a directory and everything below it in line with the file system."""
        await self.iserver.file_service.refresh_directory(_get_node(self.iserver.isession, directory))

    async def enable_push_management(
        self,
        *,
        max_trust_list_size: int = 65_535,
        min_security_mode: ua.MessageSecurityMode = ua.MessageSecurityMode.SignAndEncrypt,
        activity_timeout: float = 60.0,
    ) -> CertificateManager:
        """
        Let a SecurityAdmin replace the certificate and the trust lists of this server over OPC UA (OPC 10000-12,
        7.10, push management): the ServerConfiguration Object with UpdateCertificate, CreateSigningRequest,
        GetRejectedList, GetCertificates, ApplyChanges and CancelChanges, and the TrustLists of its
        CertificateGroups. Call it after init() and set_pki_directory (and set_user_pki_directory for the user
        TrustList), because every change is written to the PKI directory. The Methods need a user whose role is
        SecurityAdmin and a channel with at least `min_security_mode`.
        """
        manager = CertificateManager(
            self,
            max_trust_list_size=max_trust_list_size,
            min_security_mode=min_security_mode,
            activity_timeout=activity_timeout,
        )
        await manager.enable()
        self._certificate_manager = manager
        return manager

    # --- end of File transfer and certificate management ---

    def set_trust_store(self, trust_store: TrustStore) -> None:
        """
        Set the trusted certificates, issuer certificates and revocation lists that client certificates are
        validated against. Without a trust store no client certificate is trusted.
        """
        self.iserver.trust_store = trust_store

    async def set_pki_directory(
        self, root: str | Path, create: bool = True, private_key_password: str | bytes | None = None
    ) -> None:
        """
        Use one PKI directory for the certificate, the key and the trust of this server: own/certs and own/private
        hold the application certificate (with the intermediate CA certificates of its chain) and its key,
        trusted/certs and trusted/crl the trusted certificates and their revocation lists, issuer/certs and
        issuer/crl the CA certificates for chains and their lists, and rejected/certs receives the certificates
        of clients that failed validation. An administrator trusts one by moving its file to trusted/certs and
        calling reload_trust_store (or restarting).

        With create the folders are created, and when own/certs holds no certificate a self-signed one is generated
        there with the application URI and the host names of the endpoint (set the application URI and the
        endpoint first). An existing certificate is never replaced. Explicit paths (load_certificate,
        set_trust_store, ...) keep working and replace what this call set.
        """
        base = Path(root)
        if create:
            await anyio.to_thread.run_sync(lambda: pki.create_directories(base))
        credentials = await pki.load_own_credentials(
            base,
            application_uri=self._application_uri,
            host_names=pki.default_host_names(self.endpoint.hostname),
            usage=pki.SERVER_USAGE,
            password=private_key_password,
            create=create,
        )
        self.iserver.certificate = credentials.certificate
        self.iserver.certificate_chain = credentials.chain
        self.iserver.private_key = credentials.private_key
        self.iserver.trust_store = TrustStore.from_pki_directory(base)

    def set_user_pki_directory(self, root: str | Path, create: bool = True) -> None:
        """
        Use a PKI directory for the user trust list of X509 identity tokens, with the folders trusted/certs,
        trusted/crl, issuer/certs, issuer/crl and rejected/certs of set_pki_directory and no own/. It is separate
        from the PKI directory of the application.
        """
        base = Path(root)
        if create:
            pki.create_directories(base, own=False)
        self.iserver.user_trust_store = TrustStore.from_pki_directory(base)

    async def reload_trust_store(self) -> None:
        """Load the trust store and the user trust store again, to pick up files moved into their folders."""
        for store in (self.iserver.trust_store, self.iserver.user_trust_store):
            if store is not None:
                await store.load()

    def set_user_trust_store(self, trust_store: TrustStore) -> None:
        """
        Set the trusted certificates, issuer certificates and revocation lists that the certificates of X509
        identity tokens (user certificates) are validated against. They are separate from the application
        certificates of set_trust_store. Without one, no user certificate is trusted, except the ones of a
        CertificateUserManager, which are pinned.
        """
        self.iserver.user_trust_store = trust_store

    def set_certificate_validator(self, validator: CertificateValidator) -> None:
        """
        Replace the certificate validator that checks the certificate of every client at OpenSecureChannel.
        Use set_trust_store to configure the default validator instead.
        """
        self.iserver.certificate_validator = validator

    def set_application_hook(self, hook: validator.ApplicationHook) -> None:
        """
        Assign a method that is called with the certificate and application description of a client in
        CreateSession, after the certificate validator accepted the certificate. It can only reject, by raising
        the correct status code:

            async def example_hook(certificate: x509.Certificate, app_description: ua.ApplicationDescription):
                if not_valid_condition:
                    raise ServiceError(ua.StatusCodes.BadCertificateInvalid)
        """
        self.iserver.application_hook = hook

    async def get_pubsub(self) -> PubSub:
        """
        gets the pubsub model
        """
        if self._pubsub is None:
            self._pubsub = PubSub(server=self)
            await self._pubsub.init_information_model()
        return self._pubsub

    # --- Diagnostics, programs, reverse connect, model change ---

    def add_reverse_connect(
        self, client_url: str, endpoint_url: str | None = None, retry_interval: float = 5.0
    ) -> ReverseConnection:
        """
        Connect to a client that listens at client_url and let it open the SecureChannel on that socket (reverse
        connect, OPC 10000-6 v1.05, 7.1.2.6 and 7.1.3). The server sends a ReverseHello with its application URI and
        endpoint_url (default: the endpoint of the server), keeps one such socket open for the client at all times and
        reconnects after retry_interval seconds when the client refuses or the connection fails. Can be called before
        or after start. Returns the handle for remove_reverse_connect.
        """
        connection = ReverseConnection(
            client_url,
            endpoint_url if endpoint_url is not None else (lambda: self.endpoint.geturl()),
            lambda: self._application_uri,
            retry_interval,
        )
        if any(
            c.client_url == client_url and c.endpoint_url == connection.endpoint_url for c in self._reverse_connections
        ):
            raise ValueError(f"Reverse connection to {client_url} exists")
        self._reverse_connections.append(connection)
        if self.bserver is not None:
            self.bserver.add_reverse_connection(connection)
        return connection

    def remove_reverse_connect(self, connection: ReverseConnection) -> None:
        self._reverse_connections.remove(connection)
        if self.bserver is not None:
            self.bserver.remove_reverse_connection(connection)

    def model_change(self) -> contextlib.AbstractAsyncContextManager[None]:
        """
        Collect the model changes (AddNodes, DeleteNodes, AddReferences, DeleteReferences) of everything done in the
        block, by this task and the tasks it starts, into one GeneralModelChangeEvent raised when the block ends:

            async with server.model_change():
                await folder.add_object(2, "A")
                await folder.add_object(2, "B")

        Without a block every call is a request of its own and raises its own event.
        """
        return self.iserver.model_changes.request()

    @property
    def model_change_events(self) -> str:
        """
        "all" (default): a model change event names every changed Node. "versioned": only Nodes that have a
        NodeVersion Property, the literal reading of OPC 10000-3 v1.05, 9.32.2. The NodeVersion of a named Node
        that has the Property is updated in both modes.
        """
        return self.iserver.model_change_events

    @model_change_events.setter
    def model_change_events(self, mode: str) -> None:
        if mode not in ("all", "versioned"):
            raise ValueError("model_change_events is 'all' or 'versioned'")
        self.iserver.model_change_events = mode

    @property
    def diagnostics(self) -> DiagnosticsCollector:
        """
        The server diagnostics (OPC 10000-5 v1.05, 6.3.3): `enabled` is the EnabledFlag of Server/ServerDiagnostics,
        which a client with the Admin or SecurityAdmin role can write too; `summary()` returns the counters of
        ServerDiagnosticsSummary. The counters run always, the Session and Subscription details only while enabled.
        """
        return self.iserver.diagnostics

    # --- Alarms and Conditions (Part 9) ---

    async def create_condition(
        self,
        source: Node | ua.NodeId | None,
        condition_type: Node | ua.NodeId | int,
        name: str,
        **options: Any,
    ) -> Condition:
        """
        Create a Condition or Alarm instance of a ConditionType below its source and return its handle.
        Options: node_id, namespace, notifier, confirmable, shelving, suppression, branches (default off),
        severity, condition_class, quality, comment_max_length, limits, deadbands, severities (dicts keyed by
        HighHigh, High, Low, LowLow), input_node, follow_input, normal_value, normal_node, setpoint_node,
        max_time_shelved (milliseconds).
        """
        return await self.iserver.condition_manager.create(source, condition_type, name, **options)

    async def delete_condition(self, condition: Condition) -> None:
        await self.iserver.condition_manager.delete(condition)

    def get_condition(self, condition_id: ua.NodeId | Node) -> Condition | None:
        return self.iserver.condition_manager.get(condition_id)

    @property
    def conditions(self) -> list[Condition]:
        return list(self.iserver.condition_manager.conditions.values())

    async def refresh_required(self, subscription_ids: list[int] | None = None) -> None:
        """Tell clients that their Condition state may be out of date (RefreshRequiredEvent, Part 9, 5.11.4)."""
        await self.iserver.condition_manager.refresh_required(subscription_ids)

    # --- end Alarms and Conditions ---
