"""
The high-level OPC UA client: connection, security, session, reconnect and the convenience calls on top of UaClient.
"""

import asyncio
import contextvars
import dataclasses
import json
import logging
import os
import secrets
import socket
import time
from collections.abc import Awaitable, Callable, Coroutine, Iterable, Sequence
from pathlib import Path
from typing import Any, TypeVar, cast
from urllib.parse import ParseResult, unquote, urlparse

import anyio
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import ExtendedKeyUsageOID

import enginir_opcua
from enginir_opcua import ua

from ..common.manage_nodes import delete_nodes
from ..common.node import Node
from ..common.shortcuts import Shortcuts
from ..common.structures import load_enums, load_type_definitions
from ..common.structures104 import load_data_type_definitions
from ..common.subscription import Subscription, SubscriptionHandler, subscription_parameters
from ..common.ua_utils import value_to_datavalue
from ..common.utils import ServiceError, create_nonce
from ..common.xmlexporter import XmlExporter
from ..common.xmlimporter import XmlImporter
from ..config import ClientConfig, check_certificate_uri, password_from_environment, quickstart_client_config
from ..crypto import cert_gen, pki, security_policies, uacrypto
from ..crypto.truststore import TrustStore
from ..crypto.validator import (
    ApplicationHook,
    CertificateValidator,
    PeerRole,
    ValidationContext,
    check_application_uri,
    untrusted_hint,
)
from ..observer import Observer
from ..ua.uaerrors import (
    BadCertificateInvalid,
    BadCertificateUntrusted,
    BadCommunicationError,
    BadConnectionClosed,
    BadSecureChannelClosed,
    BadSecureChannelIdInvalid,
    BadSecurityChecksFailed,
    BadSecurityPolicyRejected,
    BadSessionClosed,
    BadSessionIdInvalid,
    BadSessionNotActivated,
    ConfigurationError,
)
from .ua_client import ReverseConnectListener, ReverseTarget, StateSubscription, UaClient, UaClientState
from .ua_session import check_result_count

_logger = logging.getLogger(__name__)

SESSION_NONCE_MIN_LENGTH = 32
SESSION_NONCE_MAX_LENGTH = 128
TCP_BINARY_PROFILE = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"
LOSS_STATUS_ERRORS = (
    BadSecureChannelClosed,
    BadSecureChannelIdInvalid,
    BadSessionClosed,
    BadSessionIdInvalid,
    BadConnectionClosed,
    BadCommunicationError,
)
DEFAULT_PORT = 4840
RENEW_RETRY_DELAY = 1.0
RENEW_RETRY_MAX_DELAY = 10.0

_T = TypeVar("_T")


_supervisor_owns_requests: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "enginir_opcua.supervisor_owns_requests", default=False
)


@dataclasses.dataclass
class _ReverseConfig:
    """Reverse connect of one client (OPC 10000-6 v1.05, 7.1.3): the listener, the server it waits for."""

    listener: ReverseConnectListener
    target: ReverseTarget
    server_uri: str
    accept_timeout: float
    owns_listener: bool
    announced_endpoint_url: str | None = None


class Client:
    """
    A client of one OPC UA server: connect() opens the connection, the secure channel and the session, and keeps
    them alive (channel renewal, a liveness probe and, with auto_reconnect, reconnection with the subscriptions
    restored). get_node gives Nodes to work with. The raw services are on self.uaclient.
    """

    def __init__(
        self,
        url: str | None = None,
        timeout: float = 4,
        watchdog_intervall: float = 1.0,
        auto_reconnect: bool = False,
        reconnect_max_delay: float = 30.0,
        reconnect_request_timeout: float = 60.0,
        allow_deprecated_policies: bool = False,
        observer: Observer | None = None,
        config: ClientConfig | None = None,
    ) -> None:
        """
        :param url: url of the server.
            if you are unsure of url, write at least hostname
            and port and call get_endpoints
        :param timeout:
            Each request sent to the server expects an answer within this
            time. The timeout is specified in seconds.
        :param watchdog_intervall:
            The time between checking if the server is still alive. The timeout is specified in seconds.
        :param auto_reconnect: when True, a supervisor task is started that
            monitors transport health and re-establishes the connection
            (including re-creating all live subscriptions) on loss.
        :param reconnect_max_delay: exponential backoff cap for reconnect attempts (seconds).
        :param reconnect_request_timeout: how long requests block waiting for the
            connection to become ready while the supervisor is reconnecting.
        :param allow_deprecated_policies: allow set_security with the deprecated Basic128Rsa15 or Basic256 policy.
        :param observer: an :class:`enginir_opcua.observer.Observer` that is told about requests, state changes and
            subscription events; also available as the ``observer`` property.
        :param config: a :class:`enginir_opcua.config.ClientConfig` (see Client.quickstart); give it instead of
            `url`. Its timeout and auto_reconnect replace the parameters; the PKI directory and the security are
            applied at the first connect().

        Attributes to set before connect(): name, description, application_uri and product_uri describe this
        client; secure_channel_timeout and session_timeout (ms) are requested and replaced by the revised values;
        application_hook is an extra check of the server certificate after validation, which rejects it by raising
        a ServiceError; session_state_path, a file in which the session is kept, lets a new client process resume
        the session of the previous one with ActivateSession (OPC 10000-4 v1.05, 6.7) instead of creating one.
        """
        self._config: ClientConfig | None = config
        self._config_applied = False
        if config is not None:
            if url is not None:
                raise ConfigurationError("client: the url comes from the config; leave the url argument out")
            config.validate()
            url = config.url
            timeout = config.timeout
            auto_reconnect = config.auto_reconnect
        elif url is None:
            raise ConfigurationError("client.url: give the URL of the server, or a config")
        self._username: str | None = None
        self._password: str | None = None
        self.strip_url_credentials: bool = True
        self._server_url = urlparse(url)
        if self._server_url.scheme != "opc.tcp":
            raise ConfigurationError(f"Only opc.tcp URLs are supported, got {url!r}")
        userinfo, have_info, _ = self._server_url.netloc.rpartition("@")
        if have_info:
            username, have_password, password = userinfo.partition(":")
            self._username = unquote(username)
            if have_password:
                self._password = unquote(password)

        self.name = "engiNIR OPC UA Client"
        self.description = self.name
        self.application_uri = "urn:enginir:opcua:client"
        self.product_uri = "urn:enginir:opcua"
        self.server_uri: str | None = None
        self.security_policy: security_policies.SecurityPolicy = security_policies.SecurityPolicyNone()
        self.secure_channel_timeout = 3_600_000
        self.session_timeout = 3_600_000
        self.connection_lost_callback: Callable[[Exception], Coroutine[Any, Any, None]] | None = None
        self._policy_ids: list[ua.UserTokenPolicy] = []
        self._discovered_endpoints: list[ua.EndpointDescription] | None = None
        self.uaclient: UaClient = UaClient(timeout)
        self._namespace_uris: list[str] = []
        self.types: ua.TypeRegistry = ua.TypeRegistry(
            namespaces=lambda: self._namespace_uris, parents=(ua.default_types,)
        )
        self.uaclient.types = self.types
        if observer is not None:
            self.uaclient.observer = observer
        self.uaclient.pre_request_hook = self._wait_until_ready
        self.user_certificate: x509.Certificate | None = None
        self.user_private_key: PrivateKeyTypes | None = None
        self.user_certificate_chain: list[x509.Certificate] = []
        self._server_nonce: bytes | None = None
        self._session_counter = 1
        self.nodes: Shortcuts = Shortcuts(self.uaclient.session)
        self.max_messagesize = 0
        self.max_chunkcount = 0
        self._renew_channel_task: asyncio.Task[None] | None = None
        self._supervisor_task: asyncio.Task[None] | None = None
        self._stale_watchdog_task: asyncio.Task[None] | None = None
        self._locale: list[str] = ["en"]
        self._watchdog_intervall = watchdog_intervall
        self._subscriptions: list[Subscription] = []
        self._auto_reconnect: bool = auto_reconnect
        self._reconnect_max_delay: float = reconnect_max_delay
        self._reconnect_request_timeout: float = reconnect_request_timeout
        self._max_activation_failures: int = 3
        self._activation_failures: int = 0
        self._stale_check_margin: float = 1.5
        self._stale_check_interval: float = 0.5
        self.trust_store: TrustStore | None = None
        self.certificate_validator: CertificateValidator | None = None
        self.allow_deprecated_policies: bool = allow_deprecated_policies
        self.application_hook: ApplicationHook | None = None
        self._default_validator: CertificateValidator | None = None
        self._pinned_server_certificate: x509.Certificate | None = None
        self._own_credentials: pki.OwnCredentials | None = None
        self.session_state_path: Path | None = None
        self._reverse: _ReverseConfig | None = None
        if config is not None:
            self.name = self.description = config.name
            self.application_uri = config.application_uri
            self.session_timeout = config.session_timeout_ms
            if config.username is not None:
                self._username = config.username
                self._password = config.effective_password()

    @classmethod
    def quickstart(
        cls,
        url: str,
        profile: str = "secure",
        pki: str | Path | None = "./pki",
        username: str | None = None,
        password: str | None = None,
        **overrides: Any,
    ) -> "Client":
        """
        A client for one of the two profiles, not connected. "secure": Basic256Sha256 with SignAndEncrypt.
        "development": the server has to be on this machine, and the default is no security. `pki` is the PKI
        directory (created at the first connect() with a self-signed certificate; the server certificate has to be
        in its trusted/certs, see `enginir-opcua trust`); `overrides` any other ClientConfig field.
        """
        return cls(config=quickstart_client_config(url, profile, pki, username, password, overrides))

    async def init_pki(self) -> x509.Certificate:
        """
        Create the PKI directory of the configuration (Client.quickstart, `pki=`) and its self-signed application
        certificate now instead of at the first connect(), and return the certificate. A program that pairs this
        client with a server in code needs the certificate to put it into the server's trusted/certs first. Calling it
        again returns the same certificate; an existing certificate is never replaced.
        """
        config = self._config
        if config is None or config.pki is None:
            raise ConfigurationError(
                "client.pki: init_pki needs a PKI directory; create the client with Client.quickstart"
            )
        return await self._load_config_pki(config)

    async def _load_config_pki(self, config: ClientConfig) -> x509.Certificate:
        assert config.pki is not None
        password = password_from_environment("client.private_key_password_env", config.private_key_password_env)
        try:
            await self.set_pki_directory(config.pki, create=config.create_pki, private_key_password=password)
        except ConfigurationError as error:
            raise ConfigurationError(f"client.pki: {error}") from None
        assert self._own_credentials is not None
        check_certificate_uri(self._own_credentials.certificate, self.application_uri, "client", config.pki)
        return self._own_credentials.certificate

    async def _apply_config(self) -> None:
        config = self._config
        if config is None or self._config_applied:
            return
        policy_type = config.policy_type()
        if policy_type is not ua.SecurityPolicyType.NoSecurity:
            await self._load_config_pki(config)
            policy_name, _, mode_name = (config.security or "").partition(",")
            policy = getattr(security_policies, f"SecurityPolicy{policy_name.replace('_', '')}")
            await self.set_security(
                policy,
                mode=ua.MessageSecurityMode[mode_name],
                server_certificate=str(config.server_certificate) if config.server_certificate else None,
            )
        self._config_applied = True

    def listen_reverse(
        self,
        listen_url: str,
        server_uri: str,
        endpoint_url: str | None = None,
        accept_timeout: float = 60.0,
        rhe_deadline: float = 30.0,
    ) -> None:
        """
        Wait for the server to open the connection (reverse connect, OPC 10000-6 v1.05, 7.1.3) instead of dialling it.
        The client listens on listen_url from connect() until disconnect(), accepts a ReverseHello only from the server
        with the application URI server_uri and the endpoint endpoint_url (default: the URL of this client) and then
        runs Hello, OpenSecureChannel and the session on that socket. Call before connect().
        """
        self.use_reverse_listener(
            ReverseConnectListener(listen_url, rhe_deadline), server_uri, endpoint_url, accept_timeout, owns=True
        )

    def use_reverse_listener(
        self,
        listener: ReverseConnectListener,
        server_uri: str,
        endpoint_url: str | None = None,
        accept_timeout: float = 60.0,
        owns: bool = False,
    ) -> None:
        """Like listen_reverse, with a listener that several clients share; its owner starts and stops it."""
        if self.uaclient.state is not UaClientState.DISCONNECTED:
            raise ConfigurationError("Reverse connect must be configured before connect()")
        if not server_uri:
            raise ConfigurationError("The application URI of the server is needed for reverse connect")
        target = listener.target(server_uri, endpoint_url or self.server_url.geturl())
        self._reverse = _ReverseConfig(listener, target, server_uri, accept_timeout, owns)

    async def _close_private_reverse_listener(self) -> None:
        if self._reverse is not None and self._reverse.owns_listener:
            await self._reverse.listener.stop()

    async def __aenter__(self) -> "Client":
        await self.connect()
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: Any
    ) -> None:
        await self.disconnect()

    def __str__(self) -> str:
        return f"Client({self.server_url.geturl()})"

    __repr__ = __str__

    @property
    def observer(self) -> Observer:
        """The :class:`enginir_opcua.observer.Observer` of this client; the null observer unless one was set."""
        return self.uaclient.observer

    @observer.setter
    def observer(self, observer: Observer) -> None:
        self.uaclient.observer = observer

    @property
    def state(self) -> UaClientState:
        """Current connection state. Mirrors `self.uaclient.state`."""
        return self.uaclient.state

    def subscribe_state(self) -> StateSubscription:
        """Subscribe to state transitions; see `UaClient.subscribe_state`."""
        return self.uaclient.subscribe_state()

    @property
    def server_url(self) -> ParseResult:
        """Return the server URL with stripped credentials

        if self.strip_url_credentials is True.  Disabling this
        is not recommended for security reasons.
        """
        url = self._server_url
        _userinfo, have_info, hostinfo = url.netloc.rpartition("@")
        if have_info:
            if self.strip_url_credentials:
                url = url.__class__(url[0], hostinfo, *url[2:])
        return url

    @staticmethod
    def find_endpoint(
        endpoints: Iterable[ua.EndpointDescription],
        security_mode: ua.MessageSecurityMode,
        policy_uri: str,
        url: str | None = None,
    ) -> ua.EndpointDescription:
        """
        Find the opc.tcp binary endpoint with the required security mode and policy URI.
        Among several matches the one with the url of the caller wins, then the highest SecurityLevel.
        """
        endpoints = list(endpoints)
        _logger.debug("find_endpoint %r %r %r", endpoints, security_mode, policy_uri)
        matches = [
            ep
            for ep in endpoints
            if ep.EndpointUrl.startswith(ua.OPC_TCP_SCHEME)
            and ep.TransportProfileUri in (TCP_BINARY_PROFILE, "", None)
            and ep.SecurityMode == security_mode
            and ep.SecurityPolicyUri == policy_uri
        ]
        if not matches:
            offered = sorted({(ep.SecurityMode.name, ep.SecurityPolicyUri) for ep in endpoints})
            raise ua.UaError(f"No matching endpoints: {security_mode.name}, {policy_uri}; the server offers {offered}")
        return max(matches, key=lambda ep: (url is not None and ep.EndpointUrl == url, ep.SecurityLevel or 0))

    def set_user(self, username: str) -> None:
        """
        Set user name for the connection.
        initial user from the URL will be overwritten
        """
        if not isinstance(username, str):
            raise TypeError(f"Username must be a string, got {username} of type {type(username)}")
        self._username = username

    def set_password(self, pwd: str) -> None:
        """
        Set user password for the connection.
        initial password from the URL will be overwritten
        """
        if not isinstance(pwd, str):
            raise TypeError(f"Password must be a string, got {pwd} of type {type(pwd)}")
        self._password = pwd

    def set_locale(self, locale: Sequence[str]) -> None:
        """
        Sets the preferred locales of the client, the server chooses which locale he can provide.
        Normally the first matching locale in the list will be chosen, by the server.
        Call this before connect()
        """
        self._locale = list(locale)

    def set_max_concurrent_requests(self, max_concurrent_requests: int) -> None:
        """Set the maximum number of requests sent concurrently."""
        self.uaclient.set_max_concurrent_requests(max_concurrent_requests)

    def set_trust_store(self, trust_store: TrustStore) -> None:
        """
        Set the trusted certificates, issuer certificates and revocation lists that the server certificate is
        validated against. Without a trust store only a server certificate passed to set_security is trusted.
        Call this before connect()
        """
        self.trust_store = trust_store
        self._default_validator = None

    async def set_pki_directory(
        self, root: str | Path, create: bool = True, private_key_password: str | bytes | None = None
    ) -> None:
        """
        Use one PKI directory for the certificate, the key and the trust of this client, with the layout described
        at Server.set_pki_directory. The server certificate is validated against trusted/certs and trusted/crl and
        issuer/certs and issuer/crl, and the certificate of a server that fails validation is kept in rejected/certs.
        The trust store is loaded again at every connect, so a file moved to trusted/certs is trusted at the next one.

        With create the folders are created, and when own/certs holds no certificate a self-signed one is generated
        there with the application_uri of this client (set it first). An existing certificate is never replaced.
        Call set_security without certificate and key afterwards to use the certificate of the directory.
        """
        base = Path(root)
        if create:
            await anyio.to_thread.run_sync(lambda: pki.create_directories(base))
        self._own_credentials = await pki.load_own_credentials(
            base,
            application_uri=self.application_uri,
            host_names=pki.default_host_names(),
            usage=pki.CLIENT_USAGE,
            password=private_key_password,
            create=create,
        )
        self.set_trust_store(TrustStore.from_pki_directory(base))

    async def set_security_string(self, string: str) -> None:
        """
        Set SecureChannel mode. Call this before connect().

        :param string: Mode format ``Policy,Mode,certificate,private_key[,server_certificate]`` where:

            - ``Policy`` is ``Basic256Sha256``, ``Aes128Sha256RsaOaep`` or ``Aes256Sha256RsaPss``
            - ``Mode`` is ``Sign`` or ``SignAndEncrypt``
            - ``certificate`` and ``server_certificate`` are paths to ``.pem`` or ``.der`` files
            - ``private_key`` may be a path to a ``.pem`` or ``.der`` file or ``path::password``, where ``password`` is
              the private key password.
        """
        if not string:
            return
        parts = string.split(",")
        if len(parts) < 4:
            raise ua.UaError(f"Wrong format: `{string}`, expected at least 4 comma-separated values")

        if "::" in parts[3]:
            parts[3], client_key_password = parts[3].split("::", 1)
        else:
            client_key_password = None

        policies = {
            name.removeprefix("SecurityPolicy"): value
            for name, value in vars(security_policies).items()
            if name.startswith("SecurityPolicy") and isinstance(value, type) and hasattr(value, "URI")
        }
        policy_class = policies.get(parts[0])
        if policy_class is None or parts[0] in ("", "None"):
            raise ConfigurationError(f"Unknown security policy {parts[0]!r}; use one of {sorted(policies)}")
        modes = {"Sign": ua.MessageSecurityMode.Sign, "SignAndEncrypt": ua.MessageSecurityMode.SignAndEncrypt}
        if parts[1] not in modes:
            raise ConfigurationError(f"Unknown security mode {parts[1]!r}; use one of {sorted(modes)}")
        mode = modes[parts[1]]
        await self.set_security(
            policy_class, parts[2], parts[3], client_key_password, parts[4] if len(parts) >= 5 else None, mode
        )

    async def set_security(
        self,
        policy: type[security_policies.SecurityPolicy],
        certificate: str | uacrypto.CertProperties | bytes | Path | None = None,
        private_key: str | uacrypto.CertProperties | bytes | Path | None = None,
        private_key_password: str | bytes | None = None,
        server_certificate: str | uacrypto.CertProperties | bytes | Path | None = None,
        mode: ua.MessageSecurityMode = ua.MessageSecurityMode.SignAndEncrypt,
        certificate_chain: Sequence[str | uacrypto.CertProperties | bytes | Path] | None = None,
    ) -> None:
        """
        Set the security policy and mode of the secure channel; certificate, private key and server certificate are
        paths, file contents or CertProperties. Without certificate and private_key the ones of the PKI directory
        (set_pki_directory) are used. A server certificate given here is trusted (pinned); without one the
        endpoints are read over an unsecured channel and the server certificate must pass the trust store.
        Call this before connect()
        """
        if certificate is None or private_key is None:
            if self._own_credentials is None or certificate is not None or private_key is not None:
                raise ConfigurationError(
                    "set_security needs a certificate and a private key, or a PKI directory (set_pki_directory)"
                )
            certificate = uacrypto.der_from_x509(self._own_credentials.certificate)
            private_key = uacrypto.CertProperties(uacrypto.pem_from_key(self._own_credentials.private_key), "pem")
            private_key_password = None
            certificate_chain = [uacrypto.der_from_x509(c) for c in self._own_credentials.chain]
        if getattr(policy, "deprecated", False) and not self.allow_deprecated_policies:
            raise ConfigurationError(
                f"{policy.__name__} is deprecated and is only available with Client(allow_deprecated_policies=True)"
            )
        pin_server_certificate = server_certificate is not None
        server: uacrypto.CertProperties | x509.Certificate
        if server_certificate is None:
            new_policy = security_policies.SecurityPolicyNone()
            self.security_policy = new_policy
            self.uaclient.security_policy = new_policy
            endpoints = await self.connect_and_get_server_endpoints()
            self._discovered_endpoints = endpoints
            endpoint = Client.find_endpoint(endpoints, mode, policy.URI, self.server_url.geturl())
            discovered = uacrypto.x509_from_der(endpoint.ServerCertificate)
            if discovered is None:
                raise ua.UaError(f"The endpoint {endpoint.EndpointUrl} has no server certificate")
            server = discovered
            await self._keep_endpoint_certificate(endpoint)
        elif isinstance(server_certificate, uacrypto.CertProperties):
            server = server_certificate
        else:
            server = uacrypto.CertProperties(server_certificate)
        if not isinstance(certificate, uacrypto.CertProperties):
            certificate = uacrypto.CertProperties(certificate)
        certificate_chain = certificate_chain or []
        chain = [
            cert if isinstance(cert, uacrypto.CertProperties) else uacrypto.CertProperties(cert)
            for cert in certificate_chain
        ]
        if not isinstance(private_key, uacrypto.CertProperties):
            private_key = uacrypto.CertProperties(private_key, password=private_key_password)
        await self._set_security(policy, certificate, private_key, server, mode, chain, pin_server_certificate)

    async def _keep_endpoint_certificate(self, endpoint: ua.EndpointDescription) -> None:
        """
        Keep the certificate of a server that the endpoint list offered and the trust store does not trust in the
        rejected store, so that an administrator can trust it (`enginir-opcua trust`) before the first secure
        connect. The server has not proven yet that it holds the key; only the secure connect does.
        """
        if self.certificate_validator is not None or self.trust_store is None or not endpoint.ServerCertificate:
            return
        await self._prepare_certificate_validation()
        validator = self._default_validator
        if validator is None:
            return
        host = self.server_url.hostname
        outcome = validator.validate_application_certificate(
            endpoint.ServerCertificate, ValidationContext(PeerRole.SERVER, endpoint.SecurityPolicyUri, host_name=host)
        )
        if outcome.accepted or not outcome.untrusted_chain:
            return
        validator.keep_rejected(outcome, host)
        _logger.info(
            "The server certificate came from the endpoint list and the server has not proven yet that it holds the "
            "key; it is kept in the rejected certificates so that it can be trusted. %s",
            untrusted_hint("server", outcome, validator.trust_store),
        )

    async def _set_security(
        self,
        policy: type[security_policies.SecurityPolicy],
        certificate: uacrypto.CertProperties,
        private_key: uacrypto.CertProperties,
        server_cert: uacrypto.CertProperties | x509.Certificate,
        mode: ua.MessageSecurityMode = ua.MessageSecurityMode.SignAndEncrypt,
        certificate_chain: Sequence[uacrypto.CertProperties] | None = None,
        pin_server_certificate: bool = False,
    ) -> None:
        if isinstance(server_cert, uacrypto.CertProperties):
            server_x509 = await uacrypto.load_certificate(server_cert.path_or_content, server_cert.extension)
        else:
            server_x509 = server_cert
        self._pinned_server_certificate = server_x509 if pin_server_certificate else None
        self._default_validator = None
        cert = await uacrypto.load_certificate(certificate.path_or_content, certificate.extension)
        certificate_chain = certificate_chain or []
        chain = await asyncio.gather(
            *(uacrypto.load_certificate(c.path_or_content, c.extension) for c in certificate_chain)
        )
        pk = await uacrypto.load_private_key(
            private_key.path_or_content,
            private_key.password,
            private_key.extension,
        )
        if not isinstance(pk, rsa.RSAPrivateKey):
            raise ConfigurationError(f"{policy.__name__} needs an RSA private key, got {type(pk).__name__}")
        uacrypto.check_certificate(cert, self.application_uri, socket.gethostname())
        self.security_policy = policy(server_x509, cert, pk, mode, host_cert_chain=chain)
        self.uaclient.set_security(self.security_policy)

    async def load_client_certificate(self, path: str | Path | bytes, extension: str | None = None) -> None:
        """
        Load user certificate from file, either pem or der
        """
        self.user_certificate = await uacrypto.load_certificate(path, extension)

    async def load_client_chain(self, certs: Iterable[uacrypto.CertProperties]) -> None:
        """
        Load user intermediate chain certificates, either pem or der
        """
        self.user_certificate_chain = await asyncio.gather(
            *(uacrypto.load_certificate(cert.path_or_content, cert.extension) for cert in certs)
        )

    async def load_private_key(
        self, path: str | Path | bytes, password: str | bytes | None = None, extension: str | None = None
    ) -> None:
        """
        Load user private key. This is used for authenticating using certificate
        """
        self.user_private_key = await uacrypto.load_private_key(path, password, extension)

    async def setup_self_signed_certificate(
        self,
        key_file: Path,
        cert_file: Path,
        subject_attrs: dict[str, str] | None = None,
        extended: list[x509.ObjectIdentifier] | None = None,
        host_name: str | None = None,
    ) -> tuple[Path, Path]:
        """Generate a self-signed application instance certificate and private key at the
        given paths when they are missing or invalid, using this client's application_uri.

        Nothing is regenerated when both files already exist and the certificate is still
        valid (matching application_uri / host_name and not expired); otherwise the missing
        or invalid artifact is rebuilt. Parent directories are created as needed. The pair is
        left on disk for the caller to load through set_security; the client's own security
        state is not modified.

        :param key_file: Path to the RSA private key, in PEM (PKCS8) format. Loaded and reused
            if present; otherwise a fresh 2048-bit key is generated and written here. A
            regenerated key always forces the certificate to be regenerated too.
        :param cert_file: Path to the certificate, in DER format. Regenerated when missing,
            when the key was just regenerated, or when the existing certificate fails
            validation. Generated certificates are valid for 365 days.
        :param subject_attrs: Extra subject Distinguished Name fields as
            ``{attribute_name: value}``, e.g.
            ``{"countryName": "DE", "organizationName": "ACME"}``. The common name (CN) is set
            automatically from this client's ``application_uri``. Keys must be X.509 attribute
            names known to ``cryptography`` (see ``enginir_opcua.crypto.cert_gen.OID_NAME_MAP`` for the
            accepted set). Defaults to no extra fields.
        :param extended: Extended Key Usage OIDs declaring how the certificate may be used.
            ``None`` or an empty list defaults to ``[ExtendedKeyUsageOID.CLIENT_AUTH]``; pass
            ``[ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]`` for a pair
            usable as both client and server.
        :param host_name: Host name embedded as a DNS SubjectAltName and checked when validating
            an existing certificate. Defaults to the local machine's hostname
            (``socket.gethostname()``). The ``application_uri`` is always added as a URI SAN.
        :return: ``(cert_file, key_file)`` as ``Path`` objects, for convenient passing to
            ``set_security``.
        """
        key_file, cert_file = Path(key_file), Path(cert_file)
        key_file.parent.mkdir(parents=True, exist_ok=True)
        cert_file.parent.mkdir(parents=True, exist_ok=True)
        await cert_gen.setup_self_signed_certificate(
            key_file,
            cert_file,
            self.application_uri,
            host_name or socket.gethostname(),
            extended or [ExtendedKeyUsageOID.CLIENT_AUTH],
            subject_attrs or {},
        )
        return cert_file, key_file

    async def _with_temp_channel(self, op: Callable[[], Awaitable[_T]]) -> _T:
        """Open a transient socket + SecureChannel, run op, tear it down on exit."""
        if self.uaclient.state is not UaClientState.DISCONNECTED:
            raise ConnectionError("already connected")
        await self.connect_socket()
        try:
            await self.send_hello()
            await self.open_secure_channel()
            try:
                return await op()
            finally:
                await self.close_secure_channel()
        finally:
            self.disconnect_socket()
            await self._close_private_reverse_listener()

    async def connect_and_get_server_endpoints(self) -> list[ua.EndpointDescription]:
        """
        Connect, ask server for endpoints, and disconnect
        """
        return await self._with_temp_channel(self.get_endpoints)

    async def connect_and_find_servers(self) -> list[ua.ApplicationDescription]:
        """
        Connect, ask server for a list of known servers, and disconnect
        """
        return await self._with_temp_channel(self.find_servers)

    async def connect_and_find_servers_on_network(self) -> ua.FindServersOnNetworkResult:
        """
        Connect, ask server for a list of known servers on network, and disconnect
        """
        return await self._with_temp_channel(self.find_servers_on_network)

    async def connect(
        self,
        *,
        auto_reconnect: bool | None = None,
        reconnect_max_delay: float | None = None,
        reconnect_request_timeout: float | None = None,
    ) -> None:
        """
        High level method: connect, create and activate session.

        :param auto_reconnect: when True, a supervisor task is started that
            monitors transport health and re-establishes the connection
            (including re-creating all live subscriptions) on loss.
        :param reconnect_max_delay: exponential backoff cap for reconnect attempts (seconds).
        :param reconnect_request_timeout: how long requests block waiting for the
            connection to become ready while the supervisor is reconnecting.
        """
        _logger.info("connect (auto_reconnect=%s)", auto_reconnect)
        if self.uaclient.state is not UaClientState.DISCONNECTED:
            raise ConnectionError("already connected")
        await self._apply_config()
        if auto_reconnect is not None:
            self._auto_reconnect = auto_reconnect
        if reconnect_max_delay is not None:
            self._reconnect_max_delay = reconnect_max_delay
        if reconnect_request_timeout is not None:
            self._reconnect_request_timeout = reconnect_request_timeout
        self.uaclient.clear_disconnect_request()
        self.uaclient.reconnect_on_loss = self._auto_reconnect
        await self._connect_sequence()
        await self.get_namespace_array()
        self._supervisor_task = asyncio.create_task(self._connection_supervisor())
        self._stale_watchdog_task = asyncio.create_task(self._stale_watchdog_loop())

    async def _connect_sequence(self) -> None:
        """Run the full connect sequence: socket, hello, channel, session, activate.

        If `session_state_path` is set and a persisted session is found, attempt
        ActivateSession on the existing authentication_token first
        (OPC 10000-4 v1.05, 6.7). Fall back to CreateSession + ActivateSession when no state is
        persisted or the server has expired the session.
        """
        await self.connect_socket()
        try:
            await self.send_hello()
            await self.open_secure_channel()
            if await self._try_resume_persisted_session():
                return
            await self._create_and_activate_session()
            self._start_renew_loop()
        except Exception:
            self.disconnect_socket()
            raise

    async def _activate_with_credentials(self) -> ua.ActivateSessionResult:
        result = await self.activate_session(
            username=self._username, password=self._password, certificate=self.user_certificate
        )
        self._save_session_state()
        return result

    async def _create_and_activate_session(self) -> None:
        """CreateSession + ActivateSession, unwinding the session then the channel on failure."""
        try:
            await self.create_session()
            await self._activate_with_credentials()
        except Exception:
            await self._close_session_quiet()
            await self._close_secure_channel_quiet()
            raise

    async def _try_resume_persisted_session(self) -> bool:
        """ActivateSession on a persisted token if one is on disk (OPC 10000-4 v1.05, 6.7).

        Returns True when the session resumed; on failure clears the stale state and
        returns False so the caller falls back to CreateSession + ActivateSession.
        """
        if not self._try_load_persisted_session():
            return False
        try:
            if not self._policy_ids:
                endpoints = await self.get_endpoints()
                self._policy_ids = Client.find_endpoint(
                    endpoints, self.security_policy.Mode, self.security_policy.URI, self.server_url.geturl()
                ).UserIdentityTokens
            await self._activate_with_credentials()
        except Exception as exc:
            if isinstance(exc, BadSessionIdInvalid):
                _logger.info("Persisted session expired on server; creating fresh one")
            else:
                _logger.warning("Failed to resume persisted session; creating fresh one", exc_info=True)
            self._clear_persisted_session()
            self.uaclient.session.reset_authentication_token()
            self._server_nonce = None
            return False
        _logger.info("Resumed persisted session %s", self.uaclient.session.authentication_token)
        self._start_renew_loop()
        return True

    async def connect_sessionless(self) -> None:
        """
        High level method
        Connect without a session
        """
        _logger.info("connect")
        await self.connect_socket()
        try:
            await self.send_hello()
            await self.open_secure_channel()
        except Exception:
            self.disconnect_socket()
            raise

    async def disconnect(self) -> None:
        """
        High level method
        Close session, secure channel and socket
        """
        _logger.info("disconnect")
        try:
            await self.close_session()
        except Exception:
            _logger.exception("close_session raised during disconnect; continuing teardown")
        try:
            await self.close_secure_channel()
        except Exception:
            _logger.exception("close_secure_channel raised during disconnect; continuing teardown")
        self.disconnect_socket()
        await self._close_private_reverse_listener()
        self._clear_persisted_session()
        self._close_subscriptions()

    def _close_subscriptions(self) -> None:
        subscriptions, self._subscriptions = self._subscriptions, []
        for subscription in subscriptions:
            try:
                subscription.close("the client disconnected")
            except Exception:
                _logger.exception("Closing subscription %s failed", subscription.subscription_id)

    def _try_load_persisted_session(self) -> bool:
        """Load `authentication_token` + `server_nonce` from disk into the live session.

        Returns True when a session is loaded and worth attempting ActivateSession on.
        Returns False (and silently) when no state path is set, the file is missing,
        or the recorded session is older than `session_timeout` (server would have
        expired it already).
        """
        if self.session_state_path is None:
            return False
        try:
            raw = self.session_state_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return False
        except OSError as exc:
            _logger.warning("Could not read session state at %s: %s", self.session_state_path, exc)
            return False
        try:
            state = json.loads(raw)
            token = ua.NodeId.from_string(state["authentication_token"])
            nonce = bytes.fromhex(state["server_nonce"]) if state.get("server_nonce") else None
            saved_at = float(state.get("saved_at", 0))
        except (KeyError, ValueError, TypeError) as exc:
            _logger.warning("Persisted session state at %s is malformed: %s", self.session_state_path, exc)
            self._clear_persisted_session()
            return False
        age = time.time() - saved_at
        if age > self.session_timeout / 1000:
            _logger.info(
                "Persisted session at %s is %.0fs old (>%.0fms timeout); skipping",
                self.session_state_path,
                age,
                self.session_timeout,
            )
            self._clear_persisted_session()
            return False
        self.uaclient.session.restore_authentication_token(token)
        self._server_nonce = nonce
        return True

    def _save_session_state(self) -> None:
        """Persist the current session's auth_token + server_nonce atomically with 0o600."""
        if self.session_state_path is None:
            return
        token = self.uaclient.session.authentication_token
        if token.is_null():
            return
        state = {
            "authentication_token": token.to_string(),
            "server_nonce": self._server_nonce.hex() if self._server_nonce else None,
            "saved_at": time.time(),
        }
        path = self.session_state_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            data = json.dumps(state)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, data.encode("utf-8"))
            finally:
                os.close(fd)
            os.replace(tmp, path)
        except OSError as exc:
            _logger.warning("Could not save session state to %s: %s", path, exc)

    def _clear_persisted_session(self) -> None:
        if self.session_state_path is None:
            return
        try:
            self.session_state_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            _logger.warning("Could not delete session state at %s: %s", self.session_state_path, exc)

    async def disconnect_sessionless(self) -> None:
        """
        High level method
        Close secure channel and socket
        """
        _logger.info("disconnect")
        try:
            await self.close_secure_channel()
        finally:
            self.disconnect_socket()
            await self._close_private_reverse_listener()

    async def connect_socket(self) -> None:
        """
        connect to socket defined in url
        """

        await self._prepare_certificate_validation()
        reverse = self._reverse
        if reverse is None:
            host = self.server_url.hostname
            if not host:
                raise ConfigurationError(f"The server URL {self.server_url.geturl()!r} has no host")
            await self.uaclient.connect_socket(host, self.server_url.port or DEFAULT_PORT)
            return
        await reverse.listener.start()
        transport, reverse.announced_endpoint_url = await reverse.target.accept(reverse.accept_timeout)
        host = urlparse(reverse.target.endpoint_url).hostname or self.server_url.hostname
        expected_uri = (
            reverse.server_uri if not isinstance(self.security_policy, security_policies.SecurityPolicyNone) else None
        )
        self.uaclient.attach_socket(cast(asyncio.Transport, transport), cast(str, host), expected_uri)

    async def _prepare_certificate_validation(self) -> None:
        if self.certificate_validator is not None:
            self.uaclient.certificate_validator = self.certificate_validator
            return
        if self._default_validator is None:
            store = self.trust_store.copy() if self.trust_store else TrustStore()
            if self._pinned_server_certificate is not None:
                store.pin(self._pinned_server_certificate)
            await store.load()
            self._default_validator = CertificateValidator(store)
        else:
            await self._default_validator.trust_store.load()
        self.uaclient.certificate_validator = self._default_validator

    def disconnect_socket(self) -> None:
        """Close the TCP connection without closing the session or channel first."""
        self.uaclient.disconnect_socket()

    async def send_hello(self) -> None:
        """
        Send OPC-UA hello to server
        """
        url = self.server_url.geturl()
        if self._reverse is not None and self._reverse.announced_endpoint_url is not None:
            url = self._reverse.announced_endpoint_url
        await self.uaclient.send_hello(url, self.max_messagesize, self.max_chunkcount)

    async def open_secure_channel(self, renew: bool = False) -> None:
        """
        Open secure channel, if renew is True, renew channel
        """
        params = ua.OpenSecureChannelParameters()
        params.ClientProtocolVersion = 0
        params.RequestType = ua.SecurityTokenRequestType.Issue
        if renew:
            params.RequestType = ua.SecurityTokenRequestType.Renew
        params.SecurityMode = self.security_policy.Mode
        params.RequestedLifetime = self.secure_channel_timeout
        params.ClientNonce = create_nonce(self.security_policy.secure_channel_nonce_length)
        try:
            result = await self.uaclient.open_secure_channel(params)
        except BadSecurityChecksFailed as error:
            raise self._refused_channel(error) from error
        self._check_secure_channel_nonce(result.ServerNonce)
        if self.secure_channel_timeout != result.SecurityToken.RevisedLifetime:
            _logger.info(
                "Requested secure channel timeout to be %dms, got %dms instead",
                self.secure_channel_timeout,
                result.SecurityToken.RevisedLifetime,
            )
            self.secure_channel_timeout = result.SecurityToken.RevisedLifetime

    def _refused_channel(self, error: BadSecurityChecksFailed) -> BadSecurityChecksFailed:
        certificate = getattr(self.security_policy, "host_certificate", None)
        if not certificate:
            return error
        thumbprint = uacrypto.certificate_thumbprint(certificate).hex()
        return BadSecurityChecksFailed(
            f"the server refused the secure channel, probably because it does not trust this client's certificate "
            f"{thumbprint}; trust it on the server: enginir-opcua trust {thumbprint} --pki <server pki>"
        )

    async def close_secure_channel(self) -> None:
        """Send CloseSecureChannel; the socket stays open."""
        await self.uaclient.close_secure_channel()

    async def get_endpoints(self) -> list[ua.EndpointDescription]:
        """Get a list of OPC-UA endpoints."""

        params = ua.GetEndpointsParameters()
        params.EndpointUrl = self.server_url.geturl()
        return await self.uaclient.get_endpoints(params)

    def _registered_server(self, server: "enginir_opcua.server.Server", online: bool) -> ua.RegisteredServer:
        registered = ua.RegisteredServer()
        registered.ServerUri = server.get_application_uri()
        registered.ProductUri = server.product_uri
        registered.DiscoveryUrls = [cast(ua.String, server.endpoint.geturl())]
        registered.ServerType = server.application_type
        registered.ServerNames = [ua.LocalizedText(server.name)]
        registered.IsOnline = online
        return registered

    async def register_server(
        self,
        server: "enginir_opcua.server.Server",
        discovery_configuration: Iterable[ua.DiscoveryConfiguration] | None = None,
    ) -> None:
        """
        Register a server with a discovery server.
        RegisterServer2 is sent, with the discovery configurations if given (such as MdnsDiscoveryConfiguration).
        Only when the discovery server answers Bad_ServiceUnsupported, the older RegisterServer is sent instead.
        """
        registered = self._registered_server(server, True)
        params = ua.RegisterServer2Parameters()
        params.Server = registered
        params.DiscoveryConfiguration = list(discovery_configuration or [])
        try:
            await self.uaclient.register_server2(params)
        except ua.uaerrors.BadServiceUnsupported:
            await self.uaclient.register_server(registered)

    async def unregister_server(
        self,
        server: "enginir_opcua.server.Server",
        discovery_configuration: Iterable[ua.DiscoveryConfiguration] | None = None,
    ) -> None:
        """
        Remove a server from a discovery server: the same calls as register_server with IsOnline set to False.
        """
        registered = self._registered_server(server, False)
        params = ua.RegisterServer2Parameters()
        params.Server = registered
        params.DiscoveryConfiguration = list(discovery_configuration or [])
        try:
            await self.uaclient.unregister_server2(params)
        except ua.uaerrors.BadServiceUnsupported:
            await self.uaclient.unregister_server(registered)

    async def find_servers(self, uris: Iterable[str] | None = None) -> list[ua.ApplicationDescription]:
        """
        send a FindServer request to the server. The answer should be a list of
        servers the server knows about
        A list of uris can be provided, only server having matching uris will be returned
        """
        if uris is None:
            uris = []
        params = ua.FindServersParameters()
        params.EndpointUrl = self.server_url.geturl()
        params.ServerUris = list(uris)
        return await self.uaclient.find_servers(params)

    async def find_servers_on_network(self) -> ua.FindServersOnNetworkResult:
        """FindServersOnNetwork: the servers a discovery server knows on the network (OPC 10000-4 v1.05, 5.5.3)."""
        params = ua.FindServersOnNetworkParameters()
        return await self.uaclient.find_servers_on_network(params)

    async def create_session(self) -> ua.CreateSessionResult:
        """
        CreateSession with this client's description and session timeout, then check what the server answered:
        its nonce and signature, its certificate against the channel's, its endpoints against those discovery
        returned, and the ApplicationUri in its certificate (OPC 10000-4 v1.05, 5.7.2).
        """
        desc = ua.ApplicationDescription()
        desc.ApplicationUri = self.application_uri
        desc.ProductUri = self.product_uri
        desc.ApplicationName = ua.LocalizedText(self.name)
        desc.ApplicationType = ua.ApplicationType.Client
        params = ua.CreateSessionParameters()
        params.ServerUri = None
        nonce = create_nonce(SESSION_NONCE_MIN_LENGTH)
        params.ClientNonce = nonce
        params.ClientCertificate = self.security_policy.host_certificate or None
        params.ClientDescription = desc
        params.EndpointUrl = self.server_url.geturl()
        self._session_counter += 1
        params.SessionName = f"{self.description} Session{self._session_counter} {secrets.token_hex(4)}"
        params.RequestedSessionTimeout = self.session_timeout
        params.MaxResponseMessageSize = 0
        response = await self.uaclient.create_session(params)
        self._check_session_nonce(response.ServerNonce)
        if self.security_policy.host_certificate is None:
            data = nonce
        else:
            data = self.security_policy.host_certificate + nonce
        self.security_policy.asymmetric_cryptography.verify(data, response.ServerSignature.Signature)
        self._server_nonce = response.ServerNonce
        server_certificate = None
        if response.ServerCertificate:
            server_certificate = uacrypto.split_certificate_chain(response.ServerCertificate)[0]
        if not self.security_policy.peer_certificate:
            self.security_policy.peer_certificate = server_certificate
        elif self.security_policy.peer_certificate != server_certificate:
            raise ua.UaError("Server certificate mismatch")
        self._check_discovered_endpoints(response.ServerEndpoints)
        ep = Client.find_endpoint(
            response.ServerEndpoints, self.security_policy.Mode, self.security_policy.URI, self.server_url.geturl()
        )
        self._check_server_certificate_uri(server_certificate, ep)

        if self.application_hook and server_certificate:
            try:
                await self.application_hook(x509.load_der_x509_certificate(server_certificate), ep.Server)
            except ServiceError as exp:
                status = ua.StatusCode(exp.code)
                _logger.error("create_session fault response: %s (%s)", status.doc, status.name)
                raise ua.UaStatusCodeError(exp.code) from exp

        self._policy_ids = ep.UserIdentityTokens
        if self.session_timeout != response.RevisedSessionTimeout:
            _logger.info(
                "Requested session timeout to be %dms, got %dms instead",
                self.session_timeout,
                response.RevisedSessionTimeout,
            )
            self.session_timeout = response.RevisedSessionTimeout
        return response

    @staticmethod
    def _endpoint_summary(endpoints: Iterable[ua.EndpointDescription]) -> set[tuple[Any, ...]]:
        return {
            (
                endpoint.Server.ApplicationUri,
                endpoint.SecurityMode,
                endpoint.SecurityPolicyUri,
                endpoint.SecurityLevel,
                uacrypto.split_certificate_chain(endpoint.ServerCertificate)[0] if endpoint.ServerCertificate else b"",
                frozenset(
                    (policy.PolicyId or "", policy.TokenType, policy.SecurityPolicyUri or "")
                    for policy in endpoint.UserIdentityTokens
                ),
            )
            for endpoint in endpoints
            if endpoint.TransportProfileUri in (TCP_BINARY_PROFILE, "", None)
        }

    def _check_server_certificate_uri(self, server_certificate: bytes | None, endpoint: ua.EndpointDescription) -> None:
        if not server_certificate or self.security_policy.Mode == ua.MessageSecurityMode.None_:
            return
        outcome = check_application_uri(
            x509.load_der_x509_certificate(server_certificate), endpoint.Server.ApplicationUri
        )
        if not outcome.accepted:
            _logger.error("The server certificate does not carry the ApplicationUri %r", endpoint.Server.ApplicationUri)
            raise ua.UaStatusCodeError(outcome.status)

    def _check_discovered_endpoints(self, endpoints: Iterable[ua.EndpointDescription]) -> None:
        if self._discovered_endpoints is None:
            return
        if self._endpoint_summary(self._discovered_endpoints) != self._endpoint_summary(endpoints):
            _logger.error("The endpoints of CreateSession differ from the endpoints found by discovery")
            raise BadSecurityChecksFailed

    def _start_renew_loop(self) -> None:
        if self._renew_channel_task is not None and not self._renew_channel_task.done():
            return
        self._renew_channel_task = asyncio.create_task(self._renew_channel_loop())

    async def _wait_until_ready(self) -> None:
        """Pre-request hook: block while the supervisor is reconnecting, fail fast otherwise.

        Only RECONNECTING is gated: during initial connect (CONNECTING / SOCKET_OPEN /
        CHANNEL_OPEN) the session-establishment requests themselves must pass through.
        DISCONNECTED / DISCONNECTING raise immediately so callers see ConnectionError
        instead of silently sending to a dead transport.

        We deliberately do NOT raise on `is_disconnect_requested` alone: in-flight
        requests started before the user called `disconnect()` should be allowed
        to either complete or fail at the transport layer, not get short-circuited
        here mid-teardown.

        Requests originating from the supervisor's own reconnect work
        (CloseSession during teardown, recreate-subscription, etc.) bypass the
        gate via the `_supervisor_owns_requests` contextvar so they don't
        deadlock waiting for the very transition they're performing.
        """
        if _supervisor_owns_requests.get():
            return
        state = self.uaclient.state
        if state is UaClientState.DISCONNECTED:
            raise ConnectionError("client is disconnected")
        if state is UaClientState.DISCONNECTING:
            raise ConnectionError("client is disconnecting")
        if state is not UaClientState.RECONNECTING:
            return
        async with self.uaclient.subscribe_state() as sub:
            try:
                await sub.wait_for_state(UaClientState.CONNECTED, timeout=self._reconnect_request_timeout)
            except TimeoutError:
                raise ConnectionError(
                    f"Timed out waiting for client to reconnect (state={self.uaclient.state.value})"
                ) from None

    check_connection = _wait_until_ready

    async def _connection_supervisor(self) -> None:
        """
        Single supervisor task driving health-check and reconnect.

        Started by `connect()` after the initial connect succeeds. The loop:
          1. waits for either a periodic health-tick or a state change away from CONNECTED,
          2. on each tick, probes server_state to detect dead-but-not-closed connections,
          3. on any failure, fires `connection_lost_callback` and (if auto_reconnect)
             transitions to RECONNECTING and runs `_reconnect_with_backoff`.

        Exits when `is_disconnect_requested` is set or `auto_reconnect=False` and a loss is detected.
        """
        try:
            while not self.uaclient.is_disconnect_requested:
                try:
                    exc = await self._detect_connection_loss()
                    if exc is None:
                        continue
                    if self.uaclient.is_disconnect_requested:
                        return
                    if not await self._handle_connection_loss(exc):
                        return
                except Exception:
                    _logger.exception("Connection supervisor iteration crashed; retrying in 1s")
                    await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            pass

    async def _detect_connection_loss(self) -> Exception | None:
        """Wait for the next health signal; return the triggering exception on a
        detected loss, or None while the connection still looks healthy."""
        try:
            await self._wait_for_health_signal()
            if self.uaclient.state is not UaClientState.CONNECTED:
                raise ConnectionError("transport lost")
        except (TimeoutError, OSError, ua.UaStatusCodeError) as exc:
            return exc
        return None

    async def _handle_connection_loss(self, exc: Exception) -> bool:
        """React to a detected loss. Returns False to stop the supervisor, True to keep going."""
        _logger.info("Supervisor detected connection issue: %r", exc)
        await self._fire_connection_lost_callback(exc)
        if not self._auto_reconnect:
            await self._inform_subscriptions_lost()
            self.uaclient.mark_disconnected()
            return False
        self.uaclient.enter_reconnecting()
        return await self._reconnect_with_backoff()

    async def _inform_subscriptions_lost(self) -> None:
        try:
            await self.uaclient.inform_subscriptions(ua.StatusCode(ua.StatusCodes.BadShutdown))
        except Exception:
            _logger.debug("inform_subscriptions raised during loss handling", exc_info=True)

    async def _stale_watchdog_loop(self) -> None:
        while not self.uaclient.is_disconnect_requested:
            try:
                await asyncio.sleep(self._stale_check_interval)
                if self.uaclient.state is not UaClientState.CONNECTED:
                    continue
                await self._recreate_stale_subscriptions()
            except asyncio.CancelledError:
                return
            except Exception:
                _logger.exception("Stale subscription watchdog iteration failed")

    async def _recreate_stale_subscriptions(self) -> None:
        for sub in list(self._subscriptions):
            if not sub.is_stale(self._stale_check_margin):
                continue
            _logger.warning("Subscription %s is stale; recreating", sub.subscription_id)
            try:
                await sub.recreate()
            except Exception:
                _logger.exception("Subscription %s recreate failed; escalating to reconnect", sub.subscription_id)
                self.uaclient.notify_transport_lost()
                return

    async def _wait_for_health_signal(self) -> None:
        """Wait for either a state change (transport loss / supervisor work) or the next tick.

        On a tick with state still CONNECTED, probe server_state to detect a
        dead-but-not-closed connection. Raises on probe failure.
        """
        async with self.uaclient.subscribe_state() as sub:
            try:
                await sub.next_change(self._watchdog_intervall)
            except TimeoutError:
                pass
        if self.uaclient.state is UaClientState.CONNECTED:
            probe_timeout = min(self.session_timeout / 1000 / 2, self._watchdog_intervall)
            try:
                await asyncio.wait_for(self.nodes.server_state.read_value(), timeout=probe_timeout)
            except ua.UaStatusCodeError as exc:
                if isinstance(exc, LOSS_STATUS_ERRORS):
                    raise
                _logger.debug("The server answered the liveness probe with %s", exc)

    async def _fire_connection_lost_callback(self, exc: Exception) -> None:
        if self.connection_lost_callback is None:
            return
        try:
            await self.connection_lost_callback(exc)
        except Exception:
            _logger.exception("Error calling connection_lost_callback")

    async def _reconnect_with_backoff(self) -> bool:
        """Retry the connect sequence with exponential backoff. Returns True on success."""
        token = _supervisor_owns_requests.set(True)
        try:
            delay = 1.0
            self.uaclient.session.pause_publish()
            while not self.uaclient.is_disconnect_requested:
                await self._teardown_transport_only()
                try:
                    reused = await self._try_reactivate_existing_session()
                except (
                    BadCertificateInvalid,
                    BadCertificateUntrusted,
                    BadSecurityChecksFailed,
                    BadSecurityPolicyRejected,
                ) as exc:
                    _logger.warning("Reconnect failed with security error %r; retrying", exc)
                except Exception as exc:
                    _logger.warning("Reconnect attempt failed: %r; retrying in %.1fs", exc, delay)
                else:
                    await self._finalize_reconnect(reused)
                    return True
                await asyncio.sleep(delay)
                delay = min(delay * 2, self._reconnect_max_delay)
            return False
        finally:
            _supervisor_owns_requests.reset(token)

    async def _finalize_reconnect(self, reused: bool) -> None:
        self._subscriptions = [s for s in self._subscriptions if not s.is_deleted]
        try:
            await self._recreate_subscriptions()
        except Exception:
            _logger.exception("Subscription recreation failed; continuing")
        self.uaclient.session.resume_publish()
        self.uaclient.complete_reconnect()
        _logger.info("Reconnected successfully (session %s)", "reused" if reused else "recreated")

    async def _try_reactivate_existing_session(self) -> bool:
        """Open new socket+channel; try to re-activate the existing session.

        Returns True if the existing session was reactivated (subscriptions still
        alive on the server). Returns False if a fresh session had to be created.
        Raises on transport/channel-level failures so the outer loop can retry.
        """
        had_session = self.uaclient.has_session
        await self.connect_socket()
        try:
            await self.send_hello()
            await self.open_secure_channel()
            if had_session and await self._reactivate_session():
                return True
            await self._create_and_activate_session()
            self._start_renew_loop()
        except Exception:
            self.disconnect_socket()
            raise
        return False

    async def _reactivate_session(self) -> bool:
        """Bind the existing token to the new channel and try ActivateSession.

        Returns True if the server still held the session. Returns False (after closing it) when the server
        shows that the session is gone, or when ActivateSession failed max_activation_failures times in a row
        for another reason than a lost connection. Any other failure raises and the attempt is repeated.
        """
        self.uaclient.session.rebind_authentication_token()
        try:
            await self._activate_with_credentials()
        except (BadSessionIdInvalid, BadSessionClosed, BadSessionNotActivated):
            _logger.info("Server forgot session; falling back to create+activate")
        except ConnectionError:
            raise
        except Exception:
            self._activation_failures += 1
            if self._activation_failures < self._max_activation_failures:
                raise
            _logger.warning("Re-activate failed %s times; creating a new session", self._activation_failures)
        else:
            self._activation_failures = 0
            self._start_renew_loop()
            return True
        self._activation_failures = 0
        await self._close_session_quiet()
        return False

    async def _teardown_transport_only(self) -> None:
        """Cancel the channel-renew loop and drop the socket; leave the session intact.

        We deliberately do NOT call close_session here: OPC 10000-4 v1.05, 6.7 reconnect
        keeps the session alive server-side so ActivateSession on a new channel can
        reuse it. close_session only runs in the fallback path when the server
        rejects the reactivate.
        """
        await self._cancel_task(self._renew_channel_task)
        self._renew_channel_task = None
        if self.uaclient.has_transport:
            self.uaclient.disconnect_socket()

    async def _recreate_subscriptions(self) -> None:
        live = [s for s in self._subscriptions if not s.is_deleted]
        self._subscriptions = live
        for sub in live:
            try:
                await sub.restore()
            except Exception:
                _logger.exception("Failed to restore subscription")

    async def _close_session_quiet(self) -> None:
        """CloseSession through UaClient, which unlike close_session leaves the supervisor running."""
        try:
            await self.uaclient.close_session(False)
        except Exception:
            _logger.debug("close_session during cleanup raised", exc_info=True)

    async def _close_secure_channel_quiet(self) -> None:
        try:
            await self.uaclient.close_secure_channel()
        except Exception:
            _logger.debug("close_secure_channel during cleanup raised", exc_info=True)

    async def _renew_channel_loop(self) -> None:
        """
        Renew the SecureChannel before the SecureChannelTimeout will happen.
        In theory, we could do that only if no session activity,
        but it does not cost much.
        """
        last_renewal = time.monotonic()
        delay = 0.0
        try:
            while not self.uaclient.is_disconnect_requested:
                await asyncio.sleep(delay or max(1.0, self.secure_channel_timeout * 0.75 / 1000))
                _logger.debug("renewing channel")
                try:
                    await self.open_secure_channel(renew=True)
                except ConnectionError as e:
                    _logger.info("connection error in the channel renewal loop: %s", e)
                    return
                except Exception as e:
                    if time.monotonic() - last_renewal >= self.secure_channel_timeout / 1000:
                        _logger.error("The security token expired without a successful renewal: %r", e)
                        self.uaclient.notify_transport_lost()
                        return
                    delay = min(delay * 2, RENEW_RETRY_MAX_DELAY) if delay else RENEW_RETRY_DELAY
                    _logger.warning("Renewing the secure channel failed (%r); trying again in %.2fs", e, delay)
                else:
                    last_renewal = time.monotonic()
                    delay = 0.0
        except asyncio.CancelledError:
            raise

    def server_policy(self, token_type: ua.UserTokenType) -> ua.UserTokenPolicy:
        """
        Find UserTokenPolicy by token_type.
        If SecurityPolicyUri is empty, use default SecurityPolicyUri
        of the endpoint
        """
        for policy in self._policy_ids:
            if policy.TokenType == token_type:
                if policy.SecurityPolicyUri:
                    return policy
                return dataclasses.replace(policy, SecurityPolicyUri=self.security_policy.URI)
        raise ConfigurationError(f"The endpoint does not offer the user token type {token_type.name}")

    async def activate_session(
        self,
        username: str | None = None,
        password: str | None = None,
        certificate: x509.Certificate | None = None,
    ) -> ua.ActivateSessionResult:
        """
        ActivateSession with the user certificate (when a user private key is loaded), else the user name and
        password, else anonymously; the client signature proves the channel's certificate (OPC 10000-4 v1.05,
        5.7.3).
        """
        user_certificate = certificate
        params = ua.ActivateSessionParameters()
        challenge = b""
        if self.security_policy.peer_certificate is not None:
            challenge += self.security_policy.peer_certificate
        if self._server_nonce is not None:
            challenge += self._server_nonce
        if self.security_policy.AsymmetricSignatureURI:
            params.ClientSignature.Algorithm = self.security_policy.AsymmetricSignatureURI
        else:
            params.ClientSignature.Algorithm = security_policies.SecurityPolicyBasic256Sha256.AsymmetricSignatureURI
        params.ClientSignature.Signature = self.security_policy.asymmetric_cryptography.signature(challenge)
        params.LocaleIds = self._locale
        if user_certificate and self.user_private_key:
            self._add_certificate_auth(params, user_certificate, challenge, self.user_certificate_chain)
        elif username:
            self._add_user_auth(params, username, password)
        else:
            self._add_anonymous_auth(params)
        res = await self.uaclient.activate_session(params)
        self._check_session_nonce(res.ServerNonce)
        self._server_nonce = res.ServerNonce
        return res

    def _check_session_nonce(self, nonce: bytes | None) -> None:
        if self.security_policy.Mode == ua.MessageSecurityMode.None_:
            return
        if nonce is None or not SESSION_NONCE_MIN_LENGTH <= len(nonce) <= SESSION_NONCE_MAX_LENGTH:
            _logger.error("Server sent a session nonce of %s bytes", None if nonce is None else len(nonce))
            raise ua.uaerrors.BadNonceInvalid

    def _check_secure_channel_nonce(self, nonce: bytes | None) -> None:
        if self.security_policy.Mode == ua.MessageSecurityMode.None_:
            return
        expected = self.security_policy.secure_channel_nonce_length
        if nonce is None or len(nonce) != expected:
            _logger.error("Server sent a secure channel nonce of %s bytes, expected %s", len(nonce or b""), expected)
            raise ua.uaerrors.BadNonceInvalid

    def _add_anonymous_auth(self, params: ua.ActivateSessionParameters) -> None:
        params.UserIdentityToken = ua.AnonymousIdentityToken()
        params.UserIdentityToken.PolicyId = self.server_policy(ua.UserTokenType.Anonymous).PolicyId

    def _add_certificate_auth(
        self,
        params: ua.ActivateSessionParameters,
        certificate: x509.Certificate,
        challenge: bytes,
        certificate_chain: list[x509.Certificate] | None = None,
    ) -> None:
        params.UserIdentityToken = ua.X509IdentityToken()
        params.UserIdentityToken.CertificateData = uacrypto.der_from_x509(certificate)
        certificate_chain = certificate_chain or []
        for cert in certificate_chain:
            params.UserIdentityToken.CertificateData += uacrypto.der_from_x509(cert)
        policy = self.server_policy(ua.UserTokenType.Certificate)
        if not isinstance(self.user_private_key, rsa.RSAPrivateKey):
            raise ConfigurationError("A user certificate needs an RSA private key (load_private_key)")
        sig, alg = security_policies.sign_asymmetric(self.user_private_key, challenge, policy.SecurityPolicyUri)
        params.UserIdentityToken.PolicyId = policy.PolicyId
        params.UserTokenSignature.Algorithm = alg
        params.UserTokenSignature.Signature = sig

    def _add_user_auth(self, params: ua.ActivateSessionParameters, username: str | None, password: str | None) -> None:
        params.UserIdentityToken = ua.UserNameIdentityToken()
        params.UserIdentityToken.UserName = username
        policy = self.server_policy(ua.UserTokenType.UserName)
        if not policy.SecurityPolicyUri or policy.SecurityPolicyUri == security_policies.SecurityPolicyNone.URI:
            if password:
                if self.security_policy.Mode != ua.MessageSecurityMode.SignAndEncrypt:
                    _logger.warning("Sending plain-text password")
                params.UserIdentityToken.Password = password.encode("utf8")
            params.UserIdentityToken.EncryptionAlgorithm = None
        elif password:
            data, uri = self._encrypt_password(password, policy.SecurityPolicyUri)
            params.UserIdentityToken.Password = data
            params.UserIdentityToken.EncryptionAlgorithm = uri
        params.UserIdentityToken.PolicyId = policy.PolicyId

    def _encrypt_password(self, password: str, policy_uri: str) -> tuple[bytes, str]:
        """The legacy encrypted secret: the length-prefixed UTF-8 password and server nonce (OPC 10000-4 v1.05, 7.40.2.2)."""
        server_certificate = uacrypto.x509_from_der(self.security_policy.peer_certificate)
        if server_certificate is None:
            raise ua.UaError("The server certificate is needed to encrypt the password")
        pubkey = server_certificate.public_key()
        if not isinstance(pubkey, rsa.RSAPublicKey):
            raise ua.UaError("The server certificate has no RSA key to encrypt the password with")
        passwd = password.encode("utf8")
        if self._server_nonce is not None:
            passwd += self._server_nonce
        etoken = ua.ua_binary.Primitives.Bytes.pack(passwd)
        data, uri = security_policies.encrypt_asymmetric(pubkey, etoken, policy_uri)
        return data, uri

    async def close_session(self) -> None:
        """CloseSession, after stopping the supervisor, the stale-subscription watchdog and the channel renewal."""
        self.uaclient.request_disconnect()
        await self._cancel_task(self._stale_watchdog_task)
        self._stale_watchdog_task = None
        await self._cancel_task(self._supervisor_task)
        self._supervisor_task = None
        if self.uaclient.state is UaClientState.RECONNECTING:
            self.uaclient.mark_disconnected()
        await self._cancel_task(self._renew_channel_task)
        self._renew_channel_task = None
        token = _supervisor_owns_requests.set(True)
        try:
            await self.uaclient.close_session(True)
        finally:
            _supervisor_owns_requests.reset(token)

    @staticmethod
    async def _cancel_task(task: asyncio.Task[Any] | None) -> None:
        """Cancel a task, await its exit, and swallow CancelledError / shutdown noise."""
        if task is None or task.done():
            return
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    def get_root_node(self) -> Node:
        """The Root folder."""
        return self.get_node(ua.TwoByteNodeId(ua.ObjectIds.RootFolder))

    def get_objects_node(self) -> Node:
        """The Objects folder."""
        return self.get_node(ua.TwoByteNodeId(ua.ObjectIds.ObjectsFolder))

    def get_server_node(self) -> Node:
        """The Server object."""
        return self.get_node(ua.FourByteNodeId(ua.ObjectIds.Server))

    def get_node(self, nodeid: Node | ua.NodeId | str | int) -> Node:
        """
        Get node using NodeId object or a string representing a NodeId.
        """
        return Node(self.uaclient.session, nodeid)

    async def create_subscription(
        self,
        period: ua.CreateSubscriptionParameters | float,
        handler: SubscriptionHandler | None = None,
        publishing: bool = True,
        *,
        queue_maxsize: int = 1000,
    ) -> Subscription:
        """
        Create a subscription.

        Returns a Subscription object which can be used either:

        - **Callback mode** (legacy): pass a `handler` and implement
          `datachange_notification` / `event_notification` /
          `status_change_notification`.
        - **Iterator mode**: pass `handler=None` and use the subscription as
          an async context manager + async iterator::

              async with sub:
                  await sub.subscribe_data_change(node)
                  async for ev in sub:
                      ...

          `queue_maxsize` bounds the internal buffer.

        :param period: Either a publishing interval in milliseconds or a
            `CreateSubscriptionParameters` instance. With an interval, the keep-alive count gives a keep-alive about
            every 10 s (at most a quarter of the session timeout) and the lifetime covers at least 300 s and three
            keep-alives; use `subscription_parameters` to change that. The revised values are stored and corrected
            once by `Subscription.init`.
        :param handler: Optional callback handler. If None, iterator mode.
        :param queue_maxsize: Iterator-mode queue bound (default 1000).
        """
        if isinstance(period, ua.CreateSubscriptionParameters):
            params = period
        else:
            params = subscription_parameters(period, publishing, session_timeout=self.session_timeout)
        subscription = Subscription(
            self.uaclient.session,
            params,
            handler,
            queue_maxsize=queue_maxsize,
        )
        await subscription.init()
        self._subscriptions.append(subscription)
        return subscription

    async def delete_subscriptions(self, subscription_ids: Iterable[int]) -> list[ua.StatusCode]:
        """
        Deletes the provided list of subscription_ids
        """
        return await self.uaclient.delete_subscriptions(list(subscription_ids))

    async def get_namespace_array(self) -> list[str]:
        """Read the NamespaceArray of the server; the type registry resolves namespace URIs with it."""
        ns_node = self.get_node(ua.NodeId(ua.ObjectIds.Server_NamespaceArray))
        self._namespace_uris = list(await ns_node.read_value())
        return list(self._namespace_uris)

    async def get_namespace_index(self, uri: str) -> int:
        """The index of a namespace URI in the server's NamespaceArray; ValueError if it is not there."""
        return (await self.get_namespace_array()).index(uri)

    async def delete_nodes(
        self, nodes: Iterable[Node], recursive: bool = False
    ) -> tuple[list[Node], list[ua.StatusCode]]:
        """DeleteNodes for the nodes; see manage_nodes.delete_nodes."""
        return await delete_nodes(self.uaclient.session, nodes, recursive)

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
        importer = XmlImporter(self, strict_mode=strict_mode, auto_load_definitions=auto_load_definitions)
        return await importer.import_xml(path, xmlstring)

    async def export_xml(
        self, nodes: Iterable[Node], path: str, export_values: bool = False, model_uris: list[str] | None = None
    ) -> None:
        """
        Export defined nodes to xml
        :param export_values: exports values from variants
        :param model_uris: namespaces that are written as models, with their version and required models
        """
        exp = XmlExporter(self, export_values=export_values)
        await exp.build_etree(nodes, model_uris=model_uris)
        await exp.write_xml(path)

    async def register_namespace(self, uri: str) -> int:
        """
        Register a new namespace. Nodes should in custom namespace, not 0.
        This method is mainly implemented for symmetry with server
        """
        ns_node = self.get_node(ua.NodeId(ua.ObjectIds.Server_NamespaceArray))
        uries = await ns_node.read_value()
        if uri in uries:
            self._namespace_uris = list(uries)
            return uries.index(uri)
        uries.append(uri)
        await ns_node.write_value(uries)
        self._namespace_uris = list(uries)
        return len(uries) - 1

    async def load_type_definitions(self, nodes: Iterable[Node] | None = None) -> Any:
        """
        Load custom types (custom structures/extension objects) definition from server
        Generate Python classes for custom structures/extension objects defined in server
        These classes will available in ua module
        WARNING: protocol has changed in 1.04. use load_data_type_definitions()
        """
        _logger.warning("Deprecated since spec 1.04, call load_data_type_definitions")
        return await load_type_definitions(self, None if nodes is None else list(nodes))

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
        generate Python enums for custom enums on server.
        This enums will be available in ua module
        """
        _logger.warning("Deprecated since spec 1.04, call load_data_type_definitions")
        return await load_enums(self)

    async def register_nodes(self, nodes: Iterable[Node]) -> list[Node]:
        """
        Register nodes for faster read and write access (if supported by server)
        Rmw: This call modifies the nodeid of the nodes, the original nodeid is
        available as node.basenodeid
        """
        nodes = list(nodes)
        registered = await self.uaclient.register_nodes([node.nodeid for node in nodes])
        check_result_count(len(nodes), len(registered))
        for node, nodeid in zip(nodes, registered):
            node.basenodeid = node.nodeid
            node.nodeid = nodeid
        return nodes

    async def unregister_nodes(self, nodes: Iterable[Node]) -> None:
        """
        Unregister nodes
        """
        nodes = list(nodes)
        await self.uaclient.unregister_nodes([node.nodeid for node in nodes])
        for node in nodes:
            if node.basenodeid is None:
                continue
            node.nodeid = node.basenodeid
            node.basenodeid = None

    async def read_attributes(
        self, nodes: Iterable[Node], attr: ua.AttributeIds = ua.AttributeIds.Value
    ) -> list[ua.DataValue]:
        """
        Read the attributes of multiple nodes.
        """
        return await self.uaclient.read_attributes([node.nodeid for node in nodes], attr)

    async def read_values(self, nodes: Iterable[Node]) -> list[Any]:
        """
        Read the value of multiple nodes in one ua call.
        """
        res = await self.read_attributes(nodes, attr=ua.AttributeIds.Value)
        return [r.Value.Value if r.Value is not None else None for r in res]

    async def write_values(
        self, nodes: Iterable[Node], values: Iterable[Any], raise_on_partial_error: bool = True
    ) -> list[ua.StatusCode]:
        """
        Write values to multiple nodes in one ua call
        """
        nodeids = [node.nodeid for node in nodes]
        dvs = [value_to_datavalue(val) for val in values]
        if len(nodeids) != len(dvs):
            raise ValueError(f"{len(nodeids)} nodes and {len(dvs)} values")
        results = await self.uaclient.write_attributes(nodeids, dvs, ua.AttributeIds.Value)
        if raise_on_partial_error:
            for result in results:
                result.check()
        return results

    get_values = read_values
    set_values = write_values

    async def browse_nodes(self, nodes: Iterable[Node]) -> list[tuple[Node, ua.BrowseResult]]:
        """
        Browse the forward and inverse references of several nodes in one Browse request and return (Node,
        BrowseResult) pairs. Results the server split into pages are completed with BrowseNext, so every result
        holds all references and no ContinuationPoint.
        """
        nodes = list(nodes)
        nodestobrowse = []
        for node in nodes:
            desc = ua.BrowseDescription()
            desc.NodeId = node.nodeid
            desc.IncludeSubtypes = True
            desc.ResultMask = ua.BrowseResultMask.All
            nodestobrowse.append(desc)
        parameters = ua.BrowseParameters()
        parameters.View = ua.ViewDescription()
        parameters.RequestedMaxReferencesPerNode = 0
        parameters.NodesToBrowse = nodestobrowse
        results = await self.uaclient.browse(parameters)
        check_result_count(len(nodes), len(results))
        await self._browse_remaining_pages(results)
        return list(zip(nodes, results))

    async def _browse_remaining_pages(self, results: list[ua.BrowseResult]) -> None:
        pending = [result for result in results if result.ContinuationPoint]
        while pending:
            params = ua.BrowseNextParameters()
            params.ContinuationPoints = [result.ContinuationPoint for result in pending]
            params.ReleaseContinuationPoints = False
            pages = await self.uaclient.browse_next(params)
            check_result_count(len(pending), len(pages))
            still_open: list[ua.BrowseResult] = []
            stuck: list[bytes] = []
            for result, page in zip(pending, pages):
                previous = result.ContinuationPoint
                result.References.extend(page.References)
                result.StatusCode = page.StatusCode
                result.ContinuationPoint = page.ContinuationPoint if page.StatusCode.is_good() else None
                if not result.ContinuationPoint:
                    continue
                if page.References or result.ContinuationPoint != previous:
                    still_open.append(result)
                else:
                    stuck.append(result.ContinuationPoint)
                    result.ContinuationPoint = None
            if stuck:
                await self.uaclient.browse_next(
                    ua.BrowseNextParameters(ReleaseContinuationPoints=True, ContinuationPoints=stuck)
                )
            pending = still_open

    async def translate_browsepaths(
        self, starting_node: ua.NodeId, relative_paths: Iterable[ua.RelativePath | str]
    ) -> list[ua.BrowsePathResult]:
        """TranslateBrowsePathsToNodeIds for several RelativePaths (or their text form) from one starting node."""
        bpaths = []
        for p in relative_paths:
            try:
                rpath = ua.RelativePath.from_string(p) if isinstance(p, str) else p
            except ua.UaStringParsingError as e:
                raise ua.UaStringParsingError(f"Failed to parse one of RelativePath: {p}") from e
            bpath = ua.BrowsePath()
            bpath.StartingNode = starting_node
            bpath.RelativePath = rpath
            bpaths.append(bpath)

        return await self.uaclient.translate_browsepaths_to_nodeids(bpaths)
