"""
HaClient: one client over redundant servers, with the Warm failover mode of OPC 10000-4 v1.05, 6.6.2.4.5.3.
"""

import asyncio
import logging
import time
from collections.abc import Callable, Generator, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime
from enum import IntEnum
from functools import partial
from itertools import chain
from pathlib import Path
from typing import Any

from cryptography import x509
from sortedcontainers import SortedDict  # type: ignore

from enginir_opcua import Client, Node, ua
from enginir_opcua.client.ua_client import UaClientState
from enginir_opcua.ua.uaerrors import BadSessionClosed, BadSessionNotActivated

from ...config import default_application_uri, quickstart_client_config
from ...crypto.security_policies import SecurityPolicy
from ...crypto.truststore import TrustStore
from ...crypto.uacrypto import CertProperties
from ...ua.uaerrors import ConfigurationError
from .common import ClientNotFound, ConnectionStates, event_wait, wait_any
from .reconciliator import Reconciliator
from .virtual_subscription import TypeSubHandler, VirtualSubscription

_logger = logging.getLogger(__name__)

SUB_NAME_COUNT = 9999


class HaMode(IntEnum):
    """
    Failover modes of OPC 10000-4 v1.05, 6.6.2.4.5: COLD (6.6.2.4.5.2), WARM (6.6.2.4.5.3: the standby clients create
    the MonitoredItems but disable sampling and publishing), HOT_A and HOT_B (6.6.2.4.5.4). Only WARM is implemented;
    `HaClient` refuses the others with a NotImplementedError.
    """

    COLD = 0
    WARM = 1
    HOT_A = 2
    HOT_B = 3


def classify_service_level(level: int, healthy_state: int = ConnectionStates.HEALTHY) -> ConnectionStates:
    """The band of a ServiceLevel; levels from healthy_state up are Healthy."""
    if level >= healthy_state:
        return ConnectionStates.HEALTHY
    if level >= ConnectionStates.DEGRADED:
        return ConnectionStates.DEGRADED
    if level == ConnectionStates.NO_DATA:
        return ConnectionStates.NO_DATA
    return ConnectionStates.IN_MAINTENANCE


def redundancy_accepted(mode: HaMode, support: ua.RedundancySupport | int | None) -> bool:
    """
    Whether a server that reports `support` can be used in failover mode `mode` (OPC 10000-4 v1.05, 6.6.2.4.5.1).
    A server that reports nothing is accepted.
    """
    if support is None:
        return True
    return int(support) in (ua.RedundancySupport.Warm, ua.RedundancySupport.Hot)


@dataclass
class ServerInfo:
    """What the HaClient knows about one server: its last ServiceLevel, probe time, errors and redundancy check."""

    url: str
    status: int = ConnectionStates.NO_DATA
    retry_at: float | None = None
    last_probe_at: float | None = None
    errors: int = 0
    redundancy_ok: bool | None = None


@dataclass(frozen=True, eq=True)
class HaSecurityConfig:
    """
    The security and identity of every client of an HaClient (see HaClient.set_security), or the quick setup
    (HaClient.quickstart): `pki` is the PKI directory that every client uses for its certificate, key and trust,
    `profile` the quick-setup profile, `application_uri` the ApplicationUri of every client (default: the host-derived
    URI of Client.quickstart) and `client_settings` more ClientConfig fields. With the quick setup the clients are
    created by the HaClient constructor, so a later set_security() does not reach them and the policy fields stay unused.
    """

    policy: type[SecurityPolicy] | None = None
    certificate: CertProperties | None = None
    private_key: CertProperties | None = None
    server_certificate: CertProperties | None = None
    mode: ua.MessageSecurityMode | None = None
    trust_store: TrustStore | None = None
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    user_certificate: CertProperties | None = field(default=None, repr=False)
    user_private_key: CertProperties | None = field(default=None, repr=False)
    pki: str | Path | None = None
    profile: str = "secure"
    application_uri: str | None = None
    client_settings: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.policy is not None and self.server_certificate is None and self.trust_store is None:
            raise ValueError("server_certificate or trust_store is required when the HaClient uses security")


@dataclass(frozen=True, eq=True)
class HaConfig:
    """
    Parameters for the HaClient constructor.
    Timers and timeouts are all in seconds.
    """

    ha_mode: HaMode
    keepalive_timer: float = 5
    manager_timer: float = 5
    reconciliator_timer: float = 15
    session_timeout: int = 60
    request_timeout: int = 30
    secure_channel_timeout: int = 3600
    session_name: str = "HaClient"
    urls: list[str] = field(default_factory=list)
    probe_timeout: float | None = None
    min_active_seconds: float = 10
    maintenance_retry_interval: float = 300
    batch_mi_size: int = 1000
    stop_grace: float = 5
    allow_unsupported_redundancy: bool = False


class HaClient:
    """
    The HaClient is responsible for managing non-transparent server redundancy.
    Only the Warm failover mode is implemented (OPC 10000-4 v1.05, 6.6.2.4.5.3): the standby servers hold the same
    subscriptions and monitored items, but do not sample or publish.
    The servers must have:

    - Identical NodeIds
    - Identical browse path and AddressSpace structure
    - Identical Service Level logic
    - However nodes in the server local namespace can differ
    - Time synchronization (e.g NTP)

    It starts the OPC-UA clients and connect to the server that
    fits in the HaMode selected. Subclasses may change HEALTHY_STATE for servers with other ServiceLevels (an OPC UA
    proxy, for example) and override the hook_ methods, which do nothing.
    """

    HEALTHY_STATE = ConnectionStates.HEALTHY

    def __init__(self, config: HaConfig, security: HaSecurityConfig | None = None) -> None:
        if config.ha_mode != HaMode.WARM:
            raise NotImplementedError(f"HA mode {config.ha_mode.name} is not implemented; only WARM is supported")
        if len(config.urls) < 2 or len(set(config.urls)) != len(config.urls):
            raise ValueError("HaConfig needs at least two distinct urls")
        self._config: HaConfig = config
        self._keepalive_task: dict[KeepAlive, asyncio.Task[None]] = {}
        self._manager_task: dict[HaManager, asyncio.Task[None]] = {}
        self._reconciliator_task: dict[Reconciliator, asyncio.Task[None]] = {}
        self._gen_sub: Generator[str, None, None] = self.generate_sub_name()
        self._url_to_reset_lock = asyncio.Lock()
        self._ideal_map_lock: asyncio.Lock = asyncio.Lock()
        self._client_lock: asyncio.Lock = asyncio.Lock()

        self.clients: dict[Client, ServerInfo] = {}
        self.active_client: Client | None = None
        self._active_since: float | None = None
        self.ideal_map: dict[str, SortedDict] = {}
        self.sub_names: set[str] = set()
        self.url_to_reset: set[str] = set()
        self._state_listener_unsubs: list[Callable[[], None]] = []
        self._ready: dict[Client, asyncio.Event] = {}
        self._resetting: set[Client] = set()
        self.is_running = False

        security = security if security else HaSecurityConfig()
        for url in config.urls:
            c = self._new_client(url, security)
            c.session_timeout = self._config.session_timeout * 1000
            c.secure_channel_timeout = self._config.secure_channel_timeout * 1000
            c.description = self._config.session_name
            server_info = ServerInfo(url)
            self.clients[c] = server_info
            self._ready[c] = asyncio.Event()
            self.ideal_map[url] = SortedDict()
        self.security_config: HaSecurityConfig = security
        self.manager = HaManager(self, self._config.manager_timer)
        self.reconciliator = Reconciliator(self._config.reconciliator_timer, self)

    @classmethod
    def quickstart(
        cls,
        urls: Sequence[str],
        profile: str = "secure",
        pki: str | Path | None = "./pki",
        username: str | None = None,
        password: str | None = None,
        **overrides: Any,
    ) -> "HaClient":
        """
        An HA client for the quick setup, not started: one Client per URL, each configured like Client.quickstart with
        the same profile, PKI directory (the server certificates have to be in its trusted/certs, see
        `enginir-opcua trust`) and ApplicationUri, which is the host-derived one unless `application_uri` is given.
        `username` and `password` go to every client. `overrides` are the fields of :class:`HaConfig` (timers,
        `session_name`, ...; `ha_mode` defaults to WARM) and any other ClientConfig field (`security`, `name`, ...).
        The PKI directory and the certificate are created by `init_pki()` or at `start()`.
        """
        ha_names = {f.name for f in fields(HaConfig)} - {"urls"}
        ha_values = {key: value for key, value in overrides.items() if key in ha_names}
        client_settings = {key: value for key, value in overrides.items() if key not in ha_names}
        application_uri = client_settings.pop("application_uri", None)
        ha_values.setdefault("ha_mode", HaMode.WARM)
        security = HaSecurityConfig(
            username=username,
            password=password,
            pki=pki,
            profile=profile,
            application_uri=application_uri,
            client_settings=client_settings,
        )
        return cls(HaConfig(urls=list(urls), **ha_values), security)

    @property
    def config(self) -> HaConfig:
        """The configuration given to the constructor."""
        return self._config

    def _new_client(self, url: str, security: HaSecurityConfig) -> Client:
        if security.pki is None:
            return Client(url, timeout=self._config.request_timeout)
        settings = dict(security.client_settings)
        settings.setdefault("timeout", self._config.request_timeout)
        settings.setdefault("application_uri", security.application_uri or default_application_uri("client"))
        config = quickstart_client_config(url, security.profile, security.pki, None, None, settings)
        return Client(config=config)

    async def init_pki(self) -> x509.Certificate:
        """
        Create the PKI directory and the self-signed application certificate of the quick setup now (all clients share
        them) and return the certificate, for example to put it into the servers' trusted/certs before `start()`.
        `start()` does it too. Calling it again returns the same certificate.
        """
        if self.security_config.pki is None:
            raise ConfigurationError(
                "client.pki: init_pki needs a PKI directory; create the client with HaClient.quickstart"
            )
        return await next(iter(self.clients)).init_pki()

    async def start(self) -> None:
        """Start the keep-alive probes, the manager and the reconciliator; the clients connect in the background."""
        if self.security_config.pki is not None:
            await self.init_pki()
        for client, server in self.clients.items():
            keepalive = KeepAlive(
                client,
                server,
                self._config.keepalive_timer,
                probe_timeout=self._config.probe_timeout,
                ready=self._ready[client],
                on_change=self.manager.wake,
                band_of=self.band_of,
                maintenance_retry_interval=self._config.maintenance_retry_interval,
            )
            task = asyncio.create_task(keepalive.run())
            self._keepalive_task[keepalive] = task
            self._watch_client_state(client)

        task = asyncio.create_task(self.manager.run())
        self._manager_task[self.manager] = task

        task = asyncio.create_task(self.reconciliator.run())
        self._reconciliator_task[self.reconciliator] = task

        self.is_running = True

    def _watch_client_state(self, client: Client) -> None:
        """
        After every RECONNECTING to CONNECTED transition refresh the handles of the reconciliator, since a recreated
        Subscription has new server handles, and let it compare the modes with the ideal state.
        """
        url = client.server_url.geturl()
        prev: UaClientState | None = None

        def on_state_change(state: UaClientState) -> None:
            nonlocal prev
            if prev is UaClientState.RECONNECTING and state is UaClientState.CONNECTED:
                self.reconciliator.refresh_handles(url)
                self.reconciliator.wake()
            if state is not UaClientState.CONNECTED:
                self.manager.wake()
            prev = state

        unsub = client.uaclient.add_state_listener(on_state_change)
        self._state_listener_unsubs.append(unsub)

    async def stop(self) -> None:
        """Stop the loops (waiting up to stop_grace for them), end the Subscriptions locally and disconnect."""
        for unsub in self._state_listener_unsubs:
            try:
                unsub()
            except Exception:
                _logger.exception("state listener unsubscribe raised")
        self._state_listener_unsubs.clear()

        to_stop: list[Any] = list(chain(self._keepalive_task, self._manager_task, self._reconciliator_task))
        await asyncio.gather(*(p.stop() for p in to_stop))

        tasks = list(
            chain(
                self._keepalive_task.values(),
                self._manager_task.values(),
                self._reconciliator_task.values(),
            )
        )
        if tasks:
            _done, pending = await asyncio.wait(tasks, timeout=self._config.stop_grace)
            for task in pending:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        self._keepalive_task.clear()
        self._manager_task.clear()
        self._reconciliator_task.clear()

        await self.reconciliator.close_subscriptions("HaClient stopped")
        await asyncio.gather(*(c.disconnect() for c in self.clients), return_exceptions=True)
        self.is_running = False

    def set_security(
        self,
        policy: type[SecurityPolicy],
        certificate: CertProperties,
        private_key: CertProperties,
        server_certificate: CertProperties | None = None,
        mode: ua.MessageSecurityMode = ua.MessageSecurityMode.SignAndEncrypt,
        trust_store: TrustStore | None = None,
        username: str | None = None,
        password: str | None = None,
        user_certificate: CertProperties | None = None,
        user_private_key: CertProperties | None = None,
    ) -> None:
        """
        Set the security of every client. Either the server certificate (pinned) or a trust store is required:
        a certificate fetched from an unsecured GetEndpoints call, at start or on a reconnect, is only used
        when the trust store validates it. The user credentials, a user name and password or a user certificate
        and key, go to every client as well.
        """
        self.security_config = HaSecurityConfig(
            policy,
            certificate,
            private_key,
            server_certificate,
            mode,
            trust_store,
            username,
            password,
            user_certificate,
            user_private_key,
        )

    def band_of(self, level: int) -> ConnectionStates:
        """The band of a ServiceLevel with this client's HEALTHY_STATE."""
        return classify_service_level(level, self.HEALTHY_STATE)

    def _new_sub_name(self) -> str:
        try:
            return next(self._gen_sub)
        except (RuntimeError, StopIteration):
            self._gen_sub = self.generate_sub_name()
            return next(self._gen_sub)

    async def create_subscription(self, period: int, handler: TypeSubHandler) -> str:
        """Add a Subscription on every server (publishing only on the active one) and return its name."""
        async with self._ideal_map_lock:
            sub_name = self._new_sub_name()
            for client in self.clients:
                if client == self.active_client:
                    vs = VirtualSubscription(
                        period=period,
                        handler=handler,
                        publishing=True,
                        monitoring=ua.MonitoringMode.Reporting,
                    )
                else:
                    vs = VirtualSubscription(
                        period=period,
                        handler=handler,
                        publishing=False,
                        monitoring=ua.MonitoringMode.Disabled,
                    )
                url = client.server_url.geturl()
                self.ideal_map[url][sub_name] = vs
        self.reconciliator.wake()
        return sub_name

    @staticmethod
    def _node_strings(nodes: Iterable[Node] | Iterable[str]) -> list[str]:
        result: list[str] = []
        for n in nodes:
            if isinstance(n, Node):
                if n.nodeid is None:
                    raise ValueError(f"{n} has no NodeId")
                result.append(n.nodeid.to_string())
            else:
                result.append(n)
        return result

    async def subscribe_data_change(
        self,
        sub_name: str,
        nodes: Iterable[Node] | Iterable[str],
        attr: ua.AttributeIds = ua.AttributeIds.Value,
        queuesize: int = 0,
    ) -> None:
        """Monitor the nodes (Nodes or NodeId texts) in the named Subscription on every server; KeyError if unknown."""
        node_ids = self._node_strings(nodes)
        async with self._ideal_map_lock:
            if sub_name not in self.sub_names or any(sub_name not in self.ideal_map[url] for url in self.urls):
                raise KeyError(f"no subscription named {sub_name}")
            for url in self.urls:
                self.ideal_map[url][sub_name].subscribe_data_change(node_ids, attr, queuesize)
        for url in self.urls:
            await self.hook_on_subscribe(nodes=node_ids, attr=attr, queuesize=queuesize, url=url)
        self.reconciliator.wake()

    async def delete_subscriptions(self, sub_names: list[str]) -> None:
        """Remove the named Subscriptions from every server; KeyError for an unknown name, removing none."""
        async with self._ideal_map_lock:
            unknown = [n for n in sub_names if n not in self.sub_names]
            if unknown:
                raise KeyError(f"no subscription named {', '.join(unknown)}")
            for sub_name in sub_names:
                for url in self.urls:
                    self.ideal_map[url].pop(sub_name, None)
                self.sub_names.discard(sub_name)
        self.reconciliator.wake()

    async def _apply_identity(self, client: Client) -> None:
        security = self.security_config
        if security.username is not None:
            client.set_user(security.username)
        if security.password is not None:
            client.set_password(security.password)
        if security.user_certificate is not None:
            await client.load_client_certificate(
                security.user_certificate.path_or_content, security.user_certificate.extension
            )
        if security.user_private_key is not None:
            await client.load_private_key(
                security.user_private_key.path_or_content,
                security.user_private_key.password,
                security.user_private_key.extension,
            )

    async def reconnect(self, client: Client) -> None:
        """
        Reconnect a client of the HA set and add its URL to the reset list.

        Only call this when the client's auto-reconnect supervisor is not actively
        recovering (`client.uaclient.state` is DISCONNECTED). Calling it while the
        supervisor is mid-recovery would tear down its in-progress reconnect.
        Single-server transport drops are handled by auto-reconnect itself; this
        method is only used for the initial bring-up and as a manual full-reset.
        """
        async with self._url_to_reset_lock:
            url = client.server_url.geturl()
            self.url_to_reset.add(url)
        self._resetting.add(client)
        try:
            try:
                await client.disconnect()
            except Exception:
                pass
            await self.hook_on_reconnect(client=client)
            await self._apply_identity(client)
            security = self.security_config
            if security.policy:
                if security.trust_store is not None:
                    client.set_trust_store(security.trust_store)
                await client.set_security(
                    policy=security.policy,
                    certificate=security.certificate,
                    private_key=security.private_key,
                    server_certificate=security.server_certificate,
                    mode=security.mode if security.mode is not None else ua.MessageSecurityMode.SignAndEncrypt,
                )
            await client.connect(
                auto_reconnect=True,
                reconnect_max_delay=self._config.manager_timer,
                reconnect_request_timeout=self._config.request_timeout,
            )
            await self._check_redundancy(client)
        finally:
            self._resetting.discard(client)
            self._ready[client].set()
            self.reconciliator.wake()

    async def _check_redundancy(self, client: Client) -> None:
        info = self.clients[client]
        if self._config.allow_unsupported_redundancy or client.uaclient.state is not UaClientState.CONNECTED:
            info.redundancy_ok = None
            return
        support: int | None = None
        try:
            node = client.get_node(ua.NodeId(ua.ObjectIds.Server_ServerRedundancy_RedundancySupport))
            support = int(await node.read_value())
        except Exception:
            _logger.warning("%s does not report its RedundancySupport; accepting it", info.url, exc_info=True)
        accepted = redundancy_accepted(self._config.ha_mode, support)
        info.redundancy_ok = accepted
        if not accepted:
            _logger.error(
                "%s reports RedundancySupport %s, which does not fit failover mode %s; not using it",
                info.url,
                support,
                self._config.ha_mode.name,
            )

    async def unsubscribe(self, nodes: Iterable[Node] | Iterable[str]) -> None:
        """Stop monitoring the nodes in every Subscription on every server."""
        node_set = set(self._node_strings(nodes))
        removed: list[tuple[str, set[str]]] = []
        async with self._ideal_map_lock:
            sub_to_nodes: dict[str, set[str]] = {}
            first_url = self.urls[0]
            for sub_name, vs in self.ideal_map[first_url].items():
                to_del = node_set & vs.get_nodes()
                if to_del:
                    sub_to_nodes[sub_name] = to_del
            for url in self.urls:
                for sub_name, str_nodes in sub_to_nodes.items():
                    self.ideal_map[url][sub_name].unsubscribe(str_nodes)
                    removed.append((url, str_nodes))
        for url, str_nodes in removed:
            await self.hook_on_unsubscribe(url=url, nodes=str_nodes)
        self.reconciliator.wake()

    async def failover_warm(self, primary: Client | None, secondaries: Iterable[Client]) -> None:
        """Make primary the active client (Reporting and publishing) and the secondaries standbys (Disabled)."""
        old = self.active_client
        async with self._ideal_map_lock:
            if primary:
                self._set_monitoring_mode(ua.MonitoringMode.Reporting, clients=[primary])
                self._set_publishing_mode(True, clients=[primary])
            self.active_client = primary
            if primary is not old:
                self._active_since = time.monotonic()
            self._set_monitoring_mode(ua.MonitoringMode.Disabled, clients=secondaries)
            self._set_publishing_mode(False, clients=secondaries)
        self.reconciliator.wake()
        if primary is not old:
            old_url = old.server_url.geturl() if old else None
            new_url = primary.server_url.geturl() if primary else None
            _logger.info("Active server changed from %s to %s", old_url, new_url)
            await self.hook_on_failover(old_url, new_url)

    def _set_monitoring_mode(self, monitoring: ua.MonitoringMode, clients: Iterable[Client]) -> None:
        for client in clients:
            url = client.server_url.geturl()
            for sub in self.ideal_map[url]:
                vs = self.ideal_map[url][sub]
                vs.monitoring = monitoring

    def _set_publishing_mode(self, publishing: bool, clients: Iterable[Client]) -> None:
        for client in clients:
            url = client.server_url.geturl()
            for sub in self.ideal_map[url]:
                vs = self.ideal_map[url][sub]
                vs.publishing = publishing

    async def group_clients_by_health(self) -> tuple[list[Client], list[Client]]:
        """The clients whose server is Healthy, and the others."""
        healthy: list[Client] = []
        unhealthy: list[Client] = []
        async with self._client_lock:
            for client, server in self.clients.items():
                if server.status >= self.HEALTHY_STATE:
                    healthy.append(client)
                else:
                    unhealthy.append(client)
            return healthy, unhealthy

    def _level(self, client: Client) -> int:
        info = self.clients[client]
        if info.redundancy_ok is False:
            return ConnectionStates.NO_DATA
        return int(info.status)

    async def get_serving_client(self, clients: list[Client], serving_client: Client | None) -> Client | None:
        """
        Elect the client that serves (OPC 10000-4 v1.05, 6.6.2.4.2, 6.6.2.4.3): a Healthy active client stays whatever the
        others report. Otherwise the Healthy client with the highest ServiceLevel wins, ties going to the active
        client and then to the earlier URL. Without a Healthy client the best Degraded one is used, with a warning;
        a Degraded active client is only replaced by a better one, and not within `min_active_seconds` of its
        election. Clients with no data or in maintenance never serve.
        """
        async with self._client_lock:
            order = {c: i for i, c in enumerate(self.clients)}
            healthy_state = int(self.HEALTHY_STATE)
            current = self._level(serving_client) if serving_client is not None else None
            if serving_client is not None and current is not None and current >= healthy_state:
                return serving_client

            def preference(c: Client) -> tuple[int, bool, int]:
                return self._level(c), c is serving_client, -order[c]

            healthy = [c for c in clients if self._level(c) >= healthy_state]
            if healthy:
                return max(healthy, key=preference)
            degraded = [c for c in clients if int(ConnectionStates.DEGRADED) <= self._level(c) < healthy_state]
            if not degraded:
                return None
            best = max(degraded, key=preference)
            if serving_client is not None and current is not None and current >= ConnectionStates.DEGRADED:
                recent = (
                    self._active_since is not None
                    and time.monotonic() - self._active_since < self._config.min_active_seconds
                )
                if self._level(best) <= current or recent:
                    return serving_client
            if best is not serving_client:
                _logger.warning(
                    "No Healthy server; using the Degraded server %s (ServiceLevel %s)",
                    self.clients[best].url,
                    self._level(best),
                )
            return best

    def status(self) -> list[dict[str, Any]]:
        """Snapshot of every server for monitoring."""
        return [
            {
                "url": info.url,
                "band": self.band_of(self._level(client)),
                "level": info.status,
                "state": client.uaclient.state,
                "active": client is self.active_client,
                "last_probe_at": info.last_probe_at,
                "errors": info.errors,
                "redundancy_ok": info.redundancy_ok,
            }
            for client, info in self.clients.items()
        ]

    def get_client_warm_mode(self) -> list[Client]:
        """In Warm mode every client is connected."""
        return list(self.clients)

    def get_clients(self) -> list[Client]:
        """The clients the failover mode keeps connected."""
        ha_mode = self.ha_mode
        func = f"get_client_{ha_mode}_mode"
        get_clients = getattr(self, func)
        active_clients = get_clients()
        if not isinstance(active_clients, list):
            active_clients = [active_clients]
        return active_clients

    def get_client_by_url(self, url: str) -> Client:
        """The client of a server URL; ClientNotFound for another URL."""
        for client, srv_info in self.clients.items():
            if srv_info.url == url:
                return client
        raise ClientNotFound(f"{url} not managed by HaClient")

    @property
    def session_timeout(self) -> int:
        """The session timeout in seconds."""
        return self._config.session_timeout

    @property
    def ha_mode(self) -> str:
        """The failover mode in lower case, such as "warm"."""
        return self._config.ha_mode.name.lower()

    @property
    def urls(self) -> list[str]:
        """The server URLs, in configuration order."""
        return self._config.urls

    def generate_sub_name(self) -> Generator[str, None, None]:
        """
        Asyncio unsafe - yield names for subscriptions.
        :raises RuntimeError: when every name is taken
        """
        while True:
            for i in range(SUB_NAME_COUNT):
                sub_name = f"sub_{i}"
                if sub_name in self.sub_names:
                    continue
                self.sub_names.add(sub_name)
                yield sub_name
                break
            else:
                raise RuntimeError("no free subscription name")

    async def hook_on_reconnect(self, **kwargs: Any) -> None:
        """Called before a client is reconnected, with client=."""

    async def hook_on_subscribe(self, **kwargs: Any) -> None:
        """Called for every server after nodes were added to a Subscription, with nodes=, attr=, queuesize=, url=."""

    async def hook_on_unsubscribe(self, **kwargs: Any) -> None:
        """Called for every server after nodes were removed, with url= and nodes=."""

    async def hook_on_failover(self, old_url: str | None, new_url: str | None) -> None:
        """Called after the active server changed."""


class KeepAlive:
    """
    Probe the status of a server regularly to check its health
    """

    def __init__(
        self,
        client: Client,
        server: ServerInfo,
        timer: float,
        *,
        probe_timeout: float | None = None,
        ready: asyncio.Event | None = None,
        on_change: Callable[[], None] | None = None,
        band_of: Callable[[int], ConnectionStates] = classify_service_level,
        maintenance_retry_interval: float = 300,
    ) -> None:
        self.client: Client = client
        self.server: ServerInfo = server
        self.timer: float = timer
        self.probe_timeout: float = probe_timeout if probe_timeout is not None else timer
        self.ready = ready
        self.on_change = on_change
        self.band_of = band_of
        self.maintenance_retry_interval = maintenance_retry_interval
        self.stop_event: asyncio.locks.Event = asyncio.Event()
        self.is_running: bool = False

    async def stop(self) -> None:
        """End the probe loop."""
        self.stop_event.set()

    def _set_level(self, level: int) -> None:
        server_info = self.server
        before = self.band_of(int(server_info.status))
        server_info.status = level
        if self.band_of(level) is not before and self.on_change is not None:
            self.on_change()

    async def run(self) -> None:
        """Probe the server every timer seconds, after the client is ready, until stop()."""
        if self.ready is not None:
            ready_wait = asyncio.ensure_future(self.ready.wait())
            stop_wait = asyncio.ensure_future(self.stop_event.wait())
            try:
                await asyncio.wait({ready_wait, stop_wait}, return_when=asyncio.FIRST_COMPLETED)
            finally:
                ready_wait.cancel()
                stop_wait.cancel()
            if self.stop_event.is_set():
                return
        self.is_running = True
        _logger.info("Starting keepalive loop for %s, checking every %.1fsec", self.server.url, self.timer)
        while self.is_running:
            try:
                await self.probe()
            except Exception:
                _logger.exception("Unknown exception during keepalive liveness check")
                self.server.errors += 1
                self._set_level(ConnectionStates.NO_DATA)
            _logger.debug("ServiceLevel for %s: %s", self.server.url, self.server.status)
            if await event_wait(self.stop_event, self.timer):
                self.is_running = False
                break

    async def probe(self) -> None:
        """
        Read ServerState and ServiceLevel. A server that is not Running, or a failed read, counts as NoData; a
        server in maintenance is not probed again before its EstimatedReturnTime (or maintenance_retry_interval).
        """
        client = self.client
        server_info = self.server
        if server_info.retry_at is not None and time.monotonic() < server_info.retry_at:
            return
        if client.uaclient.state is not UaClientState.CONNECTED:
            self._set_level(ConnectionStates.NO_DATA)
            return
        try:
            async with asyncio.timeout(self.probe_timeout):
                status, slevel = await client.read_values([client.nodes.server_state, client.nodes.service_level])
        except (BadSessionNotActivated, BadSessionClosed, ConnectionError, TimeoutError) as error:
            _logger.warning("Could not read the state of %s: %r", self.server.url, error)
            self._set_level(ConnectionStates.NO_DATA)
            return
        server_info.last_probe_at = time.monotonic()
        if status != ua.ServerState.Running:
            _logger.info("ServerState is not running")
            self._set_level(ConnectionStates.NO_DATA)
            return
        self._set_level(int(slevel))
        if int(slevel) == ConnectionStates.IN_MAINTENANCE:
            await self._note_maintenance()

    async def _note_maintenance(self) -> None:
        wait = self.maintenance_retry_interval
        try:
            async with asyncio.timeout(self.probe_timeout):
                returns = await self.client.get_node(ua.NodeId(ua.ObjectIds.Server_EstimatedReturnTime)).read_value()
            if isinstance(returns, datetime):
                remaining = (returns - datetime.now(UTC)).total_seconds()
                if remaining > 0:
                    wait = remaining
        except Exception:
            _logger.debug("EstimatedReturnTime not available from %s", self.server.url, exc_info=True)
        self.server.retry_at = time.monotonic() + wait
        _logger.info("%s is in maintenance, not connecting for %.0fsec", self.server.url, wait)


class HaManager:
    """
    The manager elects the active client and brings the connections up or down, every timer seconds or when woken.
    """

    def __init__(self, ha_client: HaClient, timer: float | None = None) -> None:
        self.ha_client = ha_client
        self.timer = self.set_loop_timer(timer)
        self.stop_event = asyncio.Event()
        self.wake_event = asyncio.Event()
        self.is_running = False
        self.errors = 0

    def set_loop_timer(self, timer: float | None) -> float:
        """The loop period: timer, or the session timeout without one."""
        return timer if timer else float(self.ha_client.session_timeout)

    def wake(self) -> None:
        """Run the next step now."""
        self.wake_event.set()

    async def run(self) -> None:
        """The manager loop, until stop()."""
        ha_mode = self.ha_client.ha_mode
        update_func = f"update_state_{ha_mode}"
        update_state = getattr(self, update_func)
        reco_func = f"reconnect_{ha_mode}"
        reconnect = getattr(self, reco_func)
        self.is_running = True

        _logger.info("Starting HaManager loop, checking every %.1fsec", self.timer)
        while self.is_running:
            try:
                await update_state()
                await reconnect()
            except Exception:
                _logger.exception("HaManager step failed")
                self.errors += 1

            if await wait_any(self.timer, self.stop_event, self.wake_event):
                self.is_running = False
                break

    async def stop(self) -> None:
        """End the loop after the current step."""
        self.stop_event.set()

    async def update_state_warm(self) -> None:
        """Elect the serving client and fail over to it if it changed."""
        active_client = self.ha_client.active_client
        clients = self.ha_client.get_clients()
        primary_client = await self.ha_client.get_serving_client(list(self.ha_client.clients), active_client)
        if primary_client != active_client:
            _logger.info("Failing over active client from %s to %s", active_client, primary_client)
            secondaries = set(clients) - {primary_client} if primary_client else set(clients)
            await self.ha_client.failover_warm(primary=primary_client, secondaries=secondaries)

    async def reconnect_warm(self) -> None:
        """
        Bring up disconnected clients and disconnect the ones in maintenance. A client that is connected is never
        reset because of its ServiceLevel: the standby of a Warm pair is Degraded by design.
        """
        ha_client = self.ha_client
        now = time.monotonic()

        def log_exception(client: Client, fut: asyncio.Task[None]) -> None:
            if not fut.cancelled() and fut.exception():
                _logger.warning("Error when reconnecting %s: %s", client, fut.exception())

        tasks: list[asyncio.Task[None]] = []
        for client, info in list(ha_client.clients.items()):
            state = client.uaclient.state
            if client in ha_client._resetting:
                continue
            if info.status == ConnectionStates.IN_MAINTENANCE and state is not UaClientState.DISCONNECTED:
                if state is UaClientState.CONNECTED:
                    _logger.info("Disconnecting %s: it is in maintenance", info.url)
                    task = asyncio.create_task(client.disconnect())
                    task.add_done_callback(partial(log_exception, client))
                    tasks.append(task)
                continue
            if state is not UaClientState.DISCONNECTED:
                continue
            if info.status == ConnectionStates.IN_MAINTENANCE and info.retry_at is None:
                info.retry_at = now + ha_client._config.maintenance_retry_interval
            if info.retry_at is not None:
                if now < info.retry_at:
                    continue
                info.retry_at = None
                info.status = ConnectionStates.NO_DATA
            _logger.info("Virtually reconnecting and resubscribing %s", client)
            task = asyncio.create_task(ha_client.reconnect(client=client))
            task.add_done_callback(partial(log_exception, client))
            tasks.append(task)
        await asyncio.gather(*tasks, return_exceptions=True)
