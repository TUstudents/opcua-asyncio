"""Election, health probing and loops of the HA client, without real servers."""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from cryptography.hazmat.primitives import serialization

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ha import ConnectionStates, HaClient, HaMode, HaSecurityConfig
from enginir_opcua.client.ha.ha_client import HaConfig, HaManager, KeepAlive, ServerInfo, redundancy_accepted
from enginir_opcua.client.ha.reconciliator import Reconciliator
from enginir_opcua.client.ua_client import UaClientState
from enginir_opcua.config import default_application_uri
from enginir_opcua.crypto import pki
from enginir_opcua.ua.uaerrors import ConfigurationError
from tests.conftest import find_free_port
from tests.waiting import wait_until


def make_config(**kwargs: Any) -> HaConfig:
    values: dict[str, Any] = {
        "ha_mode": HaMode.WARM,
        "urls": ["opc.tcp://127.0.0.1:1", "opc.tcp://127.0.0.1:2"],
        "keepalive_timer": 0.1,
        "manager_timer": 0.1,
        "reconciliator_timer": 0.1,
    }
    values.update(kwargs)
    return HaConfig(**values)


def make_ha(**kwargs: Any) -> tuple[HaClient, Client, Client]:
    ha = HaClient(make_config(**kwargs))
    first, second = list(ha.clients)
    return ha, first, second


def set_state(client: Client, state: UaClientState) -> None:
    client.uaclient._state = state


def set_levels(ha: HaClient, *levels: int) -> None:
    for info, level in zip(ha.clients.values(), levels):
        info.status = level


def test_ha_requires_two_distinct_urls() -> None:
    """Part 4, 6.6.2.4.1: redundancy needs a set of at least two servers."""
    with pytest.raises(ValueError):
        HaClient(make_config(urls=["opc.tcp://127.0.0.1:1"]))
    with pytest.raises(ValueError):
        HaClient(make_config(urls=["opc.tcp://127.0.0.1:1", "opc.tcp://127.0.0.1:1"]))


@pytest.mark.parametrize("mode", [HaMode.COLD, HaMode.HOT_A, HaMode.HOT_B])
def test_cli16_other_modes_raise_a_clear_message(mode: HaMode) -> None:
    """Only the Warm failover mode is implemented, and the message names the mode."""
    with pytest.raises(NotImplementedError, match=f"HA mode {mode.name} is not implemented; only WARM is supported"):
        HaClient(make_config(ha_mode=mode))


@pytest.mark.parametrize(
    "level,band",
    [
        (0, ConnectionStates.IN_MAINTENANCE),
        (1, ConnectionStates.NO_DATA),
        (2, ConnectionStates.DEGRADED),
        (199, ConnectionStates.DEGRADED),
        (200, ConnectionStates.HEALTHY),
        (255, ConnectionStates.HEALTHY),
    ],
)
def test_ha_band_classification(level: int, band: ConnectionStates) -> None:
    """Part 4, 6.6.2.4.2, Table 105: the ServiceLevel ranges."""
    ha, _, _ = make_ha()
    assert ha.band_of(level) is band


async def test_cli47_healthy_active_stays_when_another_is_higher() -> None:
    """Part 4, 6.6.2.4.3: a Healthy active server isn't left for a server with a higher level."""
    ha, first, second = make_ha()
    set_levels(ha, 200, 255)
    assert await ha.get_serving_client([first, second], first) is first


async def test_ha_first_election_picks_the_highest_healthy_server() -> None:
    """Part 4, 6.6.2.4.2: a client with no server yet connects to the highest ServiceLevel."""
    ha, first, second = make_ha()
    set_levels(ha, 200, 255)
    assert await ha.get_serving_client([first, second], None) is second


async def test_cli15_all_degraded_uses_the_best_degraded_with_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    """Part 4, 6.6.2.4.2: with no Healthy server a Degraded one may serve."""
    ha, first, second = make_ha()
    set_levels(ha, 100, 150)
    with caplog.at_level(logging.WARNING):
        assert await ha.get_serving_client([first, second], None) is second
    assert any("Degraded" in r.getMessage() for r in caplog.records)


async def test_ha_no_active_when_all_no_data_or_maintenance() -> None:
    ha, first, second = make_ha()
    set_levels(ha, 0, 1)
    assert await ha.get_serving_client([first, second], None) is None
    assert await ha.get_serving_client([first, second], first) is None


async def test_ha_healthy_beats_degraded_when_the_active_degrades() -> None:
    ha, first, second = make_ha()
    set_levels(ha, 120, 200)
    assert await ha.get_serving_client([first, second], first) is second


async def test_ha_tie_keeps_the_current_then_config_order() -> None:
    ha, first, second = make_ha()
    set_levels(ha, 255, 255)
    assert await ha.get_serving_client([first, second], second) is second
    assert await ha.get_serving_client([first, second], None) is first


async def test_ha_min_active_seconds_prevents_flapping() -> None:
    """A Degraded server that was just chosen isn't replaced at once by another Degraded one."""
    ha, first, second = make_ha(min_active_seconds=10)
    set_levels(ha, 100, 150)
    ha._active_since = time.monotonic()
    assert await ha.get_serving_client([first, second], first) is first
    ha._active_since = time.monotonic() - 20
    assert await ha.get_serving_client([first, second], first) is second
    set_levels(ha, 100, 1)
    ha._active_since = time.monotonic()
    assert await ha.get_serving_client([first, second], second) is first


async def test_cli16_unknown_name_is_key_error_with_message_and_changes_nothing() -> None:
    ha, _, _ = make_ha()
    name = await ha.create_subscription(100, object())
    with pytest.raises(KeyError, match="no subscription named nope"):
        await ha.subscribe_data_change("nope", ["ns=2;i=1"])
    with pytest.raises(KeyError, match="nope"):
        await ha.delete_subscriptions([name, "nope"])
    assert name in ha.sub_names
    assert all(name in vsubs for vsubs in ha.ideal_map.values())
    await ha.delete_subscriptions([name])
    assert name not in ha.sub_names


def test_cli16_name_generator_raises_when_exhausted() -> None:
    ha, _, _ = make_ha()
    ha.sub_names.update(f"sub_{i}" for i in range(9999))
    with pytest.raises(RuntimeError, match="no free subscription name"):
        next(ha.generate_sub_name())


async def test_cli16_exhausted_names_raise_and_recover() -> None:
    ha, _, _ = make_ha()
    ha.sub_names.update(f"sub_{i}" for i in range(9999))
    with pytest.raises(RuntimeError):
        await ha.create_subscription(100, object())
    ha.sub_names.discard("sub_5")
    assert await ha.create_subscription(100, object()) == "sub_5"


async def test_cli16_ha_credentials_reach_every_client() -> None:
    security = HaSecurityConfig(username="operator", password="secret")
    ha = HaClient(make_config(), security)
    with (
        mock.patch.object(Client, "connect", new=mock.AsyncMock()),
        mock.patch.object(Client, "disconnect", new=mock.AsyncMock()),
    ):
        for client in list(ha.clients):
            await ha.reconnect(client)
    for client in ha.clients:
        assert client._username == "operator"
        assert client._password == "secret"


def test_ha_password_is_not_in_repr() -> None:
    assert "secret" not in repr(HaSecurityConfig(username="operator", password="secret"))


@pytest.mark.parametrize(
    "support,accepted",
    [
        (ua.RedundancySupport.Warm, True),
        (ua.RedundancySupport.Hot, True),
        (ua.RedundancySupport.HotAndMirrored, False),
        (ua.RedundancySupport.Cold, False),
        (ua.RedundancySupport.None_, False),
        (ua.RedundancySupport.Transparent, False),
        (None, True),
    ],
)
def test_cli52_hot_and_warm_accepted_hotandmirrored_refused(support: Any, accepted: bool) -> None:
    """Part 4, 6.6.2.4.5.1: the server's failover mode is compared with the client's."""
    assert redundancy_accepted(HaMode.WARM, support) is accepted


async def test_cli46_connected_degraded_standby_is_not_reset() -> None:
    """Part 4, 6.6.2.4.4: in Warm mode the standby is Degraded by design and must stay connected."""
    ha, first, second = make_ha()
    set_levels(ha, 255, 150)
    set_state(first, UaClientState.CONNECTED)
    set_state(second, UaClientState.CONNECTED)
    ha.reconnect = mock.AsyncMock()  # type: ignore[method-assign]
    await ha.manager.reconnect_warm()
    ha.reconnect.assert_not_called()


async def test_ha_disconnected_client_is_reset_once() -> None:
    ha, first, second = make_ha()
    set_levels(ha, 255, 255)
    set_state(first, UaClientState.CONNECTED)
    set_state(second, UaClientState.DISCONNECTED)
    ha.reconnect = mock.AsyncMock()  # type: ignore[method-assign]
    await ha.manager.reconnect_warm()
    ha.reconnect.assert_awaited_once_with(client=second)


async def test_ha_reconnecting_client_is_left_alone() -> None:
    ha, first, second = make_ha()
    set_state(first, UaClientState.RECONNECTING)
    set_state(second, UaClientState.CONNECTING)
    ha.reconnect = mock.AsyncMock()  # type: ignore[method-assign]
    await ha.manager.reconnect_warm()
    ha.reconnect.assert_not_called()


async def test_cli48_maintenance_server_is_disconnected_and_not_retried_before_the_return_time() -> None:
    """Part 4, 6.6.2.4.2: at ServiceLevel 0 clients disconnect and don't try again soon."""
    ha, first, second = make_ha(maintenance_retry_interval=300)
    set_levels(ha, 255, 0)
    infos = list(ha.clients.values())
    infos[1].retry_at = time.monotonic() + 300
    set_state(first, UaClientState.CONNECTED)
    set_state(second, UaClientState.CONNECTED)
    second.disconnect = mock.AsyncMock()  # type: ignore[method-assign]
    ha.reconnect = mock.AsyncMock()  # type: ignore[method-assign]
    await ha.manager.reconnect_warm()
    second.disconnect.assert_awaited_once()
    ha.reconnect.assert_not_called()
    set_state(second, UaClientState.DISCONNECTED)
    await ha.manager.reconnect_warm()
    ha.reconnect.assert_not_called()
    infos[1].retry_at = time.monotonic() - 1
    await ha.manager.reconnect_warm()
    ha.reconnect.assert_awaited_once_with(client=second)
    assert infos[1].retry_at is None


async def test_cli49_loops_survive_an_exception_in_a_step() -> None:
    """Part 4, 6.6.2.4: a failing step must not end the loop that does the failover."""
    ha, _, _ = make_ha()
    calls: list[int] = []

    async def failing_update() -> None:
        calls.append(1)
        if len(calls) == 1:
            raise KeyError("boom")

    ha.manager.update_state_warm = failing_update  # type: ignore[method-assign]
    ha.manager.reconnect_warm = mock.AsyncMock()  # type: ignore[method-assign]
    task = asyncio.create_task(ha.manager.run())
    await wait_until(lambda: len(calls) >= 2)
    assert len(calls) >= 2
    assert ha.manager.errors == 1
    await ha.manager.stop()
    await asyncio.wait_for(task, 1)

    steps: list[int] = []

    async def failing_reconciliate() -> None:
        steps.append(1)
        if len(steps) == 1:
            raise KeyError("boom")

    ha.reconciliator.reconciliate = failing_reconciliate  # type: ignore[method-assign]
    task = asyncio.create_task(ha.reconciliator.run())
    await wait_until(lambda: len(steps) >= 2)
    assert len(steps) >= 2
    assert ha.reconciliator.errors == 1
    await ha.reconciliator.stop()
    await asyncio.wait_for(task, 1)


def hanging_read(client: Client) -> None:
    async def read(nodes: Any) -> Any:
        await asyncio.sleep(100)

    client.read_values = read  # type: ignore[method-assign]


async def test_cli15_keepalive_stops_on_cancel() -> None:
    """Cancelling the probe ends it; it used to swallow the cancellation."""
    ha, first, _ = make_ha()
    set_state(first, UaClientState.CONNECTED)
    hanging_read(first)
    probe = KeepAlive(first, ha.clients[first], 5, probe_timeout=50)
    task = asyncio.create_task(probe.run())
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 1)


async def test_cli15_keepalive_waits_for_readiness_not_three_seconds() -> None:
    ha, first, _ = make_ha()
    set_state(first, UaClientState.CONNECTED)
    reads: list[int] = []

    async def read(nodes: Any) -> Any:
        reads.append(1)
        return [ua.ServerState.Running, 255]

    first.read_values = read  # type: ignore[method-assign]
    ready = asyncio.Event()
    probe = KeepAlive(first, ha.clients[first], 5, ready=ready)
    task = asyncio.create_task(probe.run())
    await asyncio.sleep(0.2)
    assert reads == []
    ready.set()
    await asyncio.sleep(0.2)
    assert reads == [1]
    assert ha.clients[first].status == 255
    await probe.stop()
    await asyncio.wait_for(task, 1)


async def test_probe_timeout_is_shorter_than_request_timeout() -> None:
    ha, first, _ = make_ha()
    set_state(first, UaClientState.CONNECTED)
    hanging_read(first)
    info = ha.clients[first]
    info.status = 255
    probe = KeepAlive(first, info, 5, probe_timeout=0.1)
    task = asyncio.create_task(probe.run())
    await wait_until(lambda: info.status == ConnectionStates.NO_DATA)
    assert info.status == ConnectionStates.NO_DATA
    await probe.stop()
    await asyncio.wait_for(task, 1)


async def test_ha_probe_without_connection_sends_nothing() -> None:
    ha, first, _ = make_ha()
    set_state(first, UaClientState.RECONNECTING)
    first.read_values = mock.AsyncMock()  # type: ignore[method-assign]
    info = ha.clients[first]
    info.status = 255
    probe = KeepAlive(first, info, 5)
    task = asyncio.create_task(probe.run())
    await asyncio.sleep(0.1)
    first.read_values.assert_not_called()
    assert info.status == ConnectionStates.NO_DATA
    await probe.stop()
    await asyncio.wait_for(task, 1)


async def test_ha_probe_change_triggers_the_manager_at_once() -> None:
    """A change of band wakes the manager instead of waiting for its timer."""
    ha, first, _ = make_ha(manager_timer=60)
    set_state(first, UaClientState.CONNECTED)
    levels = iter([255, 150] + [150] * 100)

    async def read(nodes: Any) -> Any:
        return [ua.ServerState.Running, next(levels)]

    first.read_values = read  # type: ignore[method-assign]
    woken: list[int] = []
    info = ha.clients[first]
    probe = KeepAlive(first, info, 0.05, on_change=lambda: woken.append(1))
    task = asyncio.create_task(probe.run())
    await wait_until(lambda: info.status == 150 and len(woken) == 2)
    assert info.status == 150
    assert len(woken) == 2
    await probe.stop()
    await asyncio.wait_for(task, 1)


async def test_cli50_failover_is_not_delayed_by_a_hung_reconciliation() -> None:
    """Part 4, 6.6.2.4.5.3: the reconciliator doesn't hold the ideal map lock while it waits for a server."""
    ha, first, second = make_ha()
    set_levels(ha, 255, 255)
    await ha.create_subscription(100, object())
    hang = asyncio.Event()

    async def hung(*args: Any, **kwargs: Any) -> None:
        await hang.wait()

    ha.reconciliator.update_subscriptions = hung  # type: ignore[method-assign]
    run = asyncio.create_task(ha.reconciliator.reconciliate())
    await asyncio.sleep(0.1)
    await asyncio.wait_for(ha.failover_warm(second, {first}), 0.5)
    await asyncio.wait_for(ha.create_subscription(100, object()), 0.5)
    hang.set()
    await asyncio.wait_for(run, 1)


async def test_ha_mi_request_hook_fires_once_per_change() -> None:
    """The metrics hook sees each change once with all its nodes, and nothing when no node changes."""
    from enginir_opcua.client.ha.reconciliator import Method
    from enginir_opcua.client.ha.virtual_subscription import NodeAttr, VirtualSubscription

    ha, _first, _second = make_ha(batch_mi_size=2)
    reconciliator = ha.reconciliator
    url = ha.urls[0]
    nodes = [f"ns=2;i={i}" for i in range(5)]
    real = VirtualSubscription(100, None, True, ua.MonitoringMode.Reporting)
    for node in nodes:
        real.nodes[node] = NodeAttr(ua.AttributeIds.Value, 0)
    ideal = VirtualSubscription(100, None, True, ua.MonitoringMode.Reporting)

    class FakeSubscription:
        async def unsubscribe(self, handles: Any) -> None:
            return None

    reconciliator.name_to_subscription[url]["sub"] = FakeSubscription()  # type: ignore[assignment]
    calls: list[dict[str, Any]] = []
    reconciliator.hook_mi_request = lambda **kwargs: calls.append(kwargs)  # type: ignore[method-assign]
    await reconciliator.update_nodes({url: {"sub": real}}, {url: {"sub": ideal}}, {url})
    assert [(call["action"], set(call["nodes"])) for call in calls] == [(Method.DEL_MI, set(nodes))]


async def test_ha_status_snapshot_and_failover_hook() -> None:
    ha, first, second = make_ha()
    set_levels(ha, 255, 150)
    events: list[tuple[str | None, str | None]] = []

    async def hook(old_url: str | None, new_url: str | None) -> None:
        events.append((old_url, new_url))

    ha.hook_on_failover = hook  # type: ignore[method-assign]
    await ha.failover_warm(first, {second})
    status = ha.status()
    assert status[0]["url"] == "opc.tcp://127.0.0.1:1"
    assert status[0]["active"] is True
    assert status[0]["band"] is ConnectionStates.HEALTHY
    assert status[1]["band"] is ConnectionStates.DEGRADED
    assert status[1]["active"] is False
    assert events == [(None, "opc.tcp://127.0.0.1:1")]


def test_ha_manager_and_server_info_defaults() -> None:
    ha, _, _ = make_ha()
    assert isinstance(ha.manager, HaManager)
    assert isinstance(ha.reconciliator, Reconciliator)
    assert isinstance(next(iter(ha.clients.values())), ServerInfo)
    config = HaConfig(HaMode.WARM, urls=["a", "b"])
    assert config.keepalive_timer == 5
    assert config.manager_timer == 5


async def test_cli83_quickstart_builds_clients_with_the_quick_setup_uri(tmp_path: Path) -> None:
    urls = ["opc.tcp://127.0.0.1:1/a/", "opc.tcp://127.0.0.1:2/b/"]
    ha = HaClient.quickstart(urls, pki=tmp_path / "pki", username="operator", password="secret", keepalive_timer=2)
    assert list(ha.config.urls) == urls
    assert ha.config.ha_mode is HaMode.WARM
    assert ha.config.keepalive_timer == 2
    for client in ha.get_clients():
        assert client.application_uri == default_application_uri("client")
        assert client._config is not None
        assert client._config.pki == tmp_path / "pki"
        assert client._config.policy_type() is ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt
    assert ha.security_config.username == "operator"


async def test_cli83_quickstart_takes_an_application_uri_and_client_settings(tmp_path: Path) -> None:
    ha = HaClient.quickstart(
        ["opc.tcp://127.0.0.1:1/", "opc.tcp://127.0.0.1:2/"],
        pki=tmp_path / "pki",
        application_uri="urn:example:ha-client",
        security="Aes256Sha256RsaPss,SignAndEncrypt",
    )
    for client in ha.get_clients():
        assert client.application_uri == "urn:example:ha-client"
        assert client._config is not None
        assert client._config.policy_type() is ua.SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt


def test_cli83_quickstart_refuses_unknown_settings_and_few_urls(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match=r"client\.colour: unknown setting"):
        HaClient.quickstart(["opc.tcp://127.0.0.1:1/", "opc.tcp://127.0.0.1:2/"], pki=tmp_path, colour="red")
    with pytest.raises(ValueError, match="at least two"):
        HaClient.quickstart(["opc.tcp://127.0.0.1:1/"], pki=tmp_path)


async def test_cli83_init_pki_creates_one_certificate_for_every_client(tmp_path: Path) -> None:
    ha = HaClient.quickstart(
        ["opc.tcp://127.0.0.1:1/", "opc.tcp://127.0.0.1:2/"], pki=tmp_path / "pki", application_uri="urn:ha:client"
    )
    certificate = await ha.init_pki()
    assert (tmp_path / "pki" / "own" / "certs" / pki.CERTIFICATE_NAME).exists()
    assert await ha.init_pki() == certificate
    with pytest.raises(ConfigurationError, match="init_pki"):
        await HaClient(make_config()).init_pki()


async def test_cli83_a_quickstart_ha_client_connects_to_two_secure_servers(tmp_path: Path) -> None:
    servers = []
    urls = []
    for name in ("first", "second"):
        url = f"opc.tcp://127.0.0.1:{find_free_port()}/ha/{name}/"
        server = Server.quickstart(url, pki=tmp_path / f"{name}-pki")
        await server.init()
        servers.append(server)
        urls.append(url)
    ha = HaClient.quickstart(
        urls,
        pki=tmp_path / "client-pki",
        keepalive_timer=0.2,
        manager_timer=0.2,
        reconciliator_timer=0.2,
        min_active_seconds=0.2,
    )
    certificate = await ha.init_pki()
    for name in ("first", "second"):
        (tmp_path / f"{name}-pki" / "trusted" / "certs" / "client.der").write_bytes(
            certificate.public_bytes(serialization.Encoding.DER)
        )
        shutil.copy(
            tmp_path / f"{name}-pki" / "own" / "certs" / pki.CERTIFICATE_NAME,
            tmp_path / "client-pki" / "trusted" / "certs" / f"{name}.der",
        )
    for server in servers:
        await server.start()
    try:
        await ha.start()
        await wait_until(lambda: ha.active_client is not None, timeout=30)
        assert ha.active_client is not None
        assert ha.active_client.security_policy.URI.endswith("Basic256Sha256")
    finally:
        await ha.stop()
        for server in servers:
            await server.stop()
