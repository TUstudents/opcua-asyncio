"""
The Reconciliator of the HaClient: it makes the Subscriptions on every server match the ideal map.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import astuple
from enum import Enum
from functools import partial
from typing import TYPE_CHECKING, Any

from sortedcontainers import SortedDict  # type: ignore

from enginir_opcua import Client, ua

from .common import ConnectionStates, batch, wait_any
from .virtual_subscription import VirtualSubscription

if TYPE_CHECKING:
    from enginir_opcua.common.subscription import Subscription

    from .ha_client import HaClient

_logger = logging.getLogger(__name__)

SubMap = dict[str, SortedDict]


class Method(Enum):
    """The actions of the Reconciliator, named by the method of Client or Subscription that performs them."""

    ADD_SUB = "create_subscription"
    ADD_MI = "subscribe_data_change"
    DEL_SUB = "delete"
    DEL_MI = "unsubscribe"
    MONITORING = "set_monitoring_mode"
    PUBLISHING = "set_publishing_mode"


class Reconciliator:
    """
    Reconciliator is a side-task of HaClient. It regularly
    applies the HaClient subscription configurations to actual
    OPC-UA objects.

    After a successful reconciliation and if all the client status
    are >= HEALTHY_STATE, the ideal_map is equal to the real_map.
    The hook methods (hook_mi_request and the others) are called on every change and do nothing; override them for metrics or external events.
    """

    BATCH_MI_SIZE = 1000

    def __init__(self, timer: float, ha_client: "HaClient") -> None:
        self.timer = timer
        self.ha_client = ha_client
        self.is_running = False
        self.errors = 0
        self.BATCH_MI_SIZE = ha_client._config.batch_mi_size
        self.stop_event = asyncio.Event()
        self.wake_event = asyncio.Event()
        self._url_tasks: dict[str, asyncio.Task[None]] = {}
        self.real_map: SubMap = {url: SortedDict() for url in self.ha_client.urls}
        self.name_to_subscription: defaultdict[str, dict[str, Subscription]] = defaultdict(dict)
        self.node_to_handle: defaultdict[str, dict[str, int]] = defaultdict(dict)

    def wake(self) -> None:
        """Reconcile now instead of at the next timer tick."""
        self.wake_event.set()

    async def run(self) -> None:
        """The reconciliation loop, until stop()."""
        _logger.info("Starting Reconciliator loop, checking every %.1fsec", self.timer)
        self.is_running = True
        while self.is_running:
            start = time.monotonic()
            try:
                async with self.ha_client._url_to_reset_lock:
                    await self.resubscribe()
                await self.reconciliate()
            except Exception:
                _logger.exception("Reconciliation failed")
                self.errors += 1
            _logger.debug("Reconciliation took %.2fsec", time.monotonic() - start)

            if await wait_any(self.timer, self.stop_event, self.wake_event):
                self.is_running = False
                break
        for task in self._url_tasks.values():
            task.cancel()
        await asyncio.gather(*self._url_tasks.values(), return_exceptions=True)
        self._url_tasks.clear()

    async def stop(self) -> None:
        """End the loop after the current pass."""
        self.stop_event.set()

    async def close_subscriptions(self, reason: str) -> None:
        """End the Subscription objects of every server locally, without calling the servers."""
        for subs in self.name_to_subscription.values():
            for sub in subs.values():
                sub.close(reason)
        self.name_to_subscription.clear()

    def refresh_handles(self, url: str) -> None:
        """Rebuild node_to_handle[url] from the current Subscription objects.

        Called after the underlying Client's auto-reconnect finishes restoring a
        session. TransferSubscriptions preserves server handles, but the recreate()
        fallback assigns new ones; we just refresh unconditionally so later
        unsubscribe calls use whatever the server now expects.
        """
        subs_for_url = self.name_to_subscription.get(url)
        if not subs_for_url:
            return
        handles = self.node_to_handle.setdefault(url, {})
        for sub_name, sub in subs_for_url.items():
            for mi in sub._monitored_items.values():
                if mi.node is None or mi.server_handle is None:
                    continue
                handles[mi.node.nodeid.to_string()] = mi.server_handle
            self._sync_modes(url, sub_name, sub)

    def _sync_modes(self, url: str, sub_name: str, sub: "Subscription") -> None:
        """Record the modes the Subscription really has, so that a difference to the ideal state is applied again."""
        real = self.real_map.get(url, {}).get(sub_name)
        if real is None:
            return
        real.publishing = sub.parameters.PublishingEnabled
        modes = {mi.monitoring_mode for mi in sub._monitored_items.values()}
        if len(modes) == 1:
            real.monitoring = modes.pop()

    async def resubscribe(self) -> None:
        """
        Remove all the subscriptions from the real_map.

        Deleting them from the remote server would be
        helpless because they are tied to a deleted session,
        however they should eventually time out.
        """
        _logger.debug("In resubscribe")
        url_to_reset = self.ha_client.url_to_reset
        while url_to_reset:
            url = url_to_reset.pop()
            self.real_map[url].clear()
            for sub in self.name_to_subscription.pop(url, {}).values():
                sub.close("HaClient reset the connection")
            self.node_to_handle.pop(url, None)

    async def reconciliate(self) -> None:
        """
        Identify the differences between the ideal and the real_map
        and take actual actions on the underlying OPC-UA objects.

        The ideal map is copied under its lock and the lock is released before any request goes out, so a slow
        or dead server never holds up the application or a failover. Each server is reconciled by its own task;
        a task that is still waiting for its server is left alone until it ends.

        Reconciliator steps are ordered this way:

          1 - Resubscribe newly reconnected clients
          2 - Identify gap with healthy client configurations
          3 - Remove/Add subscription
          4 - Add nodes to subscriptions
          5 - Update publishing/monitoring options
        """
        async with self.ha_client._ideal_map_lock:
            ideal_map = {
                url: SortedDict(
                    {
                        name: VirtualSubscription(
                            vs.period, vs.handler, vs.publishing, vs.monitoring, SortedDict(vs.nodes)
                        )
                        for name, vs in subs.items()
                    }
                )
                for url, subs in self.ha_client.ideal_map.items()
            }
        async with self.ha_client._client_lock:
            valid_urls = [
                info.url
                for client, info in self.ha_client.clients.items()
                if info.status >= ConnectionStates.DEGRADED and info.redundancy_ok is not False
            ]
        active = self.ha_client.active_client
        active_url = active.server_url.geturl() if active is not None else None
        valid_urls.sort(key=lambda url: url != active_url)
        real_map = self.real_map
        targets = [url for url in valid_urls if ideal_map[url] != real_map[url]]
        if not targets:
            _logger.debug("No configuration difference for the connected servers %s", valid_urls)
            return
        _logger.info("Configuration difference found for %s", targets)
        started = []
        for url in targets:
            running = self._url_tasks.get(url)
            if running is not None and not running.done():
                continue
            task = asyncio.create_task(self._reconcile_url(url, real_map, ideal_map))
            self._url_tasks[url] = task
            started.append(task)
        if started:
            await asyncio.wait(started, timeout=self.timer)

    async def _reconcile_url(self, url: str, real_map: SubMap, ideal_map: SubMap) -> None:
        targets = {url}
        await self.update_subscriptions(real_map, ideal_map, targets)
        await self.update_nodes(real_map, ideal_map, targets)
        await self.update_subscription_modes(real_map, ideal_map, targets)

    async def update_subscriptions(self, real_map: SubMap, ideal_map: SubMap, targets: set[str]) -> None:
        """Create the Subscriptions the ideal map has and delete those it no longer has."""
        tasks: list[asyncio.Task[Any]] = []
        for url in targets:
            tasks.extend(self._subs_to_del(url, real_map, ideal_map))
            tasks.extend(self._subs_to_add(url, real_map, ideal_map))
        await asyncio.gather(*tasks, return_exceptions=True)

    def _subs_to_del(self, url: str, real_map: SubMap, ideal_map: SubMap) -> list[asyncio.Task[Any]]:
        to_del: list[asyncio.Task[Any]] = []
        sub_to_del = set(real_map[url]) - set(ideal_map[url])
        if sub_to_del:
            _logger.info("Removing %d subscriptions", len(sub_to_del))
        for sub_name in sub_to_del:
            sub_handle = self.name_to_subscription[url][sub_name]
            task = asyncio.create_task(sub_handle.delete())
            task.add_done_callback(partial(self.del_from_map, url, Method.DEL_SUB, sub_name=sub_name))
            to_del.append(task)
        return to_del

    def _subs_to_add(self, url: str, real_map: SubMap, ideal_map: SubMap) -> list[asyncio.Task[Any]]:
        to_add: list[asyncio.Task[Any]] = []
        sub_to_add = set(ideal_map[url]) - set(real_map[url])
        if sub_to_add:
            _logger.info("Adding %d subscriptions", len(sub_to_add))
        client = self.ha_client.get_client_by_url(url)
        for sub_name in sub_to_add:
            vs = ideal_map[url][sub_name]
            task = asyncio.create_task(client.create_subscription(vs.period, vs.handler, publishing=vs.publishing))
            task.add_done_callback(
                partial(
                    self.add_to_map,
                    url,
                    Method.ADD_SUB,
                    period=vs.period,
                    handler=vs.handler,
                    publishing=vs.publishing,
                    monitoring=vs.monitoring,
                    sub_name=sub_name,
                )
            )
            to_add.append(task)
        return to_add

    async def update_nodes(self, real_map: SubMap, ideal_map: SubMap, targets: set[str]) -> None:
        """Add and remove the MonitoredItems of the Subscriptions that both maps have."""
        tasks: list[asyncio.Task[Any]] = []
        for url in targets:
            client = self.ha_client.get_client_by_url(url)
            for sub_name in ideal_map[url]:
                real_sub = self.name_to_subscription[url].get(sub_name)
                if not real_sub:
                    _logger.warning(
                        "Can't create nodes for %s since underlying subscription for %s doesn't exist", url, sub_name
                    )
                    continue
                vs_real = real_map[url][sub_name]
                vs_ideal = ideal_map[url][sub_name]
                tasks.extend(self._nodes_to_del(url, sub_name, real_sub, vs_real, vs_ideal))
                tasks.extend(self._nodes_to_add(url, sub_name, real_sub, client, vs_real, vs_ideal))
        await asyncio.gather(*tasks, return_exceptions=True)

    def _nodes_to_add(
        self,
        url: str,
        sub_name: str,
        real_sub: "Subscription",
        client: Client,
        vs_real: VirtualSubscription,
        vs_ideal: VirtualSubscription,
    ) -> list[asyncio.Task[Any]]:
        tasks: list[asyncio.Task[Any]] = []
        monitoring = vs_real.monitoring
        node_to_add = set(vs_ideal.nodes) - set(vs_real.nodes)
        if not node_to_add:
            return tasks
        _logger.info("Adding %d Nodes", len(node_to_add))
        attr_to_nodes: defaultdict[Any, list[Any]] = defaultdict(list)
        for node in node_to_add:
            attr_to_nodes[vs_ideal.nodes[node]].append(client.get_node(node))
        for node_attr, nodes_obj in attr_to_nodes.items():
            for batch_nodes_obj in batch(nodes_obj, self.BATCH_MI_SIZE):
                attr, queuesize = astuple(node_attr)
                task = asyncio.create_task(
                    real_sub.subscribe_data_change(batch_nodes_obj, attr, queuesize, monitoring=monitoring)
                )
                nodes = [n.nodeid.to_string() for n in batch_nodes_obj]
                task.add_done_callback(
                    partial(
                        self.add_to_map,
                        url,
                        Method.ADD_MI,
                        sub_name=sub_name,
                        nodes=nodes,
                        node_attr=node_attr,
                        monitoring=monitoring,
                    )
                )
                tasks.append(task)
        self.hook_mi_request(url=url, sub_name=sub_name, nodes=node_to_add, action=Method.ADD_MI)
        return tasks

    def _nodes_to_del(
        self,
        url: str,
        sub_name: str,
        real_sub: "Subscription",
        vs_real: VirtualSubscription,
        vs_ideal: VirtualSubscription,
    ) -> list[asyncio.Task[Any]]:
        to_del: list[asyncio.Task[Any]] = []
        node_to_del = set(vs_real.nodes) - set(vs_ideal.nodes)
        if node_to_del:
            _logger.info("Removing %d Nodes", len(node_to_del))
            for batch_nodes in batch(node_to_del, self.BATCH_MI_SIZE):
                node_handles = [
                    self.node_to_handle[url][node] for node in batch_nodes if node in self.node_to_handle[url]
                ]
                task = asyncio.create_task(real_sub.unsubscribe(node_handles))
                task.add_done_callback(
                    partial(
                        self.del_from_map,
                        url,
                        Method.DEL_MI,
                        sub_name=sub_name,
                        nodes=batch_nodes,
                    )
                )
                to_del.append(task)
            self.hook_mi_request(url=url, sub_name=sub_name, nodes=node_to_del, action=Method.DEL_MI)
        return to_del

    async def update_subscription_modes(self, real_map: SubMap, ideal_map: SubMap, targets: set[str]) -> None:
        """Apply the publishing and monitoring modes of the ideal map to the Subscriptions."""
        modes = [Method.MONITORING, Method.PUBLISHING]
        methods = [n.value for n in modes]
        tasks: list[asyncio.Task[Any]] = []
        for url in targets:
            for sub_name in real_map[url]:
                real_sub = self.name_to_subscription[url].get(sub_name)
                if not real_sub:
                    _logger.warning(
                        "Can't change modes for %s since underlying subscription for %s doesn't exist", url, sub_name
                    )
                    continue
                vs_real = real_map[url][sub_name]
                vs_ideal = ideal_map[url][sub_name]
                for action, func in zip(modes, methods):
                    attr = action.name.lower()
                    ideal_val = getattr(vs_ideal, attr)
                    real_val = getattr(vs_real, attr)
                    if ideal_val != real_val:
                        _logger.info("Changing %s for %s to %s", attr, sub_name, ideal_val)
                        set_func = getattr(real_sub, func)
                        task = asyncio.create_task(set_func(ideal_val))
                        task.add_done_callback(
                            partial(
                                self.change_mode,
                                url,
                                action,
                                ideal_val,
                                sub_name=sub_name,
                            )
                        )
                        tasks.append(task)
        await asyncio.gather(*tasks, return_exceptions=True)

    def change_mode(
        self,
        url: str,
        action: Method,
        val: bool | ua.MonitoringMode,
        fut: asyncio.Task[Any],
        **kwargs: Any,
    ) -> None:
        """Done callback of a mode change: record the new mode in the real map if the request succeeded."""
        if fut.cancelled() or fut.exception():
            _logger.warning(
                "Can't %s on %s: %s", action.value, url, fut.exception() if not fut.cancelled() else "cancelled"
            )
            return
        vs = self.real_map[url].get(kwargs["sub_name"])
        if vs is not None:
            setattr(vs, action.name.lower(), val)

    def add_to_map(self, url: str, action: Method, fut: asyncio.Task[Any], **kwargs: Any) -> None:
        """Done callback of an addition: record the Subscription or the MonitoredItems in the real map."""
        if fut.cancelled() or fut.exception():
            _logger.warning(
                "Can't %s on %s: %s", action.value, url, fut.exception() if not fut.cancelled() else "cancelled"
            )
            self._call_hook(self.hook_add_to_map_error, url=url, action=action, fut=fut, **kwargs)
            return

        sub_name = kwargs.pop("sub_name")
        if action == Method.ADD_SUB:
            vs = VirtualSubscription(**kwargs)
            self.real_map[url][sub_name] = vs
            self.name_to_subscription[url][sub_name] = fut.result()

        if action == Method.ADD_MI:
            nodes = kwargs["nodes"]
            vs = self.real_map[url].get(sub_name)
            if vs is None:
                return
            vs.subscribe_data_change(nodes, *astuple(kwargs["node_attr"]))
            for node, handle in zip(nodes, fut.result()):
                if isinstance(handle, ua.StatusCode):
                    vs.unsubscribe([node])
                    _logger.info("Node %s subscription failed: %s", node, handle)
                    if handle.value == ua.StatusCodes.BadNodeIdUnknown:
                        _logger.warning("Abandoning %s because it returned %s from %s", node, handle, url)
                        ideal_vs = self.ha_client.ideal_map[url].get(sub_name)
                        if ideal_vs is not None:
                            ideal_vs.unsubscribe([node])
                    continue
                self.node_to_handle[url][node] = handle
        self._call_hook(self.hook_add_to_map, fut=fut, url=url, action=action, **kwargs)

    def del_from_map(self, url: str, action: Method, fut: asyncio.Task[Any], **kwargs: Any) -> None:
        """Done callback of a removal: forget the Subscription or the MonitoredItems, also when the request failed."""
        if fut.cancelled() or fut.exception():
            _logger.warning(
                "Can't %s on %s: %s", action.value, url, fut.exception() if not fut.cancelled() else "cancelled"
            )
        sub_name = kwargs["sub_name"]

        if action == Method.DEL_SUB:
            self.real_map[url].pop(sub_name, None)
            self.name_to_subscription[url].pop(sub_name, None)

        if action == Method.DEL_MI:
            nodes = kwargs["nodes"]
            vs = self.real_map[url].get(sub_name)
            if vs is not None:
                vs.unsubscribe(nodes)
            for node in nodes:
                self.node_to_handle[url].pop(node, None)
        self._call_hook(self.hook_del_from_map, fut=fut, url=url, action=action, **kwargs)

    @staticmethod
    def _call_hook(hook: Callable[..., None], **kwargs: Any) -> None:
        try:
            hook(**kwargs)
        except Exception:
            _logger.exception("Reconciliator hook raised")

    async def debug_status(self) -> None:
        """
        Log the size of the maps for troubleshooting purposes
        """
        _logger.debug(
            "real_map=%s name_to_subscription=%s node_to_handle=%s",
            {url: list(subs) for url, subs in self.real_map.items()},
            {url: list(subs) for url, subs in self.name_to_subscription.items()},
            {url: len(nodes) for url, nodes in self.node_to_handle.items()},
        )

    def hook_mi_request(self, url: str, sub_name: str, nodes: set[str], action: Method) -> None:
        """Called once per change of the MonitoredItems of a Subscription, with the NodeIds (as text) it adds or removes."""

    def hook_add_to_map_error(self, url: str, action: Method, fut: asyncio.Task[Any], **kwargs: Any) -> None:
        """Called when an addition failed; fut holds the exception."""

    def hook_add_to_map(self, fut: asyncio.Task[Any], url: str, action: Method, **kwargs: Any) -> None:
        """Called after an addition was recorded in the real map."""

    def hook_del_from_map(self, fut: asyncio.Task[Any], url: str, **kwargs: Any) -> None:
        """Called after a removal was recorded in the real map."""
