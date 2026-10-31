"""
Subscriptions and MonitoredItems (OPC 10000-4 v1.05, 5.13 and 5.14) for clients and for a server's own session:
creating them, receiving their notifications in order through a handler or an async iterator, and keeping them
alive across reconnects (TransferSubscriptions, Republish or re-creation).
"""

from __future__ import annotations

import asyncio
import collections
import collections.abc
import inspect
import logging
import math
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol, cast, overload

from enginir_opcua import ua
from enginir_opcua.common.ua_utils import copy_dataclass_attr
from enginir_opcua.common.utils import ServiceError
from enginir_opcua.observer import NULL_OBSERVER, Observer, SubscriptionEvent
from enginir_opcua.ua.uaerrors import BadMessageNotAvailable, BadSubscriptionIdInvalid

if TYPE_CHECKING:
    from enginir_opcua.client.ua_session import UaSession
    from enginir_opcua.server.internal_session import InternalSession

from .conditions import condition_refresh2
from .events import Event, get_filter_from_event_type
from .node import Node

_logger = logging.getLogger(__name__)


class SubscriptionItemData:
    """
    To store useful data from a monitored item.

    The queuesize / monitoring_mode / sampling_interval fields are captured so the
    Subscription can be re-created on the server after a reconnect.
    """

    def __init__(self) -> None:
        self.node: Node | None = None
        self.client_handle: int | None = None
        self.server_handle: int | None = None
        self.attribute: ua.AttributeIds | None = None
        self.mfilter: ua.MonitoringFilter | ua.EventFilter | None = None
        self.queuesize: int = 0
        self.monitoring_mode: ua.MonitoringMode = ua.MonitoringMode.Reporting
        self.sampling_interval: ua.Duration = 0.0
        self.discard_oldest: bool = True
        self.timestamps: ua.TimestampsToReturn = ua.TimestampsToReturn.Both
        self.revised_sampling_interval: ua.Duration | None = None
        self.revised_queuesize: int | None = None
        self.filter_result: Any = None


class DataChangeNotif:
    """The MonitoredItemNotification of one data change, with the data of the item it belongs to."""

    def __init__(self, subscription_data: SubscriptionItemData, monitored_item: ua.MonitoredItemNotification) -> None:
        self.monitored_item = monitored_item
        self.subscription_data = subscription_data

    def __str__(self) -> str:
        return f"DataChangeNotification({self.subscription_data}, {self.monitored_item})"

    __repr__ = __str__


class DataChangeNotificationHandler(Protocol):
    def datachange_notification(self, node: Node, val: Any, data: DataChangeNotif) -> None:
        """
        called for every datachange notification from server
        """
        ...


class EventNotificationHandler(Protocol):
    def event_notification(self, event: Event) -> None:
        """
        called for every event notification from server
        """
        ...


class StatusChangeNotificationHandler(Protocol):
    def status_change_notification(self, status: ua.StatusChangeNotification) -> None:
        """
        called for every status change notification from server
        """
        ...


class DataChangeNotificationHandlerAsync(Protocol):
    async def datachange_notification(self, node: Node, val: Any, data: DataChangeNotif) -> None:
        """
        called for every datachange notification from server
        """
        ...


class EventNotificationHandlerAsync(Protocol):
    async def event_notification(self, event: Event) -> None:
        """
        called for every event notification from server
        """
        ...


class StatusChangeNotificationHandlerAsync(Protocol):
    async def status_change_notification(self, status: ua.StatusChangeNotification) -> None:
        """
        called for every status change notification from server
        """
        ...


SubscriptionHandler = (
    DataChangeNotificationHandler
    | EventNotificationHandler
    | StatusChangeNotificationHandler
    | DataChangeNotificationHandlerAsync
    | EventNotificationHandlerAsync
    | StatusChangeNotificationHandlerAsync
)


@dataclass(frozen=True)
class DataChangeEvent:
    """A single monitored-item data change, yielded by Subscription's async iterator.

    `replayed` is True when the event was retrieved via `Republish` after a reconnect:
    its `SourceTimestamp` may predate values the application learned through other
    channels during the disconnect window. Apps that cache values should compare
    timestamps before overwriting.
    """

    node: Node
    value: Any
    data: DataChangeNotif
    replayed: bool = False


@dataclass(frozen=True)
class OpcEvent:
    """An OPC UA event firing, yielded by Subscription's async iterator."""

    event: Event
    replayed: bool = False


@dataclass(frozen=True)
class StatusChangeEvent:
    """A server-side subscription status change, yielded by Subscription's async iterator.

    `notification.Status` is the `StatusCode`; `notification.DiagnosticInfo` carries the
    server's diagnostic data when available.
    """

    notification: ua.StatusChangeNotification
    replayed: bool = False


SubEvent = DataChangeEvent | OpcEvent | StatusChangeEvent


@dataclass(frozen=True)
class RevisedParameters:
    """The values the server agreed to for a Subscription (OPC 10000-4 v1.05, 5.14.2.2)."""

    publishing_interval: float
    lifetime_count: int
    max_keep_alive_count: int


def keep_alive_count_for(period: float, keep_alive_seconds: float) -> int:
    """The MaxKeepAliveCount for a keep-alive about every keep_alive_seconds at this publishing interval (ms)."""
    nominal = period if period > 0 else 1000.0
    return max(1, math.ceil(keep_alive_seconds * 1000 / nominal))


def lifetime_count_for(period: float, lifetime_seconds: float, keep_alive_count: int) -> int:
    """The LifetimeCount for about lifetime_seconds, at least three keep-alive counts (OPC 10000-4 v1.05, 5.14.2.2)."""
    nominal = period if period > 0 else 1000.0
    return max(3 * keep_alive_count, math.ceil(lifetime_seconds * 1000 / nominal))


def subscription_parameters(
    period: float,
    publishing: bool = True,
    *,
    keep_alive_seconds: float = 10.0,
    lifetime_seconds: float = 300.0,
    keep_alive_count: int | None = None,
    lifetime_count: int | None = None,
    session_timeout: float | None = None,
) -> ua.CreateSubscriptionParameters:
    """
    Build the parameters of CreateSubscription. The counts follow from times, not from the Session timeout, so a
    keep-alive arrives about every `keep_alive_seconds` whatever the interval, and the lifetime is at least three
    times the keep-alive (OPC 10000-4 v1.05, 5.14.2.2). `session_timeout` in milliseconds limits the keep-alive to a
    quarter of it.
    :raises ValueError: for explicit counts whose lifetime is below three keep-alives
    """
    if session_timeout:
        keep_alive_seconds = min(keep_alive_seconds, session_timeout / 4000.0)
    keep_alive = keep_alive_count if keep_alive_count is not None else keep_alive_count_for(period, keep_alive_seconds)
    lifetime = (
        lifetime_count if lifetime_count is not None else lifetime_count_for(period, lifetime_seconds, keep_alive)
    )
    if lifetime < 3 * keep_alive:
        raise ValueError(f"lifetime count {lifetime} must be at least three times the keep-alive count {keep_alive}")
    params = ua.CreateSubscriptionParameters()
    params.RequestedPublishingInterval = period if period > 0 else 0
    params.RequestedLifetimeCount = lifetime
    params.RequestedMaxKeepAliveCount = keep_alive
    params.MaxNotificationsPerPublish = 0
    params.PublishingEnabled = publishing
    params.Priority = 0
    return params


class SubscriptionState(Enum):
    """
    The client's view of a Subscription: NEW before CreateSubscription, ACTIVE, SUSPENDED while the server shuts
    down, LOST after a Bad_Timeout status change, TRANSFERRED to another session, DELETED.
    """

    NEW = "new"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    LOST = "lost"
    TRANSFERRED = "transferred"
    DELETED = "deleted"


SEQUENCE_MASK = 0xFFFFFFFF
SEQUENCE_HALF = 0x80000000
WARNING_INTERVAL = 10.0


def next_sequence_number(number: int) -> int:
    """The SequenceNumber after number; it wraps from 4294967295 to 1 (OPC 10000-4 v1.05, 5.14.1.1)."""
    return 1 if number >= SEQUENCE_MASK else number + 1


def sequence_distance(start: int, end: int) -> int:
    """How many SequenceNumbers lie from start up to end, across the wrap."""
    return (end - start) & SEQUENCE_MASK


def sequence_is_ahead(number: int, expected: int) -> bool:
    """Whether number comes after expected, less than half the number space later."""
    return number != expected and sequence_distance(expected, number) < SEQUENCE_HALF


class Subscription:
    """
    A Subscription of a Client or Server, made with create_subscription. Notifications go to the handler if one is
    given, else to an async iterator (`async for event in subscription`). subscribe_data_change and
    subscribe_events add MonitoredItems; create_monitored_items gives full control.
    :param server: the session the Subscription lives in: `UaSession` or `InternalSession`
    """

    def __init__(
        self,
        server: InternalSession | UaSession,
        params: ua.CreateSubscriptionParameters,
        handler: SubscriptionHandler | None = None,
        *,
        queue_maxsize: int = 1000,
        inbox_maxsize: int = 1000,
        max_republish: int = 100,
        republish_missing: bool = True,
        delivered_window: int = 1024,
    ) -> None:
        self.logger = logging.getLogger(__name__)
        self.server: InternalSession | UaSession = server
        self._client_handle = 200
        self._handler: SubscriptionHandler | None = handler
        self._handler_methods: dict[str, Callable[..., Any] | None] = {}
        self._event_queue: asyncio.Queue[SubEvent | None] | None = (
            None if handler is not None else asyncio.Queue(maxsize=queue_maxsize)
        )
        self._queue_maxsize = queue_maxsize
        self.inbox_maxsize = inbox_maxsize
        self.max_republish = max_republish
        self.republish_missing = republish_missing
        self.parameters: ua.CreateSubscriptionParameters = params
        self._monitored_items: dict[int, SubscriptionItemData] = {}
        self._recreate_count: int = 0
        self.subscription_id: int | None = None
        self.state: SubscriptionState = SubscriptionState.NEW
        self.last_publish_at: float | None = None
        self.last_sequence_number: int | None = None
        self.revised: RevisedParameters | None = None
        self.max_keep_alive_seconds: float = 60.0
        self.min_stale_seconds: float = 1.0
        self._created_at: float = time.monotonic()
        self._inbox: collections.deque[tuple[ua.PublishResult, bool]] = collections.deque()
        self._delivery_task: asyncio.Task[None] | None = None
        self._process_lock = asyncio.Lock()
        self._expected: int | None = None
        self._delivered_window = delivered_window
        self._delivered: collections.deque[int] = collections.deque()
        self._delivered_set: set[int] = set()
        self._last_warning: dict[str, float] = {}
        self.dropped_messages: int = 0
        self.dropped_events: int = 0
        self.unknown_handle_notifications: int = 0
        self.unmatched_events: int = 0
        self.duplicates: int = 0
        self.lost_messages: int = 0
        self.failed_items: list[tuple[int, ua.StatusCode]] = []

    @property
    def _remote(self) -> bool:
        return hasattr(self.server, "update_subscription")

    def _remote_session(self, operation: str) -> UaSession:
        if not self._remote:
            raise ua.uaerrors.UaError(f"{operation}() is not supported in {self.server}.")
        return cast("UaSession", self.server)

    @property
    def is_deleted(self) -> bool:
        """True once the Subscription was deleted or closed."""
        return self.state is SubscriptionState.DELETED

    @property
    def _observer(self) -> Observer:
        return getattr(self.server, "observer", NULL_OBSERVER)

    def _observe(self, hook: Callable[[], None]) -> None:
        try:
            hook()
        except Exception:
            self.logger.exception("observer raised")

    def _warn_limited(self, key: str, message: str, *args: Any) -> None:
        now = time.monotonic()
        if now - self._last_warning.get(key, -WARNING_INTERVAL) >= WARNING_INTERVAL:
            self._last_warning[key] = now
            self.logger.warning(message, *args)

    async def init(self) -> ua.CreateSubscriptionResult:
        """CreateSubscription on the server; Client.create_subscription and Server.create_subscription call it."""
        return await self._create(SubscriptionEvent.CREATED)

    async def _create(self, event: SubscriptionEvent) -> ua.CreateSubscriptionResult:
        if self._remote:
            response = await cast("UaSession", self.server).create_subscription(self.parameters, callback=self)
        else:
            response = await self.server.create_subscription(self.parameters, callback=self.publish_callback)
        self.subscription_id = response.SubscriptionId
        self._created_at = time.monotonic()
        self.last_publish_at = None
        self.state = SubscriptionState.ACTIVE
        self.revised = RevisedParameters(
            response.RevisedPublishingInterval, response.RevisedLifetimeCount, response.RevisedMaxKeepAliveCount
        )
        self.logger.info("Subscription created %s", self.subscription_id)
        self._observe(lambda: self._observer.on_subscription_event(self.subscription_id, event))
        await self._correct_revised_values()
        return response

    async def _correct_revised_values(self) -> None:
        revised = self.revised
        if revised is None or not self._remote:
            return
        keep_alive_seconds = revised.publishing_interval * revised.max_keep_alive_count / 1000.0
        if (
            keep_alive_seconds <= self.max_keep_alive_seconds
            and revised.lifetime_count >= 3 * revised.max_keep_alive_count
        ):
            return
        keep_alive = keep_alive_count_for(revised.publishing_interval, 10.0)
        params = ua.ModifySubscriptionParameters()
        copy_dataclass_attr(self.parameters, params)
        params.SubscriptionId = self.subscription_id
        params.RequestedPublishingInterval = revised.publishing_interval
        params.RequestedMaxKeepAliveCount = keep_alive
        params.RequestedLifetimeCount = lifetime_count_for(revised.publishing_interval, 300.0, keep_alive)
        self.logger.info("Subscription %s: correcting the revised counts once", self.subscription_id)
        await self.update(params)

    async def update(self, params: ua.ModifySubscriptionParameters) -> ua.ModifySubscriptionResult:
        """ModifySubscription (client only); a LifetimeCount below three keep-alive counts is raised to that."""
        session = self._remote_session("update")
        if params.RequestedLifetimeCount < 3 * params.RequestedMaxKeepAliveCount:
            params.RequestedLifetimeCount = 3 * params.RequestedMaxKeepAliveCount
        response = await session.update_subscription(params)
        self.logger.info("Subscription updated %s", params.SubscriptionId)
        copy_dataclass_attr(params, self.parameters)
        self.revised = RevisedParameters(
            response.RevisedPublishingInterval, response.RevisedLifetimeCount, response.RevisedMaxKeepAliveCount
        )
        return response

    def _register_sink(self, subscription_id: int) -> None:
        if self._remote:
            cast("UaSession", self.server).register_sink(subscription_id, self)

    def _unregister_sink(self, subscription_id: int | None) -> None:
        if subscription_id is not None and self._remote:
            cast("UaSession", self.server).unregister_sink(subscription_id)

    def _acknowledge(self, sequence_number: int) -> None:
        if self._remote and self.subscription_id is not None:
            cast("UaSession", self.server).acknowledge(self.subscription_id, sequence_number)

    async def publish_callback(self, publish_result: ua.PublishResult) -> None:
        """
        Compatibility entry of the publish pipeline: hands the result to `enqueue`.
        """
        self.enqueue(publish_result)

    def enqueue(self, publish_result: ua.PublishResult, replayed: bool = False) -> None:
        """
        Accept a `PublishResult` from the publish pipeline. Never blocks and never raises: the result goes into the
        inbox of this Subscription, and its own delivery task translates and delivers it.
        """
        try:
            if self.state in (SubscriptionState.DELETED, SubscriptionState.TRANSFERRED):
                return
            self.last_publish_at = time.monotonic()
            if self.state is SubscriptionState.SUSPENDED:
                self.state = SubscriptionState.ACTIVE
            self._inbox.append((publish_result, replayed))
            if len(self._inbox) > self.inbox_maxsize:
                self._inbox.popleft()
                self.dropped_messages += 1
                self._observe(lambda: self._observer.on_messages_dropped(self.subscription_id, 1))
                self._warn_limited(
                    "inbox",
                    "Subscription %s: inbox full, dropped the oldest message (%s dropped so far)",
                    self.subscription_id,
                    self.dropped_messages,
                )
            self._ensure_delivery_task()
        except Exception:
            self.logger.exception("enqueue failed")

    def session_event(self, status: ua.StatusCode) -> None:
        """A status of the session, delivered like a StatusChangeNotification; Bad_Shutdown suspends."""
        if status.value == ua.StatusCodes.BadShutdown and self.state is SubscriptionState.ACTIVE:
            self.state = SubscriptionState.SUSPENDED
        message = ua.NotificationMessage(NotificationData=[ua.StatusChangeNotification(Status=status)])  # type: ignore[list-item]
        self.enqueue(ua.PublishResult(self.subscription_id or 0, NotificationMessage=message))

    def _ensure_delivery_task(self) -> None:
        if self._delivery_task is None or self._delivery_task.done():
            self._delivery_task = asyncio.get_running_loop().create_task(self._delivery_loop())

    async def _delivery_loop(self) -> None:
        while self._inbox:
            publish_result, replayed = self._inbox.popleft()
            try:
                async with self._process_lock:
                    await self._process(publish_result, replayed)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.exception("Exception processing a publish result of subscription %s", self.subscription_id)

    async def _process(self, publish_result: ua.PublishResult, replayed: bool) -> None:
        notification_message = publish_result.NotificationMessage
        number = int(notification_message.SequenceNumber)
        data = notification_message.NotificationData
        if number == 0 or not self._remote:
            await self._deliver_message(notification_message, replayed)
            return
        available = list(publish_result.AvailableSequenceNumbers or [])
        if not data:
            if self._expected is not None and sequence_is_ahead(number, self._expected):
                await self._fill_gap(self._expected, number, available)
            self._observe(lambda: self._observer.on_notification(self.subscription_id, 0))
            return
        if self._expected is None or number == self._expected:
            pass
        elif sequence_is_ahead(number, self._expected):
            await self._fill_gap(self._expected, number, available)
        elif number in self._delivered_set:
            self.duplicates += 1
            return
        await self._accept(number, notification_message, replayed)

    async def _accept(self, number: int, notification_message: ua.NotificationMessage, replayed: bool) -> None:
        if self._expected is None or number == self._expected or sequence_is_ahead(number, self._expected):
            self._expected = next_sequence_number(number)
        self._delivered.append(number)
        self._delivered_set.add(number)
        if len(self._delivered) > self._delivered_window:
            self._delivered_set.discard(self._delivered.popleft())
        self.last_sequence_number = number
        await self._deliver_message(notification_message, replayed)

    async def _fill_gap(self, start: int, end: int, available: list[int]) -> None:
        distance = sequence_distance(start, end)
        candidates = sorted(
            {n for n in available if sequence_distance(start, n) < distance}, key=lambda n: sequence_distance(start, n)
        )
        fetched = 0
        if self.republish_missing and self.subscription_id is not None:
            for number in candidates[: self.max_republish]:
                try:
                    fetched_message = await cast("UaSession", self.server).republish(self.subscription_id, number)
                except BadMessageNotAvailable:
                    continue
                except Exception:
                    self.logger.warning(
                        "republish failed for sub %s seq %s", self.subscription_id, number, exc_info=True
                    )
                    continue
                if not fetched_message.NotificationData:
                    continue
                self._acknowledge(number)
                self._delivered.append(number)
                self._delivered_set.add(number)
                if len(self._delivered) > self._delivered_window:
                    self._delivered_set.discard(self._delivered.popleft())
                await self._deliver_message(fetched_message, True)
                fetched += 1
        lost = distance - fetched
        self._expected = end
        if lost:
            self.lost_messages += lost
            self.logger.warning("Subscription %s: %s notification messages were lost", self.subscription_id, lost)
            self._observe(lambda: self._observer.on_messages_lost(self.subscription_id, lost))

    async def _deliver_message(self, notification_message: ua.NotificationMessage, replayed: bool) -> None:
        notification_data = notification_message.NotificationData
        if notification_data is None:
            return
        produced = 0
        for event in self._explode_notifications(notification_data, replayed):
            await self._deliver(event)
            produced += 1
            if isinstance(event, StatusChangeEvent):
                self._apply_status_change(event.notification.Status)
        self._observe(lambda: self._observer.on_notification(self.subscription_id, produced))

    def _apply_status_change(self, status: ua.StatusCode) -> None:
        if status.value == ua.StatusCodes.GoodSubscriptionTransferred:
            self._finish(SubscriptionState.TRANSFERRED)
        elif status.value == ua.StatusCodes.BadTimeout:
            if self.state is SubscriptionState.ACTIVE:
                self.state = SubscriptionState.LOST
        elif status.value == ua.StatusCodes.BadShutdown and self.state is SubscriptionState.ACTIVE:
            self.state = SubscriptionState.SUSPENDED

    def _explode_notifications(self, notification_data: Iterable[Any], replayed: bool = False) -> Iterable[SubEvent]:
        """Translate server `NotificationData` items into typed `SubEvent`s."""
        for notif in notification_data:
            if isinstance(notif, ua.DataChangeNotification):
                yield from self._explode_datachange(notif, replayed)
            elif isinstance(notif, ua.EventNotificationList):
                yield from self._explode_events(notif, replayed)
            elif isinstance(notif, ua.StatusChangeNotification):
                yield StatusChangeEvent(notification=notif, replayed=replayed)
            else:
                self._warn_limited(
                    f"type-{type(notif).__name__}", "Notification type not supported yet for notification %s", notif
                )

    def _explode_datachange(
        self, datachange: ua.DataChangeNotification, replayed: bool = False
    ) -> Iterable[DataChangeEvent]:
        for item in datachange.MonitoredItems:
            data = self._monitored_items.get(item.ClientHandle)
            if data is None or data.node is None:
                self.unknown_handle_notifications += 1
                self.logger.debug("Received a notification for unknown handle: %s", item.ClientHandle)
                continue
            event_data = DataChangeNotif(data, item)
            value: Any = None
            if item.Value is not None and item.Value.Value is not None:
                value = item.Value.Value.Value
            yield DataChangeEvent(node=data.node, value=value, data=event_data, replayed=replayed)

    def _explode_events(self, eventlist: ua.EventNotificationList, replayed: bool = False) -> Iterable[OpcEvent]:
        for event in eventlist.Events:
            data = self._monitored_items.get(event.ClientHandle)
            if data is None:
                self.unknown_handle_notifications += 1
                self.logger.debug("Received event for unknown handle: %s", event.ClientHandle)
                continue
            if not isinstance(data.mfilter, ua.EventFilter):
                self.unmatched_events += 1
                self.logger.debug(
                    "Received event notification but monitored item has no event filter: %s", event.ClientHandle
                )
                continue
            result = Event.from_event_fields(data.mfilter.SelectClauses, event.EventFields)
            result.server_handle = data.server_handle
            yield OpcEvent(event=result, replayed=replayed)

    async def _deliver(self, event: SubEvent) -> None:
        """
        Deliver one event to either the iterator queue or the handler.
        """
        if self._event_queue is not None:
            self._put_event(event)
        else:
            await self._dispatch_to_handler(event)

    def _put_event(self, event: SubEvent | None) -> None:
        queue = self._event_queue
        if queue is None:
            return
        if queue.full():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            if event is not None:
                self.dropped_events += 1
                self._observe(lambda: self._observer.on_messages_dropped(self.subscription_id, 1))
                self._warn_limited(
                    "queue",
                    "Subscription %s: event queue full, dropped the oldest event (%s dropped so far)",
                    self.subscription_id,
                    self.dropped_events,
                )
        queue.put_nowait(event)

    def _handler_method(self, name: str) -> Callable[..., Any] | None:
        if name not in self._handler_methods:
            method = getattr(self._handler, name, None)
            self._handler_methods[name] = method
            if method is None:
                self.logger.error("Subscription handler has no %s method; those events are dropped", name)
        return self._handler_methods[name]

    async def _dispatch_to_handler(self, event: SubEvent) -> None:
        """Call the right handler method for `event`, in the delivery task of this Subscription."""
        if self._handler is None:
            return
        if isinstance(event, DataChangeEvent):
            method = self._handler_method("datachange_notification")
            args: tuple[Any, ...] = (event.node, event.value, event.data)
        elif isinstance(event, OpcEvent):
            method = self._handler_method("event_notification")
            args = (event.event,)
        else:
            method = self._handler_method("status_change_notification")
            args = (event.notification,)
        if method is None:
            self.dropped_events += 1
            self._observe(lambda: self._observer.on_messages_dropped(self.subscription_id, 1))
            return
        try:
            result = method(*args)
            if inspect.isawaitable(result):
                await result
        except Exception:
            self.logger.exception("Exception calling subscription handler")

    async def __aenter__(self) -> Subscription:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> None:
        await self.delete()

    def __aiter__(self) -> Subscription:
        if self._handler is not None:
            raise RuntimeError(
                "Subscription is in handler mode; create it without a handler to use the async iterator API"
            )
        if self._event_queue is None:
            self._event_queue = asyncio.Queue(maxsize=self._queue_maxsize)
        return self

    async def __anext__(self) -> SubEvent:
        if self._event_queue is None:
            self._event_queue = asyncio.Queue(maxsize=self._queue_maxsize)
        item = await self._event_queue.get()
        if item is None:
            self._event_queue.put_nowait(None)
            raise StopAsyncIteration
        return item

    async def next_event(self, timeout: float | None = None) -> SubEvent | None:
        """Return the next event, or None on timeout. Counterpart to `__anext__`.

        Returns None if `timeout` elapses; raises `StopAsyncIteration` if the
        subscription has been closed and the queue is drained.
        """
        if self._event_queue is None:
            self._event_queue = asyncio.Queue(maxsize=self._queue_maxsize)
        try:
            if timeout is None:
                item = await self._event_queue.get()
            else:
                item = await asyncio.wait_for(self._event_queue.get(), timeout)
        except TimeoutError:
            return None
        if item is None:
            self._event_queue.put_nowait(None)
            raise StopAsyncIteration
        return item

    async def delete(self) -> None:
        """
        Delete subscription on server. This is automatically done by Client and Server classes on exit.
        A Good result and Bad_SubscriptionIdInvalid both count as deleted; any other Bad status is raised after the
        local cleanup, which always happens.
        """
        if self.state is SubscriptionState.DELETED:
            return
        failure: ua.StatusCode | None = None
        try:
            if self.subscription_id is not None and self.state is not SubscriptionState.TRANSFERRED:
                try:
                    results = await self.server.delete_subscriptions([self.subscription_id])
                except (TimeoutError, ConnectionError, OSError):
                    self.logger.info("delete_subscriptions: transport unavailable; local cleanup only")
                else:
                    status = results[0]
                    if not status.is_good() and status.value != ua.StatusCodes.BadSubscriptionIdInvalid:
                        failure = status
        finally:
            self._finish(SubscriptionState.DELETED)
        if failure is not None:
            failure.check()

    def close(self, reason: str = "") -> None:
        """
        End this Subscription locally: iterators end and the observer hears DELETED, but nothing goes to the server.
        """
        self.logger.info("Subscription %s closed: %s", self.subscription_id, reason)
        self._finish(SubscriptionState.DELETED)

    def _finish(self, state: SubscriptionState) -> None:
        if self.state is SubscriptionState.DELETED:
            return
        previous = self.state
        self.state = state
        self._unregister_sink(self.subscription_id)
        self._inbox.clear()
        task = self._delivery_task
        if task is not None and not task.done() and task is not asyncio.current_task():
            task.cancel()
        self._put_event(None)
        if state is SubscriptionState.DELETED and previous is not SubscriptionState.DELETED:
            self._observe(lambda: self._observer.on_subscription_event(self.subscription_id, SubscriptionEvent.DELETED))

    def is_stale(self, margin: float) -> bool:
        """
        Whether no publish (data or keep-alive) arrived for margin times the keep-alive period; a LOST Subscription
        is stale, a NEW, SUSPENDED or ended one is not.
        """
        if self.subscription_id is None or self.state is SubscriptionState.SUSPENDED:
            return False
        if self.state is SubscriptionState.LOST:
            return True
        if self.state is not SubscriptionState.ACTIVE:
            return False
        if self.revised is not None:
            interval_s = self.revised.publishing_interval / 1000.0
            keepalive = max(self.revised.max_keep_alive_count, 1)
        else:
            interval_s = self.parameters.RequestedPublishingInterval / 1000.0
            keepalive = max(int(self.parameters.RequestedMaxKeepAliveCount or 1), 1)
        stale_after = max(interval_s * keepalive * margin, self.min_stale_seconds)
        reference = self.last_publish_at if self.last_publish_at is not None else self._created_at
        return (time.monotonic() - reference) >= stale_after

    def _reset_tracking(self) -> None:
        self._expected = None
        self._delivered.clear()
        self._delivered_set.clear()
        self.last_sequence_number = None

    async def restore(self) -> None:
        """
        After a reconnect: move the Subscription to the new session with TransferSubscriptions and Republish what
        was missed, or re-create it with its MonitoredItems when that fails.
        """
        if self.state in (SubscriptionState.DELETED, SubscriptionState.TRANSFERRED):
            return
        if self.subscription_id is None or not self._remote:
            await self.recreate()
            return
        session = cast("UaSession", self.server)
        params = ua.TransferSubscriptionsParameters()
        params.SubscriptionIds = [self.subscription_id]
        params.SendInitialValues = False
        try:
            results = await session.transfer_subscriptions(params)
        except Exception:
            self.logger.info("transfer_subscriptions failed; falling back to recreate", exc_info=True)
            await self.recreate()
            return
        result = results[0] if results else None
        available: list[int] = []
        if result is not None and result.StatusCode.value == ua.StatusCodes.BadNothingToDo:
            pass
        elif result is None or not result.StatusCode.is_good():
            self.logger.info(
                "transfer_subscriptions returned %s; falling back to recreate",
                result.StatusCode if result else "no result",
            )
            await self.recreate()
            return
        else:
            available = list(result.AvailableSequenceNumbers or [])
        self._register_sink(self.subscription_id)
        if not await self._republish_after_restore(available):
            self.logger.info("republish could not fill gap for sub %s; recreating", self.subscription_id)
            await self.recreate()
            return
        self.last_publish_at = None
        self._created_at = time.monotonic()
        self.state = SubscriptionState.ACTIVE

    async def _republish_after_restore(self, available: list[int]) -> bool:
        if self.subscription_id is None:
            return True
        session = cast("UaSession", self.server)
        if self._expected is not None:
            number = self._expected
        else:
            number = min(available) if available else 1
        start = number
        async with self._process_lock:
            for _ in range(self.max_republish):
                try:
                    fetched = await session.republish(self.subscription_id, number)
                except BadMessageNotAvailable:
                    break
                except BadSubscriptionIdInvalid:
                    return False
                except Exception:
                    self.logger.warning(
                        "republish failed for sub %s seq %s", self.subscription_id, number, exc_info=True
                    )
                    return False
                if not fetched.NotificationData:
                    break
                self._acknowledge(number)
                await self._accept(number, fetched, True)
                number = next_sequence_number(number)
        missing = [n for n in available if n not in self._delivered_set and sequence_distance(start, n) < SEQUENCE_HALF]
        return not missing

    async def recreate(self) -> None:
        """
        Re-create this subscription and its monitored items on the server.

        Used by the auto-reconnect supervisor (after the connection has been
        restored — the server-side subscription is gone) and by the
        stale-subscription watchdog (transport is still up but the server has
        dropped this subscription). Client handles are preserved so existing
        notification routing keeps working.
        """
        if self.state in (SubscriptionState.DELETED, SubscriptionState.TRANSFERRED):
            return
        self._recreate_count += 1
        saved_monitored_items: list[SubscriptionItemData] = [
            item for item in self._monitored_items.values() if item.server_handle is not None
        ]
        old_subscription_id = self.subscription_id
        self._monitored_items.clear()
        self.failed_items = []
        self.subscription_id = None
        self.last_publish_at = None
        self._reset_tracking()
        self._unregister_sink(old_subscription_id)
        if old_subscription_id is not None and self._remote:
            try:
                await self.server.delete_subscriptions([old_subscription_id])
            except Exception:
                self.logger.debug("best-effort delete of old sub %s failed", old_subscription_id, exc_info=True)

        await self._create(SubscriptionEvent.RECREATED)

        if not saved_monitored_items:
            return

        mirs: list[ua.MonitoredItemCreateRequest] = []
        for item in saved_monitored_items:
            if item.node is None or item.attribute is None or item.client_handle is None:
                self.logger.warning("Skipping monitored item with missing fields during recreate")
                continue
            rv = ua.ReadValueId()
            rv.NodeId = item.node.nodeid
            rv.AttributeId = item.attribute
            mparams = ua.MonitoringParameters()
            mparams.ClientHandle = item.client_handle
            mparams.SamplingInterval = item.sampling_interval
            mparams.QueueSize = item.queuesize
            mparams.DiscardOldest = item.discard_oldest
            if item.mfilter is not None:
                mparams.Filter = item.mfilter
            mir = ua.MonitoredItemCreateRequest()
            mir.ItemToMonitor = rv
            mir.MonitoringMode = item.monitoring_mode
            mir.RequestedParameters = mparams
            mirs.append(mir)
            item.server_handle = None
            self._monitored_items[item.client_handle] = item

        if not mirs:
            return
        params = ua.CreateMonitoredItemsParameters()
        params.SubscriptionId = self.subscription_id
        params.ItemsToCreate = mirs
        params.TimestampsToReturn = saved_monitored_items[0].timestamps
        try:
            results = await self.server.create_monitored_items(params)
        except ServiceError as e:
            raise ua.UaStatusCodeError(e.code) from e
        for idx, result in enumerate(results):
            mi = params.ItemsToCreate[idx]
            restored = self._monitored_items.get(mi.RequestedParameters.ClientHandle)
            if restored is None:
                continue
            if not result.StatusCode.is_good():
                self.logger.warning(
                    "Failed to re-create monitored item (client_handle=%s): %s",
                    mi.RequestedParameters.ClientHandle,
                    result.StatusCode,
                )
                self.failed_items.append((mi.RequestedParameters.ClientHandle, result.StatusCode))
                del self._monitored_items[mi.RequestedParameters.ClientHandle]
                continue
            restored.server_handle = result.MonitoredItemId
            restored.revised_sampling_interval = result.RevisedSamplingInterval
            restored.revised_queuesize = result.RevisedQueueSize
            restored.filter_result = result.FilterResult

    @overload
    async def subscribe_data_change(
        self,
        nodes: Node,
        attr: ua.AttributeIds = ua.AttributeIds.Value,
        queuesize: int = 0,
        monitoring: ua.MonitoringMode = ua.MonitoringMode.Reporting,
        sampling_interval: ua.Duration = -1,
    ) -> int: ...

    @overload
    async def subscribe_data_change(
        self,
        nodes: Iterable[Node],
        attr: ua.AttributeIds = ua.AttributeIds.Value,
        queuesize: int = 0,
        monitoring: ua.MonitoringMode = ua.MonitoringMode.Reporting,
        sampling_interval: ua.Duration = -1,
    ) -> list[int | ua.StatusCode]: ...

    async def subscribe_data_change(
        self,
        nodes: Node | Iterable[Node],
        attr: ua.AttributeIds = ua.AttributeIds.Value,
        queuesize: int = 0,
        monitoring: ua.MonitoringMode = ua.MonitoringMode.Reporting,
        sampling_interval: ua.Duration = -1,
    ) -> int | list[int | ua.StatusCode]:
        """
        Subscribe to data change events of one or multiple nodes.
        The default attribute used for the subscription is `Value`.
        Return value is a handle which can be used to modify/cancel the subscription.
        The handle is an integer value for single Nodes. If the creation of the subscription fails an
        `UaStatusCodeError` is raised.
        If multiple Nodes are supplied, a List of integers or ua.StatusCode objects is returned. A list of
        StatusCode objects are returned to indicate that the subscription has failed (no exception will be
        raised in this case).
        If more control is necessary the `create_monitored_items` method can be used directly.

        :param nodes: One Node or an Iterable of Nodes
        :param attr: The Node attribute you want to subscribe to
        :param queuesize: 0 or 1 for default queue size (shall be 1 - no queuing), n for FIFO queue
        :param sampling_interval: ua.Duration in milliseconds, -1 for the publishing interval of the Subscription
        :return: Handle for changing/cancelling of the subscription
        """
        return await self._subscribe(
            nodes, attr, queuesize=queuesize, monitoring=monitoring, sampling_interval=sampling_interval
        )

    async def _create_eventfilter(
        self,
        evtypes: Node | ua.NodeId | str | int | Iterable[Node | ua.NodeId | str | int],
        where_clause_generation: bool = True,
    ) -> ua.EventFilter:
        raw_types: Iterable[Node | ua.NodeId | str | int]
        if isinstance(evtypes, int | str | ua.NodeId | Node):
            raw_types = [evtypes]
        else:
            raw_types = evtypes
        nodes = [Node(self.server, t) for t in raw_types]
        return await get_filter_from_event_type(nodes, where_clause_generation)

    async def subscribe_events(
        self,
        sourcenode: Node | ua.NodeId | str | int = ua.ObjectIds.Server,
        evtypes: Node | ua.NodeId | str | int | Iterable[Node | ua.NodeId | str | int] = ua.ObjectIds.BaseEventType,
        evfilter: ua.EventFilter | None = None,
        queuesize: int = 0,
        where_clause_generation: bool = True,
    ) -> int:
        """
        Subscribe to events from a node. Default node is Server node.
        In most servers the server node is the only one you can subscribe to.
        If evtypes is not provided, evtype defaults to BaseEventType.
        If evtypes is a list or tuple of custom event types, the events will be filtered to the supplied types.
        A handle (integer value) is returned which can be used to modify/cancel the subscription.

        :param sourcenode: int, str, ua.NodeId or Node
        :param evtypes: ua.ObjectIds, str, ua.NodeId or Node
        :param evfilter: ua.EventFilter which provides the SelectClauses and WhereClause
        :param queuesize: 0 for default queue size, 1 for minimum queue size, n for FIFO queue,
            MaxUInt32 for max queue size
        :param where_clause_generation: False builds the filter without a WhereClause, for servers such as TwinCAT
            and Codesys that cannot evaluate one. For BaseEventType alone no WhereClause is sent anyway, since it
            would let every Event through.
        :return: Handle for changing/cancelling of the subscription
        """
        sourcenode = Node(self.server, sourcenode)
        if evfilter is None:
            if isinstance(evtypes, int | str | ua.NodeId | Node) and Node(self.server, evtypes).nodeid == ua.NodeId(
                ua.ObjectIds.BaseEventType
            ):
                where_clause_generation = False
            evfilter = await self._create_eventfilter(evtypes, where_clause_generation)
        return await self._subscribe(sourcenode, ua.AttributeIds.EventNotifier, evfilter, queuesize=queuesize)

    async def subscribe_alarms_and_conditions(
        self,
        sourcenode: Node | ua.NodeId | str | int = ua.ObjectIds.Server,
        evtypes: Node | ua.NodeId | str | int | Iterable[Node | ua.NodeId | str | int] = ua.ObjectIds.ConditionType,
        evfilter: ua.EventFilter | None = None,
        queuesize: int = 0,
        refresh: bool = True,
    ) -> int:
        """
        Subscribe to alarm and condition events from a node. Default node is Server node.
        In many servers the server node is the only one you can subscribe to.
        If evtypes is not provided, evtype defaults to ConditionType.
        If evtypes is a list or tuple of custom event types, the events will be filtered to the supplied types.
        With refresh (the default) the retained Conditions are requested right after the item is created
        (ConditionRefresh2, else ConditionRefresh; OPC 10000-9, 4.5). A server that refuses the refresh only
        gets a warning in the log.
        A handle (integer value) is returned which can be used to modify/cancel the subscription.

        :param sourcenode: int, str, ua.NodeId or Node
        :param evtypes: ua.ObjectIds, str, ua.NodeId or Node
        :param evfilter: ua.EventFilter which provides the SelectClauses and WhereClause
        :param queuesize: 0 for default queue size, 1 for minimum queue size, n for FIFO queue,
            MaxUInt32 for max queue size
        :return: Handle for changing/cancelling of the subscription
        """
        handle = await self.subscribe_events(sourcenode, evtypes, evfilter, queuesize)
        if refresh:
            try:
                await condition_refresh2(self.server, self, handle)
            except ua.UaStatusCodeError as error:
                _logger.warning("ConditionRefresh failed after subscribing: %s", error)
        return handle

    @overload
    async def _subscribe(
        self,
        nodes: Node,
        attr: ua.AttributeIds = ua.AttributeIds.Value,
        mfilter: ua.MonitoringFilter | None = None,
        queuesize: int = 0,
        monitoring: ua.MonitoringMode = ua.MonitoringMode.Reporting,
        sampling_interval: ua.Duration = -1,
    ) -> int: ...

    @overload
    async def _subscribe(
        self,
        nodes: Iterable[Node],
        attr: ua.AttributeIds = ua.AttributeIds.Value,
        mfilter: ua.MonitoringFilter | None = None,
        queuesize: int = 0,
        monitoring: ua.MonitoringMode = ua.MonitoringMode.Reporting,
        sampling_interval: ua.Duration = -1,
    ) -> list[int | ua.StatusCode]: ...

    async def _subscribe(
        self,
        nodes: Node | Iterable[Node],
        attr: ua.AttributeIds = ua.AttributeIds.Value,
        mfilter: ua.MonitoringFilter | None = None,
        queuesize: int = 0,
        monitoring: ua.MonitoringMode = ua.MonitoringMode.Reporting,
        sampling_interval: ua.Duration = -1,
    ) -> int | list[int | ua.StatusCode]:
        """
        Private low level method for subscribing.
        :param nodes: One Node or an Iterable of Nodes.
        :param attr: ua.AttributeId which shall be subscribed
        :param mfilter: ua.MonitoringFilter which shall be applied
        :param queuesize: queue size
        :param monitoring: ua.MonitoringMode
        :param sampling_interval: ua.Duration
        :return: Integer handle or if multiple Nodes were given a List of Integer handles/ua.StatusCode
        """
        is_list = isinstance(nodes, collections.abc.Iterable)
        node_list = list(nodes) if isinstance(nodes, collections.abc.Iterable) else [nodes]
        mirs = [
            self._make_monitored_item_request(node, attr, mfilter, queuesize, monitoring, sampling_interval)
            for node in node_list
        ]
        mids = await self.create_monitored_items(mirs)
        if is_list:
            return mids
        first = mids[0]
        if isinstance(first, ua.StatusCode):
            first.check()
            raise ua.uaerrors.UaError(f"Unexpected Good StatusCode in monitored-item failure path: {first}")
        return first

    def _make_monitored_item_request(
        self,
        node: Node,
        attr: ua.AttributeIds,
        mfilter: ua.MonitoringFilter | None,
        queuesize: int,
        monitoring: ua.MonitoringMode,
        sampling_interval: ua.Duration,
    ) -> ua.MonitoredItemCreateRequest:
        rv = ua.ReadValueId()
        rv.NodeId = node.nodeid
        rv.AttributeId = attr
        mparams = ua.MonitoringParameters()
        self._client_handle += 1
        mparams.ClientHandle = self._client_handle
        mparams.SamplingInterval = sampling_interval
        mparams.QueueSize = queuesize
        mparams.DiscardOldest = True
        if mfilter is not None:
            mparams.Filter = mfilter
        mir = ua.MonitoredItemCreateRequest()
        mir.ItemToMonitor = rv
        mir.MonitoringMode = monitoring
        mir.RequestedParameters = mparams
        return mir

    async def create_monitored_items(
        self, monitored_items: Iterable[ua.MonitoredItemCreateRequest]
    ) -> list[int | ua.StatusCode]:
        """
        CreateMonitoredItems with requests made by the caller. Returns per request the MonitoredItemId, the handle
        for unsubscribe, or the Bad StatusCode. The ClientHandles must be unique within the Subscription, since
        notifications are matched to the items by them.
        """
        monitored_items = list(monitored_items)
        recreate_count = self._recreate_count
        params = ua.CreateMonitoredItemsParameters()
        params.SubscriptionId = self.subscription_id
        params.ItemsToCreate = monitored_items
        params.TimestampsToReturn = ua.TimestampsToReturn.Both
        for mi in monitored_items:
            data = SubscriptionItemData()
            data.client_handle = mi.RequestedParameters.ClientHandle
            data.node = Node(self.server, mi.ItemToMonitor.NodeId)
            data.attribute = mi.ItemToMonitor.AttributeId
            data.mfilter = mi.RequestedParameters.Filter
            data.queuesize = mi.RequestedParameters.QueueSize
            data.discard_oldest = mi.RequestedParameters.DiscardOldest
            data.timestamps = params.TimestampsToReturn
            data.monitoring_mode = mi.MonitoringMode
            data.sampling_interval = mi.RequestedParameters.SamplingInterval
            self._monitored_items[mi.RequestedParameters.ClientHandle] = data
        try:
            results = await self.server.create_monitored_items(params)
        except ServiceError as e:
            self._forget_monitored_items(params.ItemsToCreate, recreate_count)
            raise ua.UaStatusCodeError(e.code) from e
        except Exception:
            self._forget_monitored_items(params.ItemsToCreate, recreate_count)
            raise

        if recreate_count != self._recreate_count:
            self._forget_monitored_items(params.ItemsToCreate, recreate_count)
            raise ua.UaStatusCodeError(ua.StatusCodes.BadSubscriptionIdInvalid)
        mids: list[int | ua.StatusCode] = []
        for idx, result in enumerate(results):
            mi = params.ItemsToCreate[idx]
            if not result.StatusCode.is_good():
                del self._monitored_items[mi.RequestedParameters.ClientHandle]
                mids.append(result.StatusCode)
                continue
            data = self._monitored_items[mi.RequestedParameters.ClientHandle]
            data.server_handle = result.MonitoredItemId
            data.revised_sampling_interval = result.RevisedSamplingInterval
            data.revised_queuesize = result.RevisedQueueSize
            data.filter_result = result.FilterResult
            mids.append(result.MonitoredItemId)
        return mids

    def _forget_monitored_items(self, requests: list[ua.MonitoredItemCreateRequest], recreate_count: int) -> None:
        if recreate_count != self._recreate_count:
            return
        for mi in requests:
            self._monitored_items.pop(mi.RequestedParameters.ClientHandle, None)

    async def unsubscribe(self, handle: int | Iterable[int]) -> None:
        """
        Unsubscribe from datachange or events using the handle returned while subscribing.
        If you delete the subscription, you do not need to unsubscribe.
        :param handle: The handle that was returned when subscribing to the node/nodes
        """
        requested: list[int] = [handle] if isinstance(handle, int) else list(handle)
        by_server_handle = {i.server_handle: i for i in self._monitored_items.values() if i.server_handle is not None}
        handles: list[int] = []
        for h in requested:
            if h in by_server_handle:
                handles.append(h)
            else:
                self.logger.warning("unsubscribe: handle %s is not an item of subscription %s", h, self.subscription_id)
        if not handles:
            return
        params = ua.DeleteMonitoredItemsParameters()
        params.SubscriptionId = self.subscription_id
        params.MonitoredItemIds = handles
        try:
            results = await self.server.delete_monitored_items(params)
        except ServiceError as e:
            raise ua.UaStatusCodeError(e.code) from e
        failed: list[tuple[int, ua.StatusCode]] = []
        for h, status in zip(handles, results):
            if status.is_good() or status.value == ua.StatusCodes.BadMonitoredItemIdInvalid:
                item = by_server_handle[h]
                if item.client_handle is not None:
                    self._monitored_items.pop(item.client_handle, None)
            else:
                failed.append((h, status))
        if failed:
            detail = ", ".join(f"{h}: {status}" for h, status in failed)
            raise ua.UaStatusCodeError(failed[0][1].value, detail=f"unsubscribe failed for handles {detail}")

    async def modify_monitored_item(
        self,
        handle: int,
        new_samp_time: ua.Duration | None = None,
        new_queuesize: int | None = None,
        mod_filter_val: float | None = -1,
    ) -> list[ua.MonitoredItemModifyResult]:
        """
        Modify a monitored item. Parameters that are not given keep the values the item was created with.
        :param handle: Handle returned when originally subscribing
        :param new_samp_time: New wanted sample time
        :param new_queuesize: New wanted queuesize
        :param mod_filter_val: -1 keeps the filter, None removes it, 0 or more sets an absolute deadband
        :return: Return a Modify Monitored Item Result
        """
        item = next((i for i in self._monitored_items.values() if i.server_handle == handle), None)
        if item is None or item.client_handle is None:
            raise ValueError("The monitored item was not found.")
        mod_filter: ua.MonitoringFilter | ua.EventFilter | None
        if isinstance(item.mfilter, ua.EventFilter) or (mod_filter_val is not None and mod_filter_val < 0):
            mod_filter = item.mfilter
        elif mod_filter_val is None:
            mod_filter = None
        else:
            mod_filter = ua.DataChangeFilter()
            mod_filter.Trigger = ua.DataChangeTrigger.StatusValue
            mod_filter.DeadbandType = ua.DeadbandType.Absolute
            mod_filter.DeadbandValue = mod_filter_val
        sampling_interval = item.sampling_interval if new_samp_time is None else new_samp_time
        queuesize = item.queuesize if new_queuesize is None else new_queuesize
        modif_item = ua.MonitoredItemModifyRequest()
        modif_item.MonitoredItemId = handle
        modif_item.RequestedParameters = self._modify_monitored_item_request(
            queuesize, sampling_interval, mod_filter, item.client_handle, item.discard_oldest
        )
        params = ua.ModifyMonitoredItemsParameters()
        params.SubscriptionId = self.subscription_id
        params.TimestampsToReturn = item.timestamps
        params.ItemsToModify.append(modif_item)
        try:
            results = await self.server.modify_monitored_items(params)
        except ServiceError as e:
            raise ua.UaStatusCodeError(e.code) from e
        result = results[0]
        result.StatusCode.check()
        item.sampling_interval = sampling_interval
        item.queuesize = queuesize
        item.mfilter = mod_filter
        item.revised_sampling_interval = result.RevisedSamplingInterval
        item.revised_queuesize = result.RevisedQueueSize
        item.filter_result = result.FilterResult
        return results

    def _modify_monitored_item_request(
        self,
        new_queuesize: int,
        new_samp_time: ua.Duration,
        mod_filter: ua.MonitoringFilter | ua.EventFilter | None,
        client_handle: ua.IntegerId,
        discard_oldest: bool = True,
    ) -> ua.MonitoringParameters:
        req_params = ua.MonitoringParameters()
        req_params.ClientHandle = client_handle
        req_params.QueueSize = new_queuesize
        req_params.DiscardOldest = discard_oldest
        req_params.Filter = mod_filter
        req_params.SamplingInterval = new_samp_time
        return req_params

    @overload
    async def deadband_monitor(
        self,
        var: Node,
        deadband_val: ua.Double,
        deadbandtype: ua.UInt32 = 1,
        queuesize: int = 0,
        attr: ua.AttributeIds = ua.AttributeIds.Value,
    ) -> int: ...

    @overload
    async def deadband_monitor(
        self,
        var: Iterable[Node],
        deadband_val: ua.Double,
        deadbandtype: ua.UInt32 = 1,
        queuesize: int = 0,
        attr: ua.AttributeIds = ua.AttributeIds.Value,
    ) -> list[int | ua.StatusCode]: ...

    async def deadband_monitor(
        self,
        var: Node | Iterable[Node],
        deadband_val: ua.Double,
        deadbandtype: ua.UInt32 = 1,
        queuesize: int = 0,
        attr: ua.AttributeIds = ua.AttributeIds.Value,
    ) -> int | list[int | ua.StatusCode]:
        """
        Subscribe to data changes beyond a deadband, reported on a change of status or value (OPC 10000-4 v1.05,
        7.22.2). Returns the handle, or for several Variables a list of handles and Bad StatusCodes.
        :param var: Variable to which you want to subscribe
        :param deadband_val: the deadband: an absolute value, or 0 to 100 for a percent deadband
        :param deadbandtype: ua.DeadbandType.Absolute (1, the default) or ua.DeadbandType.Percent (2)
        :param queuesize: Wanted queue size, 0 or 1 for the server default (1 for data items)
        :param attr: Attribute ID
        """
        deadband_filter = ua.DataChangeFilter()
        deadband_filter.Trigger = ua.DataChangeTrigger.StatusValue
        deadband_filter.DeadbandType = deadbandtype
        deadband_filter.DeadbandValue = deadband_val
        return await self._subscribe(var, attr, deadband_filter, queuesize)

    async def set_monitoring_mode(
        self, monitoring: ua.MonitoringMode, handles: int | Iterable[int] | None = None
    ) -> list[ua.StatusCode]:
        """
        SetMonitoringMode (client only): Disabled stops sampling, Sampling samples without reporting and Reporting
        samples and reports (OPC 10000-4 v1.05, 5.13.4).

        :param monitoring: The monitoring mode to apply
        :param handles: Handles of the items to change, default all items
        :return: Return a Set Monitoring Mode Result
        """
        session = self._remote_session("set_monitoring_mode")
        wanted = None if handles is None else {handles} if isinstance(handles, int) else set(handles)
        items = [
            i
            for i in self._monitored_items.values()
            if i.server_handle is not None and (wanted is None or i.server_handle in wanted)
        ]
        if not items:
            return []
        params = ua.SetMonitoringModeParameters()
        params.SubscriptionId = self.subscription_id
        params.MonitoredItemIds = [i.server_handle for i in items if i.server_handle is not None]
        params.MonitoringMode = monitoring
        results = await session.set_monitoring_mode(params)
        for item, status in zip(items, results):
            if status.is_good():
                item.monitoring_mode = monitoring
        return results

    async def set_publishing_mode(self, publishing: bool) -> list[ua.StatusCode]:
        """
        SetPublishingMode (client only): with publishing False the server sends only keep-alives; the monitoring
        modes do not change.

        :param publishing: The publishing mode to apply
        :return: Return a Set Publishing Mode Result
        """
        session = self._remote_session("set_publishing_mode")
        if self.subscription_id is None:
            raise ua.uaerrors.UaError("set_publishing_mode() called before subscription was created on the server.")
        params = ua.SetPublishingModeParameters()
        params.SubscriptionIds = [self.subscription_id]
        params.PublishingEnabled = publishing
        result = await session.set_publishing_mode(params)
        if result[0].is_good():
            self.parameters.PublishingEnabled = publishing
        return result
