"""Client helpers for Alarms and Conditions (OPC 10000-9): Method calls by ConditionId, refresh, a current-alarm list."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING

from enginir_opcua import ua

from .events import Event, get_filter_from_event_type
from .node import Node
from .session_interface import AbstractSession

if TYPE_CHECKING:
    from enginir_opcua import Client, Server
    from enginir_opcua.common.subscription import Subscription

type ConditionHost = Client | Server

_logger = logging.getLogger(__name__)

CONDITION_TYPE = ua.NodeId(ua.ObjectIds.ConditionType)
ENABLE = ua.NodeId(ua.ObjectIds.ConditionType_Enable)
DISABLE = ua.NodeId(ua.ObjectIds.ConditionType_Disable)
ADD_COMMENT = ua.NodeId(ua.ObjectIds.ConditionType_AddComment)
REFRESH = ua.NodeId(ua.ObjectIds.ConditionType_ConditionRefresh)
REFRESH2 = ua.NodeId(ua.ObjectIds.ConditionType_ConditionRefresh2)
ACKNOWLEDGE = ua.NodeId(ua.ObjectIds.AcknowledgeableConditionType_Acknowledge)
CONFIRM = ua.NodeId(ua.ObjectIds.AcknowledgeableConditionType_Confirm)
TIMED_SHELVE = ua.NodeId(ua.ObjectIds.ShelvedStateMachineType_TimedShelve)
ONE_SHOT_SHELVE = ua.NodeId(ua.ObjectIds.ShelvedStateMachineType_OneShotShelve)
UNSHELVE = ua.NodeId(ua.ObjectIds.ShelvedStateMachineType_Unshelve)
REFRESH_START = ua.NodeId(ua.ObjectIds.RefreshStartEventType)
REFRESH_END = ua.NodeId(ua.ObjectIds.RefreshEndEventType)


def _id(value: Node | ua.NodeId | int | str) -> ua.NodeId:
    if isinstance(value, Node):
        return value.nodeid
    if isinstance(value, ua.NodeId):
        return value
    return ua.NodeId.from_string(value) if isinstance(value, str) else ua.NodeId(value)


def _comment(comment: str | ua.LocalizedText | None) -> ua.Variant:
    if comment is None:
        comment = ua.LocalizedText()
    elif isinstance(comment, str):
        comment = ua.LocalizedText(comment)
    return ua.Variant(comment, ua.VariantType.LocalizedText)


def _event_id(event_id: bytes | ua.Variant) -> ua.Variant:
    if isinstance(event_id, ua.Variant):
        return event_id
    return ua.Variant(bytes(event_id), ua.VariantType.ByteString)


async def _call(
    client: ConditionHost | AbstractSession, condition: Node | ua.NodeId, method: ua.NodeId, *arguments: ua.Variant
) -> None:
    nodeid = _id(condition)
    get_node = getattr(client, "get_node", None)
    node: Node = get_node(nodeid) if get_node is not None else Node(client, nodeid)  # type: ignore[arg-type]
    await node.call_method(method, *arguments)


async def condition_event_filter(
    client: ConditionHost, types: Node | ua.NodeId | int | Iterable[Node | ua.NodeId | int] = CONDITION_TYPE
) -> ua.EventFilter:
    """
    The EventFilter of a current-alarm display: the fields of the types, the ConditionId and OfType as where
    clause. TrueState and FalseState are left out; they are metadata of the type, not Event fields (Part 9, 5.2).
    """
    raw = [types] if isinstance(types, Node | ua.NodeId | int) else list(types)
    flt = await get_filter_from_event_type([client.get_node(_id(item)) for item in raw])
    flt.SelectClauses = [
        clause
        for clause in flt.SelectClauses
        if not (len(clause.BrowsePath) > 1 and clause.BrowsePath[-1].Name in ("TrueState", "FalseState"))
    ]
    return flt


async def acknowledge(
    client: ConditionHost | AbstractSession,
    condition: Node | ua.NodeId,
    event_id: bytes | ua.Variant,
    comment: str | ua.LocalizedText | None = None,
) -> None:
    """Acknowledge the Condition state of the Event event_id (Part 9, 5.7.3)."""
    await _call(client, condition, ACKNOWLEDGE, _event_id(event_id), _comment(comment))


async def confirm(
    client: ConditionHost | AbstractSession,
    condition: Node | ua.NodeId,
    event_id: bytes | ua.Variant,
    comment: str | ua.LocalizedText | None = None,
) -> None:
    """Confirm the Condition state of the Event event_id (Part 9, 5.7.4)."""
    await _call(client, condition, CONFIRM, _event_id(event_id), _comment(comment))


async def add_comment(
    client: ConditionHost | AbstractSession,
    condition: Node | ua.NodeId,
    event_id: bytes | ua.Variant,
    comment: str | ua.LocalizedText,
) -> None:
    """Add a comment to the Condition state of the Event event_id (Part 9, 5.5.6)."""
    await _call(client, condition, ADD_COMMENT, _event_id(event_id), _comment(comment))


async def enable(client: ConditionHost | AbstractSession, condition: Node | ua.NodeId) -> None:
    """Enable the Condition (Part 9, 5.5.5)."""
    await _call(client, condition, ENABLE)


async def disable(client: ConditionHost | AbstractSession, condition: Node | ua.NodeId) -> None:
    """Disable the Condition (Part 9, 5.5.4)."""
    await _call(client, condition, DISABLE)


async def timed_shelve(
    client: ConditionHost | AbstractSession, condition: Node | ua.NodeId, milliseconds: float
) -> None:
    """Shelve the alarm for the given time (Part 9, 5.8.17.4); condition is the alarm or its ShelvingState."""
    await _call(client, condition, TIMED_SHELVE, ua.Variant(float(milliseconds), ua.VariantType.Double))


async def one_shot_shelve(client: ConditionHost | AbstractSession, condition: Node | ua.NodeId) -> None:
    """Shelve the alarm until it next goes inactive (Part 9, 5.8.17.6)."""
    await _call(client, condition, ONE_SHOT_SHELVE)


async def unshelve(client: ConditionHost | AbstractSession, condition: Node | ua.NodeId) -> None:
    """End the shelving of the alarm (Part 9, 5.8.17.2)."""
    await _call(client, condition, UNSHELVE)


def _subscription_id(subscription: Subscription | int) -> int:
    if isinstance(subscription, int):
        return subscription
    if subscription.subscription_id is None:
        raise ua.UaError("The subscription has not been created on the server")
    return subscription.subscription_id


async def condition_refresh(client: ConditionHost | AbstractSession, subscription: Subscription | int) -> None:
    """ConditionRefresh for every Event item of a Subscription (Part 9, 5.5.7)."""
    argument = ua.Variant(_subscription_id(subscription), ua.VariantType.UInt32)
    await _call(client, CONDITION_TYPE, REFRESH, argument)


async def condition_refresh2(
    client: ConditionHost | AbstractSession, subscription: Subscription | int, monitored_item_id: int
) -> None:
    """ConditionRefresh2 for one item; a server without it (Bad_MethodInvalid) gets ConditionRefresh (Part 9, 5.5.8)."""
    arguments = [
        ua.Variant(_subscription_id(subscription), ua.VariantType.UInt32),
        ua.Variant(int(monitored_item_id), ua.VariantType.UInt32),
    ]
    try:
        await _call(client, CONDITION_TYPE, REFRESH2, *arguments)
    except ua.uaerrors.BadMethodInvalid:
        await condition_refresh(client, subscription)


class ConditionTracker:
    """
    A subscription handler that keeps the current state of Conditions, as the "current Alarm display" of
    OPC 10000-9, 4.5 describes: every retained Condition and branch by (ConditionId, BranchId), refreshed
    entries unflagged, entries left over after RefreshEnd removed, Events with Retain false removed.
    Pass it as the handler of a Subscription that selects the ConditionId (`condition_event_filter`).
    """

    def __init__(self, on_change: Callable[[Event, bool], None] | None = None) -> None:
        self.entries: dict[tuple[ua.NodeId, ua.NodeId], Event] = {}
        self._suspect: set[tuple[ua.NodeId, ua.NodeId]] = set()
        self._on_change = on_change

    def event_notification(self, event: Event) -> None:
        """The subscription handler callback: update the entries and call on_change(event, retained)."""
        event_type = getattr(event, "EventType", None)
        if event_type == REFRESH_START:
            self._suspect = set(self.entries)
            return
        if event_type == REFRESH_END:
            for key in list(self._suspect):
                self._remove(key)
            self._suspect.clear()
            return
        condition_id = getattr(event, "NodeId", None)
        if not isinstance(condition_id, ua.NodeId):
            return
        branch = getattr(event, "BranchId", None)
        key = (condition_id, branch if isinstance(branch, ua.NodeId) else ua.NodeId())
        self._suspect.discard(key)
        if getattr(event, "Retain", False):
            self.entries[key] = event
            self._notify(event, True)
        else:
            self._remove(key, event)

    def _remove(self, key: tuple[ua.NodeId, ua.NodeId], event: Event | None = None) -> None:
        removed = self.entries.pop(key, None)
        notified = event if event is not None else removed
        if notified is not None:
            self._notify(notified, False)

    def _notify(self, event: Event, retained: bool) -> None:
        if self._on_change is not None:
            try:
                self._on_change(event, retained)
            except Exception:
                _logger.exception("Condition change callback failed")
