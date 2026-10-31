"""
Server callbacks: listeners the server calls before and after Read and Write and when MonitoredItems change.
"""

import inspect
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Any


class CallbackType(Enum):
    """
    The possible types of a Callback type.

    Members: Null, ItemSubscriptionCreated, ItemSubscriptionModified, ItemSubscriptionDeleted,
    PreWrite, PostWrite, PreRead, PostRead.

    """

    Null = 0
    ItemSubscriptionCreated = 1
    ItemSubscriptionModified = 2
    ItemSubscriptionDeleted = 3
    PreWrite = 4
    PostWrite = 5
    PreRead = 6
    PostRead = 7


type EventName = CallbackType | str


class Callback:
    """The event passed to a listener; dispatch sets its name."""

    def __init__(self) -> None:
        self.__name: EventName | None = None

    def setName(self, name: EventName | None) -> None:
        self.__name = name

    def getName(self) -> EventName | None:
        return self.__name


class ServerItemCallback(Callback):
    """
    A callback about one request: its parameters, the response (None before the service ran), the user and
    whether the request came from a client (is_external) or from the server itself.
    """

    def __init__(self, request_params: Any, response_params: Any, user: Any = None, is_external: bool = False) -> None:
        super().__init__()
        self.request_params = request_params
        self.response_params = response_params
        self.is_external = is_external
        self.user = user


Listener = Callable[[Callback, "CallbackService"], Awaitable[None] | None]


class CallbackService:
    """Listeners by event; a listener may be a function or a coroutine function."""

    def __init__(self) -> None:
        self._listeners: dict[EventName, list[tuple[int, int, Listener]]] = {}
        self._sequence = 0

    async def dispatch(self, eventName: EventName, event: Callback | None = None) -> Callback:
        """Call the listeners of eventName one after the other, lowest priority first, and return the event."""
        if event is None:
            event = Callback()
        elif not isinstance(event, Callback):
            raise ValueError("Unexpected event type given")
        event.setName(eventName)
        for _, _, listener in list(self._listeners.get(eventName, [])):
            result = listener(event, self)
            if inspect.isawaitable(result):
                await result
        return event

    def addListener(self, eventName: EventName, listener: Listener, priority: int = 0) -> None:
        """Add a listener; listeners of the same priority run in the order they were added."""
        self._sequence += 1
        entries = [*self._listeners.get(eventName, []), (priority, self._sequence, listener)]
        entries.sort(key=lambda entry: entry[:2])
        self._listeners[eventName] = entries

    def removeListener(self, eventName: EventName, listener: Listener | None = None) -> None:
        """Remove one listener of eventName, or all of them when listener is None."""
        if eventName not in self._listeners:
            return
        if listener is None:
            del self._listeners[eventName]
        else:
            self._listeners[eventName] = [entry for entry in self._listeners[eventName] if entry[2] is not listener]
