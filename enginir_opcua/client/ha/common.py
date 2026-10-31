"""
Helpers of the high-availability client.
"""

import asyncio
import logging
from collections.abc import Iterable, Iterator
from enum import IntEnum
from itertools import chain, islice

from enginir_opcua.common.utils import wait_for

_logger = logging.getLogger(__name__)


class ClientNotFound(Exception):
    """A URL that is not one of the servers of the HaClient."""


class ConnectionStates(IntEnum):
    """
    The ServiceLevel bands of OPC 10000-4 v1.05, 6.6.2.4.2: Maintenance (0), NoData (1), Degraded (2 to 199) and
    Healthy (200 to 255); each member is the lowest level of its band.
    """

    IN_MAINTENANCE = 0
    NO_DATA = 1
    DEGRADED = 2
    HEALTHY = 200


async def event_wait(evt: asyncio.Event, timeout: float) -> bool:
    """Wait for the event at most timeout seconds; whether it is set."""
    try:
        await wait_for(evt.wait(), timeout)
    except TimeoutError:
        pass
    return evt.is_set()


async def wait_any(timeout: float, stop: asyncio.Event, *wakeups: asyncio.Event) -> bool:
    """
    Wait until the stop event or one of the wake-up events is set, or the timeout passes.
    A wake-up event that ended the wait is cleared. Returns True when the stop event is set.
    """
    if stop.is_set():
        return True
    events = (stop, *wakeups)
    for event in wakeups:
        if event.is_set():
            event.clear()
            return False
    waiters = [asyncio.ensure_future(event.wait()) for event in events]
    try:
        await asyncio.wait(waiters, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for waiter in waiters:
            waiter.cancel()
        await asyncio.gather(*waiters, return_exceptions=True)
    for event in wakeups:
        event.clear()
    return stop.is_set()


def batch[T](iterable: Iterable[T], size: int) -> Iterator[list[T]]:
    """The items in lists of at most size."""
    iterator = iter(iterable)
    while True:
        try:
            batchiter = islice(iterator, size)
            yield list(chain([next(batchiter)], batchiter))
        except StopIteration:
            break
