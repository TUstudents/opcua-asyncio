"""
Helper function and classes that do not rely on enginir_opcua library.
Helper function and classes depending on ua object are in ua_utils.py
"""

import asyncio
import copy
import logging
import os
from collections.abc import Awaitable
from dataclasses import Field, fields
from typing import TYPE_CHECKING, Any, get_type_hints

from ..ua.uaerrors import UaError

if TYPE_CHECKING:
    from ..ua.uatypes import TypeRegistry

_logger = logging.getLogger(__name__)


class ServiceError(UaError):
    """A service failure with the StatusCode code, which the server answers with a ServiceFault."""

    def __init__(self, code: int) -> None:
        super().__init__("UA Service Error")
        self.code = code


class NotEnoughData(UaError):
    """A read past the end of a Buffer."""


class Buffer:
    """
    A read cursor over a window of bytes, used by the binary decoder. types is the TypeRegistry of the connection,
    which decodes ExtensionObjects.
    """

    def __init__(self, data: bytes, start_pos: int = 0, size: int = -1, types: TypeRegistry | None = None) -> None:
        if start_pos < 0 or start_pos > len(data):
            raise UaError(f"Buffer start {start_pos} is outside the data of {len(data)} bytes")
        if size == -1:
            size = len(data) - start_pos
        if size < 0 or start_pos + size > len(data):
            raise UaError(f"Buffer window of {size} bytes at {start_pos} is outside the data of {len(data)} bytes")
        self._data = data
        self._start = start_pos
        self._end = start_pos + size
        self._cur_pos = start_pos
        self.types = types

    def __str__(self) -> str:
        return f"Buffer(size:{len(self)}, data:{self._data[self._cur_pos : self._end]!r})"

    __repr__ = __str__

    def __len__(self) -> int:
        return self._end - self._cur_pos

    def __bool__(self) -> bool:
        return self._end > self._cur_pos

    def __bytes__(self) -> bytes:
        """Return remains of buffer as bytes."""
        return bytes(self._data[self._cur_pos : self._end])

    def _check_size(self, size: int) -> None:
        if size < 0 or size > len(self):
            raise NotEnoughData(f"Not enough data left in buffer, request for {size}, we have {len(self)}")

    def read(self, size: int) -> bytes:
        """
        read and pop number of bytes for buffer
        """
        self._check_size(size)
        pos = self._cur_pos
        self._cur_pos += size
        return self._data[pos : self._cur_pos]

    def copy(self, size: int = -1) -> "Buffer":
        """
        return a shadow copy, optionally only copy 'size' bytes
        """
        if size == -1:
            size = len(self)
        self._check_size(size)
        return Buffer(self._data, self._cur_pos, size, self.types)

    def skip(self, size: int) -> None:
        """
        skip size bytes in buffer
        """
        self._check_size(size)
        self._cur_pos += size

    @property
    def cur_pos(self) -> int:
        """The position of the cursor in the underlying data."""
        return self._cur_pos

    def rewind(self, cur_pos: int | None = None) -> None:
        """
        rewind the buffer to cur_pos, or to the start of its window
        """
        if cur_pos is None:
            cur_pos = self._start
        if cur_pos < self._start or cur_pos > self._end:
            raise UaError(f"Cannot rewind to {cur_pos}, the buffer window is {self._start} to {self._end}")
        self._cur_pos = cur_pos


def create_nonce(size: int = 32) -> bytes:
    """size random bytes from the operating system's secure source."""
    return os.urandom(size)


def fields_with_resolved_types(
    class_or_instance: Any,
    globalns: dict[str, Any] | None = None,
    localns: dict[str, Any] | None = None,
    include_extras: bool = False,
) -> tuple[Field, ...]:
    """Return a tuple describing the fields of this dataclass.

    Accepts a dataclass or an instance of one. Tuple elements are of
    type Field. ForwardRefs and string types will be resolved.
    """

    fields_ = fields(class_or_instance)
    cls = class_or_instance if isinstance(class_or_instance, type) else type(class_or_instance)
    resolved_fieldtypes = get_type_hints(  # type: ignore[call-arg]
        cls, globalns=globalns, localns=localns, include_extras=include_extras
    )

    resolved: list[Field] = []
    for field in fields_:
        field = copy.copy(field)
        try:
            field.type = resolved_fieldtypes[field.name]
        except KeyError:
            _logger.info("could not resolve fieldtype for field=%s of class_or_instance=%s", field, class_or_instance)
        resolved.append(field)

    return tuple(resolved)


async def wait_for[T](aw: Awaitable[T], timeout: int | float | None) -> T:
    """
    asyncio.wait_for. Kept as a single place to change timeout handling; since Python 3.12 it no longer
    swallows cancellations (https://github.com/python/cpython/issues/87555).
    """
    return await asyncio.wait_for(aw, timeout)
