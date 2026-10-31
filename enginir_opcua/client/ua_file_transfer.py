"""
Client side of OPC UA File Transfer: reading and writing the content of a FileType Object in chunks, and driving a
FileDirectoryType Object.

See also OPC 10000-20 (File Transfer; Annex C of OPC 10000-5 in v1.04).
"""

import asyncio
import logging
import weakref
from collections.abc import AsyncIterator
from types import TracebackType
from typing import Any

from enginir_opcua import ua
from enginir_opcua.common.node import Node
from enginir_opcua.ua import NodeId, OpenFileMode, Variant, VariantType

_logger = logging.getLogger(__name__)

DEFAULT_CHUNK_SIZE = 65536
MAX_READ_LENGTH = 2**31 - 1
MAX_POSITION = 2**64 - 1

METHOD_FALLBACKS: dict[str, int] = {
    "Open": ua.ObjectIds.FileType_Open,
    "Close": ua.ObjectIds.FileType_Close,
    "Read": ua.ObjectIds.FileType_Read,
    "Write": ua.ObjectIds.FileType_Write,
    "GetPosition": ua.ObjectIds.FileType_GetPosition,
    "SetPosition": ua.ObjectIds.FileType_SetPosition,
    "CreateDirectory": ua.ObjectIds.FileDirectoryType_CreateDirectory,
    "CreateFile": ua.ObjectIds.FileDirectoryType_CreateFile,
    "Delete": ua.ObjectIds.FileDirectoryType_DeleteFileSystemObject,
    "MoveOrCopy": ua.ObjectIds.FileDirectoryType_MoveOrCopy,
}

TRANSPORT_OVERHEAD = 1024
_max_byte_string_length: "weakref.WeakKeyDictionary[Any, int | None]" = weakref.WeakKeyDictionary()


class InvalidStateError(ua.uaerrors.UaError):
    """A call that doesn't fit the state of the file object, for example reading a file that is not open."""


class FileTransferError(ua.uaerrors.UaError):
    """
    A read or write failed in the middle. `partial_data` holds the bytes read so far, `bytes_written` the bytes
    the server confirmed. The original exception is the `__cause__`.
    """

    def __init__(self, message: str, partial_data: bytes = b"", bytes_written: int = 0) -> None:
        super().__init__(message)
        self.partial_data = partial_data
        self.bytes_written = bytes_written

    @property
    def bytes_read(self) -> int:
        """How many bytes were read before the failure."""
        return len(self.partial_data)


def validate_open_mode(open_mode: int) -> int:
    """
    Check an open mode against OPC 10000-5, C.2.1.
    :raises ValueError: when the mode isn't a valid combination of Read, Write, EraseExisting and Append
    """
    mode = int(open_mode)
    if mode < 0 or mode > 255:
        raise ValueError(f"open mode {mode} does not fit a Byte")
    if mode & 0xF0:
        raise ValueError(f"open mode {mode} sets reserved bits")
    if not mode & (OpenFileMode.Read | OpenFileMode.Write):
        raise ValueError(f"open mode {mode} needs Read or Write")
    if mode & OpenFileMode.EraseExisting and not mode & OpenFileMode.Write:
        raise ValueError(f"open mode {mode}: EraseExisting needs Write")
    return mode


class _MethodCaller:
    def __init__(self, node: Node, timeout: float | None) -> None:
        self._node = node
        self._timeout = timeout
        self._methods: dict[str, NodeId] = {}

    async def _resolve(self, name: str) -> NodeId:
        method = self._methods.get(name)
        if method is not None:
            return method
        try:
            method = (await self._node.get_child(name)).nodeid
        except ua.uaerrors.UaError:
            fallback = METHOD_FALLBACKS.get(name)
            if fallback is None:
                raise ua.uaerrors.UaError(f"The Method {name} was not found on {self._node}") from None
            _logger.debug("Method %s not found on %s, using the Method of the type", name, self._node)
            method = NodeId(fallback)
        self._methods[name] = method
        return method

    async def _call(self, name: str, *args: Any) -> Any:
        method = await self._resolve(name)
        _logger.debug("Calling %s on %s", name, self._node)
        return await self._node.call_method(method, *args, timeout=self._timeout)


class UaFile(_MethodCaller):
    """
    Provides the functionality to work with "C.2 FileType".
    """

    _property_nodes: dict[str, Node | None]

    def __init__(
        self,
        file_node: Node,
        open_mode: int = OpenFileMode.Read,
        *,
        chunk_size: int | None = None,
        timeout: float | None = None,
    ) -> None:
        """
        Initializes a new instance of the UaFile class. Nothing is sent.
        :param file_node: The node of the file to open.
        :param open_mode: The open mode, see: enginir_opcua.ua.OpenFileMode.
        :param chunk_size: Bytes per Read and Write call; default the smaller of 64 KiB and the server's
        MaxByteStringLength.
        :param timeout: Timeout in seconds of every Method call.
        :raises ValueError: for an open mode that OPC UA doesn't allow.
        """
        super().__init__(file_node, timeout)
        self._file_node = file_node
        self._open_mode = validate_open_mode(open_mode)
        if chunk_size is not None and not 1 <= chunk_size <= MAX_READ_LENGTH:
            raise ValueError(f"chunk_size {chunk_size} is outside 1 to {MAX_READ_LENGTH}")
        self._requested_chunk_size = chunk_size
        self._chunk_size: int | None = chunk_size
        self._file_handle: int | None = None
        self._session_identity: int | None = None
        self._lock = asyncio.Lock()
        self._property_nodes = {}

    @property
    def handle(self) -> int | None:
        """The FileHandle the server returned from Open, None while the file is closed."""
        return self._file_handle

    @property
    def is_open(self) -> bool:
        """Whether the file is open."""
        return self._file_handle is not None

    @property
    def chunk_size(self) -> int:
        """The bytes per Read or Write call."""
        return self._chunk_size or DEFAULT_CHUNK_SIZE

    def _identity(self) -> int | None:
        return getattr(self._file_node.session, "session_generation", None)

    async def __aenter__(self) -> "UaFile":
        await self.open()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if exc_type is None:
            await self.close()
            return
        try:
            await self.close()
        except Exception:
            _logger.warning("closing %s failed after an error in the body", self._file_node, exc_info=True)

    async def open(self, open_mode: int | None = None) -> int:
        """
        Open is used to open a file represented by an Object of FileType.
        The open mode of OPC UA differs significantly from the
        python build-in functionality.
        => See the OPC UA specification for more information.
        :param open_mode: Open mode defined in C.2.1.
        :return: The file handle.
        :raises InvalidStateError: when the file is already open
        """
        if self._file_handle is not None:
            raise InvalidStateError(f"{self._file_node} is already open")
        mode = self._open_mode if open_mode is None else validate_open_mode(open_mode)
        _logger.debug("Request to open file %s in mode: %s", self._file_node, mode)
        async with self._lock:
            handle = await self._call("Open", Variant(mode, VariantType.Byte))
            self._file_handle = int(handle)
            self._session_identity = self._identity()
        return self._file_handle

    def adopt(self, handle: int) -> None:
        """
        Make this object the owner of a handle the server gave out elsewhere, for example by
        `UaDirectory.create_file(name, True)`, so that `close()` releases it.
        """
        if self._file_handle is not None:
            raise InvalidStateError(f"{self._file_node} is already open")
        self._file_handle = int(handle)
        self._session_identity = self._identity()

    def _require_open(self) -> int:
        if self._file_handle is None:
            raise InvalidStateError(f"{self._file_node} is not open")
        if self._session_identity != self._identity():
            self._file_handle = None
            raise ConnectionError("file handle belongs to a closed session")
        return self._file_handle

    async def close(self) -> None:
        """
        Close is used to close a file represented by a FileType.
        When a client closes a file the handle becomes invalid. The handle is dropped even when the call fails,
        and a second close does nothing.
        """
        handle = self._file_handle
        if handle is None:
            return
        self._file_handle = None
        if self._session_identity != self._identity():
            _logger.info("file handle of %s belongs to a closed session; not closing", self._file_node)
            return
        _logger.debug("Request to close file %s", self._file_node)
        await asyncio.shield(self._locked_call("Close", Variant(handle, VariantType.UInt32)))

    async def _locked_call(self, name: str, *args: Any) -> Any:
        async with self._lock:
            return await self._call(name, *args)

    async def _resolve_chunk_size(self) -> int:
        if self._chunk_size is not None:
            return self._clamp_to_transport(self._chunk_size)
        session = self._file_node.session
        if session not in _max_byte_string_length:
            try:
                limit = await Node(
                    session, NodeId(ua.ObjectIds.Server_ServerCapabilities_MaxByteStringLength)
                ).read_value()
            except Exception:
                limit = None
            _max_byte_string_length[session] = int(limit) if limit else None
        limit = _max_byte_string_length[session]
        self._chunk_size = min(DEFAULT_CHUNK_SIZE, limit) if limit else DEFAULT_CHUNK_SIZE
        return self._clamp_to_transport(self._chunk_size)

    def _clamp_to_transport(self, size: int) -> int:
        client = getattr(self._file_node.session, "_client", None)
        protocol = getattr(client, "protocol", None)
        if protocol is None:
            return size
        limits = protocol._channel.limits
        for limit in (limits.max_message_size, limits.send_max_message_size):
            if limit:
                size = min(size, max(1, limit - TRANSPORT_OVERHEAD))
        return size

    async def _read_chunk(self, handle: int, length: int) -> bytes:
        data = await self._call("Read", Variant(handle, VariantType.UInt32), Variant(length, VariantType.Int32))
        return data if data is not None else b""

    async def read_chunk(self, length: int) -> bytes:
        """
        One Read call. The server may return fewer bytes than asked; an empty result is the end of the file.
        """
        if not 1 <= length <= MAX_READ_LENGTH:
            raise ValueError(f"length {length} is outside 1 to {MAX_READ_LENGTH}")
        handle = self._require_open()
        async with self._lock:
            return await self._read_chunk(handle, length)

    async def iter_chunks(self, chunk_size: int | None = None) -> AsyncIterator[bytes]:
        """
        Read from the current position to the end of the file, yielding every non-empty result of the Read Method.
        """
        size = chunk_size or await self._resolve_chunk_size()
        while chunk := await self.read_chunk(size):
            yield chunk

    async def read(self, max_bytes: int | None = None) -> bytes:
        """
        Read the file from the current position to the end, in chunks. An empty file gives b"".
        The file position is advanced to the end.
        :param max_bytes: stop with a ValueError when the file is larger than this
        :raises FileTransferError: when a Read fails; `partial_data` holds what was read so far
        """
        handle = self._require_open()
        size = await self._resolve_chunk_size()
        chunks: list[bytes] = []
        total = 0
        async with self._lock:
            while True:
                try:
                    chunk = await self._read_chunk(handle, size)
                except Exception as exc:
                    raise FileTransferError(
                        f"reading {self._file_node} failed after {total} bytes: {exc}", b"".join(chunks)
                    ) from exc
                if not chunk:
                    break
                total += len(chunk)
                if max_bytes is not None and total > max_bytes:
                    raise ValueError(f"the file is larger than max_bytes={max_bytes}")
                chunks.append(chunk)
        return b"".join(chunks)

    async def write(self, data: bytes) -> None:
        """
        Write is used to write a part of the file starting from the current file position.
        The file position is advanced by the number of bytes written. The data is split into chunks.
        :param data: Contains the data to be written at the position of the file.
        It is server-dependent whether the written data are persistently
        stored if the session is ended without calling the Close Method with the fileHandle.
        Writing an empty or null ByteString sends nothing.
        :raises FileTransferError: when a Write fails; `bytes_written` holds the confirmed bytes
        """
        handle = self._require_open()
        if not data:
            return
        size = await self._resolve_chunk_size()
        written = 0
        async with self._lock:
            for offset in range(0, len(data), size):
                piece = bytes(data[offset : offset + size])
                try:
                    await self._call(
                        "Write", Variant(handle, VariantType.UInt32), Variant(piece, VariantType.ByteString)
                    )
                except Exception as exc:
                    raise FileTransferError(
                        f"writing {self._file_node} failed after {written} bytes: {exc}", bytes_written=written
                    ) from exc
                written += len(piece)

    async def get_position(self) -> int:
        """
        GetPosition is used to provide the current position of the file handle.
        :return: The position of the fileHandle in the file.
        If a Read or Write is called it starts at that position.
        """
        handle = self._require_open()
        return int(await self._locked_call("GetPosition", Variant(handle, VariantType.UInt32)))

    async def set_position(self, position: int) -> None:
        """
        SetPosition is used to set the current position of the file handle.
        :param position: The position to be set for the fileHandle in the file.
        If a Read or Write is called it starts at that position.
        If the position is higher than the file size the position is set to the end of the file.
        """
        if not 0 <= position <= MAX_POSITION:
            raise ValueError(f"position {position} is outside 0 to {MAX_POSITION}")
        handle = self._require_open()
        await self._locked_call(
            "SetPosition", Variant(handle, VariantType.UInt32), Variant(position, VariantType.UInt64)
        )

    async def _property(self, name: str) -> Node | None:
        if name not in self._property_nodes:
            try:
                self._property_nodes[name] = await self._file_node.get_child(name)
            except ua.uaerrors.UaError:
                self._property_nodes[name] = None
        return self._property_nodes[name]

    async def _read_property(self, name: str, optional: bool = False) -> Any:
        node = await self._property(name)
        if node is None:
            if optional:
                return None
            raise ua.uaerrors.UaError(f"The Property {name} was not found on {self._file_node}")
        return await node.read_value()

    async def get_size(self) -> int:
        """
        Size defines the size of the file in Bytes.
        When a file is opened for write the size might not be accurate.
        :return: The size of the file in Bytes.
        """
        return int(await self._read_property("Size"))

    async def get_writable(self) -> bool:
        """
        Writable indicates whether the file is writable.
        It does not take any user access rights into account, i.e. although the file
        is writable this may be restricted to a certain user / user group.
        The Property does not take into account whether the file is currently
        opened for writing by another client and thus currently locked and not writable by others.
        """
        return bool(await self._read_property("Writable"))

    async def get_user_writable(self) -> bool:
        """
        UserWritable indicates whether the file is writable taking user access rights into account.
        The Property does not take into account whether the file is currently opened
        for writing by another client and thus currently locked and not writable by others.
        """
        return bool(await self._read_property("UserWritable"))

    async def get_open_count(self) -> int:
        """
        OpenCount indicates the number of currently valid file handles on the file.
        """
        return int(await self._read_property("OpenCount"))

    async def get_mime_type(self) -> str | None:
        """
        MimeType is an optional Property; None when the file has none.
        """
        return await self._read_property("MimeType", optional=True)


class UaDirectory(_MethodCaller):
    """
    Provides the functionality to work with "C.3 File System".
    """

    def __init__(self, directory_node: Node, *, timeout: float | None = None) -> None:
        super().__init__(directory_node, timeout)
        self._directory_node = directory_node

    async def create_directory(self, directory_name: str) -> NodeId:
        """
        CreateDirectory is used to create a new FileDirectoryType Object organized by this Object.
        :param directory_name: The name of the directory to create.
        The name is used for the BrowseName and DisplayName of the directory object and also
        for the directory in the file system.
        For the BrowseName, the directoryName is used for the name part of the QualifiedName.
        The namespace index is Server specific.
        For the DisplayName, the directoryName is used for the text part of the LocalizedText.
        The locale part is Server specific.
        :return: The NodeId of the created directory Object.
        """
        _logger.debug("Request to create directory %s in %s", directory_name, self._directory_node)
        return await self._call("CreateDirectory", Variant(directory_name, VariantType.String))

    async def create_file(self, file_name: str, request_file_open: bool = False) -> tuple[NodeId, int]:
        """
        CreateFile is used to create a new FileType Object organized by this Object.
        The created file can be written using the Write Method of the FileType.
        :param file_name: The name of the file to create. The name is used for the
        BrowseName and DisplayName of the file object and also for the file in the
        file system.
        For the BrowseName, the fileName is used for the name part of the QualifiedName.
        The namespace index is Server specific. For the DisplayName, the fileName is
        used for the text part of the LocalizedText. The locale part is Server specific.
        :param request_file_open: Flag indicating if the new file should be opened
        with the Write and Read bits set in the open mode after the creation of the file.
        If the flag is set to True, the file is created and opened for writing.
        If the flag is set to False, the file is just created.
        :return: The NodeId of the created file Object.
        The fileHandle is returned if the requestFileOpen is set to True.
        The fileNodeId and the fileHandle can be used to access the new file
        through the FileType Object representing the new file.
        If requestFileOpen is set to False, the returned value shall be 0
        and shall be ignored by the caller.
        """
        _logger.debug("Request to create file %s in %s", file_name, self._directory_node)
        node_id, handle = await self._call(
            "CreateFile", Variant(file_name, VariantType.String), Variant(request_file_open, VariantType.Boolean)
        )
        return node_id, int(handle)

    async def delete(self, object_to_delete: NodeId) -> None:
        """
        Delete is used to delete a file or directory organized by this Object.
        :param object_to_delete: The NodeId of the file or directory to delete.
        In the case of a directory, all file and directory Objects below the
        directory to delete are deleted recursively.
        """
        _logger.debug("Request to delete file %s from %s", object_to_delete, self._directory_node)
        await self._call("Delete", Variant(object_to_delete, VariantType.NodeId))

    async def move_or_copy(
        self, object_to_move_or_copy: NodeId, target_directory: NodeId, create_copy: bool, new_name: str
    ) -> NodeId:
        """
        MoveOrCopy is used to move or copy a file or directory organized by this Object
        to another directory or to rename a file or directory.
        :param object_to_move_or_copy: The NodeId of the file or directory to move or copy.
        :param target_directory: The NodeId of the target directory of the move or copy command.
        If the file or directory is just renamed, the targetDirectory matches the ObjectId
        passed to the method call.
        :param create_copy: A flag indicating if a copy of the file or directory should be
        created at the target directory.
        :param new_name: The new name of the file or directory in the new location.
        If the string is empty, the name is unchanged.
        :return: The NodeId of the moved or copied object. Even if the Object is moved,
        the Server may return a new NodeId.
        """
        _logger.debug(
            "Request to %s%s file system object %s from %s to %s, new name=%s",
            "" if create_copy else "move",
            "copy" if create_copy else "",
            object_to_move_or_copy,
            self._directory_node,
            target_directory,
            new_name,
        )
        return await self._call(
            "MoveOrCopy",
            Variant(object_to_move_or_copy, VariantType.NodeId),
            Variant(target_directory, VariantType.NodeId),
            Variant(create_copy, VariantType.Boolean),
            Variant(new_name, VariantType.String),
        )
