# mypy: disable-error-code="empty-body"
"""
sync API of enginir_opcua
"""

from __future__ import annotations

import asyncio
import atexit
import functools
import itertools
import logging
import time
import weakref
from collections import deque
from collections.abc import Callable, Coroutine, Iterable, Iterator, Mapping, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from threading import Condition, RLock, Thread, current_thread
from threading import Event as ThreadEvent
from types import TracebackType
from typing import Any, Literal, TypeVar, overload

from cryptography import x509

from enginir_opcua import client, common, server, ua
from enginir_opcua.common import node, shortcuts, subscription, type_dictionary_builder, xmlexporter
from enginir_opcua.common.events import Event
from enginir_opcua.config import ClientConfig, ServerConfig, quickstart_client_config, quickstart_server_config
from enginir_opcua.crypto import security_policies, uacrypto
from enginir_opcua.crypto.permission_rules import UserRole
from enginir_opcua.crypto.truststore import TrustStore
from enginir_opcua.observer import Observer
from enginir_opcua.server.conditions import Condition as ServerCondition
from enginir_opcua.server.file_transfer import FileProvider
from enginir_opcua.server.user_managers import UserManager

_logger = logging.getLogger(__name__)

_T = TypeVar("_T")
_DROP_WARNING_INTERVAL = 10.0
_HANDLER_GRACE = 5.0
_NEXT_EVENT_GRACE = 1.0


class ThreadLoopNotRunning(RuntimeError): ...


_UNSET: Any = object()
_running_loops: weakref.WeakSet[ThreadLoop] = weakref.WeakSet()
_EXIT_TIMEOUT = 5.0


class ThreadLoop:
    """
    A thread that runs an event loop, and the way to run a coroutine on it from another thread (:meth:`post`).

    It can be started again after :meth:`stop`. The thread is a daemon thread. ``timeout`` is the time in seconds
    that :meth:`post` waits for a coroutine (``None`` for no limit).
    """

    def __init__(self, timeout: float | None = 120, stop_grace: float = 5.0) -> None:
        self.loop: asyncio.AbstractEventLoop | None = None
        self.timeout: float | None = timeout
        self.stop_grace: float = stop_grace
        self._thread: Thread | None = None
        self._lock: RLock = RLock()
        self._exit_hooks: dict[int, Callable[[], Coroutine[Any, Any, Any]]] = {}
        self._hook_ids: Iterator[int] = itertools.count()

    def is_alive(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def is_running(self) -> bool:
        loop = self.loop
        return self.is_alive() and loop is not None and loop.is_running()

    def start(self) -> None:
        with self._lock:
            if self.is_alive():
                raise RuntimeError("the ThreadLoop is already running")
            ready = ThreadEvent()
            failure: list[BaseException] = []
            thread = Thread(target=self._run, args=(ready, failure), name="ThreadLoop", daemon=True)
            self._thread = thread
            thread.start()
            ready.wait()
            if failure:
                thread.join()
                self._thread = None
                raise failure[0]
            _running_loops.add(self)

    def _run(self, ready: ThreadEvent, failure: list[BaseException]) -> None:
        try:
            loop = asyncio.new_event_loop()
        except BaseException as exc:
            failure.append(exc)
            ready.set()
            return
        self.loop = loop
        _logger.debug("Threadloop: %s", loop)
        loop.call_soon(ready.set)
        try:
            loop.run_forever()
        except BaseException as exc:
            failure.append(exc)
            ready.set()
        finally:
            self._close_loop(loop)

    def _close_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        try:
            tasks = asyncio.all_tasks(loop)
            for task in tasks:
                task.cancel()
            if tasks:
                loop.run_until_complete(asyncio.wait(tasks, timeout=self.stop_grace))
            loop.run_until_complete(loop.shutdown_asyncgens())
        finally:
            loop.close()

    def stop(self) -> None:
        with self._lock:
            thread = self._thread
            if thread is None:
                return
            if thread is current_thread():
                raise RuntimeError("stop() can't be called from the loop thread")
            loop = self.loop
            if thread.is_alive() and loop is not None and not loop.is_closed():
                try:
                    loop.call_soon_threadsafe(loop.stop)
                except RuntimeError:
                    pass
            thread.join()
            self._thread = None
            _running_loops.discard(self)

    def add_exit_hook(self, factory: Callable[[], Coroutine[Any, Any, Any]]) -> int:
        hook_id = next(self._hook_ids)
        self._exit_hooks[hook_id] = factory
        return hook_id

    def remove_exit_hook(self, hook_id: int | None) -> None:
        if hook_id is not None:
            self._exit_hooks.pop(hook_id, None)

    def post(self, coro: Coroutine[Any, Any, _T], timeout: float | None = _UNSET) -> _T:
        loop = self.loop
        thread = self._thread
        if loop is None or thread is None or not thread.is_alive() or not loop.is_running():
            coro.close()
            raise ThreadLoopNotRunning(
                f"could not post {coro} since asyncio loop in thread has not been started or has been stopped"
            )
        if thread is current_thread():
            coro.close()
            raise RuntimeError(
                "a synchronous call was made on the loop thread, where it could only wait for itself;"
                " use the asynchronous API here, or move the call to a handler thread"
            )
        limit = self.timeout if timeout is _UNSET else timeout
        future = asyncio.run_coroutine_threadsafe(self._bounded(coro, limit), loop)
        try:
            return future.result()
        except BaseException:
            future.cancel()
            raise

    @staticmethod
    async def _bounded(coro: Coroutine[Any, Any, _T], limit: float | None) -> _T:
        if limit is None:
            return await coro
        name = getattr(coro, "__qualname__", repr(coro))
        try:
            async with asyncio.timeout(limit) as scope:
                return await coro
        except TimeoutError:
            if scope.expired():
                raise TimeoutError(f"{name} did not finish within {limit} s and was cancelled") from None
            raise

    def __enter__(self) -> ThreadLoop:
        self.start()
        return self

    def __exit__(
        self, exc_t: type[BaseException] | None, exc_v: BaseException | None, trace: TracebackType | None
    ) -> None:
        self.stop()


def _stop_running_loops() -> None:
    for tloop in list(_running_loops):
        for factory in list(tloop._exit_hooks.values()):
            try:
                tloop.post(factory(), timeout=_EXIT_TIMEOUT)
            except Exception:
                _logger.debug("exit hook failed", exc_info=True)
        try:
            tloop.stop()
        except Exception:
            _logger.debug("stopping the loop at exit failed", exc_info=True)


atexit.register(_stop_running_loops)


class _HandlerThread:
    def __init__(self, name: str, maxsize: int, grace: float, on_drop: Callable[[], None]) -> None:
        self._name = name
        self._maxsize = maxsize
        self._grace = grace
        self._on_drop = on_drop
        self._queue: deque[Callable[[], Any]] = deque()
        self._cond = Condition()
        self._thread: Thread | None = None
        self._stopping = False
        self._last_warning = float("-inf")
        self.dropped = 0

    def submit(self, call: Callable[[], Any]) -> None:
        with self._cond:
            if self._thread is None or not self._thread.is_alive():
                self._stopping = False
                self._thread = Thread(target=self._run, name=self._name, daemon=True)
                self._thread.start()
            if len(self._queue) >= self._maxsize:
                self._queue.popleft()
                self.dropped += 1
                self._report_drop()
            self._queue.append(call)
            self._cond.notify()

    def _report_drop(self) -> None:
        now = time.monotonic()
        if now - self._last_warning >= _DROP_WARNING_INTERVAL:
            self._last_warning = now
            _logger.warning("%s: queue full, dropped the oldest call (%s dropped so far)", self._name, self.dropped)
        try:
            self._on_drop()
        except Exception:
            _logger.exception("observer raised")

    def _run(self) -> None:
        while True:
            with self._cond:
                while not self._queue and not self._stopping:
                    self._cond.wait()
                if self._stopping:
                    return
                call = self._queue.popleft()
            try:
                call()
            except Exception:
                _logger.exception("Exception in a handler of %s", self._name)

    def stop(self) -> None:
        with self._cond:
            thread = self._thread
            if thread is None:
                return
            self._stopping = True
            self._queue.clear()
            self._cond.notify_all()
        if thread is not current_thread():
            thread.join(self._grace)
        self._thread = None


def _convert_in(value: Any) -> Any:
    if isinstance(value, SyncNode | Client | Server | Subscription | SyncCondition):
        return value.aio_obj
    kind = type(value)
    if kind is list:
        return [_convert_in(item) for item in value]
    if kind is tuple:
        return tuple(_convert_in(item) for item in value)
    if kind is set or kind is frozenset:
        return kind(_convert_in(item) for item in value)
    if kind is dict:
        return {key: _convert_in(item) for key, item in value.items()}
    return value


def _to_async(args: tuple[Any, ...] | list[Any], kwargs: dict[str, Any]) -> tuple[list[Any], dict[str, Any]]:
    return [_convert_in(arg) for arg in args], {key: _convert_in(value) for key, value in kwargs.items()}


def _to_sync(tloop: ThreadLoop, result: Any) -> Any:
    if isinstance(result, node.Node):
        return SyncNode(tloop, result)
    if isinstance(result, server.event_generator.EventGenerator):
        return EventGenerator(tloop, result)
    if isinstance(result, subscription.Subscription):
        return Subscription(tloop, result)
    if isinstance(result, ServerCondition):
        return SyncCondition(tloop, result)
    kind = type(result)
    if kind is list:
        return [_to_sync(tloop, item) for item in result]
    if kind is tuple:
        return tuple(_to_sync(tloop, item) for item in result)
    if kind is set or kind is frozenset:
        return kind(_to_sync(tloop, item) for item in result)
    if kind is dict:
        return {key: _to_sync(tloop, item) for key, item in result.items()}
    return result


def syncmethod(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    decorator for sync methods
    """

    @functools.wraps(func)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        ensure_loop = getattr(self, "_ensure_loop", None)
        if ensure_loop is not None:
            ensure_loop()
        args, kwargs = _to_async(args, kwargs)
        aio_func = getattr(self.aio_obj, func.__name__)
        result = self.tloop.post(aio_func(*args, **kwargs))
        return _to_sync(self.tloop, result)

    return wrapper


def sync_wrapper(aio_func: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(aio_func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not args:
            raise RuntimeError("first argument of function must a ThreadLoop object")
        if isinstance(args[0], ThreadLoop):
            tloop = args[0]
            args = tuple(args[1:])
        elif hasattr(args[0], "tloop"):
            tloop = args[0].tloop
        else:
            raise RuntimeError("first argument of function must a ThreadLoop object")
        args, kwargs = _to_async(args, kwargs)
        result = tloop.post(aio_func(*args, **kwargs))
        return _to_sync(tloop, result)

    return wrapper


def syncfunc(aio_func: Callable[..., Any]) -> Callable[..., Callable[..., Any]]:
    """
    decorator for sync function
    """

    def decorator(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Callable[..., Any]:
        return sync_wrapper(aio_func)

    return decorator


def sync_uaclient_method(aio_func: Callable[..., Any]) -> Callable[[Client], functools.partial[Any]]:
    """
    Make a blocking function from a method of the low level ``UaClient``, for example::

        from enginir_opcua.client.ua_client import UaClient
        from enginir_opcua.sync import Client

        with Client('opc.tcp://localhost:4840') as client:
            read_attributes = sync_uaclient_method(UaClient.read_attributes)(client)
            results = read_attributes(...)
    """

    def sync_method(client: Client) -> functools.partial[Any]:
        uaclient = client.aio_obj.uaclient
        return functools.partial(sync_wrapper(aio_func), client.tloop, uaclient)

    return sync_method


def sync_async_client_method(aio_func: Callable[..., Any]) -> Callable[[Client], functools.partial[Any]]:
    """
    Make a blocking function from a method of the async ``Client``, for example::

        from enginir_opcua.client import Client as AsyncClient
        from enginir_opcua.sync import Client

        with Client('opc.tcp://localhost:4840') as client:
            read_attributes = sync_async_client_method(AsyncClient.read_attributes)(client)
            results = read_attributes(...)
    """

    def sync_method(client: Client) -> functools.partial[Any]:
        return functools.partial(sync_wrapper(aio_func), client.tloop, client)

    return sync_method


@syncfunc(aio_func=common.methods.call_method_full)
def call_method_full(
    parent: SyncNode, methodid: ua.NodeId | ua.QualifiedName | str, *args: Any
) -> ua.CallMethodResult: ...


@syncfunc(aio_func=common.ua_utils.data_type_to_variant_type)
def data_type_to_variant_type(dtype_node: SyncNode) -> ua.VariantType: ...


@syncfunc(aio_func=common.copy_node_util.copy_node)
def copy_node(
    parent: SyncNode, node: SyncNode, nodeid: ua.NodeId | None = None, recursive: bool = True
) -> list[SyncNode]: ...


@syncfunc(aio_func=common.instantiate_util.instantiate)
def instantiate(
    parent: SyncNode,
    node_type: SyncNode,
    nodeid: ua.NodeId | None = None,
    bname: ua.QualifiedName | None = None,
    dname: ua.LocalizedText | None = None,
    idx: int = 0,
    instantiate_optional: bool = True,
) -> list[SyncNode]: ...


class _SubHandler:
    def __init__(self, tloop: ThreadLoop, handlers: _HandlerThread, sync_handler: Any) -> None:
        self.tloop: ThreadLoop = tloop
        self.handlers: _HandlerThread = handlers
        self.sync_handler: Any = sync_handler
        if hasattr(sync_handler, "datachange_notification"):
            self.datachange_notification = self._datachange_notification
        if hasattr(sync_handler, "event_notification"):
            self.event_notification = self._event_notification
        if hasattr(sync_handler, "status_change_notification"):
            self.status_change_notification = self._status_change_notification

    def _datachange_notification(self, node: node.Node, val: Any, data: Any) -> None:
        sync_node = SyncNode(self.tloop, node)
        self.handlers.submit(lambda: self.sync_handler.datachange_notification(sync_node, val, data))

    def _event_notification(self, event: Event) -> None:
        self.handlers.submit(lambda: self.sync_handler.event_notification(event))

    def _status_change_notification(self, status: ua.StatusChangeNotification) -> None:
        self.handlers.submit(lambda: self.sync_handler.status_change_notification(status))


def _aio_property(name: str, writable: bool = True) -> Any:
    def getter(self: Any) -> Any:
        return getattr(self.aio_obj, name)

    def setter(self: Any, value: Any) -> None:
        setattr(self.aio_obj, name, value)

    return property(getter, setter if writable else None, doc=f"the ``{name}`` of the async object")


class _Owner:
    tloop: ThreadLoop
    close_tloop: bool
    _handlers: _HandlerThread
    _exit_hook: int | None

    def _ensure_loop(self) -> None:
        if self.close_tloop and not self.tloop.is_alive():
            self.tloop.start()

    def _stop_own_tloop(self) -> None:
        self._handlers.stop()
        self.tloop.remove_exit_hook(self._exit_hook)
        self._exit_hook = None
        if self.close_tloop:
            self.tloop.stop()

    def _note_drop(self) -> None:
        return None


class Client(_Owner):
    """
    Sync Client, see doc for async Client.

    The sync client has these extra parameters:

    - ``tloop``: the :class:`ThreadLoop` to run on. Without one the client starts its own and stops it at
      ``disconnect()``; ``connect()`` starts it again, so a client can be reconnected.
    - ``sync_wrapper_timeout``: how long (seconds, default 120, ``None`` for no limit) the wrapper waits for an async
      call to return; a call that takes longer is cancelled and raises ``TimeoutError``.
    - ``handler_queue_maxsize``: how many subscription callbacks may wait for the handler thread (default 1000);
      when the queue is full the oldest callback is dropped and the observer hears ``on_messages_dropped``.
    - ``observer``: an :class:`enginir_opcua.observer.Observer`; its hooks run on the loop thread.

    Subscription handlers, state listeners and ``connection_lost_callback`` run on a separate handler thread, so they
    may call the sync API.
    """

    def __init__(
        self,
        url: str | None = None,
        timeout: float = 4,
        tloop: ThreadLoop | None = None,
        sync_wrapper_timeout: float | None = 120,
        watchdog_intervall: float = 1.0,
        allow_deprecated_policies: bool = False,
        auto_reconnect: bool = False,
        reconnect_max_delay: float = 30.0,
        reconnect_request_timeout: float = 60.0,
        handler_queue_maxsize: int = 1000,
        observer: Observer | None = None,
        config: ClientConfig | None = None,
    ) -> None:
        self.tloop: ThreadLoop = tloop  # type: ignore[assignment]
        self.close_tloop: bool = False
        self._exit_hook: int | None = None
        self._handlers: _HandlerThread = _HandlerThread(
            "sync client handlers", handler_queue_maxsize, _HANDLER_GRACE, self._note_drop
        )
        if not self.tloop:
            self.tloop = ThreadLoop(sync_wrapper_timeout)
            self.tloop.start()
            self.close_tloop = True
        try:
            self.aio_obj: client.Client = client.Client(
                url,
                timeout,
                watchdog_intervall,
                auto_reconnect=auto_reconnect,
                reconnect_max_delay=reconnect_max_delay,
                reconnect_request_timeout=reconnect_request_timeout,
                allow_deprecated_policies=allow_deprecated_policies,
                observer=observer,
                config=config,
            )
            self.nodes: Shortcuts = Shortcuts(self.tloop, self.aio_obj.uaclient.session)
        except Exception:
            self._stop_own_tloop()
            raise

    @classmethod
    def quickstart(
        cls,
        url: str,
        profile: str = "secure",
        pki: str | Path | None = "./pki",
        username: str | None = None,
        password: str | None = None,
        tloop: ThreadLoop | None = None,
        **overrides: Any,
    ) -> Client:
        """
        Sync twin of Client.quickstart. ``tloop`` is the :class:`ThreadLoop` to run on, for example the one of a
        quickstart server; without one the client starts its own.
        """
        return cls(config=quickstart_client_config(url, profile, pki, username, password, overrides), tloop=tloop)

    def _note_drop(self) -> None:
        self.aio_obj.uaclient.observer.on_messages_dropped(None, 1)

    def __str__(self) -> str:
        return "Sync" + self.aio_obj.__str__()

    __repr__ = __str__

    application_uri = _aio_property("application_uri")
    name = _aio_property("name")
    description = _aio_property("description")
    product_uri = _aio_property("product_uri")
    server_uri = _aio_property("server_uri")
    security_policy = _aio_property("security_policy")
    session_timeout = _aio_property("session_timeout")
    secure_channel_timeout = _aio_property("secure_channel_timeout")
    max_messagesize = _aio_property("max_messagesize")
    max_chunkcount = _aio_property("max_chunkcount")
    strip_url_credentials = _aio_property("strip_url_credentials")
    session_state_path = _aio_property("session_state_path")
    application_hook = _aio_property("application_hook")
    observer = _aio_property("observer")
    server_url = _aio_property("server_url", writable=False)
    state = _aio_property("state", writable=False)

    @property
    def connection_lost_callback(self) -> Callable[[Exception], Any] | None:
        return self._connection_lost_callback

    @connection_lost_callback.setter
    def connection_lost_callback(self, callback: Callable[[Exception], Any] | None) -> None:
        self._connection_lost_callback = callback
        if callback is None:
            self.aio_obj.connection_lost_callback = None
            return

        async def forward(exc: Exception) -> None:
            self._handlers.submit(lambda: callback(exc))

        self.aio_obj.connection_lost_callback = forward

    _connection_lost_callback: Callable[[Exception], Any] | None = None

    def add_state_listener(self, callback: Callable[[client.ua_client.UaClientState], Any]) -> Callable[[], None]:
        return self.aio_obj.uaclient.add_state_listener(lambda state: self._handlers.submit(lambda: callback(state)))

    def connect(
        self,
        *,
        auto_reconnect: bool | None = None,
        reconnect_max_delay: float | None = None,
        reconnect_request_timeout: float | None = None,
    ) -> None:
        self._ensure_loop()
        self.tloop.post(
            self.aio_obj.connect(
                auto_reconnect=auto_reconnect,
                reconnect_max_delay=reconnect_max_delay,
                reconnect_request_timeout=reconnect_request_timeout,
            )
        )
        self.tloop.remove_exit_hook(self._exit_hook)
        self._exit_hook = self.tloop.add_exit_hook(self.aio_obj.disconnect)

    def disconnect(self) -> None:
        try:
            if self.tloop.is_running():
                self.tloop.post(self.aio_obj.disconnect())
        finally:
            self._stop_own_tloop()

    @syncmethod
    def connect_sessionless(self) -> None: ...

    def disconnect_sessionless(self) -> None:
        try:
            if self.tloop.is_running():
                self.tloop.post(self.aio_obj.disconnect_sessionless())
        finally:
            self._stop_own_tloop()

    @syncmethod
    def connect_socket(self) -> None: ...

    def disconnect_socket(self) -> None:
        try:
            self.aio_obj.disconnect_socket()
        finally:
            self._stop_own_tloop()

    def set_user(self, username: str) -> None:
        self.aio_obj.set_user(username)

    def set_password(self, pwd: str) -> None:
        self.aio_obj.set_password(pwd)

    def set_locale(self, locale: Sequence[str]) -> None:
        self.aio_obj.set_locale(locale)

    def set_max_concurrent_requests(self, max_concurrent_requests: int) -> None:
        self.aio_obj.set_max_concurrent_requests(max_concurrent_requests)

    @syncmethod
    def load_private_key(
        self, path: str, password: str | bytes | None = None, extension: str | None = None
    ) -> None: ...

    @syncmethod
    def load_client_certificate(self, path: str, extension: str | None = None) -> None: ...

    @syncmethod
    def setup_self_signed_certificate(
        self,
        key_file: Path,
        cert_file: Path,
        subject_attrs: dict[str, str] | None = None,
        extended: list[Any] | None = None,
        host_name: str | None = None,
    ) -> tuple[Path, Path]: ...

    @syncmethod
    def load_client_chain(self, certs: Iterable[uacrypto.CertProperties]) -> None: ...

    @syncmethod
    def load_type_definitions(self, nodes: Iterable[SyncNode] | None = None) -> dict[str, type]: ...

    @syncmethod
    def load_data_type_definitions(
        self, node: SyncNode | None = None, overwrite_existing: bool = False
    ) -> dict[str, type]: ...

    @syncmethod
    def get_namespace_array(self) -> list[str]: ...

    def set_trust_store(self, trust_store: TrustStore) -> None:
        self.aio_obj.set_trust_store(trust_store)

    @syncmethod
    def init_pki(self) -> x509.Certificate: ...

    @syncmethod
    def set_pki_directory(
        self, root: str | Path, create: bool = True, private_key_password: str | bytes | None = None
    ) -> None: ...

    @syncmethod
    def set_security(
        self,
        policy: type[security_policies.SecurityPolicy],
        certificate: str | uacrypto.CertProperties | bytes | Path | None = None,
        private_key: str | uacrypto.CertProperties | bytes | Path | None = None,
        private_key_password: str | bytes | None = None,
        server_certificate: str | uacrypto.CertProperties | bytes | None = None,
        mode: ua.MessageSecurityMode = ua.MessageSecurityMode.SignAndEncrypt,
        certificate_chain: Sequence[str | uacrypto.CertProperties | bytes | Path] | None = None,
    ) -> None: ...

    @syncmethod
    def set_security_string(self, string: str) -> None: ...

    @syncmethod
    def load_enums(self) -> dict[str, type]: ...

    def create_subscription(
        self,
        period: ua.CreateSubscriptionParameters | float,
        handler: Any = None,
        publishing: bool = True,
        *,
        queue_maxsize: int = 1000,
    ) -> Subscription:
        wrapped = _SubHandler(self.tloop, self._handlers, handler) if handler is not None else None
        coro = self.aio_obj.create_subscription(period, wrapped, publishing, queue_maxsize=queue_maxsize)
        aio_sub = self.tloop.post(coro)
        return Subscription(self.tloop, aio_sub)

    @syncmethod
    def delete_subscriptions(self, subscription_ids: Iterable[int]) -> list[ua.StatusCode]: ...

    @syncmethod
    def get_namespace_index(self, uri: str) -> int: ...

    def get_node(self, nodeid: SyncNode | ua.NodeId | str | int) -> SyncNode:
        aio_nodeid = nodeid.aio_obj if isinstance(nodeid, SyncNode) else nodeid
        return SyncNode(self.tloop, self.aio_obj.get_node(aio_nodeid))

    def get_root_node(self) -> SyncNode:
        return SyncNode(self.tloop, self.aio_obj.get_root_node())

    def get_objects_node(self) -> SyncNode:
        return SyncNode(self.tloop, self.aio_obj.get_objects_node())

    def get_server_node(self) -> SyncNode:
        return SyncNode(self.tloop, self.aio_obj.get_server_node())

    @syncmethod
    def connect_and_get_server_endpoints(self) -> list[ua.EndpointDescription]: ...

    @syncmethod
    def connect_and_find_servers(self) -> list[ua.ApplicationDescription]: ...

    @syncmethod
    def connect_and_find_servers_on_network(self) -> ua.FindServersOnNetworkResult: ...

    @syncmethod
    def send_hello(self) -> None: ...

    @syncmethod
    def open_secure_channel(self, renew: bool = False) -> None: ...

    @syncmethod
    def close_secure_channel(self) -> None: ...

    @syncmethod
    def get_endpoints(self) -> list[ua.EndpointDescription]: ...

    @syncmethod
    def register_server(
        self,
        server: Server,
        discovery_configuration: ua.DiscoveryConfiguration | None = None,
    ) -> None: ...

    @syncmethod
    def unregister_server(
        self,
        server: Server,
        discovery_configuration: ua.DiscoveryConfiguration | None = None,
    ) -> None: ...

    @syncmethod
    def find_servers(self, uris: Iterable[str] | None = None) -> list[ua.ApplicationDescription]: ...

    @syncmethod
    def find_servers_on_network(self) -> ua.FindServersOnNetworkResult: ...

    @syncmethod
    def create_session(self) -> ua.CreateSessionResult: ...

    @syncmethod
    def check_connection(self) -> None: ...

    def server_policy(self, token_type: ua.UserTokenType) -> ua.UserTokenPolicy:
        return self.aio_obj.server_policy(token_type)

    @syncmethod
    def activate_session(
        self,
        username: str | None = None,
        password: str | None = None,
        certificate: x509.Certificate | None = None,
    ) -> ua.ActivateSessionResult: ...

    @syncmethod
    def close_session(self) -> None: ...

    @syncmethod
    def delete_nodes(
        self, nodes: Iterable[SyncNode], recursive: bool = False
    ) -> tuple[list[SyncNode], list[ua.StatusCode]]: ...

    @syncmethod
    def import_xml(
        self,
        path: str | None = None,
        xmlstring: str | None = None,
        strict_mode: bool = True,
        auto_load_definitions: bool = True,
    ) -> list[ua.NodeId]: ...

    @syncmethod
    def export_xml(
        self,
        nodes: Iterable[SyncNode],
        path: str,
        export_values: bool = False,
        model_uris: list[str] | None = None,
    ) -> None: ...

    @syncmethod
    def register_namespace(self, uri: str) -> int: ...

    @syncmethod
    def register_nodes(self, nodes: Iterable[SyncNode]) -> list[SyncNode]: ...

    @syncmethod
    def unregister_nodes(self, nodes: Iterable[SyncNode]) -> None: ...

    @syncmethod
    def read_attributes(
        self, nodes: Iterable[SyncNode], attr: ua.AttributeIds = ua.AttributeIds.Value
    ) -> list[ua.DataValue]: ...

    @syncmethod
    def read_values(self, nodes: Iterable[SyncNode]) -> list[Any]: ...

    @syncmethod
    def write_values(
        self, nodes: Iterable[SyncNode], values: Iterable[Any], raise_on_partial_error: bool = True
    ) -> list[ua.StatusCode]: ...

    get_values = read_values  # legacy
    set_values = write_values  # legacy

    @syncmethod
    def browse_nodes(self, nodes: Iterable[SyncNode]) -> list[tuple[SyncNode, ua.BrowseResult]]: ...

    @syncmethod
    def translate_browsepaths(
        self, starting_node: ua.NodeId, relative_paths: Iterable[ua.RelativePath | str]
    ) -> list[ua.BrowsePathResult]: ...

    @staticmethod
    def find_endpoint(
        endpoints: Iterable[ua.EndpointDescription],
        security_mode: ua.MessageSecurityMode,
        policy_uri: str,
        url: str | None = None,
    ) -> ua.EndpointDescription:
        return client.Client.find_endpoint(endpoints, security_mode, policy_uri, url)

    def __enter__(self) -> Client:
        try:
            self.connect()
        except Exception:
            try:
                self.disconnect()
            except Exception:
                _logger.debug("disconnect after a failed connect failed", exc_info=True)
            raise
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self.disconnect()


class Shortcuts:
    root: SyncNode
    objects: SyncNode
    server: SyncNode
    base_object_type: SyncNode
    base_data_type: SyncNode
    base_event_type: SyncNode
    base_variable_type: SyncNode
    folder_type: SyncNode
    enum_data_type: SyncNode
    option_set_type: SyncNode
    types: SyncNode
    data_types: SyncNode
    event_types: SyncNode
    reference_types: SyncNode
    variable_types: SyncNode
    object_types: SyncNode
    namespace_array: SyncNode
    namespaces: SyncNode
    opc_binary: SyncNode
    base_structure_type: SyncNode
    base_union_type: SyncNode
    server_state: SyncNode
    service_level: SyncNode
    HasComponent: SyncNode
    HasProperty: SyncNode
    Organizes: SyncNode
    HasEncoding: SyncNode

    def __init__(self, tloop: ThreadLoop, aio_server: Any) -> None:
        self.tloop: ThreadLoop = tloop
        self.aio_obj: shortcuts.Shortcuts = shortcuts.Shortcuts(aio_server)
        for k, v in self.aio_obj.__dict__.items():
            setattr(self, k, SyncNode(self.tloop, v))


class Server(_Owner):
    """
    Sync Server, see doc for async Server.

    The sync server has these extra parameters:

    - ``tloop``: the :class:`ThreadLoop` to run on. Without one the server starts its own and stops it at ``stop()``.
    - ``sync_wrapper_timeout``: how long (seconds, default 120, ``None`` for no limit) the wrapper waits for an async
      call to return; a call that takes longer is cancelled and raises ``TimeoutError``.
    - ``handler_queue_maxsize``: how many subscription callbacks may wait for the handler thread (default 1000).

    Subscription handlers run on a separate handler thread, so they may call the sync API. Callbacks that the server
    itself calls on the loop thread (``set_attribute_value_callback``, ``set_attribute_value_setter``) must not.
    """

    def __init__(
        self,
        shelf_file: Path | None = None,
        tloop: ThreadLoop | None = None,
        sync_wrapper_timeout: float | None = 120,
        allow_no_security: bool = False,
        allow_deprecated_policies: bool = False,
        user_manager: UserManager | None = None,
        handler_queue_maxsize: int = 1000,
        config: ServerConfig | None = None,
    ) -> None:
        self.tloop: ThreadLoop = tloop  # type: ignore[assignment]
        self.close_tloop: bool = False
        self._exit_hook: int | None = None
        self._handlers: _HandlerThread = _HandlerThread(
            "sync server handlers", handler_queue_maxsize, _HANDLER_GRACE, self._note_drop
        )
        if not self.tloop:
            self.tloop = ThreadLoop(timeout=sync_wrapper_timeout)
            self.tloop.start()
            self.close_tloop = True
        try:
            self.aio_obj: server.Server = server.Server(
                user_manager=user_manager,
                allow_no_security=allow_no_security,
                allow_deprecated_policies=allow_deprecated_policies,
                config=config,
            )
            self.tloop.post(self.aio_obj.init(shelf_file))
            self.nodes: Shortcuts = Shortcuts(self.tloop, self.aio_obj.iserver.isession)
        except Exception:
            self._stop_own_tloop()
            raise

    @classmethod
    def quickstart(
        cls,
        endpoint: str,
        profile: str = "secure",
        pki: str | Path | None = "./pki",
        users: str | Path | UserManager | None = None,
        tloop: ThreadLoop | None = None,
        **overrides: Any,
    ) -> Server:
        """
        Sync twin of Server.quickstart. The sync server initialises itself in the constructor, so the PKI directory
        is created here. ``tloop`` is the :class:`ThreadLoop` to run on, for example the one of a quickstart client;
        without one the server starts its own.
        """
        return cls(config=quickstart_server_config(endpoint, profile, pki, users, overrides), tloop=tloop)

    def __str__(self) -> str:
        return "Sync" + self.aio_obj.__str__()

    __repr__ = __str__

    allow_plaintext_password = _aio_property("allow_plaintext_password")
    max_string_length = _aio_property("max_string_length")
    max_byte_string_length = _aio_property("max_byte_string_length")
    max_array_length = _aio_property("max_array_length")
    types = _aio_property("types", writable=False)

    def get_root_node(self) -> SyncNode:
        return SyncNode(self.tloop, self.aio_obj.get_root_node())

    def get_objects_node(self) -> SyncNode:
        return SyncNode(self.tloop, self.aio_obj.get_objects_node())

    @syncmethod
    def create_condition(
        self,
        source: SyncNode | ua.NodeId | None,
        condition_type: SyncNode | ua.NodeId | int,
        name: str,
        **options: Any,
    ) -> SyncCondition: ...

    @syncmethod
    def delete_condition(self, condition: SyncCondition) -> None: ...

    def get_condition(self, condition_id: ua.NodeId | SyncNode) -> SyncCondition | None:
        found = self.aio_obj.get_condition(_convert_in(condition_id))
        return SyncCondition(self.tloop, found) if found is not None else None

    @property
    def conditions(self) -> list[SyncCondition]:
        return [SyncCondition(self.tloop, found) for found in self.aio_obj.conditions]

    @syncmethod
    def refresh_required(self, subscription_ids: list[int] | None = None) -> None: ...

    def set_match_discovery_endpoint_url(self, match_discovery_endpoint_url: bool) -> None:
        self.aio_obj.set_match_discovery_endpoint_url(match_discovery_endpoint_url)

    def set_match_discovery_client_ip(self, match_discovery_client_ip: bool) -> None:
        self.aio_obj.set_match_discovery_client_ip(match_discovery_client_ip)

    def set_force_server_timestamp(self, force_server_timestamp: bool) -> None:
        self.aio_obj.set_force_server_timestamp(force_server_timestamp)

    def accept_server_registrations(self, enabled: bool = True) -> None:
        self.aio_obj.accept_server_registrations(enabled)

    def set_user_trust_store(self, trust_store: TrustStore) -> None:
        self.aio_obj.set_user_trust_store(trust_store)

    def set_certificate_validator(self, validator: Any) -> None:
        self.aio_obj.set_certificate_validator(validator)

    def set_application_hook(self, hook: Any) -> None:
        self.aio_obj.set_application_hook(hook)

    def set_attribute_value_setter(
        self, nodeid: ua.NodeId, setter: Callable[..., Any], attr: ua.AttributeIds = ua.AttributeIds.Value
    ) -> None:
        self.aio_obj.set_attribute_value_setter(nodeid, setter, attr)

    def read_attribute_value(self, nodeid: ua.NodeId, attr: ua.AttributeIds = ua.AttributeIds.Value) -> ua.DataValue:
        return self.aio_obj.read_attribute_value(nodeid, attr)

    def subscribe_server_callback(self, event: Any, handle: Callable[..., Any]) -> None:
        self.aio_obj.subscribe_server_callback(event, handle)

    def unsubscribe_server_callback(self, event: Any, handle: Callable[..., Any]) -> None:
        self.aio_obj.unsubscribe_server_callback(event, handle)

    @syncmethod
    def set_build_info(
        self,
        product_uri: str,
        manufacturer_name: str,
        product_name: str,
        software_version: str,
        build_number: str,
        build_date: datetime,
    ) -> None: ...

    @syncmethod
    def load_certificate_chain(self, chain: Iterable[str | bytes | Path]) -> None: ...

    @syncmethod
    def find_servers(self, uris: list[str] | None = None) -> list[ua.ApplicationDescription]: ...

    @syncmethod
    def get_endpoints(self) -> list[ua.EndpointDescription]: ...

    @syncmethod
    def register_to_discovery(
        self,
        url: str = "opc.tcp://localhost:4840",
        period: int = 60,
        discovery_configuration: ua.DiscoveryConfiguration | None = None,
    ) -> None: ...

    @syncmethod
    def unregister_from_discovery(
        self,
        url: str = "opc.tcp://localhost:4840",
        discovery_configuration: ua.DiscoveryConfiguration | None = None,
    ) -> None: ...

    @syncmethod
    def create_custom_data_type(
        self,
        idx: int | ua.NodeId,
        name: str | ua.QualifiedName,
        basetype: ua.NodeId | int = ua.ObjectIds.BaseDataType,
        properties: list[tuple[Any, ...]] | None = None,
        description: str | None = None,
    ) -> SyncNode: ...

    @syncmethod
    def create_custom_event_type(
        self,
        idx: int | ua.NodeId,
        name: str | ua.QualifiedName,
        basetype: ua.NodeId | int = ua.ObjectIds.BaseEventType,
        properties: list[tuple[Any, ...]] | None = None,
    ) -> SyncNode: ...

    @syncmethod
    def create_custom_object_type(
        self,
        idx: int | ua.NodeId,
        name: str | ua.QualifiedName,
        basetype: ua.NodeId | int = ua.ObjectIds.BaseObjectType,
        properties: list[tuple[Any, ...]] | None = None,
        variables: list[tuple[Any, ...]] | None = None,
        methods: list[tuple[Any, ...]] | None = None,
    ) -> SyncNode: ...

    @syncmethod
    def create_custom_variable_type(
        self,
        idx: int | ua.NodeId,
        name: str | ua.QualifiedName,
        basetype: ua.NodeId | int = ua.ObjectIds.BaseVariableType,
        properties: list[tuple[Any, ...]] | None = None,
        variables: list[tuple[Any, ...]] | None = None,
        methods: list[tuple[Any, ...]] | None = None,
    ) -> SyncNode: ...

    @syncmethod
    def export_xml(
        self,
        nodes: Iterable[SyncNode],
        path: str,
        export_values: bool = False,
        model_uris: list[str] | None = None,
    ) -> None: ...

    @syncmethod
    def export_xml_by_ns(
        self, path: str, namespaces: list[str | int] | None = None, export_values: bool = False
    ) -> None: ...

    @syncmethod
    def delete_nodes(
        self, nodes: Iterable[SyncNode], recursive: bool = False
    ) -> tuple[list[SyncNode], list[ua.StatusCode]]: ...

    @syncmethod
    def read_attributes(
        self, nodes: Iterable[SyncNode], attr: ua.AttributeIds = ua.AttributeIds.Value
    ) -> list[ua.DataValue]: ...

    @syncmethod
    def historize_node_data_change(
        self,
        node: SyncNode | list[SyncNode] | tuple[SyncNode, ...],
        period: timedelta = timedelta(days=7),
        count: int = 0,
    ) -> None: ...

    @syncmethod
    def dehistorize_node_data_change(self, node: SyncNode | list[SyncNode] | tuple[SyncNode, ...]) -> None: ...

    @syncmethod
    def historize_node_event(
        self,
        node: SyncNode | list[SyncNode] | tuple[SyncNode, ...],
        period: timedelta = timedelta(days=7),
        count: int = 0,
    ) -> None: ...

    @syncmethod
    def dehistorize_node_event(self, node: SyncNode | list[SyncNode] | tuple[SyncNode, ...]) -> None: ...

    def __enter__(self) -> Server:
        self.start()
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self.stop()

    @syncmethod
    def load_certificate(self, path_or_content: str | bytes | Path, format: str | None = None) -> None: ...

    @syncmethod
    def load_private_key(
        self, path_or_content: str | Path | bytes, password: str | bytes | None = None, format: str | None = None
    ) -> None: ...

    def set_endpoint(self, url: str) -> None:
        return self.aio_obj.set_endpoint(url)

    def set_server_name(self, name: str) -> None:
        return self.aio_obj.set_server_name(name)

    def get_application_uri(self) -> str:
        return self.aio_obj.get_application_uri()

    @syncmethod
    def set_application_uri(self, uri: str) -> None: ...

    def set_security_policy(
        self, security_policy: list[ua.SecurityPolicyType], permission_ruleset: Any | None = None
    ) -> None:
        return self.aio_obj.set_security_policy(security_policy, permission_ruleset)

    def set_security_IDs(self, policy_ids: list[str]) -> None:
        return self.aio_obj.set_security_IDs(policy_ids)

    def set_trust_store(self, trust_store: TrustStore) -> None:
        return self.aio_obj.set_trust_store(trust_store)

    @syncmethod
    def init_pki(self) -> x509.Certificate: ...

    @syncmethod
    def set_pki_directory(
        self, root: str | Path, create: bool = True, private_key_password: str | bytes | None = None
    ) -> None: ...

    def set_user_pki_directory(self, root: str | Path, create: bool = True) -> None:
        return self.aio_obj.set_user_pki_directory(root, create)

    @syncmethod
    def reload_trust_store(self) -> None: ...

    # --- File transfer and certificate management (Part 20, Part 12) ---
    @syncmethod
    def add_file(
        self,
        parent: SyncNode | ua.NodeId,
        name: str,
        provider: FileProvider | str | Path,
        *,
        writable: bool = False,
        max_size: int | None = None,
        mime_type: str | None = None,
        max_byte_string_length: int | None = None,
        write_role: UserRole = UserRole.User,
        namespace: int | None = None,
    ) -> SyncNode: ...

    @syncmethod
    def add_directory(
        self,
        parent: SyncNode | ua.NodeId,
        name: str,
        root: str | Path,
        *,
        writable: bool = False,
        max_file_size: int | None = None,
        max_entries: int = 10_000,
        write_role: UserRole = UserRole.User,
        namespace: int | None = None,
    ) -> SyncNode: ...

    @syncmethod
    def refresh_directory(self, directory: SyncNode | ua.NodeId) -> None: ...

    @syncmethod
    def enable_push_management(
        self,
        *,
        max_trust_list_size: int = 65_535,
        min_security_mode: ua.MessageSecurityMode = ua.MessageSecurityMode.SignAndEncrypt,
        activity_timeout: float = 60.0,
    ) -> Any: ...

    # --- end of File transfer and certificate management ---

    def set_identity_tokens(self, tokens: list[type]) -> None:
        return self.aio_obj.set_identity_tokens(tokens)

    def disable_clock(self, val: bool = True) -> None:
        return self.aio_obj.disable_clock(val)

    @syncmethod
    def register_namespace(self, uri: str) -> int: ...

    @syncmethod
    def get_namespace_array(self) -> list[str]: ...

    def start(self) -> None:
        self._ensure_loop()
        self.tloop.post(self.aio_obj.start())
        self.tloop.remove_exit_hook(self._exit_hook)
        self._exit_hook = self.tloop.add_exit_hook(self.aio_obj.stop)

    def stop(self) -> None:
        try:
            if self.tloop.is_running():
                self.tloop.post(self.aio_obj.stop())
        finally:
            self._stop_own_tloop()

    def link_method(self, node: SyncNode, callback: Callable[..., Any]) -> None:
        return self.aio_obj.link_method(node, callback)

    @syncmethod
    def get_event_generator(
        self, etype: Any | None = None, emitting_node: ua.NodeId | int = ua.ObjectIds.Server
    ) -> EventGenerator: ...

    def get_node(self, nodeid: SyncNode | ua.NodeId | str | int) -> SyncNode:
        aio_nodeid = nodeid.aio_obj if isinstance(nodeid, SyncNode) else nodeid
        return SyncNode(self.tloop, self.aio_obj.get_node(aio_nodeid))

    @syncmethod
    def import_xml(
        self,
        path: str | None = None,
        xmlstring: str | None = None,
        strict_mode: bool = True,
        auto_load_definitions: bool = True,
    ) -> list[ua.NodeId]: ...

    @syncmethod
    def get_namespace_index(self, uri: str) -> int: ...

    @syncmethod
    def load_enums(self) -> dict[str, type]: ...

    @syncmethod
    def load_type_definitions(self, nodes: Iterable[SyncNode] | None = None) -> Any: ...

    @syncmethod
    def load_data_type_definitions(
        self, node: SyncNode | None = None, overwrite_existing: bool = False
    ) -> dict[str, type]: ...

    @syncmethod
    def write_attribute_value(
        self, nodeid: ua.NodeId, datavalue: ua.DataValue, attr: ua.AttributeIds = ua.AttributeIds.Value
    ) -> None: ...

    def set_attribute_value_callback(
        self,
        nodeid: ua.NodeId,
        callback: Callable[[ua.NodeId, ua.AttributeIds], ua.DataValue],
        attr: ua.AttributeIds = ua.AttributeIds.Value,
    ) -> None:
        self.aio_obj.set_attribute_value_callback(nodeid, callback, attr)

    def create_subscription(
        self,
        period: ua.CreateSubscriptionParameters | float,
        handler: Any = None,
        *,
        queue_maxsize: int = 1000,
    ) -> Subscription:
        wrapped = _SubHandler(self.tloop, self._handlers, handler) if handler is not None else None
        coro = self.aio_obj.create_subscription(period, wrapped, queue_maxsize=queue_maxsize)
        aio_sub = self.tloop.post(coro)
        return Subscription(self.tloop, aio_sub)


class EventGenerator:
    def __init__(self, tloop: ThreadLoop, aio_evgen: server.event_generator.EventGenerator) -> None:
        self.aio_obj: server.event_generator.EventGenerator = aio_evgen
        self.tloop: ThreadLoop = tloop

    @property
    def event(self) -> Event:
        return self.aio_obj.event

    def trigger(self, time: datetime | None = None, message: str | None = None) -> None:
        return self.tloop.post(self.aio_obj.trigger(time, message))


def new_node(sync_node: SyncNode, nodeid: ua.NodeId | str | int) -> SyncNode:
    """
    given a sync node, create a new SyncNode with the given nodeid
    """
    return SyncNode(sync_node.tloop, node.Node(sync_node.aio_obj.session, nodeid))


class SyncNode:
    def __init__(self, tloop: ThreadLoop, aio_node: node.Node) -> None:
        self.aio_obj: node.Node = aio_node
        self.tloop: ThreadLoop = tloop

    def __eq__(self, other: object) -> bool:
        return other is not None and isinstance(other, SyncNode) and self.aio_obj == other.aio_obj

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __str__(self) -> str:
        return self.aio_obj.__str__()

    def __repr__(self) -> str:
        return "Sync" + self.aio_obj.__repr__()

    def __hash__(self) -> int:
        return self.aio_obj.__hash__()

    def __get_nodeid(self) -> ua.NodeId:
        return self.aio_obj.nodeid

    def __set_nodeid(self, value: ua.NodeId) -> None:
        self.aio_obj.nodeid = value

    nodeid: ua.NodeId = property(__get_nodeid, __set_nodeid)

    @syncmethod
    def read_type_definition(self) -> ua.NodeId | None: ...

    @syncmethod
    def get_parent(self) -> SyncNode | None: ...

    @syncmethod
    def read_node_class(self) -> ua.NodeClass: ...

    @syncmethod
    def read_attribute(
        self,
        attr: ua.AttributeIds,
        indexrange: str | None = None,
        raise_on_bad_status: bool = True,
    ) -> ua.DataValue: ...

    @syncmethod
    def write_attribute(
        self,
        attributeid: ua.AttributeIds,
        datavalue: ua.DataValue,
        indexrange: str | None = None,
    ) -> None: ...

    @syncmethod
    def read_browse_name(self) -> ua.QualifiedName: ...

    @syncmethod
    def read_display_name(self) -> ua.LocalizedText: ...

    @syncmethod
    def read_data_type(self) -> ua.NodeId: ...

    @syncmethod
    def read_array_dimensions(self) -> list[int]: ...

    @syncmethod
    def read_value_rank(self) -> int: ...

    @syncmethod
    def delete(self, delete_references: bool = True, recursive: bool = False) -> list[SyncNode]: ...

    @syncmethod
    def get_children(
        self,
        refs: SyncNode | ua.NodeId | str | int = ua.ObjectIds.HierarchicalReferences,
        nodeclassmask: ua.NodeClass = ua.NodeClass.Unspecified,
    ) -> list[SyncNode]: ...

    @syncmethod
    def get_properties(self) -> list[SyncNode]: ...

    @syncmethod
    def get_children_descriptions(
        self,
        refs: int = ua.ObjectIds.HierarchicalReferences,
        nodeclassmask: ua.NodeClass = ua.NodeClass.Unspecified,
        includesubtypes: bool = True,
        result_mask: ua.BrowseResultMask = ua.BrowseResultMask.All,
    ) -> list[ua.ReferenceDescription]: ...

    @syncmethod
    def get_user_access_level(self) -> set[ua.AccessLevel]: ...

    @overload
    def get_child(
        self,
        path: ua.QualifiedName | str | Iterable[ua.QualifiedName | str],
        return_all: Literal[False] = False,
    ) -> SyncNode: ...

    @overload
    def get_child(
        self,
        path: ua.QualifiedName | str | Iterable[ua.QualifiedName | str],
        return_all: Literal[True] = True,
    ) -> list[SyncNode]: ...

    @syncmethod
    def get_child(
        self,
        path: ua.QualifiedName | str | Iterable[ua.QualifiedName | str],
        return_all: bool = False,
    ) -> SyncNode | list[SyncNode]: ...

    @syncmethod
    def get_children_by_path(
        self,
        paths: Iterable[ua.QualifiedName | str | Iterable[ua.QualifiedName | str]],
        raise_on_partial_error: bool = True,
    ) -> list[list[SyncNode | None]]: ...

    @syncmethod
    def read_raw_history(
        self,
        starttime: datetime | None = None,
        endtime: datetime | None = None,
        numvalues: int = 0,
        return_bounds: bool = False,
    ) -> list[ua.DataValue]: ...

    @syncmethod
    def history_read(
        self,
        details: ua.ReadRawModifiedDetails,
        continuation_point: bytes | None = None,
        release_continuation_point: bool = False,
    ) -> ua.HistoryReadResult: ...

    @syncmethod
    def read_event_history(
        self,
        starttime: datetime | None = None,
        endtime: datetime | None = None,
        numvalues: int = 0,
        evtypes: SyncNode
        | ua.NodeId
        | str
        | int
        | Iterable[SyncNode | ua.NodeId | str | int] = ua.ObjectIds.BaseEventType,
    ) -> list[Event]: ...

    @syncmethod
    def history_read_events(
        self,
        details: ua.ReadEventDetails,
        continuation_point: bytes | None = None,
        release_continuation_point: bool = False,
    ) -> ua.HistoryReadResult: ...

    @syncmethod
    def set_modelling_rule(self, mandatory: bool) -> None: ...

    @syncmethod
    def add_variable(
        self,
        nodeid: ua.NodeId | str,
        bname: ua.QualifiedName | str,
        val: Any,
        varianttype: ua.VariantType | None = None,
        datatype: ua.NodeId | int | None = None,
    ) -> SyncNode: ...

    @syncmethod
    def add_property(
        self,
        nodeid: ua.NodeId | str,
        bname: ua.QualifiedName | str,
        val: Any,
        varianttype: ua.VariantType | None = None,
        datatype: ua.NodeId | int | None = None,
    ) -> SyncNode: ...

    @syncmethod
    def add_object(
        self,
        nodeid: ua.NodeId | str,
        bname: ua.QualifiedName | str,
        objecttype: int | None = None,
        instantiate_optional: bool = True,
    ) -> SyncNode: ...

    @syncmethod
    def add_object_type(
        self, nodeid: ua.NodeId | str | int, bname: ua.QualifiedName | str, is_abstract: bool = False
    ) -> SyncNode: ...

    @syncmethod
    def add_variable_type(
        self,
        nodeid: ua.NodeId | str | int,
        bname: ua.QualifiedName | str,
        datatype: ua.NodeId | int,
        is_abstract: bool = False,
        value: Any = None,
    ) -> SyncNode: ...

    @syncmethod
    def add_folder(self, nodeid: ua.NodeId | str, bname: ua.QualifiedName | str) -> SyncNode: ...

    @syncmethod
    def add_method(
        self,
        nodeid: ua.NodeId | str | int,
        bname: ua.QualifiedName | str,
        callback: Callable[..., Any] | None = None,
        inputs: list[Any] | None = None,
        outputs: list[Any] | None = None,
    ) -> SyncNode: ...

    @syncmethod
    def add_data_type(
        self,
        nodeid: ua.NodeId | str | int,
        bname: ua.QualifiedName | str,
        description: str | None = None,
        is_abstract: bool = False,
    ) -> SyncNode: ...

    @syncmethod
    def set_writable(self, writable: bool = True) -> None: ...

    @syncmethod
    def write_value(self, value: Any, varianttype: ua.VariantType | None = None) -> None: ...

    set_value = write_value  # legacy
    set_data_value = write_value  # legacy

    @syncmethod
    def write_params(self, params: ua.WriteParameters) -> list[ua.StatusCode]: ...

    @syncmethod
    def read_params(self, params: ua.ReadParameters) -> list[ua.DataValue]: ...

    @syncmethod
    def read_value(self) -> Any: ...

    get_value = read_value  # legacy

    @syncmethod
    def read_data_value(self, raise_on_bad_status: bool = True) -> ua.DataValue: ...

    get_data_value = read_data_value  # legacy

    @syncmethod
    def read_data_type_as_variant_type(self) -> ua.VariantType: ...

    get_data_type_as_variant_type = read_data_type_as_variant_type  # legacy

    @syncmethod
    def call_method(
        self, methodid: ua.NodeId | ua.QualifiedName | str, *args: Any, timeout: float | None = None
    ) -> Any: ...

    @syncmethod
    def get_references(
        self,
        refs: SyncNode | ua.NodeId | str | int = ua.ObjectIds.References,
        direction: ua.BrowseDirection = ua.BrowseDirection.Both,
        nodeclassmask: ua.NodeClass = ua.NodeClass.Unspecified,
        includesubtypes: bool = True,
        result_mask: ua.BrowseResultMask = ua.BrowseResultMask.All,
    ) -> list[ua.ReferenceDescription]: ...

    @syncmethod
    def add_reference(
        self,
        target: SyncNode | ua.NodeId | str | int,
        reftype: SyncNode | ua.NodeId | str | int,
        forward: bool = True,
        bidirectional: bool = True,
        target_class: ua.NodeClass | None = None,
    ) -> None: ...

    @syncmethod
    def read_description(self) -> ua.LocalizedText: ...

    @syncmethod
    def get_variables(self) -> list[SyncNode]: ...

    @overload
    def get_path(self, max_length: int = 20, as_string: Literal[False] = False) -> list[SyncNode]: ...

    @overload
    def get_path(self, max_length: int = 20, as_string: Literal[True] = True) -> list[str]: ...

    @syncmethod
    def get_path(self, max_length: int = 20, as_string: bool = False) -> list[SyncNode] | list[str]: ...

    @syncmethod
    def read_attributes(self, attrs: Iterable[ua.AttributeIds]) -> list[ua.DataValue]: ...

    @syncmethod
    def add_reference_type(
        self,
        nodeid: ua.NodeId | str,
        bname: ua.QualifiedName | str,
        symmetric: bool = True,
        inversename: str | None = None,
    ) -> SyncNode: ...

    @syncmethod
    def delete_reference(
        self,
        target: SyncNode | ua.NodeId | str | int,
        reftype: SyncNode | ua.NodeId | str | int,
        forward: bool = True,
        bidirectional: bool = True,
    ) -> None: ...

    @syncmethod
    def get_access_level(self) -> set[ua.AccessLevel]: ...

    @syncmethod
    def get_description_refs(self) -> list[SyncNode]: ...

    @syncmethod
    def get_encoding_refs(self) -> list[SyncNode]: ...

    @syncmethod
    def get_methods(self) -> list[SyncNode]: ...

    @syncmethod
    def get_referenced_nodes(
        self,
        refs: SyncNode | ua.NodeId | str | int = ua.ObjectIds.References,
        direction: ua.BrowseDirection = ua.BrowseDirection.Both,
        nodeclassmask: ua.NodeClass = ua.NodeClass.Unspecified,
        includesubtypes: bool = True,
    ) -> list[SyncNode]: ...

    @syncmethod
    def read_data_type_definition(self) -> ua.DataTypeDefinition: ...

    @syncmethod
    def read_event_notifier(self) -> set[ua.EventNotifier]: ...

    @syncmethod
    def register(self) -> None: ...

    @syncmethod
    def set_attr_bit(self, attr: ua.AttributeIds, bit: int) -> None: ...

    @syncmethod
    def set_event_notifier(self, values: Iterable[ua.EventNotifier]) -> None: ...

    @syncmethod
    def unregister(self) -> None: ...

    @syncmethod
    def unset_attr_bit(self, attr: ua.AttributeIds, bit: int) -> None: ...

    @syncmethod
    def write_array_dimensions(self, value: int) -> None: ...

    @syncmethod
    def write_data_type_definition(self, sdef: ua.DataTypeDefinition) -> None: ...

    @syncmethod
    def write_value_rank(self, value: int) -> None: ...

    @syncmethod
    def set_read_only(self) -> None: ...

    @syncmethod
    def history_update(self, details: ua.HistoryUpdateDetails) -> ua.HistoryUpdateResult: ...


class SyncCondition:
    """
    Sync twin of the server's Condition handle (Alarms and Conditions, see Server.create_condition). The calls block
    until the server has changed the state and published the events; the properties read the current state.
    """

    def __init__(self, tloop: ThreadLoop, condition: ServerCondition) -> None:
        self.tloop: ThreadLoop = tloop
        self.aio_obj: ServerCondition = condition

    def __str__(self) -> str:
        return f"SyncCondition({self.aio_obj.name}, {self.aio_obj.condition_id})"

    __repr__ = __str__

    @property
    def node(self) -> SyncNode:
        return SyncNode(self.tloop, self.aio_obj.node)

    name = _aio_property("name", writable=False)
    type_id = _aio_property("type_id", writable=False)
    source_id = _aio_property("source_id", writable=False)
    source_name = _aio_property("source_name", writable=False)
    condition_id = _aio_property("condition_id", writable=False)
    enabled = _aio_property("enabled", writable=False)
    retain = _aio_property("retain", writable=False)
    acked = _aio_property("acked", writable=False)
    confirmed = _aio_property("confirmed", writable=False)
    active = _aio_property("active", writable=False)
    severity = _aio_property("severity", writable=False)
    shelving_state = _aio_property("shelving_state", writable=False)
    branches = _aio_property("branches", writable=False)
    limits = _aio_property("limits", writable=False)
    deadbands = _aio_property("deadbands", writable=False)
    severities = _aio_property("severities", writable=False)

    def last_event_id(self, branch_id: ua.NodeId | None = None) -> bytes | None:
        return self.aio_obj.last_event_id(branch_id)

    def retained_events(self) -> list[Any]:
        return self.aio_obj.retained_events()

    @syncmethod
    def enable(self) -> None: ...

    @syncmethod
    def disable(self) -> None: ...

    @syncmethod
    def activate(self, severity: int | None = None, message: str | ua.LocalizedText | None = None) -> None: ...

    @syncmethod
    def deactivate(self, message: str | ua.LocalizedText | None = None) -> None: ...

    @syncmethod
    def set_severity(self, severity: int) -> None: ...

    @syncmethod
    def set_quality(self, quality: ua.StatusCode) -> None: ...

    @syncmethod
    def set_retain(self, retain: bool) -> None: ...

    @syncmethod
    def set_suppressed(self, flag: bool) -> None: ...

    @syncmethod
    def set_out_of_service(self, flag: bool) -> None: ...

    @syncmethod
    def acknowledge(
        self, event_id: bytes | None = None, comment: str | ua.LocalizedText | None = None, *, user: str | None = None
    ) -> None: ...

    @syncmethod
    def confirm(
        self, event_id: bytes | None = None, comment: str | ua.LocalizedText | None = None, *, user: str | None = None
    ) -> None: ...

    @syncmethod
    def add_comment(
        self, comment: str | ua.LocalizedText, event_id: bytes | None = None, *, user: str | None = None
    ) -> None: ...

    @syncmethod
    def update_value(self, value: Any, setpoint: float | None = None) -> None: ...

    @syncmethod
    def set_limits(
        self,
        limits: Mapping[str, float] | None = None,
        deadbands: Mapping[str, float] | None = None,
        severities: Mapping[str, int] | None = None,
    ) -> None: ...

    @syncmethod
    def shelve_timed(
        self, milliseconds: float, comment: str | ua.LocalizedText | None = None, *, user: str | None = None
    ) -> None: ...

    @syncmethod
    def shelve_one_shot(self, comment: str | ua.LocalizedText | None = None, *, user: str | None = None) -> None: ...

    @syncmethod
    def unshelve(self, comment: str | ua.LocalizedText | None = None, *, user: str | None = None) -> None: ...


class Subscription:
    def __init__(self, tloop: ThreadLoop, sub: subscription.Subscription) -> None:
        self.tloop: ThreadLoop = tloop
        self.aio_obj: subscription.Subscription = sub

    def __enter__(self) -> Subscription:
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, tb: Any) -> None:
        self.delete()

    def __iter__(self) -> Subscription:
        return self

    def __next__(self) -> subscription.SubEvent:
        try:
            return self._wrap_event(self.tloop.post(self.aio_obj.__anext__(), timeout=None))
        except StopAsyncIteration:
            raise StopIteration from None

    def next_event(self, timeout: float | None = None) -> subscription.SubEvent | None:
        limit = None if timeout is None else timeout + _NEXT_EVENT_GRACE
        event = self.tloop.post(self.aio_obj.next_event(timeout=timeout), timeout=limit)
        return self._wrap_event(event) if event is not None else None

    def _wrap_event(self, event: subscription.SubEvent) -> subscription.SubEvent:
        if isinstance(event, subscription.DataChangeEvent):
            return subscription.DataChangeEvent(
                node=SyncNode(self.tloop, event.node),  # type: ignore[arg-type]
                value=event.value,
                data=event.data,
            )
        return event

    @syncmethod
    def subscribe_data_change(
        self,
        nodes: SyncNode | Iterable[SyncNode],
        attr: ua.AttributeIds = ua.AttributeIds.Value,
        queuesize: int = 0,
        monitoring: ua.MonitoringMode = ua.MonitoringMode.Reporting,
        sampling_interval: ua.Duration = -1,
    ) -> int | list[int | ua.StatusCode]: ...

    @syncmethod
    def subscribe_events(
        self,
        sourcenode: SyncNode | ua.NodeId | str | int = ua.ObjectIds.Server,
        evtypes: SyncNode
        | ua.NodeId
        | str
        | int
        | Iterable[SyncNode | ua.NodeId | str | int] = ua.ObjectIds.BaseEventType,
        evfilter: ua.EventFilter | None = None,
        queuesize: int = 0,
        where_clause_generation: bool = True,
    ) -> int: ...

    def _make_monitored_item_request(
        self,
        node: SyncNode,
        attr: ua.AttributeIds,
        mfilter: ua.MonitoringFilter | None,
        queuesize: int,
        monitoring: ua.MonitoringMode,
        sampling_interval: ua.Duration,
    ) -> ua.MonitoredItemCreateRequest:
        return self.aio_obj._make_monitored_item_request(node, attr, mfilter, queuesize, monitoring, sampling_interval)

    @syncmethod
    def unsubscribe(self, handle: int | Iterable[int]) -> None: ...

    @syncmethod
    def create_monitored_items(
        self, monitored_items: Iterable[ua.MonitoredItemCreateRequest]
    ) -> list[int | ua.StatusCode]: ...

    @syncmethod
    def delete(self) -> None: ...

    is_deleted = _aio_property("is_deleted", writable=False)

    def is_stale(self, margin: float) -> bool:
        return self.aio_obj.is_stale(margin)

    @syncmethod
    def update(self, params: ua.ModifySubscriptionParameters) -> ua.ModifySubscriptionResult: ...

    @syncmethod
    def recreate(self) -> None: ...

    @syncmethod
    def subscribe_alarms_and_conditions(
        self,
        sourcenode: SyncNode | ua.NodeId | str | int = ua.ObjectIds.Server,
        evtypes: SyncNode
        | ua.NodeId
        | str
        | int
        | Iterable[SyncNode | ua.NodeId | str | int] = ua.ObjectIds.ConditionType,
        evfilter: ua.EventFilter | None = None,
        queuesize: int = 0,
        refresh: bool = True,
    ) -> int: ...

    @syncmethod
    def modify_monitored_item(
        self,
        handle: int,
        new_samp_time: ua.Duration | None = None,
        new_queuesize: int | None = None,
        mod_filter_val: int | None = -1,
    ) -> list[ua.MonitoredItemModifyResult]: ...

    @syncmethod
    def deadband_monitor(
        self,
        var: SyncNode | Iterable[SyncNode],
        deadband_val: ua.Double,
        deadbandtype: ua.UInt32 = 1,
        queuesize: int = 0,
        attr: ua.AttributeIds = ua.AttributeIds.Value,
    ) -> int | list[int | ua.StatusCode]: ...

    @syncmethod
    def set_monitoring_mode(
        self, monitoring: ua.MonitoringMode, handles: int | Iterable[int] | None = None
    ) -> list[ua.StatusCode]: ...

    @syncmethod
    def set_publishing_mode(self, publishing: bool) -> list[ua.StatusCode]: ...


class XmlExporter:
    def __init__(self, sync_server: Server) -> None:
        self.tloop: ThreadLoop = sync_server.tloop
        self.aio_obj: xmlexporter.XmlExporter = xmlexporter.XmlExporter(sync_server.aio_obj)

    @syncmethod
    def build_etree(self, node_list: Iterable[SyncNode], uris: list[str] | None = None) -> None: ...

    @syncmethod
    def write_xml(self, xmlpath: Path, pretty: bool = True) -> None: ...


class DataTypeDictionaryBuilder:
    def __init__(
        self, server: Server, idx: int, ns_urn: str, dict_name: str, dict_node_id: ua.NodeId | None = None
    ) -> None:
        self.tloop: ThreadLoop = server.tloop
        self.aio_obj: type_dictionary_builder.DataTypeDictionaryBuilder = (
            type_dictionary_builder.DataTypeDictionaryBuilder(server.aio_obj, idx, ns_urn, dict_name, dict_node_id)
        )
        self.init()

    @property
    def dict_id(self) -> ua.NodeId | None:
        return self.aio_obj.dict_id

    @syncmethod
    def init(self) -> None: ...

    @syncmethod
    def create_data_type(self, type_name: str, nodeid: ua.NodeId | None = None, init: bool = True) -> Any: ...

    @syncmethod
    def set_dict_byte_string(self) -> None: ...


def new_struct_field(
    name: str,
    dtype: ua.NodeId | SyncNode | ua.VariantType,
    array: bool = False,
    optional: bool = False,
    description: str = "",
) -> ua.StructureField:
    if isinstance(dtype, SyncNode):
        dtype = dtype.aio_obj
    return common.structures104.new_struct_field(name, dtype, array, optional, description)


@syncfunc(aio_func=common.structures104.new_enum)
def new_enum(
    server: Server | Client,
    idx: int | ua.NodeId,
    name: str | ua.QualifiedName,
    values: list[str],
    optional: bool = False,
) -> SyncNode: ...


@syncfunc(aio_func=common.structures104.new_struct)
def new_struct(
    server: Server | Client,
    idx: int | ua.NodeId,
    name: int | ua.QualifiedName,
    fields: list[ua.StructureField],
) -> tuple[SyncNode, list[SyncNode]]: ...
