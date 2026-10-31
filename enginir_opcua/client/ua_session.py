"""
OPC-UA Session: session-scoped state and services.

A `UaSession` owns the session lifecycle (CreateSession/ActivateSession/CloseSession),
the authentication token, the publish loop, and all session-scoped service calls
defined in `AbstractSession`. It uses a `UaClient` only as a transport.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from collections.abc import Callable, Iterable
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol

from enginir_opcua import ua
from enginir_opcua.common.methods import forget_input_arguments
from enginir_opcua.common.session_interface import AbstractSession
from enginir_opcua.common.utils import Buffer
from enginir_opcua.observer import Observer
from enginir_opcua.ua.ua_binary import struct_from_binary
from enginir_opcua.ua.uaerrors import (
    BadNoSubscription,
    BadSecureChannelClosed,
    BadSecureChannelIdInvalid,
    BadSessionClosed,
    BadSessionIdInvalid,
    BadSessionNotActivated,
    BadTimeout,
    BadTooManyPublishRequests,
    BadUserAccessDenied,
    UaStructParsingError,
)

if TYPE_CHECKING:
    from enginir_opcua.client.ua_client import UaClient


_logger = logging.getLogger(__name__)

NO_SUBSCRIPTION_RETRY_DELAYS = (0.1, 1.0)
PUBLISH_ERROR_RETRY_DELAY = 1.0
PUBLISH_ERROR_MAX_DELAY = 30.0
PUBLISH_DECODE_ERROR_LIMIT = 5
ROUND_TRIP_WEIGHT = 0.3
SESSION_LOST_ERRORS = (
    ConnectionError,
    BadSessionClosed,
    BadSessionIdInvalid,
    BadSessionNotActivated,
    BadSecureChannelClosed,
    BadSecureChannelIdInvalid,
)
ROUND_TRIP_REQUESTS = (
    ua.ReadRequest,
    ua.CreateSubscriptionRequest,
    ua.ModifySubscriptionRequest,
    ua.SetPublishingModeRequest,
    ua.CreateMonitoredItemsRequest,
)


def check_result_count(requested: int, received: int) -> None:
    if requested != received:
        raise ua.UaError(f"The server answered {received} results for {requested} request items")


class Sink(Protocol):
    def enqueue(self, result: ua.PublishResult) -> None: ...


class SinkMap(dict[int, Any]):
    def __init__(self, changed: Callable[[Iterable[int]], None]) -> None:
        super().__init__()
        self._changed = changed

    def __setitem__(self, key: int, value: Any) -> None:
        super().__setitem__(key, value)
        self._changed(())

    def __delitem__(self, key: int) -> None:
        super().__delitem__(key)
        self._changed((key,))

    def pop(self, key: int, *default: Any) -> Any:
        present = key in self
        value = super().pop(key, *default)
        if present:
            self._changed((key,))
        return value

    def clear(self) -> None:
        keys = tuple(self)
        super().clear()
        self._changed(keys)


class SessionState(Enum):
    NEW = "new"
    CREATING = "creating"
    CREATED = "created"
    ACTIVATING = "activating"
    ACTIVATED = "activated"
    CLOSING = "closing"
    CLOSED = "closed"


class UaSession(AbstractSession):
    """
    Owns the OPC-UA session: authentication token, publish loop, subscription
    callbacks, and the AbstractSession service set. Uses a `UaClient` for
    transport-level RPC.
    """

    def __init__(self, client: UaClient) -> None:
        self.logger = logging.getLogger(f"{__name__}.UaSession")
        self._client = client
        self.authentication_token: ua.NodeId = ua.NodeId()
        self._state: SessionState = SessionState.NEW
        self.session_generation = 0
        self.max_outstanding_publish_requests = 10
        self.max_publish_timeout = 3600.0
        self.max_pending_acks = 2000
        self._subscription_callbacks: SinkMap = SinkMap(self._sinks_changed)
        self._publish_task: asyncio.Task[None] | None = None
        self._publish_workers: set[asyncio.Task[None]] = set()
        self._publish_wake = asyncio.Event()
        self._publish_suspended = False
        self._publish_in_flight = 0
        self._publish_limit: int | None = None
        self._ack_ledger: dict[tuple[int, int], None] = {}
        self._publishing_intervals: dict[int, float] = {}
        self._keep_alive_times: dict[int, float] = {}
        self._round_trip: float | None = None
        self._late_tasks: set[asyncio.Task[Any]] = set()
        self._sleeping_workers: set[asyncio.Task[Any]] = set()

    @property
    def observer(self) -> Observer:
        return self._client.observer

    @property
    def state(self) -> SessionState:
        return self._state

    def _set_state(self, target: SessionState) -> None:
        """Set state. Callers know the right transition; no validation here."""
        self._state = target

    @property
    def has_session(self) -> bool:
        """True when a server-side session exists that ActivateSession could reuse."""
        return self._state is not SessionState.CLOSED and not self.authentication_token.is_null()

    def restore_authentication_token(self, token: ua.NodeId) -> None:
        """Adopt `token` and bind it to the transport so the next ActivateSession
        resumes the matching server-side session instead of creating a new one."""
        self.authentication_token = token
        if self._client.protocol is not None:
            self._client.protocol.authentication_token = token

    def rebind_authentication_token(self) -> None:
        """Re-apply the current token to a freshly opened transport during reconnect."""
        self.restore_authentication_token(self.authentication_token)

    def reset_authentication_token(self) -> None:
        """Forget the current token so a fresh CreateSession is required."""
        self.restore_authentication_token(ua.NodeId())

    async def _send_request(
        self,
        request: Any,
        timeout: float | None = None,
        message_type: bytes = ua.MessageType.SecureMessage,
    ) -> Buffer:
        if not isinstance(request, ROUND_TRIP_REQUESTS):
            return await self._client._send_request(request, timeout, message_type)
        started = time.monotonic()
        data = await self._client._send_request(request, timeout, message_type)
        self._note_round_trip(time.monotonic() - started)
        return data

    def _note_round_trip(self, seconds: float) -> None:
        if self._round_trip is None:
            self._round_trip = seconds
        else:
            self._round_trip += ROUND_TRIP_WEIGHT * (seconds - self._round_trip)

    async def create_session(self, parameters: ua.CreateSessionParameters) -> ua.CreateSessionResult:
        if self._client.protocol is None:
            raise ConnectionError("Connection is not open")
        self.logger.info("create_session")
        forget_input_arguments(self)
        self._set_state(SessionState.CREATING)
        try:
            request = ua.CreateSessionRequest()
            request.Parameters = parameters
            data = await self._send_request(request)
            response = struct_from_binary(ua.CreateSessionResponse, data)
            self.logger.debug(response)
            response.ResponseHeader.ServiceResult.check()
        except BaseException:
            self._set_state(SessionState.NEW)
            raise
        self.restore_authentication_token(response.Parameters.AuthenticationToken)
        self.session_generation += 1
        self._set_state(SessionState.CREATED)
        return response.Parameters

    async def activate_session(self, parameters: ua.ActivateSessionParameters) -> ua.ActivateSessionResult:
        self.logger.info("activate_session")
        previous_state = self._state
        self._set_state(SessionState.ACTIVATING)
        try:
            request = ua.ActivateSessionRequest()
            request.Parameters = parameters
            data = await self._send_request(request)
            response = struct_from_binary(ua.ActivateSessionResponse, data)
            self.logger.debug(response)
            response.ResponseHeader.ServiceResult.check()
        except BaseException:
            # Roll back to whichever state we were in (CREATED or ACTIVATED)
            self._state = previous_state
            raise
        self._set_state(SessionState.ACTIVATED)
        return response.Parameters

    async def close_session(self, delete_subscriptions: bool) -> None:
        self.logger.info("close_session")
        if self._state in (SessionState.CLOSED, SessionState.CLOSING):
            return
        if self._state is SessionState.NEW:
            self._set_state(SessionState.CLOSING)
            await self.stop_publish()
            self._set_state(SessionState.CLOSED)
            return
        if not self._client.protocol:
            self.logger.warning("close_session but connection wasn't established")
            self._set_state(SessionState.CLOSING)
            await self.stop_publish()
            self._set_state(SessionState.CLOSED)
            return
        self._set_state(SessionState.CLOSING)
        await self.stop_publish()
        if delete_subscriptions:
            self._subscription_callbacks.clear()
            self._ack_ledger.clear()
        if self._client.protocol.is_closed:
            self.logger.warning("close_session was called but connection is closed")
            self._set_state(SessionState.CLOSED)
            return
        try:
            request = ua.CloseSessionRequest()
            request.DeleteSubscriptions = delete_subscriptions
            data = await self._send_request(request)
            response = struct_from_binary(ua.CloseSessionResponse, data)
            try:
                response.ResponseHeader.ServiceResult.check()
            except BadSessionClosed:
                # Closing the session with open publish requests leads to BadSessionClosed responses;
                # ignore it.
                pass
            except BadUserAccessDenied:
                # Older versions of enginir_opcua didn't allow closing non-activated sessions; ignore it.
                pass
        finally:
            self._set_state(SessionState.CLOSED)

    # --- View Service Set ---

    async def browse(self, parameters: ua.BrowseParameters, timeout: float | None = None) -> list[ua.BrowseResult]:
        self.logger.info("browse")
        request = ua.BrowseRequest()
        request.Parameters = parameters
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.BrowseResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Results

    async def browse_next(
        self, parameters: ua.BrowseNextParameters, timeout: float | None = None
    ) -> list[ua.BrowseResult]:
        self.logger.debug("browse next")
        request = ua.BrowseNextRequest()
        request.Parameters = parameters
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.BrowseNextResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Parameters.Results

    async def translate_browsepaths_to_nodeids(
        self, browse_paths: list[ua.BrowsePath], timeout: float | None = None
    ) -> list[ua.BrowsePathResult]:
        self.logger.debug("translate_browsepath_to_nodeid")
        request = ua.TranslateBrowsePathsToNodeIdsRequest()
        request.Parameters.BrowsePaths = browse_paths
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.TranslateBrowsePathsToNodeIdsResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Results

    async def register_nodes(self, nodes: list[ua.NodeId], timeout: float | None = None) -> list[ua.NodeId]:
        self.logger.info("register_nodes")
        request = ua.RegisterNodesRequest()
        request.Parameters.NodesToRegister = nodes
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.RegisterNodesResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Parameters.RegisteredNodeIds

    async def unregister_nodes(self, nodes: list[ua.NodeId], timeout: float | None = None) -> None:
        self.logger.info("unregister_nodes")
        request = ua.UnregisterNodesRequest()
        request.Parameters.NodesToUnregister = nodes
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.UnregisterNodesResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()

    # --- Attribute Service Set ---

    async def read(self, parameters: ua.ReadParameters, timeout: float | None = None) -> list[ua.DataValue]:
        self.logger.debug("read")
        request = ua.ReadRequest()
        request.Parameters = parameters
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.ReadResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Results

    async def write(self, params: ua.WriteParameters, timeout: float | None = None) -> list[ua.StatusCode]:
        self.logger.debug("write")
        request = ua.WriteRequest()
        request.Parameters = params
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.WriteResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Results

    async def history_read(
        self, params: ua.HistoryReadParameters, timeout: float | None = None
    ) -> list[ua.HistoryReadResult]:
        self.logger.info("history_read")
        request = ua.HistoryReadRequest()
        request.Parameters = params
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.HistoryReadResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Results

    async def history_update(
        self, params: ua.HistoryUpdateParameters, timeout: float | None = None
    ) -> list[ua.HistoryUpdateResult]:
        self.logger.info("history_update")
        request = ua.HistoryUpdateRequest()
        request.Parameters = params
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.HistoryUpdateResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Results

    async def read_attributes(
        self, nodeids: list[ua.NodeId], attr: ua.AttributeIds, timeout: float | None = None
    ) -> list[ua.DataValue]:
        self.logger.info("read_attributes of several nodes")
        request = ua.ReadRequest()
        for nodeid in nodeids:
            rv = ua.ReadValueId()
            rv.NodeId = nodeid
            rv.AttributeId = attr
            request.Parameters.NodesToRead.append(rv)
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.ReadResponse, data)
        response.ResponseHeader.ServiceResult.check()
        check_result_count(len(request.Parameters.NodesToRead), len(response.Results))
        return response.Results

    async def write_attributes(
        self,
        nodeids: list[ua.NodeId],
        datavalues: list[ua.DataValue],
        attributeid: ua.AttributeIds = ua.AttributeIds.Value,
        timeout: float | None = None,
    ) -> list[ua.StatusCode]:
        self.logger.info("write_attributes of several nodes")
        request = ua.WriteRequest()
        nodeids = list(nodeids)
        datavalues = list(datavalues)
        if len(nodeids) != len(datavalues):
            raise ValueError(f"{len(nodeids)} nodes and {len(datavalues)} values")
        for nodeid, datavalue in zip(nodeids, datavalues):
            attr = ua.WriteValue()
            attr.NodeId = nodeid
            attr.AttributeId = attributeid
            attr.Value = datavalue
            request.Parameters.NodesToWrite.append(attr)
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.WriteResponse, data)
        response.ResponseHeader.ServiceResult.check()
        check_result_count(len(nodeids), len(response.Results))
        return response.Results

    # --- NodeManagement Service Set ---

    async def add_nodes(
        self, nodestoadd: list[ua.AddNodesItem], timeout: float | None = None
    ) -> list[ua.AddNodesResult]:
        self.logger.info("add_nodes")
        request = ua.AddNodesRequest()
        request.Parameters.NodesToAdd = nodestoadd
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.AddNodesResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Results

    async def add_references(
        self, refs: list[ua.AddReferencesItem], timeout: float | None = None
    ) -> list[ua.StatusCode]:
        self.logger.info("add_references")
        request = ua.AddReferencesRequest()
        request.Parameters.ReferencesToAdd = refs
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.AddReferencesResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Results

    async def delete_references(
        self, refs: list[ua.DeleteReferencesItem], timeout: float | None = None
    ) -> list[ua.StatusCode]:
        self.logger.info("delete")
        request = ua.DeleteReferencesRequest()
        request.Parameters.ReferencesToDelete = refs
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.DeleteReferencesResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Parameters.Results

    async def delete_nodes(self, params: ua.DeleteNodesParameters, timeout: float | None = None) -> list[ua.StatusCode]:
        self.logger.info("delete_nodes")
        request = ua.DeleteNodesRequest()
        request.Parameters = params
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.DeleteNodesResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Results

    # --- Method Service Set ---

    async def call(
        self, methodstocall: list[ua.CallMethodRequest], timeout: float | None = None
    ) -> list[ua.CallMethodResult]:
        request = ua.CallRequest()
        request.Parameters.MethodsToCall = methodstocall
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.CallResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Results

    # --- Subscription Service Set ---

    async def create_subscription(
        self,
        params: ua.CreateSubscriptionParameters,
        callback: Sink | Callable[..., Any],
        timeout: float | None = None,
    ) -> ua.CreateSubscriptionResult:
        self.logger.debug("create_subscription")
        request = ua.CreateSubscriptionRequest()
        request.Parameters = params
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.CreateSubscriptionResponse, data)
        response.ResponseHeader.ServiceResult.check()
        result = response.Parameters
        self.note_subscription_timing(
            result.SubscriptionId, result.RevisedPublishingInterval / 1000, result.RevisedMaxKeepAliveCount
        )
        self._subscription_callbacks[result.SubscriptionId] = callback
        self.logger.info("create_subscription success SubscriptionId %s", result.SubscriptionId)
        self.ensure_publish_loop()
        return result

    def register_sink(self, subscription_id: int, sink: Sink | Callable[..., Any]) -> None:
        self._subscription_callbacks[subscription_id] = sink

    def unregister_sink(self, subscription_id: int) -> None:
        self._subscription_callbacks.pop(subscription_id, None)

    def note_subscription_timing(self, subscription_id: int, publishing_interval: float, keep_alive_count: int) -> None:
        self._publishing_intervals[subscription_id] = publishing_interval
        self._keep_alive_times[subscription_id] = publishing_interval * keep_alive_count
        self._publish_wake.set()

    async def update_subscription(
        self, params: ua.ModifySubscriptionParameters, timeout: float | None = None
    ) -> ua.ModifySubscriptionResult:
        request = ua.ModifySubscriptionRequest()
        request.Parameters = params
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.ModifySubscriptionResponse, data)
        response.ResponseHeader.ServiceResult.check()
        result = response.Parameters
        self.note_subscription_timing(
            params.SubscriptionId, result.RevisedPublishingInterval / 1000, result.RevisedMaxKeepAliveCount
        )
        self.logger.info("update_subscription success SubscriptionId %s", params.SubscriptionId)
        return result

    modify_subscription = update_subscription  # legacy support

    async def delete_subscriptions(
        self, subscription_ids: list[int], timeout: float | None = None
    ) -> list[ua.StatusCode]:
        self.logger.debug("delete_subscriptions %r", subscription_ids)
        ids = [int(sid) for sid in subscription_ids]
        request = ua.DeleteSubscriptionsRequest()
        request.Parameters.SubscriptionIds = ids
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.DeleteSubscriptionsResponse, data)
        response.ResponseHeader.ServiceResult.check()
        if len(response.Results) != len(ids):
            raise ua.UaError(f"DeleteSubscriptions answered {len(response.Results)} results for {len(ids)} ids")
        for sid, status in zip(ids, response.Results):
            self._subscription_callbacks.pop(sid, None)
            if not status.is_good() and status.value != ua.StatusCodes.BadSubscriptionIdInvalid:
                self.logger.warning("delete_subscriptions failed for %s: %s", sid, status)
        return response.Results

    async def transfer_subscriptions(
        self, params: ua.TransferSubscriptionsParameters, timeout: float | None = None
    ) -> list[ua.TransferResult]:
        self.logger.info("transfer_subscriptions %s", list(params.SubscriptionIds))
        request = ua.TransferSubscriptionsRequest()
        request.Parameters = params
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.TransferSubscriptionsResponse, data)
        response.ResponseHeader.ServiceResult.check()
        return response.Parameters.Results

    async def republish(
        self, subscription_id: int, retransmit_sequence_number: int, timeout: float | None = None
    ) -> ua.NotificationMessage:
        self.logger.debug("republish sub=%s seq=%s", subscription_id, retransmit_sequence_number)
        request = ua.RepublishRequest()
        request.Parameters.SubscriptionId = subscription_id
        request.Parameters.RetransmitSequenceNumber = retransmit_sequence_number
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.RepublishResponse, data)
        response.ResponseHeader.ServiceResult.check()
        return response.NotificationMessage

    def inform_sinks(self, status: ua.StatusCode) -> None:
        status_message = ua.StatusChangeNotification(Status=status)
        notification_message = ua.NotificationMessage(NotificationData=[status_message])  # type: ignore[list-item]
        for subscription_id, sink in list(self._subscription_callbacks.items()):
            event = getattr(sink, "session_event", None)
            if event is not None:
                self._call_sink(subscription_id, lambda event=event: event(status))
            else:
                result = ua.PublishResult(subscription_id, NotificationMessage=notification_message)
                self._deliver(subscription_id, sink, result)

    async def inform_subscriptions(self, status: ua.StatusCode) -> None:
        self.inform_sinks(status)

    async def publish(
        self, acks: list[ua.SubscriptionAcknowledgement], timeout: float | None = 0, timeout_hint: float | None = None
    ) -> ua.PublishResponse:
        """Send a PublishRequest to the server."""
        self.logger.debug("publish %r", acks)
        request = ua.PublishRequest()
        request.Parameters.SubscriptionAcknowledgements = acks if acks else []
        data = await self._client._send_request(request, timeout, timeout_hint=timeout_hint, limited=False)
        try:
            response = struct_from_binary(ua.PublishResponse, data)
        except Exception as ex:
            self.logger.exception("Error parsing notification from server")
            raise UaStructParsingError from ex
        return response

    # --- Publish pipeline ---

    @property
    def publish_suspended(self) -> bool:
        return self._publish_suspended

    @property
    def publish_requests_outstanding(self) -> int:
        return self._publish_in_flight

    def acknowledge(self, subscription_id: int, sequence_number: int) -> None:
        self._ack_ledger[(subscription_id, sequence_number)] = None
        self._trim_ledger()

    def _trim_ledger(self) -> None:
        excess = len(self._ack_ledger) - self.max_pending_acks
        if excess <= 0:
            return
        self.logger.warning("The acknowledgement ledger is full; dropping the %s oldest entries", excess)
        for key in list(self._ack_ledger)[:excess]:
            del self._ack_ledger[key]

    def _take_acks(self) -> list[ua.SubscriptionAcknowledgement]:
        acks = [ua.SubscriptionAcknowledgement(SubscriptionId=sid, SequenceNumber=seq) for sid, seq in self._ack_ledger]
        self._ack_ledger.clear()
        return acks

    def _return_acks(self, acks: list[ua.SubscriptionAcknowledgement]) -> None:
        returned = {
            (a.SubscriptionId, a.SequenceNumber): None for a in acks if a.SubscriptionId in self._subscription_callbacks
        }
        self._ack_ledger = {**returned, **self._ack_ledger}
        self._trim_ledger()

    def _sinks_changed(self, removed: Iterable[int]) -> None:
        for subscription_id in removed:
            self._publishing_intervals.pop(subscription_id, None)
            self._keep_alive_times.pop(subscription_id, None)
            for key in [key for key in self._ack_ledger if key[0] == subscription_id]:
                del self._ack_ledger[key]
        self._publish_wake.set()
        if self._subscription_callbacks:
            self.ensure_publish_loop()
        else:
            for worker in list(self._sleeping_workers):
                worker.cancel()

    def ensure_publish_loop(self) -> None:
        if not self._subscription_callbacks:
            return
        if self._publish_task is None or self._publish_task.done():
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                return
            self._publish_task = loop.create_task(self._publish_pump())
        self._publish_wake.set()

    def pause_publish(self) -> None:
        self._publish_suspended = True
        for worker in self._publish_workers:
            worker.cancel()

    def resume_publish(self) -> None:
        self._publish_suspended = False
        self._publish_limit = None
        self.ensure_publish_loop()
        self._publish_wake.set()

    async def stop_publish(self) -> None:
        tasks = list(self._publish_workers)
        if self._publish_task is not None:
            tasks.append(self._publish_task)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._publish_workers.clear()
        self._publish_task = None
        for task in list(self._late_tasks):
            task.cancel()

    def _publish_target(self) -> int:
        if not self._subscription_callbacks:
            return 0
        target = len(self._subscription_callbacks) + 1
        intervals = [
            i for sid, i in self._publishing_intervals.items() if sid in self._subscription_callbacks and i > 0
        ]
        if self._round_trip is not None and intervals:
            target = max(target, math.ceil(self._round_trip / min(intervals)) + 1)
        target = min(target, self.max_outstanding_publish_requests)
        if self._publish_limit is not None:
            target = min(target, self._publish_limit)
        return max(1, target)

    def _publish_timeout(self) -> tuple[float, float]:
        request_timeout = self._client._timeout
        keep_alive = max(
            (t for sid, t in self._keep_alive_times.items() if sid in self._subscription_callbacks), default=0.0
        )
        hint = min(keep_alive + request_timeout, self.max_publish_timeout)
        return hint, hint + request_timeout

    def _publish_may_run(self) -> bool:
        return not self._publish_suspended and self._state not in (SessionState.CLOSING, SessionState.CLOSED)

    async def _publish_pump(self) -> None:
        while self._state not in (SessionState.CLOSING, SessionState.CLOSED):
            self._publish_wake.clear()
            if self._publish_may_run():
                target = self._publish_target()
                while len(self._publish_workers) < target:
                    worker = asyncio.get_running_loop().create_task(self._publish_worker())
                    self._publish_workers.add(worker)
                    worker.add_done_callback(self._publish_worker_done)
            await self._publish_wake.wait()

    def _publish_worker_done(self, worker: asyncio.Task[None]) -> None:
        self._publish_workers.discard(worker)
        if not worker.cancelled() and worker.exception() is not None:
            self.logger.error("Publish worker crashed", exc_info=worker.exception())
        self._publish_wake.set()

    async def _publish_worker(self) -> None:
        no_subscription_count = 0
        error_delay = 0.0
        decode_failures = 0
        while self._publish_may_run() and self._subscription_callbacks:
            if len(self._publish_workers) > self._publish_target():
                return
            acks = self._take_acks()
            hint, deadline = self._publish_timeout()
            try:
                response = await self._send_publish(acks, deadline, hint)
            except asyncio.CancelledError:
                self._return_acks(acks)
                raise
            except (BadTimeout, TimeoutError):
                self._return_acks(acks)
                continue
            except BadTooManyPublishRequests:
                self._return_acks(acks)
                self._publish_limit = max(1, len(self._publish_workers) - 1)
                self.logger.info("Too many Publish requests; keeping at most %s", self._publish_limit)
                return
            except BadNoSubscription:
                self._return_acks(acks)
                if not await self._wait_after_no_subscription(no_subscription_count):
                    return
                no_subscription_count += 1
                continue
            except SESSION_LOST_ERRORS as error:
                self._return_acks(acks)
                self.logger.info("Publish stopped, the session or the connection is gone: %r", error)
                self._publish_suspended = True
                return
            except UaStructParsingError:
                self._return_acks(acks)
                decode_failures += 1
                if decode_failures >= PUBLISH_DECODE_ERROR_LIMIT:
                    self._publish_suspended = True
                    self.inform_sinks(ua.StatusCode(ua.StatusCodes.BadDecodingError))
                    return
                continue
            except ua.UaStatusCodeError as error:
                self._return_acks(acks)
                error_delay = (
                    min(error_delay * 2, PUBLISH_ERROR_MAX_DELAY) if error_delay else PUBLISH_ERROR_RETRY_DELAY
                )
                self.logger.warning("Publish failed with %s; trying again in %.2fs", error, error_delay)
                await self._worker_sleep(error_delay)
                continue
            decode_failures = 0
            error_delay = 0.0
            if not await self._handle_publish_response(response, acks):
                if not await self._wait_after_no_subscription(no_subscription_count):
                    return
                no_subscription_count += 1
            else:
                no_subscription_count = 0

    async def _wait_after_no_subscription(self, count: int) -> bool:
        if not self._subscription_callbacks:
            return False
        delays = NO_SUBSCRIPTION_RETRY_DELAYS
        await self._worker_sleep(delays[min(count, len(delays) - 1)])
        return bool(self._subscription_callbacks)

    async def _send_publish(
        self, acks: list[ua.SubscriptionAcknowledgement], deadline: float, hint: float
    ) -> ua.PublishResponse:
        self._publish_in_flight += 1
        try:
            return await self.publish(acks, deadline, hint)
        finally:
            self._publish_in_flight -= 1

    async def _worker_sleep(self, delay: float) -> None:
        task = asyncio.current_task()
        assert task is not None
        self._sleeping_workers.add(task)
        try:
            await asyncio.sleep(delay)
        finally:
            self._sleeping_workers.discard(task)

    async def _handle_publish_response(
        self, response: ua.PublishResponse, acks: list[ua.SubscriptionAcknowledgement]
    ) -> bool:
        result = response.Parameters
        for ack, status in zip(acks, result.Results):
            if status.value == ua.StatusCodes.BadSequenceNumberUnknown:
                self.logger.debug(
                    "The server does not know sequence number %s of %s", ack.SequenceNumber, ack.SubscriptionId
                )
            elif not status.is_good():
                self.logger.warning(
                    "Acknowledgement of %s/%s answered %s", ack.SubscriptionId, ack.SequenceNumber, status
                )
        subscription_id = result.SubscriptionId
        if not subscription_id:
            return False
        sink = self._subscription_callbacks.get(subscription_id)
        if sink is None:
            self.logger.warning(
                "Received data for unknown subscription %s active are %s",
                subscription_id,
                list(self._subscription_callbacks),
            )
            return True
        self._deliver(subscription_id, sink, result)
        if result.NotificationMessage.NotificationData and result.AvailableSequenceNumbers:
            self.acknowledge(subscription_id, result.NotificationMessage.SequenceNumber)
        return True

    def _deliver(self, subscription_id: int, sink: Any, result: ua.PublishResult) -> None:
        enqueue = getattr(sink, "enqueue", None)
        if enqueue is not None:
            self._call_sink(subscription_id, lambda: enqueue(result))
        else:
            self._call_sink(subscription_id, lambda: self._run_callback(sink, result))

    def _call_sink(self, subscription_id: int, call: Callable[[], Any]) -> None:
        try:
            call()
        except Exception:
            self.logger.exception("Sink of subscription %s raised", subscription_id)

    def _run_callback(self, callback: Callable[..., Any], result: ua.PublishResult) -> None:
        outcome = callback(result)
        if asyncio.iscoroutine(outcome):
            task = asyncio.get_running_loop().create_task(self._await_callback(outcome))
            self._late_tasks.add(task)
            task.add_done_callback(self._late_tasks.discard)

    async def _await_callback(self, outcome: Any) -> None:
        try:
            await outcome
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("Exception while calling user callback")

    # --- MonitoredItem Service Set ---

    async def create_monitored_items(
        self,
        params: ua.CreateMonitoredItemsParameters,
        timeout: float | None = None,
    ) -> list[ua.MonitoredItemCreateResult]:
        self.logger.info("create_monitored_items")
        request = ua.CreateMonitoredItemsRequest()
        request.Parameters = params
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.CreateMonitoredItemsResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Results

    async def delete_monitored_items(
        self, params: ua.DeleteMonitoredItemsParameters, timeout: float | None = None
    ) -> list[ua.StatusCode]:
        self.logger.info("delete_monitored_items")
        request = ua.DeleteMonitoredItemsRequest()
        request.Parameters = params
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.DeleteMonitoredItemsResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Results

    async def modify_monitored_items(
        self,
        params: ua.ModifyMonitoredItemsParameters,
        timeout: float | None = None,
    ) -> list[ua.MonitoredItemModifyResult]:
        self.logger.info("modify_monitored_items")
        request = ua.ModifyMonitoredItemsRequest()
        request.Parameters = params
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.ModifyMonitoredItemsResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Results

    async def set_monitoring_mode(
        self, params: ua.SetMonitoringModeParameters, timeout: float | None = None
    ) -> list[ua.uatypes.StatusCode]:
        self.logger.info("set_monitoring_mode")
        request = ua.SetMonitoringModeRequest()
        request.Parameters = params
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.SetMonitoringModeResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Parameters.Results

    async def set_publishing_mode(
        self, params: ua.SetPublishingModeParameters, timeout: float | None = None
    ) -> list[ua.uatypes.StatusCode]:
        self.logger.info("set_publishing_mode")
        request = ua.SetPublishingModeRequest()
        request.Parameters = params
        data = await self._send_request(request, timeout)
        response = struct_from_binary(ua.SetPublishingModeResponse, data)
        self.logger.debug(response)
        response.ResponseHeader.ServiceResult.check()
        return response.Parameters.Results
