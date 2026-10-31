import asyncio
import struct
from typing import Any
from unittest.mock import AsyncMock

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ua_client import UaClient
from enginir_opcua.common.utils import Buffer
from enginir_opcua.ua.uaerrors import BadSessionIdInvalid, BadTooManySessions
from tests.conftest import find_free_port, port_num
from tests.waiting import wait_until


async def test_max_connections_1(opc):
    opc.server.iserver.session_manager.max_sessions = 1
    port = opc.server.endpoint.port
    if port == port_num:
        # if client we already have one connection
        with pytest.raises(BadTooManySessions):
            async with Client(f"opc.tcp://127.0.0.1:{port}"):
                pass
    else:
        async with Client(f"opc.tcp://127.0.0.1:{port}"):
            with pytest.raises(BadTooManySessions):
                async with Client(f"opc.tcp://127.0.0.1:{port}"):
                    pass
    opc.server.iserver.session_manager.max_sessions = 100


async def test_dos_server(opc):
    # See issue 1013 a crafted packet triggered dos
    port = opc.server.endpoint.port
    async with Client(f"opc.tcp://127.0.0.1:{port}") as c:
        # craft invalid packet that trigger dos
        message_type, chunk_type, packet_size = [ua.MessageType.SecureOpen, b"E", 0]
        c.uaclient.protocol.transport.write(struct.pack("<3scI", message_type, chunk_type, packet_size))
        # sleep to give the server time to handle the message because we bypass the asyncio
        await asyncio.sleep(1.0)
        with pytest.raises(ConnectionError):
            # now try to read a value to see if server is still alive
            server_time_node = c.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_CurrentTime))
            await server_time_node.read_value()


async def test_safe_disconnect():
    c = Client(url="opc.tcp://example:4840")
    await c.disconnect()
    # second disconnect should be noop
    await c.disconnect()


async def test_client_connection_lost():
    class LostSubHandler:
        def __init__(self) -> None:
            self.status = ua.StatusCodes.Good

        def status_change_notification(self, status: ua.StatusChangeNotification):
            self.status = status.Status

    # Test the disconnect behavoir
    port = find_free_port()
    srv = Server(allow_no_security=True)
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    await srv.start()
    async with Client(f"opc.tcp://127.0.0.1:{port}", timeout=0.5, watchdog_intervall=1) as cl:
        myhandler = LostSubHandler()
        _ = await cl.create_subscription(1, myhandler)
        await srv.stop()
        await wait_until(lambda: myhandler.status.value == ua.StatusCodes.BadShutdown)
        with pytest.raises(ConnectionError):
            # check if connection is alive
            await cl.check_connection()
        # check if the status_change_notification was triggered
        assert myhandler.status.value == ua.StatusCodes.BadShutdown
        # check if exception is correct rethrown on second call
        with pytest.raises(ConnectionError):
            await cl.check_connection()
        # check if a exception is thrown when a normal function is called
        with pytest.raises(ConnectionError):
            await cl.get_namespace_array()


async def test_client_connection_lost_callback():
    port = find_free_port()
    srv = Server(allow_no_security=True)
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    await srv.start()

    class Clb:
        def __init__(self):
            self.called = False
            self.ex = None

        async def clb(self, ex):
            self.called = True
            self.ex = ex

    clb = Clb()

    async with Client(f"opc.tcp://127.0.0.1:{port}", timeout=0.5, watchdog_intervall=1) as cl:
        cl.connection_lost_callback = clb.clb
        await srv.stop()
        await wait_until(lambda: clb.called)
        assert clb.called
        assert isinstance(clb.ex, Exception)


async def test_session_watchdog():
    port = find_free_port()
    srv = Server(allow_no_security=True)
    await srv.init()
    srv.iserver.min_session_timeout_ms = 100
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    await srv.start()
    client = Client(f"opc.tcp://127.0.0.1:{port}", timeout=0.5, watchdog_intervall=1)
    client.session_timeout = 1000  # 1 second
    await client.connect()
    # Kill the keepalive tasks so the server-side session times out from inactivity.
    if client._renew_channel_task is not None:
        client._renew_channel_task.cancel()
    if client._supervisor_task is not None:
        client._supervisor_task.cancel()
    await wait_until(lambda: not srv.iserver.session_manager.sessions)
    with pytest.raises(BadSessionIdInvalid):
        server_time_node = client.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_CurrentTime))
        await server_time_node.read_value()
    await client.disconnect()


def test_request_limit_has_a_high_default() -> None:
    assert UaClient._max_concurrent_requests == 100


@pytest.mark.asyncio
async def test_request_limit_caps_in_flight_requests() -> None:
    client = Client("opc.tcp://localhost:4840")
    client.set_max_concurrent_requests(2)
    release = asyncio.Event()
    limit_reached = asyncio.Event()
    active = 0
    peak = 0

    async def send_request(
        request: Any,
        timeout: float | None = None,
        message_type: bytes = ua.MessageType.SecureMessage,
    ) -> Buffer:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        if active == 2:
            limit_reached.set()
        await release.wait()
        active -= 1
        return Buffer(b"")

    protocol = AsyncMock()
    protocol.send_request.side_effect = send_request
    client.uaclient.protocol = protocol

    requests = [asyncio.create_task(client.uaclient._send_request(ua.ReadRequest())) for _ in range(3)]
    await asyncio.wait_for(limit_reached.wait(), timeout=1)
    await asyncio.sleep(0)

    assert client.uaclient._max_concurrent_requests == 2
    assert active == 2
    assert peak == 2

    release.set()
    await asyncio.gather(*requests)
