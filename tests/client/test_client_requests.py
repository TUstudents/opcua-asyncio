import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Any

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.client import client as client_module
from enginir_opcua.client.ua_client import UaClient, UaClientState, UASocketProtocol
from enginir_opcua.common.connection import SecureChannel
from enginir_opcua.common.methods import uamethod
from enginir_opcua.ua.ua_binary import struct_to_binary
from tests.harness import RawPeer, RawServer, connect_client, open_channel_as_server, receive_message


async def handshaken(raw_server: RawServer, timeout: float = 0.3) -> tuple[UaClient, RawPeer, SecureChannel]:
    uaclient, peer = await connect_client(raw_server)
    channel = await open_channel_as_server(uaclient, peer)
    protocol = uaclient.protocol
    assert protocol is not None
    protocol.timeout = timeout
    return uaclient, peer, channel


async def receive_request_id(peer: RawPeer, channel: SecureChannel) -> int:
    return (await receive_message(peer, channel)).request_id()


async def send_read_response(peer: RawPeer, channel: SecureChannel, request_id: int) -> None:
    response = ua.ReadResponse()
    response.Results = [ua.DataValue(ua.Variant(1, ua.VariantType.Int32))]
    await peer.send(channel.message_to_binary(struct_to_binary(response), request_id=request_id))


def read_request() -> ua.ReadRequest:
    request = ua.ReadRequest()
    request.Parameters.NodesToRead = [ua.ReadValueId(NodeId=ua.NodeId(2259), AttributeId=ua.AttributeIds.Value)]
    return request


async def timed_out_request(
    protocol: UASocketProtocol, peer: RawPeer, channel: SecureChannel, timeout: float = 0.2
) -> int:
    request_task = asyncio.create_task(protocol.send_request(read_request(), timeout))
    request_id = await receive_request_id(peer, channel)
    with pytest.raises(TimeoutError):
        await request_task
    return request_id


async def test_cli1_timed_out_request_leaves_no_table_entry(raw_server: RawServer) -> None:
    """Part 6, 6.7.7: a request that timed out is no longer pending."""
    uaclient, peer, channel = await handshaken(raw_server)
    protocol = uaclient.protocol
    assert protocol is not None
    await timed_out_request(protocol, peer, channel)
    assert protocol._callbackmap == {}


async def test_cli1_cancelled_request_leaves_no_table_entry(raw_server: RawServer) -> None:
    """Part 6, 6.7.7: a request that the caller cancelled is no longer pending."""
    uaclient, peer, channel = await handshaken(raw_server)
    protocol = uaclient.protocol
    assert protocol is not None
    request_task = asyncio.create_task(protocol.send_request(read_request(), 5))
    await receive_request_id(peer, channel)
    request_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await request_task
    assert protocol._callbackmap == {}


async def test_cli1_late_response_is_dropped_silently(raw_server: RawServer, caplog: pytest.LogCaptureFixture) -> None:
    """Part 6, 6.7.7: the response of an abandoned request is discarded; the channel stays usable."""
    uaclient, peer, channel = await handshaken(raw_server)
    protocol = uaclient.protocol
    assert protocol is not None
    request_id = await timed_out_request(protocol, peer, channel)
    with caplog.at_level(logging.DEBUG):
        await send_read_response(peer, channel, request_id)
        await asyncio.sleep(0.2)
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert not protocol.is_closed
    second = asyncio.create_task(protocol.send_request(read_request(), 2))
    await send_read_response(peer, channel, await receive_request_id(peer, channel))
    await second


async def test_cli1_response_for_an_id_never_issued_closes_the_channel(raw_server: RawServer) -> None:
    """Part 6, 6.7.7: the client verifies the RequestId of a response; an id it never sent ends the connection."""
    uaclient, peer, channel = await handshaken(raw_server)
    protocol = uaclient.protocol
    assert protocol is not None
    await send_read_response(peer, channel, 4711)
    assert await peer.is_closed_by_peer()
    assert protocol.is_closed


async def test_cli38_timed_out_renewal_does_not_block_the_next_one(raw_server: RawServer) -> None:
    """Part 6, 6.7.4: a renewal that timed out leaves the channel able to send the next renewal."""
    uaclient, peer, _channel = await handshaken(raw_server)
    renew = ua.OpenSecureChannelParameters(
        RequestType=ua.SecurityTokenRequestType.Renew,
        SecurityMode=ua.MessageSecurityMode.None_,
        RequestedLifetime=3_600_000,
    )
    for _ in range(2):
        with pytest.raises(TimeoutError):
            await uaclient.open_secure_channel(renew)
        await peer.receive()


async def test_cli38_renewal_retries_while_the_token_is_valid(server: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    """Part 6, 6.7.4: a failed renewal is tried again while the security token is still valid."""
    monkeypatch.setattr(client_module, "RENEW_RETRY_DELAY", 0.05)
    client = Client(server.endpoint.geturl())
    await client.connect()
    client.secure_channel_timeout = 2000
    try:
        real_renewal = client.open_secure_channel
        attempts: list[bool] = []

        async def renewal(renew: bool = False) -> None:
            attempts.append(renew)
            if len(attempts) == 1:
                raise TimeoutError
            await real_renewal(renew=renew)

        monkeypatch.setattr(client, "open_secure_channel", renewal)
        await Client._cancel_task(client._renew_channel_task)
        client._renew_channel_task = None
        client._start_renew_loop()
        await asyncio.sleep(2.0)
        assert len(attempts) >= 2
        assert client._renew_channel_task is not None and not client._renew_channel_task.done()
    finally:
        await client.disconnect()


async def test_cli38_renewal_failing_past_the_token_lifetime_is_a_loss(
    server: Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 6, 6.7.4: when no renewal succeeded before the token expired, the channel is lost."""
    monkeypatch.setattr(client_module, "RENEW_RETRY_DELAY", 0.05)
    client = Client(server.endpoint.geturl())
    await client.connect()
    client.secure_channel_timeout = 2000
    try:

        async def renewal(renew: bool = False) -> None:
            raise TimeoutError

        monkeypatch.setattr(client, "open_secure_channel", renewal)
        await Client._cancel_task(client._renew_channel_task)
        client._renew_channel_task = None
        async with client.subscribe_state() as states:
            client._start_renew_loop()
            await states.wait_for_state(UaClientState.DISCONNECTED, timeout=5)
    finally:
        await client.disconnect()


@pytest.fixture(scope="module")
async def typed_node(server: Server) -> ua.NodeId:
    def record(parent: ua.NodeId, *arguments: ua.Variant) -> list[ua.Variant]:
        return [ua.Variant(",".join(argument.VariantType.name for argument in arguments), ua.VariantType.String)]

    node = await server.nodes.objects.add_method(
        ua.NodeId("TypedMethod", 2),
        ua.QualifiedName("TypedMethod", 2),
        record,
        [ua.VariantType.Int32, ua.VariantType.Byte, ua.VariantType.UInt16, ua.VariantType.Float],
        [ua.VariantType.String],
    )
    return node.nodeid


@pytest.fixture
async def typed_method(server: Server, typed_node: ua.NodeId) -> AsyncIterator[tuple[Client, ua.NodeId]]:
    client = Client(server.endpoint.geturl())
    await client.connect()
    yield client, typed_node
    await client.disconnect()


async def test_cli23_int_argument_is_sent_as_the_declared_type(typed_method: tuple[Client, ua.NodeId]) -> None:
    """Part 4, 5.12.2.2: the arguments have the types the method declares; a Python int is not always Int64."""
    client, method_id = typed_method
    objects = client.get_objects_node()
    assert await objects.call_method(method_id, 1, 2, 3, 4.5) == "Int32,Byte,UInt16,Float"


async def test_cli23_variant_argument_is_sent_unchanged(typed_method: tuple[Client, ua.NodeId]) -> None:
    """An explicit Variant is the override: it is sent as it is, and the server's answer is reported."""
    client, method_id = typed_method
    objects = client.get_objects_node()
    arguments = [ua.Variant(1, ua.VariantType.Int64), 2, 3, 4.5]
    with pytest.raises(ua.UaStatusCodeError) as error:
        await objects.call_method(method_id, *arguments)
    assert error.value.code == ua.StatusCodes.BadInvalidArgument
    results = error.value.input_argument_results  # type: ignore[attr-defined]
    assert results[0].value == ua.StatusCodes.BadTypeMismatch
    assert results[1].is_good()


@pytest.mark.parametrize(
    "arguments",
    [("text", 2, 3, 4.5), (1.5, 2, 3, 4.5), (1, 300, 3, 4.5), (1, 2, -1, 4.5), (1, 2, 3, "x"), (1, [2], 3, 4.5)],
)
async def test_cli23_unconvertible_argument_is_a_type_error(
    typed_method: tuple[Client, ua.NodeId], arguments: tuple[Any, ...]
) -> None:
    """Part 4, 5.12.2.2: a value that cannot become the declared type fails before the call."""
    client, method_id = typed_method
    with pytest.raises(TypeError):
        await client.get_objects_node().call_method(method_id, *arguments)


async def test_cli23_too_many_arguments_fail_locally(typed_method: tuple[Client, ua.NodeId]) -> None:
    """Part 4, 5.12.2.2: Bad_TooManyArguments."""
    client, method_id = typed_method
    with pytest.raises(ua.uaerrors.BadTooManyArguments):
        await client.get_objects_node().call_method(method_id, 1, 2, 3, 4.5, 5)


async def test_cli23_bytes_for_a_byte_array_are_sent_as_a_byte_string(server: Server) -> None:
    """Part 4, 5.12.2.2, Table 62: a ByteString is accepted for an array of Byte."""

    def record(parent: ua.NodeId, *arguments: ua.Variant) -> list[ua.Variant]:
        return [ua.Variant(arguments[0].VariantType.name, ua.VariantType.String)]

    node = await server.nodes.objects.add_method(
        ua.NodeId("ByteArrayMethod", 2),
        ua.QualifiedName("ByteArrayMethod", 2),
        record,
        [[ua.VariantType.Byte]],
        [ua.VariantType.String],
    )
    client = Client(server.endpoint.geturl())
    async with client:
        assert await client.get_objects_node().call_method(node.nodeid, b"\x01\x02") == "ByteString"


async def test_cli33_call_method_accepts_a_timeout(server: Server) -> None:
    """Part 4, 7.33: a long call needs a longer deadline than the client's normal request timeout."""

    @uamethod
    async def slow(parent: Any) -> int:
        await asyncio.sleep(1.0)
        return 7

    node = await server.nodes.objects.add_method(
        ua.NodeId("SlowMethod", 2), ua.QualifiedName("SlowMethod", 2), slow, [], [ua.VariantType.Int64]
    )
    async with Client(server.endpoint.geturl(), timeout=0.3) as client:
        objects = client.get_objects_node()
        with pytest.raises(TimeoutError):
            await objects.call_method(node.nodeid)
        assert await objects.call_method(node.nodeid, timeout=5) == 7
