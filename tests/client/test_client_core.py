import asyncio
import logging
from collections.abc import Iterator

import pytest

from enginir_opcua import Client, Node, Server, ua
from enginir_opcua.client.ua_client import UaClientState
from enginir_opcua.client.ua_session import SessionState
from tests.harness import ResponseTampering, signing_client


@pytest.fixture
async def connected(server: Server) -> Iterator[Client]:
    client = Client(server.endpoint.geturl())
    await client.connect()
    yield client  # type: ignore[misc]
    await client.disconnect()


async def test_cli9_register_and_unregister_nodes_accept_generators(connected: Client) -> None:
    """Part 4, 5.9.5: every node of the request is registered and paired with its result."""
    nodes = [
        connected.get_node(ua.ObjectIds.Server_ServerStatus),
        connected.get_node(ua.ObjectIds.Server_NamespaceArray),
    ]
    registered = await connected.register_nodes(node for node in nodes)
    assert [node.basenodeid for node in registered] == [
        ua.NodeId(ua.ObjectIds.Server_ServerStatus),
        ua.NodeId(ua.ObjectIds.Server_NamespaceArray),
    ]
    await connected.unregister_nodes(node for node in registered)
    assert all(node.basenodeid is None for node in registered)


async def test_cli9_browse_nodes_accepts_a_generator(connected: Client) -> None:
    """Part 4, 5.8.2: every node of the request is browsed and paired with its result."""
    nodes = [connected.get_root_node(), connected.get_objects_node()]
    pairs = await connected.browse_nodes(node for node in nodes)
    assert [node.nodeid for node, _ in pairs] == [node.nodeid for node in nodes]


async def test_browse_nodes_follows_continuation_points(server: Server, connected: Client) -> None:
    """Part 4, 5.9.3: the client reads every page of a Browse with BrowseNext."""
    node = connected.get_node(ua.ObjectIds.Server)
    expected = await node.get_references(ua.ObjectIds.References, ua.BrowseDirection.Forward)
    server.iserver.max_browse_references_per_node = 2
    try:
        ((_, result),) = await connected.browse_nodes([node])
    finally:
        server.iserver.max_browse_references_per_node = 10_000
    assert len(expected) > 2
    assert not result.ContinuationPoint
    assert [ref.NodeId for ref in result.References] == [ref.NodeId for ref in expected]


async def test_cli9_result_count_mismatch_is_an_error(connected: Client, tampered_responses: ResponseTampering) -> None:
    """Part 4, 5.3: a response has one result per request item; a different count is an error."""

    def drop_one(response: ua.ReadResponse) -> None:
        response.Results = response.Results[:-1]

    tampered_responses.on(ua.ReadResponse, drop_one)
    nodes = [
        connected.get_node(ua.ObjectIds.Server_NamespaceArray),
        connected.get_node(ua.ObjectIds.Server_ServerArray),
    ]
    with pytest.raises(ua.UaError, match="2"):
        await connected.read_attributes(nodes)


async def test_cli9_write_values_needs_equal_lengths(connected: Client) -> None:
    """Part 4, 5.10.4: one value per node."""
    nodes = [connected.get_node(ua.ObjectIds.Server_NamespaceArray)]
    with pytest.raises(ValueError):
        await connected.write_values(nodes, [1, 2])


async def test_cli2_register_server2_succeeds_without_the_fallback(server: Server) -> None:
    """Part 4, 5.5.6: RegisterServer2 is tried first; RegisterServer is not sent when it works."""
    client = Client(server.endpoint.geturl())
    calls: list[str] = []

    async def register_server2(params: ua.RegisterServer2Parameters) -> list[ua.StatusCode]:
        calls.append("2")
        return []

    async def register_server(registered: ua.RegisteredServer) -> None:
        calls.append("1")

    client.uaclient.register_server2 = register_server2  # type: ignore[method-assign]
    client.uaclient.register_server = register_server  # type: ignore[method-assign]
    await client.register_server(server)
    await client.register_server(server, [ua.MdnsDiscoveryConfiguration()])
    assert calls == ["2", "2"]


async def test_cli2_register_server_falls_back_only_when_register_server2_is_unsupported(server: Server) -> None:
    """Part 4, 5.5.5 and 5.5.6: RegisterServer is the fallback for Bad_ServiceUnsupported only."""
    client = Client(server.endpoint.geturl())
    calls: list[tuple[str, bool]] = []

    async def unsupported(params: ua.RegisterServer2Parameters) -> list[ua.StatusCode]:
        raise ua.uaerrors.BadServiceUnsupported

    async def refused(params: ua.RegisterServer2Parameters) -> list[ua.StatusCode]:
        raise ua.uaerrors.BadUserAccessDenied

    async def register_server(registered: ua.RegisteredServer) -> None:
        calls.append(("1", registered.IsOnline))

    client.uaclient.register_server = register_server  # type: ignore[method-assign]
    client.uaclient.unregister_server = register_server  # type: ignore[method-assign]
    client.uaclient.register_server2 = unsupported  # type: ignore[method-assign]
    client.uaclient.unregister_server2 = unsupported  # type: ignore[method-assign]
    await client.register_server(server)
    await client.unregister_server(server)
    assert calls == [("1", True), ("1", False)]
    client.uaclient.register_server2 = refused  # type: ignore[method-assign]
    with pytest.raises(ua.uaerrors.BadUserAccessDenied):
        await client.register_server(server)
    assert len(calls) == 2


async def test_cli25_failed_connect_leaves_no_session_on_the_server(
    signing_server: Server, tampered_responses: ResponseTampering
) -> None:
    """Part 4, 5.7.2.1: a client that rejects the CreateSession response closes the Session it created."""

    def shorten(response: ua.CreateSessionResponse) -> None:
        response.Parameters.ServerNonce = b"\x01" * 8

    tampered_responses.on(ua.CreateSessionResponse, shorten)
    client = await signing_client(signing_server)
    with pytest.raises(ua.uaerrors.BadNonceInvalid):
        await client.connect()
    await asyncio.sleep(0.3)
    assert signing_server.iserver.session_manager.sessions == {}
    assert client.state is UaClientState.DISCONNECTED
    assert client.uaclient.session.state is SessionState.CLOSED


async def test_cli37_second_connect_raises_and_keeps_the_first_session(server: Server) -> None:
    """Part 4, 5.7.2.1: one Session per client; a second connect does not open another one."""
    sessions = server.iserver.session_manager.sessions
    before = len(sessions)
    async with Client(server.endpoint.geturl()) as client:
        assert len(sessions) == before + 1
        with pytest.raises(ConnectionError, match="already connected"):
            await client.connect()
        assert len(sessions) == before + 1
        assert await client.nodes.server_state.read_value() == ua.ServerState.Running


async def test_cli36_url_without_a_port_uses_4840(monkeypatch: pytest.MonkeyPatch) -> None:
    """Part 6, 7.1.3: opc.tcp has a registered default port."""
    client = Client("opc.tcp://example.invalid")
    connected: list[tuple[str, int]] = []

    async def connect_socket(host: str, port: int) -> None:
        connected.append((host, port))

    monkeypatch.setattr(client.uaclient, "connect_socket", connect_socket)
    await client.connect_socket()
    assert connected == [("example.invalid", 4840)]


@pytest.mark.parametrize("url", ["http://example.invalid:4840", "localhost:4840", "example.invalid"])
def test_cli36_other_schemes_are_a_configuration_error(url: str) -> None:
    """Only opc.tcp is implemented."""
    with pytest.raises(ua.uaerrors.ConfigurationError):
        Client(url)


async def test_cli24_revised_session_timeout_is_logged_at_info_with_both_values(
    server: Server, caplog: pytest.LogCaptureFixture
) -> None:
    """Part 4, 5.7.2.2: a server may revise the session timeout; the log line gives the requested and revised value."""
    client = Client(server.endpoint.geturl())
    client.session_timeout = 1_234_567_890
    client.secure_channel_timeout = 3_600_000
    with caplog.at_level(logging.INFO):
        async with client:
            pass
    records = [r for r in caplog.records if "session timeout" in r.getMessage()]
    assert len(records) == 1
    assert records[0].levelno == logging.INFO
    assert "1234567890ms" in records[0].getMessage()


async def test_cli27_reconnect_gate_survives_disconnect_and_connect(server: Server) -> None:
    """Part 4, 6.7: requests wait for the reconnect also on a client that was disconnected and connected again."""
    client = Client(server.endpoint.geturl(), reconnect_request_timeout=0.3)
    await client.connect()
    await client.disconnect()
    await client.connect()
    try:
        assert client.uaclient.pre_request_hook is not None
        client.uaclient.enter_reconnecting()
        with pytest.raises(ConnectionError):
            await client.nodes.server_state.read_value()
    finally:
        client.uaclient.mark_disconnected()
        await client.disconnect()


async def test_cli28_disconnect_closes_subscription_objects_and_ends_iterators(server: Server) -> None:
    """Part 4, 5.7.4.1: closing the Session ends its Subscriptions; the local objects end with them."""
    client = Client(server.endpoint.geturl())
    await client.connect()
    subscription = await client.create_subscription(100)
    events: list[object] = []

    async def consume() -> None:
        async for event in subscription:
            events.append(event)

    consumer = asyncio.create_task(consume())
    await asyncio.sleep(0.1)
    await client.disconnect()
    await asyncio.wait_for(consumer, 2)
    assert subscription.is_deleted
    assert client._subscriptions == []


async def test_cli28_connect_after_disconnect_does_not_recreate_old_subscriptions(server: Server) -> None:
    """Part 4, 5.7.4.1: a Subscription of the closed Session does not come back with the next connect."""
    service = server.iserver.subscription_service
    before = len(service.subscriptions)
    client = Client(server.endpoint.geturl())
    client._stale_check_margin = 0
    client._stale_check_interval = 0.05
    await client.connect()
    await client.create_subscription(100)
    await client.disconnect()
    await client.connect()
    await asyncio.sleep(0.5)
    assert len(service.subscriptions) == before
    await client.disconnect()


async def test_session_generation_increases_with_every_new_session(server: Server) -> None:
    """File handles and other per-Session state are invalidated by a new Session."""
    client = Client(server.endpoint.geturl())
    session = client.uaclient.session
    assert session.session_generation == 0
    await client.connect()
    assert session.session_generation == 1
    await client.disconnect()
    await client.connect()
    assert session.session_generation == 2
    await client.disconnect()


async def test_state_listeners_can_be_added_and_removed(server: Server) -> None:
    """The state listener API is public."""
    client = Client(server.endpoint.geturl())
    seen: list[UaClientState] = []
    unsubscribe = client.uaclient.add_state_listener(seen.append)
    await client.connect()
    client.uaclient.remove_state_listener(seen.append)
    unsubscribe()
    count = len(seen)
    await client.disconnect()
    assert count > 0
    assert len(seen) == count


_logger = logging.getLogger(__name__)


pytestmark = pytest.mark.asyncio


async def test_service_fault(server, admin_client):
    request = ua.ReadRequest()
    request.TypeId = ua.FourByteNodeId(999)  # bad type!
    with pytest.raises(ua.UaStatusCodeError):
        await admin_client.uaclient.protocol.send_request(request)


async def test_objects_anonymous(server, client):
    objects = client.nodes.objects
    with pytest.raises(ua.UaStatusCodeError):
        await objects.write_attribute(ua.AttributeIds.WriteMask, ua.DataValue(999))
    with pytest.raises(ua.UaStatusCodeError):
        await objects.add_folder(3, "MyFolder")


async def test_folder_anonymous(server, admin_client, client):
    objects = admin_client.nodes.objects
    f = await objects.add_folder(3, "MyFolderRO")
    f_ro = client.get_node(f.nodeid)
    assert f == f_ro
    with pytest.raises(ua.UaStatusCodeError):
        await f_ro.add_folder(3, "MyFolder2")
    await server.delete_nodes([f, f_ro])


async def test_variable_anonymous(server, admin_client, client):
    objects = admin_client.nodes.objects
    v = await objects.add_variable(3, "MyROVariable", 6)
    v_ro = client.get_node(v.nodeid)
    with pytest.raises(ua.uaerrors.BadNotWritable):
        await v.write_value(4)
    with pytest.raises(ua.uaerrors.BadNotWritable):
        await v_ro.write_value(2)
    assert await v_ro.read_value() == 6
    await server.get_node(v.nodeid).set_writable(True)
    await v_ro.write_value(2)
    assert await v_ro.read_value() == 2
    await server.get_node(v.nodeid).set_writable(False)
    with pytest.raises(ua.UaStatusCodeError):
        await v_ro.write_value(9)
    assert await v_ro.read_value() == 2


async def test_context_manager(server):
    """Context manager calls connect() and disconnect()"""
    state = [0]

    async def increment_state(*args, **kwargs):
        state[0] += 1

    # create client and replace instance methods with dummy methods
    client = Client("opc.tcp://dummy_address:10000")
    client.connect = increment_state.__get__(client)
    client.disconnect = increment_state.__get__(client)

    assert state[0] == 0
    async with client:
        # test if client connected
        assert state[0] == 1
    # test if client disconnected
    assert state[0] == 2


async def test_enumstrings_getvalue(server, client):
    """
    The real exception is server side, but is detected by using a client.
    All due the server trace is also visible on the console.
    The client only 'sees' an TimeoutError
    """
    nenumstrings = client.get_node(ua.ObjectIds.AxisScaleEnumeration_EnumStrings)
    await nenumstrings.read_value()


async def test_custom_enum_struct(server, client):
    await client.load_type_definitions()
    ns = await client.get_namespace_index("http://yourorganisation.org/struct_enum_example/")
    myvar = client.get_node(ua.NodeId(6009, ns))
    val = await myvar.read_value()
    assert 242 == val.IntVal1
    assert ua.ExampleEnum.EnumVal2 == val.EnumVal


async def test_multiple_read_and_write_value(server, client):
    f = await server.nodes.objects.add_folder(3, "Multiple_read_write_test")
    v1 = await f.add_variable(3, "a", 1)
    await v1.set_writable()
    v2 = await f.add_variable(3, "b", 2)
    await v2.set_writable()
    v3 = await f.add_variable(3, "c", 3)
    await v3.set_writable()
    v_ro = await f.add_variable(3, "ro", 3)

    vals = await client.read_values([v1, v2, v3])
    assert vals == [1, 2, 3]
    rets = await client.write_values([v1, v2, v3], [4, 5, 6])
    assert rets == [
        ua.StatusCode(value=ua.StatusCodes.Good),
        ua.StatusCode(value=ua.StatusCodes.Good),
        ua.StatusCode(value=ua.StatusCodes.Good),
    ]
    vals = await client.read_values([v1, v2, v3])
    assert vals == [4, 5, 6]
    with pytest.raises(ua.uaerrors.BadNotWritable):
        await client.write_values([v1, v2, v_ro], [4, 5, 6])
    rets = await client.write_values([v1, v2, v_ro], [4, 5, 6], raise_on_partial_error=False)
    assert rets == [
        ua.StatusCode(value=ua.StatusCodes.Good),
        ua.StatusCode(ua.StatusCodes.Good),
        ua.StatusCode(ua.StatusCodes.BadNotWritable),
    ]


async def test_read_and_write_status_check(server, client):
    f = await server.nodes.objects.add_folder(3, "read_and_write_status_check")
    v1 = await f.add_variable(3, "a", 1)
    await v1.set_writable()

    testValue = 1
    testStatusCode = ua.StatusCode(ua.StatusCodes.Bad)

    # set value StatusCode to Bad
    variant = ua.Variant(testValue, ua.VariantType.Int64)
    dataValue = ua.DataValue(variant, StatusCode=testStatusCode)
    await v1.set_value(dataValue)

    # check that reading the value generates an error
    # with raise_on_bad_status set to True as default
    with pytest.raises(ua.UaStatusCodeError):
        val = await v1.read_data_value()

    # check that reading the value does not generate an error
    # with raise_on_bad_status set to False
    val = await v1.read_data_value(False)
    assert val.Value.Value is None, "Value should be Null if StatusCode is Bad"
    assert val.StatusCode == testStatusCode, (
        "StatusCode expected " + str(val.StatusCode) + ", but instead got " + str(testStatusCode)
    )

    # check that reading the value generates an error
    # with raise_on_bad_status set to True
    with pytest.raises(ua.UaStatusCodeError):
        val = await v1.read_data_value(True)


async def test_browse_nodes(server, client):
    nodes = [
        client.get_node("ns=0;i=2267"),
        client.get_node("ns=0;i=2259"),
    ]
    results = await client.browse_nodes(nodes)
    assert len(results) == 2
    assert isinstance(results, list)
    assert results[0][0] == nodes[0]
    assert results[1][0] == nodes[1]
    assert isinstance(results[0][0], Node)
    assert isinstance(results[1][0], Node)
    assert isinstance(results[0][1], ua.BrowseResult)
    assert isinstance(results[1][1], ua.BrowseResult)


async def test_translate_browsepaths(server, client: Client):
    server_node = await client.nodes.objects.get_child("Server")

    relative_paths = ["/0:ServiceLevel", "/0:ServerStatus/0:State"]
    results = await client.translate_browsepaths(server_node.nodeid, relative_paths)
    assert len(results) == 2
    assert isinstance(results, list)
    assert results[0].StatusCode.value == ua.StatusCodes.Good
    assert results[0].Targets[0].TargetId == ua.NodeId.from_string("ns=0;i=2267")
    assert results[1].StatusCode.value == ua.StatusCodes.Good
    assert results[1].Targets[0].TargetId == ua.NodeId.from_string("ns=0;i=2259")
    for result in results:
        assert isinstance(result, ua.BrowsePathResult)

    results2 = await client.translate_browsepaths(server_node.nodeid, ["/0:UnknownPath"])
    assert len(results2) == 1
    assert isinstance(results2, list)
    assert results2[0].StatusCode.value == ua.StatusCodes.BadNoMatch
    assert len(results2[0].Targets) == 0

    with pytest.raises(ua.UaStringParsingError):
        await client.translate_browsepaths(server_node.nodeid, ["/1:<Boiler"])


async def test_strip_credentials_in_url():
    """Check that the credentials are correctly stripped in the server url"""

    client = Client("opc.tcp://user:password@dummy_address:10000")
    assert client.server_url.netloc == "dummy_address:10000"

    client = Client("opc.tcp://user:password@dummy_address:10000")
    client.strip_url_credentials = False
    assert client.server_url.netloc == "user:password@dummy_address:10000"


def test_cli71_default_client_name_is_enginir() -> None:
    client = Client("opc.tcp://127.0.0.1:4840")
    assert client.name == "engiNIR OPC UA Client"
    assert client.description == "engiNIR OPC UA Client"
