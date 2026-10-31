from typing import Any

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common.node import Node

NODE = ua.NodeId("n", 2)


def description(number: int) -> ua.ReferenceDescription:
    return ua.ReferenceDescription(NodeId=ua.NodeId(number, 2), BrowseName=ua.QualifiedName(f"c{number}", 2))


class FakeSession:
    def __init__(self) -> None:
        self.browse_results: list[ua.BrowseResult] = []
        self.next_results: list[ua.BrowseResult | Exception] = []
        self.browse_next_calls: list[ua.BrowseNextParameters] = []
        self.history_results: list[ua.HistoryReadResult] = []
        self.history_calls: list[ua.HistoryReadParameters] = []
        self.translate_results: list[ua.BrowsePathResult] = []
        self.update_result = ua.HistoryUpdateResult()
        self.add_reference_items: list[ua.AddReferencesItem] = []
        self.reads: list[ua.ReadParameters] = []
        self.node_class = ua.NodeClass.Object

    async def browse(self, params: ua.BrowseParameters) -> list[ua.BrowseResult]:
        return self.browse_results

    async def browse_next(self, params: ua.BrowseNextParameters) -> list[ua.BrowseResult]:
        self.browse_next_calls.append(params)
        item = self.next_results.pop(0) if self.next_results else ua.BrowseResult()
        if isinstance(item, Exception):
            raise item
        return [item]

    async def history_read(self, params: ua.HistoryReadParameters) -> list[ua.HistoryReadResult]:
        self.history_calls.append(params)
        return [self.history_results.pop(0) if self.history_results else ua.HistoryReadResult()]

    async def translate_browsepaths_to_nodeids(self, paths: list[ua.BrowsePath]) -> list[ua.BrowsePathResult]:
        return self.translate_results

    async def history_update(self, params: ua.HistoryUpdateParameters) -> list[ua.HistoryUpdateResult]:
        return [self.update_result]

    async def add_references(self, items: list[ua.AddReferencesItem]) -> list[ua.StatusCode]:
        self.add_reference_items = items
        return [ua.StatusCode() for _ in items]

    async def read(self, params: ua.ReadParameters) -> list[ua.DataValue]:
        self.reads.append(params)
        node_class = self.node_class if params.NodesToRead[0].NodeId != NODE else ua.NodeClass.Object
        return [ua.DataValue(ua.Variant(int(node_class), ua.VariantType.Int32))]


def numbers(values: list[ua.DataValue]) -> list[Any]:
    return [v.Value.Value for v in values if v.Value is not None]


def node(session: FakeSession) -> Node:
    return Node(session, NODE)  # type: ignore[arg-type]


async def test_com14_bad_browse_result_raises() -> None:
    session = FakeSession()
    session.browse_results = [ua.BrowseResult(StatusCode=ua.StatusCode(ua.StatusCodes.BadNodeIdUnknown))]
    with pytest.raises(ua.uaerrors.BadNodeIdUnknown):
        await node(session).get_children()


async def test_com14_browse_next_failure_raises_and_releases() -> None:
    session = FakeSession()
    session.browse_results = [ua.BrowseResult(ContinuationPoint=b"cp1", References=[description(1)])]
    session.next_results = [ua.BrowseResult(StatusCode=ua.StatusCode(ua.StatusCodes.BadContinuationPointInvalid))]
    with pytest.raises(ua.uaerrors.BadContinuationPointInvalid):
        await node(session).get_children()
    assert session.browse_next_calls[-1].ReleaseContinuationPoints is True
    assert session.browse_next_calls[-1].ContinuationPoints == [b"cp1"]


async def test_com14_browse_next_pages_are_joined() -> None:
    session = FakeSession()
    session.browse_results = [ua.BrowseResult(ContinuationPoint=b"cp1", References=[description(1)])]
    session.next_results = [ua.BrowseResult(References=[description(2)])]
    children = await node(session).get_children()
    assert [child.nodeid.Identifier for child in children] == [1, 2]
    assert all(call.ReleaseContinuationPoints is False for call in session.browse_next_calls)


def raw_page(values: list[int], point: bytes | None) -> ua.HistoryReadResult:
    data = ua.HistoryData(DataValues=[ua.DataValue(ua.Variant(v, ua.VariantType.Int32)) for v in values])
    return ua.HistoryReadResult(ContinuationPoint=point, HistoryData=data)


async def test_com16_raw_history_follows_points() -> None:
    session = FakeSession()
    session.history_results = [raw_page([1, 2], b"a"), raw_page([3], None)]
    values = await node(session).read_raw_history()
    assert numbers(values) == [1, 2, 3]
    assert len(session.history_calls) == 2


async def test_com16_raw_history_releases_open_point() -> None:
    session = FakeSession()
    session.history_results = [raw_page([1, 2], b"a")]
    values = await node(session).read_raw_history(numvalues=2)
    assert numbers(values) == [1, 2]
    last = session.history_calls[-1]
    assert last.ReleaseContinuationPoints is True
    assert last.NodesToRead[0].ContinuationPoint == b"a"


async def test_com16_raw_history_truncates_to_numvalues() -> None:
    session = FakeSession()
    session.history_results = [raw_page([1, 2, 3], b"a")]
    values = await node(session).read_raw_history(numvalues=2)
    assert numbers(values) == [1, 2]


def event_page(count: int, point: bytes | None, start: int = 0) -> ua.HistoryReadResult:
    events = [ua.HistoryEventFieldList(EventFields=[ua.Variant(start + i, ua.VariantType.Int32)]) for i in range(count)]
    return ua.HistoryReadResult(ContinuationPoint=point, HistoryData=ua.HistoryEvent(Events=events))


async def test_com16_event_history_follows_continuation_points() -> None:
    session = FakeSession()
    session.history_results = [event_page(2, b"a"), event_page(1, None, 2)]
    session.browse_results = [ua.BrowseResult()]
    events = await node(session).read_event_history()
    assert len(events) == 3
    assert session.history_calls[1].NodesToRead[0].ContinuationPoint == b"a"


async def test_history_without_history_data_is_empty() -> None:
    """Part 4, 5.11.3: a GoodNoData result may carry a null HistoryData."""
    session = FakeSession()
    session.history_results = [ua.HistoryReadResult(StatusCode=ua.StatusCode(ua.StatusCodes.GoodNoData))] * 2
    session.browse_results = [ua.BrowseResult()]
    assert await node(session).read_raw_history() == []
    assert await node(session).read_event_history() == []


async def test_com17_incompletely_resolved_target_is_not_found() -> None:
    session = FakeSession()
    session.translate_results = [
        ua.BrowsePathResult(
            Targets=[ua.BrowsePathTarget(TargetId=ua.NodeId(1, 2), RemainingPathIndex=1)],
        )
    ]
    with pytest.raises(ua.uaerrors.BadNoMatch):
        await node(session).get_child("2:a")
    assert await node(session).get_children_by_path(["2:a"], raise_on_partial_error=False) == [None]
    with pytest.raises(ua.UaStatusCodeErrors):
        await node(session).get_children_by_path(["2:a"])


async def test_com17_complete_target_is_found() -> None:
    session = FakeSession()
    session.translate_results = [
        ua.BrowsePathResult(Targets=[ua.BrowsePathTarget(TargetId=ua.NodeId(1, 2), RemainingPathIndex=0xFFFFFFFF)])
    ]
    assert (await node(session).get_child("2:a")).nodeid == ua.NodeId(1, 2)


async def test_com106_history_update_operation_result_raises() -> None:
    session = FakeSession()
    session.update_result = ua.HistoryUpdateResult(OperationResults=[ua.StatusCode(ua.StatusCodes.BadNodeIdUnknown)])
    with pytest.raises(ua.uaerrors.BadNodeIdUnknown):
        await node(session).history_update(ua.UpdateDataDetails())


async def test_com104_add_reference_sends_target_node_class() -> None:
    session = FakeSession()
    session.node_class = ua.NodeClass.Variable
    await node(session).add_reference(ua.NodeId(9, 2), ua.ObjectIds.Organizes, True, True)
    assert [item.TargetNodeClass for item in session.add_reference_items] == [
        ua.NodeClass.Variable,
        ua.NodeClass.Object,
    ]


async def test_com104_target_node_class_can_be_given() -> None:
    session = FakeSession()
    await node(session).add_reference(
        ua.NodeId(9, 2), ua.ObjectIds.Organizes, True, False, target_class=ua.NodeClass.Method
    )
    assert session.add_reference_items[0].TargetNodeClass == ua.NodeClass.Method
    assert session.reads == []


@pytest.fixture(scope="module")
async def local_server() -> Any:
    srv = Server()
    await srv.init()
    await srv.register_namespace("urn:test:node")
    yield srv


async def test_com13_write_array_dimensions_writes_an_array(local_server: Server) -> None:
    variable = await local_server.nodes.objects.add_variable(ua.NodeId(0, 2), "2:Arr", [1, 2, 3])
    await variable.write_array_dimensions([3])
    assert await variable.read_array_dimensions() == [3]
    await variable.write_array_dimensions(4)
    assert await variable.read_array_dimensions() == [4]


async def test_com97_read_value_rank_above_four(local_server: Server) -> None:
    variable = await local_server.nodes.objects.add_variable(ua.NodeId(0, 2), "2:Arr", [1, 2, 3])
    await variable.write_value_rank(5)
    assert await variable.read_value_rank() == 5
    await variable.write_value_rank(1)
    assert await variable.read_value_rank() is ua.ValueRank.OneDimension


async def test_get_path_ends_with_the_node(local_server: Server) -> None:
    folder = await local_server.nodes.objects.add_folder(ua.NodeId(0, 2), "2:F")
    path = await folder.get_path()
    assert path[0].nodeid == ua.NodeId(ua.ObjectIds.RootFolder)
    assert path[-1] == folder
