import asyncio
from typing import Any

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common.events import (
    Event,
    _event_type_nodes_up_to_base,
    get_event_obj_from_type_node,
    get_event_properties_from_type_node,
    select_clauses_from_evtype,
    where_clause_from_evtype,
)
from enginir_opcua.common.utils import wait_for


@pytest.fixture(scope="module")
async def srv() -> Any:
    server = Server()
    await server.init()
    await server.register_namespace("urn:test:events")
    yield server


async def test_com29_where_clause_uses_of_type(srv: Server) -> None:
    """Part 4, 7.7.3: OfType is decided by the server and includes subtypes."""
    node = srv.get_node(ua.ObjectIds.AuditEventType)
    clause = await where_clause_from_evtype([node])
    assert len(clause.Elements) == 1
    element = clause.Elements[0]
    assert element.FilterOperator == ua.FilterOperator.OfType
    assert element.FilterOperands[0].Value.Value == node.nodeid


async def test_com29_where_clause_for_two_types_uses_or(srv: Server) -> None:
    first, second, third = (srv.get_node(i) for i in (ua.ObjectIds.AuditEventType, 2041, 2052))
    clause = await where_clause_from_evtype([first, second, third])
    operators = [e.FilterOperator for e in clause.Elements]
    assert (
        operators
        == [ua.FilterOperator.Or, ua.FilterOperator.OfType, ua.FilterOperator.Or] + [ua.FilterOperator.OfType] * 2
    )
    assert clause.Elements[0].FilterOperands[1].Index == 2
    wanted = [e.FilterOperands[0].Value.Value for e in clause.Elements if e.FilterOperator == ua.FilterOperator.OfType]
    assert wanted == [first.nodeid, second.nodeid, third.nodeid]


async def test_com29_unknown_parent_chain_raises(srv: Server) -> None:
    orphan = await srv.nodes.base_object_type.add_object_type(ua.NodeId("orphan", 2), "2:orphan")
    with pytest.raises(ua.UaError):
        await _event_type_nodes_up_to_base(orphan)
    with pytest.raises(ua.UaError):
        await select_clauses_from_evtype([orphan])


async def test_a_cycle_of_event_types_raises_instead_of_hanging(srv: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    from enginir_opcua.common.node import Node

    first = await srv.nodes.base_event_type.add_object_type(ua.NodeId("cycle_a", 2), "2:cycle_a")
    second = await first.add_object_type(ua.NodeId("cycle_b", 2), "2:cycle_b")
    original = Node.get_referenced_nodes

    async def looping(self: Node, *args: Any, **kwargs: Any) -> list[Node]:
        if self.nodeid == first.nodeid and kwargs.get("direction") == ua.BrowseDirection.Inverse:
            await asyncio.sleep(0)
            return [second]
        return await original(self, *args, **kwargs)

    monkeypatch.setattr(Node, "get_referenced_nodes", looping)
    for helper in (select_clauses_from_evtype([second]), get_event_obj_from_type_node(second)):
        with pytest.raises(ua.UaError):
            await wait_for(helper, 5)
    assert await wait_for(get_event_properties_from_type_node(second), 5) is None


async def test_com28_property_is_not_browsed_again(srv: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    from enginir_opcua.common.node import Node

    base = srv.get_node(ua.ObjectIds.BaseEventType)
    calls: list[ua.NodeId] = []
    original = Node.get_references

    async def spy(self: Node, *args: Any, **kwargs: Any) -> Any:
        calls.append(self.nodeid)
        return await original(self, *args, **kwargs)

    monkeypatch.setattr(Node, "get_references", spy)
    clauses = await select_clauses_from_evtype([base])
    assert any(c.BrowsePath[0].Name == "Severity" for c in clauses)
    severity = ua.NodeId(ua.ObjectIds.BaseEventType_Severity)
    assert severity not in calls


def test_com28_from_event_fields_accepts_plain_int_attribute_id() -> None:
    clause = ua.SimpleAttributeOperand()
    clause.AttributeId = int(ua.AttributeIds.NodeId)  # type: ignore[assignment]
    event = Event.from_event_fields([clause], [ua.Variant(ua.NodeId(1, 2))])
    assert event.NodeId == ua.NodeId(1, 2)  # type: ignore[attr-defined]


def test_com110_fewer_values_than_clauses_raises() -> None:
    clause = ua.SimpleAttributeOperand()
    clause.AttributeId = ua.AttributeIds.NodeId
    with pytest.raises(ua.UaError):
        Event.from_event_fields([clause, clause], [ua.Variant(1)])
