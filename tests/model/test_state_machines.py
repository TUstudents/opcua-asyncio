import copy
from typing import Any

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common.statemachine import FiniteStateMachine, State, StateMachine, Transition


def required[T](value: T | None) -> T:
    assert value is not None
    return value


@pytest.fixture(scope="module")
async def srv() -> Any:
    server = Server()
    await server.init()
    await server.register_namespace("urn:test:sm")
    yield server


async def build(srv: Server, optionals: bool = True) -> tuple[FiniteStateMachine, State, State, Transition]:
    machine = FiniteStateMachine(srv, srv.nodes.objects, 2, "Machine")
    await machine.install(optionals=optionals)
    idle = State(None, "Idle", 0)
    busy = State(None, "Busy", 1)
    await machine.add_state(idle, state_type=ua.NodeId(ua.ObjectIds.InitialStateType))
    await machine.add_state(busy)
    go = Transition(None, "Go", 1)
    await machine.add_transition(go, from_state=idle, to_state=busy)
    return machine, idle, busy, go


async def test_com44_finite_state_machine_installs_with_generated_type(srv: Server) -> None:
    """Part 5, B.4.5: FiniteStateMachineType is abstract; a concrete subtype is instantiated."""
    machine = FiniteStateMachine(srv, srv.nodes.objects, 2, "M")
    await machine.install()
    kind = await machine._state_machine_node.read_type_definition()
    assert kind is not None and kind != ua.NodeId(ua.ObjectIds.FiniteStateMachineType)
    assert (await srv.get_node(kind).read_attribute(ua.AttributeIds.IsAbstract)).Value.Value is False  # type: ignore[union-attr]


async def test_com44_given_abstract_type_raises(srv: Server) -> None:
    machine = FiniteStateMachine(
        srv, srv.nodes.objects, 2, "M2", state_machine_type=ua.NodeId(ua.ObjectIds.FiniteStateMachineType)
    )
    with pytest.raises(ValueError):
        await machine.install()


async def test_com44_example_runs() -> None:
    server = Server(allow_no_security=True)
    await server.init()
    namespace = await server.register_namespace("urn:test:example")
    machine = FiniteStateMachine(server, server.nodes.objects, namespace, "FiniteStateMachine")
    await machine.install(optionals=True)
    states = [State(None, f"S{i}", i) for i in range(3)]
    for state in states:
        await machine.add_state(state)
    transitions = []
    for i, (a, b) in enumerate([(0, 1), (1, 2), (2, 0)], 1):
        transition = Transition(None, f"T{i}", i)
        await machine.add_transition(transition, from_state=states[a], to_state=states[b])
        transitions.append(transition)
    await machine.set_available_states([required(s.node).nodeid for s in states])
    await machine.set_available_transitions([required(t.node).nodeid for t in transitions])
    await machine.change_state(states[0], transitions[2])
    await machine.change_state(states[1], transitions[0])


async def test_com45_available_lists(srv: Server) -> None:
    machine, _idle, _busy, go = await build(srv)
    with pytest.raises(ValueError):
        await machine.set_available_states("nope")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        await machine.set_available_transitions([1])  # type: ignore[list-item]
    await machine.set_available_transitions([required(go.node).nodeid])
    value = await (await machine._state_machine_node.get_child("AvailableTransitions")).read_value()
    assert value == [required(go.node).nodeid]
    bare, *_ = await build(srv, optionals=False)
    with pytest.raises(ua.UaError):
        await bare.set_available_transitions([required(go.node).nodeid])


async def test_com46_transition_time_is_created_in_the_machine_namespace(srv: Server) -> None:
    machine = StateMachine(srv, srv.nodes.objects, 2, "Plain")
    await machine.install(optionals=True)
    last = await machine._state_machine_node.get_child("LastTransition")
    times = [c for c in await last.get_children() if (await c.read_browse_name()).Name == "TransitionTime"]
    assert len(times) == 1
    assert times[0].nodeid.NamespaceIndex == 2


async def test_com47_state_number_zero_is_valid(srv: Server) -> None:
    machine, idle, _busy, _go = await build(srv)
    await machine.change_state(idle)
    number = await machine._current_state_number_node.read_value()  # type: ignore[union-attr]
    assert number == 0


async def test_com95_duplicates_and_second_initial_state_raise(srv: Server) -> None:
    machine, _idle, _busy, _go = await build(srv)
    with pytest.raises(ValueError):
        await machine.add_state(State(None, "Idle", 7))
    with pytest.raises(ValueError):
        await machine.add_state(State(None, "Other", 1))
    with pytest.raises(ValueError):
        await machine.add_state(State(None, "Second", 9), state_type=ua.NodeId(ua.ObjectIds.InitialStateType))
    with pytest.raises(ValueError):
        await machine.add_state(State(None, "Bad", 9), state_type=ua.NodeId(ua.ObjectIds.BaseObjectType))
    with pytest.raises(ValueError):
        await machine.add_state(State(None, "NoNumber", None))


async def test_com95_transition_has_from_and_to_state_references(srv: Server) -> None:
    _machine, idle, busy, go = await build(srv)
    assert await required(go.node).get_referenced_nodes(ua.ObjectIds.FromState, ua.BrowseDirection.Forward) == [
        idle.node
    ]
    assert await required(go.node).get_referenced_nodes(ua.ObjectIds.ToState, ua.BrowseDirection.Forward) == [busy.node]


async def test_com95_transition_to_foreign_state_raises(srv: Server) -> None:
    machine, idle, _busy, _go = await build(srv)
    with pytest.raises(ValueError):
        await machine.add_transition(Transition(None, "Bad", 5), from_state=idle, to_state=State(None, "Ghost", 8))


async def test_com93_change_state_on_base_machine(srv: Server) -> None:
    machine = StateMachine(srv, srv.nodes.objects, 2, "Base")
    await machine.install(optionals=True)
    state = State(None, "Run", 1)
    await machine.add_state(state)
    transition = Transition(None, "Start", 1)
    await machine.add_transition(transition)
    await machine.change_state(state, transition)
    assert (await required(machine._current_state_node).read_value()).Text == "Run"
    assert await machine._current_state_id_node.read_value() == "Run"  # type: ignore[union-attr]


async def test_com93_finite_machine_id_is_the_state_node_id(srv: Server) -> None:
    machine, idle, busy, go = await build(srv)
    await machine.change_state(idle)
    await machine.change_state(busy, go)
    assert await machine._current_state_id_node.read_value() == required(busy.node).nodeid  # type: ignore[union-attr]
    assert await machine._last_transition_id_node.read_value() == required(go.node).nodeid  # type: ignore[union-attr]


async def test_com94_transition_without_last_transition_is_skipped(srv: Server) -> None:
    machine, idle, busy, go = await build(srv, optionals=False)
    await machine.change_state(idle)
    await machine.change_state(busy, go)
    assert (await required(machine._current_state_node).read_value()).Text == "Busy"


async def test_com94_init_binds_an_existing_machine(srv: Server) -> None:
    machine, _idle, _busy, _go = await build(srv)
    second = FiniteStateMachine(srv, srv.nodes.objects, 2, "Bound")
    await second.init(machine._state_machine_node)
    assert second._event_generator().event.SourceNode == machine._state_machine_node.nodeid
    assert second._last_transition_node is not None


async def test_transition_must_connect_the_states(srv: Server) -> None:
    machine, _idle, busy, go = await build(srv)
    await machine.change_state(busy)
    with pytest.raises(ValueError):
        await machine.change_state(busy, go)
    with pytest.raises(ValueError):
        await machine.change_state(State(None, "Ghost", 3))
    assert machine._current_state is busy


async def test_com95_every_change_triggers_an_event_with_states_and_message(srv: Server) -> None:
    machine, idle, busy, go = await build(srv)
    received: list[Any] = []
    original = machine._event_generator().trigger

    async def spy(*args: Any, **kwargs: Any) -> Any:
        received.append(copy.copy(machine._event_generator().event))
        return await original(*args, **kwargs)

    machine._event_generator().trigger = spy  # type: ignore[method-assign]
    await machine.change_state(idle)
    await machine.change_state(busy, go)
    assert [e.Message.Text for e in received] == ["Idle", "Idle to Busy"]
    last = received[-1]
    assert (last.FromState.Text, last.ToState.Text, last.Transition.Text) == ("Idle", "Busy", "Go")
    assert last.FromState.Locale == "en-US"


def test_com47_server_without_event_generator_is_rejected() -> None:
    with pytest.raises(ValueError):
        StateMachine(object(), None, 2, "x")  # type: ignore[arg-type]
