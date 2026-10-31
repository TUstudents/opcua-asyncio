"""
State machines of OPC 10000-16 (StateMachineType, FiniteStateMachineType; Annex B of OPC 10000-5 in v1.04) in the
address space of a local server: the helpers keep CurrentState and LastTransition current and raise
TransitionEvents. Sub state machines and the specialised state machines of other parts are not implemented.
"""

from __future__ import annotations

import datetime
import logging
from typing import TYPE_CHECKING, Any

from enginir_opcua import Node, ua
from enginir_opcua.common.event_objects import TransitionEvent

from .instantiate_util import is_abstract
from .ua_utils import is_subtype

if TYPE_CHECKING:
    from enginir_opcua import Server
    from enginir_opcua.server.event_generator import EventGenerator

_logger = logging.getLogger(__name__)

_STATE_TYPE = ua.NodeId(ua.ObjectIds.StateType)
_INITIAL_STATE_TYPE = ua.NodeId(ua.ObjectIds.InitialStateType)
_TRANSITION_TYPE = ua.NodeId(ua.ObjectIds.TransitionType)
_STATE_MACHINE_TYPE = ua.NodeId(ua.ObjectIds.StateMachineType)
_FINITE_STATE_MACHINE_TYPE = ua.NodeId(ua.ObjectIds.FiniteStateMachineType)


class State:
    """
    A State of a machine, represented by an Object of StateType.

    :param name: the BrowseName of the State and the text written to CurrentState.
    :param id: the value written to the Id property of CurrentState; by default the NodeId of the State
        or its name, depending on the DataType the property declares.
    :param number: the unique StateNumber (UInt32, 0 is allowed).
    :param node: set by add_state, or given when the State already exists in the address space.
    """

    def __init__(self, id: Any, name: str | None = None, number: int | None = None, node: Node | None = None) -> None:
        self.id: ua.Variant | None = ua.Variant(id) if id is not None else None
        self.name = name
        self.number = number
        self.node = node
        self.initial = False


class Transition:
    """
    A Transition of a machine, represented by an Object of TransitionType.
    name: the BrowseName of the Transition and the text written to LastTransition.
    id: the value written to the Id property of LastTransition, like State.id.
    number: the unique TransitionNumber (UInt32).
    from_state, to_state: set by add_transition.
    """

    def __init__(self, id: Any, name: str | None = None, number: int | None = None, node: Node | None = None) -> None:
        self.id: ua.Variant | None = ua.Variant(id) if id is not None else None
        self.name = name
        self.number = number
        self.from_state: State | None = None
        self.to_state: State | None = None
        self._transitiontime = datetime.datetime.now(datetime.UTC)
        self.node = node


class StateMachine:
    """
    A StateMachineType instance: CurrentState (mandatory) and LastTransition (optional), generating TransitionEvents.
    server is the local Server that fires the events, parent the node the machine is created below, idx the
    namespace of the new nodes (default: the parent's).
    """

    def __init__(
        self,
        server: Server,
        parent: Node,
        idx: int | None = None,
        name: str | None = None,
    ) -> None:
        if not hasattr(server, "get_event_generator"):
            raise ValueError(f"server: {type(server)} cannot generate events")
        if not isinstance(parent, Node):
            raise ValueError(f"parent: {type(parent)} is not a instance of Node class")
        if idx is None:
            idx = parent.nodeid.NamespaceIndex
        if name is None:
            name = "StateMachine"
        self.locale = "en-US"
        self._server = server
        self._parent = parent
        self._machine: Node | None = None
        self._state_machine_type = _STATE_MACHINE_TYPE
        self._name = name
        self._idx = idx
        self._optionals = False
        self._current_state_node: Node | None = None
        self._current_state_id_node: Node | None = None
        self._current_state_name_node: Node | None = None
        self._current_state_number_node: Node | None = None
        self._current_state_effective_display_name_node: Node | None = None
        self._last_transition_node: Node | None = None
        self._last_transition_id_node: Node | None = None
        self._last_transition_name_node: Node | None = None
        self._last_transition_number_node: Node | None = None
        self._last_transition_transitiontime_node: Node | None = None
        self._evgen: EventGenerator | None = None
        self.evtype = TransitionEvent()
        self._current_state = State(None)
        self._states: list[State] = []
        self._transitions: list[Transition] = []

    @property
    def _state_machine_node(self) -> Node:
        if self._machine is None:
            raise ua.UaError(f"Statemachine: {self._name} is not installed; call install() or init() first")
        return self._machine

    @_state_machine_node.setter
    def _state_machine_node(self, node: Node) -> None:
        self._machine = node

    def _event_generator(self) -> EventGenerator:
        if self._evgen is None:
            raise ua.UaError(f"Statemachine: {self._name} is not installed; call install() or init() first")
        return self._evgen

    async def _concrete_type(self) -> ua.NodeId:
        return self._state_machine_type

    async def install(self, optionals: bool = False) -> None:
        """
        Create the machine below the parent. With optionals the machine also has LastTransition and its TransitionTime.
        """
        self._optionals = optionals
        machine_type = await self._concrete_type()
        self._state_machine_node = await self._parent.add_object(
            self._idx, self._name, objecttype=machine_type, instantiate_optional=optionals
        )
        if self._optionals:
            last_transition = await self._state_machine_node.get_child(["LastTransition"])
            names = [await child.read_browse_name() for child in await last_transition.get_children()]
            if ua.QualifiedName("TransitionTime", 0) not in names:
                await last_transition.add_property(
                    ua.NodeId(NamespaceIndex=self._idx),
                    ua.QualifiedName("TransitionTime", 0),
                    ua.Variant(datetime.datetime.now(datetime.UTC), VariantType=ua.VariantType.DateTime),
                )
        await self.init(self._state_machine_node)

    async def _property_nodes(self, variable: Node) -> dict[str, Node]:
        return {(await prop.read_browse_name()).Name: prop for prop in await variable.get_properties()}

    async def init(self, statemachine: Node) -> None:
        """
        Bind to an existing machine: find CurrentState, LastTransition and their properties and prepare the events.
        """
        self._state_machine_node = statemachine
        self._current_state_node = await statemachine.get_child(["CurrentState"])
        current = await self._property_nodes(self._current_state_node)
        self._current_state_id_node = current.get("Id")
        self._current_state_name_node = current.get("Name")
        self._current_state_number_node = current.get("Number")
        self._current_state_effective_display_name_node = current.get("EffectiveDisplayName")
        try:
            self._last_transition_node = await statemachine.get_child(["LastTransition"])
        except ua.UaStatusCodeError:
            self._last_transition_node = None
        if self._last_transition_node is not None:
            last = await self._property_nodes(self._last_transition_node)
            self._last_transition_id_node = last.get("Id")
            self._last_transition_name_node = last.get("Name")
            self._last_transition_number_node = last.get("Number")
            self._last_transition_transitiontime_node = last.get("TransitionTime")
        self._evgen = await self._server.get_event_generator(self.evtype, self._state_machine_node)

    async def _id_variant(self, item: State | Transition, id_node: Node) -> ua.Variant:
        datatype = await id_node.read_data_type()
        if datatype == ua.NodeId(ua.ObjectIds.NodeId):
            if item.id is not None and item.id.VariantType != ua.VariantType.NodeId:
                raise ValueError(f"Statemachine: {self._name} -> id of {item.name} must be a NodeId")
            return item.id if item.id is not None else self._node_id_variant(item)
        if datatype == ua.NodeId(ua.ObjectIds.String):
            if item.id is not None and item.id.VariantType != ua.VariantType.String:
                raise ValueError(f"Statemachine: {self._name} -> id of {item.name} must be a String")
            return item.id if item.id is not None else ua.Variant(item.name, ua.VariantType.String)
        return item.id if item.id is not None else self._node_id_variant(item)

    def _node_id_variant(self, item: State | Transition) -> ua.Variant:
        if item.node is None:
            raise ValueError(f"Statemachine: {self._name} -> {item.name} has no node")
        return ua.Variant(item.node.nodeid, ua.VariantType.NodeId)

    def _check_change(self, state: State, transition: Transition | None) -> None:
        if not isinstance(state, State):
            raise ValueError(f"Statemachine: {self._name} -> state: {state} is not a instance of State class")
        if state.node is None or not any(state is known for known in self._states):
            raise ValueError(f"Statemachine: {self._name} -> state {state.name} was not added with add_state")
        if transition is None:
            return
        if not isinstance(transition, Transition):
            raise ValueError(
                f"Statemachine: {self._name} -> transition: {transition} is not a instance of Transition class"
            )
        if not any(transition is known for known in self._transitions):
            raise ValueError(f"Statemachine: {self._name} -> transition {transition.name} was not added")
        if transition.to_state is not None and transition.to_state is not state:
            raise ValueError(
                f"Statemachine: {self._name} -> transition {transition.name} does not lead to {state.name}"
            )
        current = self._current_state
        if transition.from_state is not None and current.node is not None and transition.from_state is not current:
            raise ValueError(
                f"Statemachine: {self._name} -> transition {transition.name} does not start at {current.name}"
            )

    async def change_state(
        self,
        state: State,
        transition: Transition | None = None,
        event_msg: str | ua.LocalizedText | None = None,
        severity: int = 500,
    ) -> None:
        """
        Make state the current state, record the transition if given, and raise a TransitionEvent.
        The state and transition must have been added to this machine and the transition must connect the
        current state to the new one. event_msg is the Message of the event, by default "<from> to <to>".
        """
        self._check_change(state, transition)
        if isinstance(event_msg, str):
            event_msg = ua.LocalizedText(event_msg, self.locale)
        if event_msg is not None and not isinstance(event_msg, ua.LocalizedText):
            raise ValueError(f"Statemachine: {self._name} -> event_msg: {event_msg} is not a instance of LocalizedText")
        previous = self._current_state
        await self._write_state(state)
        if transition:
            await self._write_transition(transition)
        from_text = ua.LocalizedText(previous.name, self.locale) if previous.name else ua.LocalizedText()
        to_text = ua.LocalizedText(state.name, self.locale)
        if event_msg is None:
            event_msg = ua.LocalizedText(
                f"{previous.name} to {state.name}" if previous.name else state.name, self.locale
            )
        evgen = self._event_generator()
        event: Any = evgen.event
        event.Message = event_msg
        event.Severity = severity
        event.ToState = to_text
        event.FromState = from_text
        event.Transition = ua.LocalizedText(transition.name, self.locale) if transition else ua.LocalizedText()
        await evgen.trigger()
        self._current_state = state

    async def _write_state(self, state: State) -> None:
        if self._current_state_node is None:
            raise ua.UaError(f"Statemachine: {self._name} is not installed; call install() or init() first")
        await self._current_state_node.write_value(
            ua.LocalizedText(state.name, self.locale), ua.VariantType.LocalizedText
        )
        if self._current_state_id_node:
            await self._current_state_id_node.write_value(await self._id_variant(state, self._current_state_id_node))
        if self._current_state_name_node and state.name:
            await self._current_state_name_node.write_value(
                ua.QualifiedName(state.name, self._idx), ua.VariantType.QualifiedName
            )
        if self._current_state_number_node and state.number is not None:
            await self._current_state_number_node.write_value(state.number, ua.VariantType.UInt32)
        if self._current_state_effective_display_name_node:
            await self._current_state_effective_display_name_node.write_value(
                ua.LocalizedText(state.name, self.locale), ua.VariantType.LocalizedText
            )

    async def _write_transition(self, transition: Transition) -> None:
        if self._last_transition_node is None:
            return
        transition._transitiontime = datetime.datetime.now(datetime.UTC)
        await self._last_transition_node.write_value(
            ua.LocalizedText(transition.name, self.locale), ua.VariantType.LocalizedText
        )
        if self._last_transition_id_node:
            await self._last_transition_id_node.write_value(
                await self._id_variant(transition, self._last_transition_id_node)
            )
        if self._last_transition_name_node and transition.name:
            await self._last_transition_name_node.write_value(
                ua.QualifiedName(transition.name, self._idx), ua.VariantType.QualifiedName
            )
        if self._last_transition_number_node and transition.number is not None:
            await self._last_transition_number_node.write_value(transition.number, ua.VariantType.UInt32)
        if self._last_transition_transitiontime_node:
            await self._last_transition_transitiontime_node.write_value(
                transition._transitiontime, ua.VariantType.DateTime
            )

    def _check_unique(self, item: State | Transition, known: list[State] | list[Transition], kind: str) -> str:
        if not item.name:
            raise ValueError(f"Statemachine: {self._name} -> {kind}.name is None")
        if item.number is None:
            raise ValueError(f"Statemachine: {self._name} -> {kind}.number is None")
        if not 0 <= item.number <= 0xFFFFFFFF:
            raise ValueError(f"Statemachine: {self._name} -> {kind}.number {item.number} is not a UInt32")
        for other in known:
            if other.name == item.name:
                raise ValueError(f"Statemachine: {self._name} -> {kind} name {item.name} is used twice")
            if other.number == item.number:
                raise ValueError(f"Statemachine: {self._name} -> {kind} number {item.number} is used twice")
        return item.name

    async def add_state(self, state: State, state_type: ua.NodeId = _STATE_TYPE, optionals: bool = False) -> Node:
        """
        Add a State object to the machine. state_type is StateType, InitialStateType or any subtype of StateType;
        a machine has at most one State of InitialStateType.
        """
        if not isinstance(state, State):
            raise ValueError(f"Statemachine: {self._name} -> state: {state} is not a instance of State class")
        if not await is_subtype(Node(self._parent.session, state_type), _STATE_TYPE):
            raise ValueError(f"Statemachine: {self._name} -> state_type: {state_type} is not a StateType")
        name = self._check_unique(state, self._states, "State")
        if state_type == _INITIAL_STATE_TYPE and any(s.initial for s in self._states):
            raise ValueError(f"Statemachine: {self._name} -> the machine already has an initial State")
        node = await self._state_machine_node.add_object(
            self._idx, name, objecttype=state_type, instantiate_optional=optionals
        )
        state.node = node
        state.initial = state_type == _INITIAL_STATE_TYPE
        state_number = await node.get_child(["StateNumber"])
        await state_number.write_value(state.number, ua.VariantType.UInt32)
        self._states.append(state)
        return node

    async def add_transition(
        self,
        transition: Transition,
        transition_type: ua.NodeId = _TRANSITION_TYPE,
        optionals: bool = False,
        from_state: State | None = None,
        to_state: State | None = None,
    ) -> Node:
        """
        Add a Transition object to the machine. With from_state and to_state, which must belong to the machine,
        it gets one FromState and one ToState reference, and change_state only accepts it between these states.
        """
        if not isinstance(transition, Transition):
            raise ValueError(f"Statemachine: {self._name} -> transition: {transition} is not a instance of Transition")
        for end in (from_state, to_state):
            if end is not None and not any(end is known for known in self._states):
                raise ValueError(f"Statemachine: {self._name} -> state {end.name} was not added with add_state")
        if (from_state is None) != (to_state is None):
            raise ValueError(f"Statemachine: {self._name} -> a transition needs both from_state and to_state")
        name = self._check_unique(transition, self._transitions, "Transition")
        node = await self._state_machine_node.add_object(
            self._idx, name, objecttype=transition_type, instantiate_optional=optionals
        )
        transition.node = node
        transition_number = await node.get_child(["TransitionNumber"])
        await transition_number.write_value(transition.number, ua.VariantType.UInt32)
        if (
            from_state is not None
            and to_state is not None
            and from_state.node is not None
            and to_state.node is not None
        ):
            await node.add_reference(from_state.node, ua.ObjectIds.FromState, True, True, ua.NodeClass.Object)
            await node.add_reference(to_state.node, ua.ObjectIds.ToState, True, True, ua.NodeClass.Object)
            transition.from_state = from_state
            transition.to_state = to_state
        self._transitions.append(transition)
        return node


class FiniteStateMachine(StateMachine):
    """
    A FiniteStateMachineType instance: the States and Transitions are objects of the machine, and the machine
    can list the available ones. FiniteStateMachineType is abstract, so install creates a concrete subtype
    in the namespace of the machine unless the application gives one with state_machine_type.
    """

    def __init__(
        self,
        server: Server,
        parent: Node,
        idx: int | None = None,
        name: str | None = None,
        state_machine_type: ua.NodeId | None = None,
    ) -> None:
        super().__init__(server, parent, idx, name)
        if name is None:
            self._name = "FiniteStateMachine"
        self._state_machine_type = state_machine_type or _FINITE_STATE_MACHINE_TYPE
        self._given_type = state_machine_type is not None
        self._available_states_node: Node | None = None
        self._available_transitions_node: Node | None = None

    async def _concrete_type(self) -> ua.NodeId:
        base = Node(self._parent.session, self._state_machine_type)
        if self._given_type:
            if not await is_subtype(base, _FINITE_STATE_MACHINE_TYPE) or await is_abstract(base):
                raise ValueError(
                    f"Statemachine: {self._name} -> {base.nodeid} is not a concrete FiniteStateMachineType"
                )
            return self._state_machine_type
        created = await base.add_object_type(
            ua.NodeId(NamespaceIndex=self._idx), ua.QualifiedName(f"{self._name}Type", self._idx)
        )
        return created.nodeid

    async def _list_node(self, name: str) -> Node:
        try:
            return await self._state_machine_node.get_child([name])
        except ua.UaStatusCodeError:
            raise ua.UaError(f"Statemachine: {self._name} has no {name}, install it with optionals=True") from None

    @staticmethod
    def _check_node_ids(nodeids: list[ua.NodeId]) -> None:
        if not isinstance(nodeids, list) or not all(isinstance(n, ua.NodeId) for n in nodeids):
            raise ValueError(f"{nodeids} is not a list of NodeIds")

    async def set_available_states(self, states: list[ua.NodeId]) -> None:
        """Write AvailableStates, the States the machine can be in now; it needs install(optionals=True)."""
        self._check_node_ids(states)
        if self._available_states_node is None:
            self._available_states_node = await self._list_node("AvailableStates")
        await self._available_states_node.write_value(states, varianttype=ua.VariantType.NodeId)

    async def set_available_transitions(self, transitions: list[ua.NodeId]) -> None:
        """Write AvailableTransitions, the Transitions possible now; it needs install(optionals=True)."""
        self._check_node_ids(transitions)
        if self._available_transitions_node is None:
            self._available_transitions_node = await self._list_node("AvailableTransitions")
        await self._available_transitions_node.write_value(transitions, varianttype=ua.VariantType.NodeId)
