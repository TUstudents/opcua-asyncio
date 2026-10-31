"""
The Program state machine of OPC 10000-10 v1.05 (ProgramStateMachineType): Ready, Running, Suspended and Halted, nine
Transitions, the control Methods Start, Suspend, Resume, Halt and Reset, and a ProgramTransitionEvent per Transition.

The States, Transitions and Methods of the standard type live on the type (OPC 10000-16 v1.05, 4.4.19); a Program
points its CurrentState and LastTransition at those nodes and adds the control Methods it supports to the instance.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from enginir_opcua import Node, ua
from enginir_opcua.common.event_objects import ProgramTransitionEvent

from .statemachine import State, StateMachine, Transition

if TYPE_CHECKING:
    from enginir_opcua import Server

_logger = logging.getLogger(__name__)

PROGRAM_TYPE = ua.NodeId(ua.ObjectIds.ProgramStateMachineType)
NO_LIMIT = 0xFFFFFFFF

STATES = {
    "Halted": (ua.ObjectIds.ProgramStateMachineType_Halted, 11),
    "Ready": (ua.ObjectIds.ProgramStateMachineType_Ready, 12),
    "Running": (ua.ObjectIds.ProgramStateMachineType_Running, 13),
    "Suspended": (ua.ObjectIds.ProgramStateMachineType_Suspended, 14),
}
TRANSITIONS = {
    "HaltedToReady": (ua.ObjectIds.ProgramStateMachineType_HaltedToReady, 1, "Halted", "Ready"),
    "ReadyToRunning": (ua.ObjectIds.ProgramStateMachineType_ReadyToRunning, 2, "Ready", "Running"),
    "RunningToHalted": (ua.ObjectIds.ProgramStateMachineType_RunningToHalted, 3, "Running", "Halted"),
    "RunningToReady": (ua.ObjectIds.ProgramStateMachineType_RunningToReady, 4, "Running", "Ready"),
    "RunningToSuspended": (ua.ObjectIds.ProgramStateMachineType_RunningToSuspended, 5, "Running", "Suspended"),
    "SuspendedToRunning": (ua.ObjectIds.ProgramStateMachineType_SuspendedToRunning, 6, "Suspended", "Running"),
    "SuspendedToHalted": (ua.ObjectIds.ProgramStateMachineType_SuspendedToHalted, 7, "Suspended", "Halted"),
    "SuspendedToReady": (ua.ObjectIds.ProgramStateMachineType_SuspendedToReady, 8, "Suspended", "Ready"),
    "ReadyToHalted": (ua.ObjectIds.ProgramStateMachineType_ReadyToHalted, 9, "Ready", "Halted"),
}
METHOD_TRANSITIONS: dict[str, dict[str, str]] = {
    "Start": {"Ready": "ReadyToRunning"},
    "Suspend": {"Running": "RunningToSuspended"},
    "Resume": {"Suspended": "SuspendedToRunning"},
    "Halt": {"Ready": "ReadyToHalted", "Running": "RunningToHalted", "Suspended": "SuspendedToHalted"},
    "Reset": {"Halted": "HaltedToReady"},
}
DIAGNOSTIC_COMPONENTS = (
    "CreateSessionId",
    "CreateClientName",
    "InvocationCreationTime",
    "LastTransitionTime",
    "LastMethodCall",
    "LastMethodSessionId",
    "LastMethodInputArguments",
    "LastMethodOutputArguments",
    "LastMethodInputValues",
    "LastMethodOutputValues",
    "LastMethodCallTime",
    "LastMethodReturnStatus",
)

ControlHandler = Callable[..., Awaitable[Any]]


@dataclass
class ProgramHandlers:
    """
    The control Methods a Program supports. A callback gets the program and the input arguments (plain values) and
    returns the output arguments (a list) or nothing. A Method without a callback is not created on the instance.
    inputs and outputs map a Method name to its argument declarations (ua.Argument, VariantType or NodeId).
    """

    start: ControlHandler | None = None
    suspend: ControlHandler | None = None
    resume: ControlHandler | None = None
    halt: ControlHandler | None = None
    reset: ControlHandler | None = None
    inputs: dict[str, list[Any]] = field(default_factory=dict)
    outputs: dict[str, list[Any]] = field(default_factory=dict)


def _caller() -> tuple[ua.NodeId, str]:
    try:
        from enginir_opcua.server.internal_session import current_call_session
    except ImportError:
        return ua.NodeId(), ""
    session = current_call_session.get()
    if session is None:
        return ua.NodeId(), ""
    return session.session_id, session.name


class ProgramStateMachine(StateMachine):
    """
    One Program invocation. After `await program.install()` the instance exists below the parent; the control Methods
    run the callbacks of the handlers, internal transitions are made with complete(), fail() and internal_transition().
    """

    def __init__(
        self,
        server: Server,
        parent: Node,
        name: str = "Program",
        handlers: ProgramHandlers | None = None,
        *,
        initial_state: str = "Halted",
        auto_delete: bool = False,
        deletable: bool = False,
        max_recycle_count: int = NO_LIMIT,
        max_instance_count: int = NO_LIMIT,
        diagnostics: bool = True,
        final_result: bool = False,
    ) -> None:
        super().__init__(server, parent, None, name)
        if initial_state not in ("Halted", "Ready"):
            raise ValueError("initial_state is Halted or Ready")
        self.handlers = handlers or ProgramHandlers()
        self.initial_state = initial_state
        self.auto_delete = auto_delete
        self.deletable = deletable
        self.max_recycle_count = max_recycle_count
        self.max_instance_count = max_instance_count
        self._with_diagnostics = diagnostics
        self._with_final_result = final_result
        self.evtype = ProgramTransitionEvent()
        self._lock = asyncio.Lock()
        self._program_states: dict[str, State] = {}
        self._program_transitions: dict[str, Transition] = {}
        self._methods: dict[str, Node] = {}
        self._recycle_count = 0
        self._diagnostic = ua.ProgramDiagnostic2DataType()
        self._diagnostic_node: Node | None = None
        self._diagnostic_parts: dict[str, Node] = {}
        self._recycle_node: Node | None = None
        self.final_result_node: Node | None = None
        self._deleted = False

    @property
    def node(self) -> Node:
        """The Program instance in the address space."""
        return self._state_machine_node

    @property
    def diagnostics_node(self) -> Node | None:
        """The ProgramDiagnostic variable, None without diagnostics."""
        return self._diagnostic_node

    @property
    def state(self) -> str:
        """The name of the current State: Ready, Running, Suspended or Halted."""
        return self._current_state.name or ""

    def _instances(self) -> dict[ua.NodeId, list[ProgramStateMachine]]:
        registry: dict[ua.NodeId, list[ProgramStateMachine]] = self._server.__dict__.setdefault(
            "_program_instances", {}
        )
        return registry

    async def install(self, optionals: bool = True) -> None:
        """
        Create the Program below the parent in its initial state. The Program always has its optional parts;
        optionals is there for the signature of StateMachine.install.
        """
        siblings = self._instances().setdefault(PROGRAM_TYPE, [])
        if self.max_instance_count != NO_LIMIT and len(siblings) >= self.max_instance_count:
            raise ua.uaerrors.BadResourceUnavailable()
        try:
            await self._parent.get_child(ua.QualifiedName(self._name, self._idx))
        except ua.UaStatusCodeError:
            pass
        else:
            raise ua.uaerrors.BadBrowseNameDuplicated()
        self._state_machine_node = await self._parent.add_object(
            self._idx, self._name, objecttype=PROGRAM_TYPE, instantiate_optional=True
        )
        await self.init(self._state_machine_node)
        self._idx = 0
        session_id, client_name = _caller()
        if not self._with_final_result:
            await self._remove_optional("FinalResultData")
        if not self._with_diagnostics:
            await self._remove_optional("ProgramDiagnostic")
        for name, (node_number, number) in STATES.items():
            self._program_states[name] = State(
                ua.NodeId(node_number), name, number, Node(self._parent.session, ua.NodeId(node_number))
            )
        self._states.extend(self._program_states.values())
        for name, (node_number, number, source, target) in TRANSITIONS.items():
            transition = Transition(
                ua.NodeId(node_number), name, number, Node(self._parent.session, ua.NodeId(node_number))
            )
            transition.from_state = self._program_states[source]
            transition.to_state = self._program_states[target]
            self._program_transitions[name] = transition
        self._transitions.extend(self._program_transitions.values())
        await self._write_properties()
        await self._add_methods()
        if self._with_diagnostics:
            await self._setup_diagnostics(session_id, client_name)
        initial = self._program_states[self.initial_state]
        await self._write_state(initial)
        self._current_state = initial
        await self._update_executable()
        siblings.append(self)
        await self._write_instance_counts()
        if self._server is not None and hasattr(self._server, "iserver"):
            self._server.iserver.node_mgt_service.delete_guards.append(self._guard_delete)

    async def _remove_optional(self, name: str) -> None:
        try:
            child = await self._state_machine_node.get_child(ua.QualifiedName(name, 0))
        except ua.UaStatusCodeError:
            return
        await child.delete(recursive=True)

    async def _child(self, name: str) -> Node | None:
        try:
            return await self._state_machine_node.get_child(ua.QualifiedName(name, 0))
        except ua.UaStatusCodeError:
            return None

    async def _write_properties(self) -> None:
        values: dict[str, tuple[Any, ua.VariantType]] = {
            "Creatable": (False, ua.VariantType.Boolean),
            "Deletable": (self.deletable, ua.VariantType.Boolean),
            "AutoDelete": (self.auto_delete, ua.VariantType.Boolean),
            "RecycleCount": (0, ua.VariantType.Int32),
            "MaxRecycleCount": (self.max_recycle_count, ua.VariantType.UInt32),
            "MaxInstanceCount": (self.max_instance_count, ua.VariantType.UInt32),
            "InstanceCount": (0, ua.VariantType.UInt32),
        }
        for name, (value, variant_type) in values.items():
            node = await self._child(name)
            if node is not None:
                await node.write_value(value, variant_type)
            else:
                await self._state_machine_node.add_property(
                    ua.NodeId(NamespaceIndex=self._parent.nodeid.NamespaceIndex),
                    ua.QualifiedName(name, 0),
                    ua.Variant(value, variant_type),
                )
        self._recycle_node = await self._child("RecycleCount")

    async def _write_instance_counts(self) -> None:
        siblings = self._instances().get(PROGRAM_TYPE, [])
        for program in siblings:
            node = await program._child("InstanceCount")
            if node is not None:
                await node.write_value(len(siblings), ua.VariantType.UInt32)

    async def _add_methods(self) -> None:
        for name in METHOD_TRANSITIONS:
            handler = getattr(self.handlers, name.lower())
            if handler is None:
                continue

            async def call(parent: ua.NodeId, *args: ua.Variant, method: str = name) -> list[ua.Variant]:
                return await self._control(method, [a.Value if isinstance(a, ua.Variant) else a for a in args])

            node = await self._state_machine_node.add_method(
                ua.NodeId(NamespaceIndex=self._parent.nodeid.NamespaceIndex),
                ua.QualifiedName(name, 0),
                call,
                self.handlers.inputs.get(name),
                self.handlers.outputs.get(name),
            )
            self._methods[name] = node

    async def _update_executable(self) -> None:
        for name, node in self._methods.items():
            allowed = self.state in METHOD_TRANSITIONS[name]
            for attribute in (ua.AttributeIds.Executable, ua.AttributeIds.UserExecutable):
                await node.write_attribute(attribute, ua.DataValue(ua.Variant(allowed, ua.VariantType.Boolean)))

    async def _control(self, method: str, arguments: list[Any]) -> list[ua.Variant]:
        session_id, _ = _caller()
        output: list[ua.Variant] = []
        status = ua.StatusCode()
        try:
            async with self._lock:
                transition = METHOD_TRANSITIONS[method].get(self.state)
                if transition is None or self._deleted:
                    raise ua.uaerrors.BadInvalidState()
                if method == "Reset" and self._recycle_limit_reached():
                    raise ua.uaerrors.BadInvalidState()
                handler: ControlHandler = getattr(self.handlers, method.lower())
                result = await handler(self, *arguments)
                output = [value if isinstance(value, ua.Variant) else ua.Variant(value) for value in (result or [])]
                await self._transition(transition)
        except ua.UaStatusCodeError as error:
            status = ua.StatusCode(error.code)
            raise
        except Exception:
            status = ua.StatusCode(ua.StatusCodes.BadUnexpectedError)
            raise
        finally:
            await self._record_call(method, session_id, arguments, output, status)
        return output

    def _recycle_limit_reached(self) -> bool:
        return self.max_recycle_count != NO_LIMIT and self._recycle_count >= self.max_recycle_count

    async def _transition(self, name: str, intermediate_result: Any = None, internal: bool = False) -> None:
        _, _, source, target = TRANSITIONS[name]
        if self.state != source:
            raise ua.uaerrors.BadInvalidState()
        event: Any = self._event_generator().event
        event.IntermediateResult = (
            intermediate_result
            if intermediate_result is None or isinstance(intermediate_result, ua.Variant)
            else ua.Variant(intermediate_result)
        )
        await self.change_state(self._program_states[target], self._program_transitions[name])
        if name == "HaltedToReady":
            self._recycle_count += 1
            if self._recycle_node is not None:
                await self._recycle_node.write_value(self._recycle_count, ua.VariantType.Int32)
        await self._update_executable()
        self._diagnostic.LastTransitionTime = datetime.datetime.now(datetime.UTC)
        await self._write_diagnostics()
        if self.auto_delete and internal and target == "Halted":
            await self.delete(force=True)

    async def internal_transition(self, name: str, result: Any = None) -> None:
        """A Transition that no Method causes (RunningToReady, SuspendedToReady) or that the program makes itself."""
        if name not in TRANSITIONS:
            raise ValueError(f"{name} is not a Transition of a Program")
        async with self._lock:
            await self._transition(name, result, internal=True)

    async def complete(self, result: Any = None, recycle: bool = False) -> None:
        """The program finished: RunningToReady if it can run again (recycle), else RunningToHalted."""
        await self.internal_transition("RunningToReady" if recycle else "RunningToHalted", result)

    async def fail(self, reason: str | None = None, result: Any = None) -> None:
        """The program failed: RunningToHalted."""
        if reason:
            _logger.warning("Program %s failed: %s", self._name, reason)
        await self.internal_transition("RunningToHalted", result)

    async def _setup_diagnostics(self, session_id: ua.NodeId, client_name: str) -> None:
        self._diagnostic_node = await self._child("ProgramDiagnostic")
        if self._diagnostic_node is None:
            return
        for name in DIAGNOSTIC_COMPONENTS:
            try:
                self._diagnostic_parts[name] = await self._diagnostic_node.get_child(ua.QualifiedName(name, 0))
            except ua.UaStatusCodeError:
                continue
        now = datetime.datetime.now(datetime.UTC)
        self._diagnostic = ua.ProgramDiagnostic2DataType(
            CreateSessionId=session_id,
            CreateClientName=client_name,
            InvocationCreationTime=now,
            LastTransitionTime=now,
            LastMethodCall="",
            LastMethodSessionId=ua.NodeId(),
            LastMethodInputArguments=[],
            LastMethodOutputArguments=[],
            LastMethodInputValues=[],
            LastMethodOutputValues=[],
            LastMethodCallTime=now,
            LastMethodReturnStatus=ua.StatusCode(),
        )
        await self._write_diagnostics()

    async def _record_call(
        self, method: str, session_id: ua.NodeId, arguments: list[Any], output: list[ua.Variant], status: ua.StatusCode
    ) -> None:
        if self._diagnostic_node is None:
            return
        d = self._diagnostic
        d.LastMethodCall = method
        d.LastMethodSessionId = session_id
        d.LastMethodCallTime = datetime.datetime.now(datetime.UTC)
        d.LastMethodReturnStatus = status
        d.LastMethodInputArguments = self._arguments(self.handlers.inputs.get(method))
        d.LastMethodOutputArguments = self._arguments(self.handlers.outputs.get(method))
        d.LastMethodInputValues = [ua.Variant(a) if not isinstance(a, ua.Variant) else a for a in arguments]
        d.LastMethodOutputValues = list(output)
        await self._write_diagnostics()

    @staticmethod
    def _arguments(declared: list[Any] | None) -> list[ua.Argument]:
        return [a for a in (declared or []) if isinstance(a, ua.Argument)]

    async def _write_diagnostics(self) -> None:
        if self._diagnostic_node is None:
            return
        await self._diagnostic_node.write_value(ua.Variant(self._diagnostic, ua.VariantType.ExtensionObject))
        for name, node in self._diagnostic_parts.items():
            value = getattr(self._diagnostic, name)
            try:
                await node.write_value(ua.Variant(value, _list_type(name)) if isinstance(value, list) else value)
            except ua.UaStatusCodeError:
                _logger.debug("Could not update %s of %s", name, self._name, exc_info=True)

    def _guard_delete(self, node_id: ua.NodeId) -> ua.StatusCode | None:
        if node_id != self._state_machine_node.nodeid:
            return None
        if not self.deletable:
            return ua.StatusCode(ua.StatusCodes.BadNoDeleteRights)
        if self.state != "Halted":
            return ua.StatusCode(ua.StatusCodes.BadInvalidState)
        return None

    async def delete(self, force: bool = False) -> None:
        """Remove the Program. It has to be Halted; an auto-delete program removes itself this way."""
        if self.state != "Halted" and not force:
            raise ua.uaerrors.BadInvalidState()
        if self._deleted:
            return
        self._deleted = True
        guards = self._server.iserver.node_mgt_service.delete_guards if hasattr(self._server, "iserver") else []
        if self._guard_delete in guards:
            guards.remove(self._guard_delete)
        siblings = self._instances().get(PROGRAM_TYPE, [])
        if self in siblings:
            siblings.remove(self)
        await self._state_machine_node.delete(recursive=True)
        await self._write_instance_counts()


def _list_type(name: str) -> ua.VariantType:
    if name.endswith("Arguments"):
        return ua.VariantType.ExtensionObject
    return ua.VariantType.Variant
