"""
Events (OPC 10000-3 v1.05, 4.6; OPC 10000-4 v1.05, 7.7.3): the Event object, building EventFilters from EventTypes
and turning a custom EventType of the address space into an Event to fire.
"""

import copy
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from enginir_opcua import ua

from ..ua.uaerrors import UaError
from .ua_utils import is_subtype

if TYPE_CHECKING:
    from enginir_opcua.common.node import Node


_BROWSE_MASK = ua.BrowseResultMask.NodeClass | ua.BrowseResultMask.ReferenceTypeId | ua.BrowseResultMask.BrowseName
_OBJECTS_AND_VARIABLES = ua.NodeClass.Object | ua.NodeClass.Variable
_BASE_EVENT_TYPE = ua.NodeId(ua.ObjectIds.BaseEventType)


class Event:
    """
    An Event: its fields are attributes named by their browse path ("Severity", "EnabledState/Id"). The generated
    classes in event_objects (BaseEvent and the other standard EventTypes) derive from it. On the server side a
    field needs its VariantType, so add fields with add_property; on the client side from_event_fields builds the
    Event from the fields of a notification.
    """

    def __init__(self, emitting_node: ua.NodeId | int = ua.ObjectIds.Server) -> None:
        self.server_handle: int | None = None
        self.select_clauses: list[ua.SimpleAttributeOperand] | None = None
        self.event_fields: list[ua.Variant] | None = None
        self.data_types: dict[str, ua.VariantType | ua.VariantTypeCustom] = {}
        self.emitting_node = emitting_node if isinstance(emitting_node, ua.NodeId) else ua.NodeId(emitting_node)
        self.internal_properties = [*self.__dict__.keys(), "internal_properties"]

    def __str__(self) -> str:
        return "{0}({1})".format(
            self.__class__.__name__,
            [str(k) + ":" + str(v) for k, v in self.__dict__.items() if k not in self.internal_properties],
        )

    __repr__ = __str__

    def add_property(self, name: str, val: Any, datatype: ua.VariantType | ua.VariantTypeCustom) -> None:
        """Set the field name to val and record the VariantType it is sent as."""
        setattr(self, name, val)
        self.data_types[name] = datatype

    add_variable = add_property

    def get_event_props_as_fields_dict(self) -> dict[str, ua.Variant]:
        """Every field that has a VariantType, as Variants; a value that does not fit its type becomes a null."""
        field_vars: dict[str, ua.Variant] = {}
        for key, datatype in self.data_types.items():
            value = getattr(self, key, None)
            try:
                field_vars[key] = ua.Variant(value, datatype)
            except ua.UaError:
                field_vars[key] = ua.Variant(None, ua.VariantType.Null)
        return field_vars

    @staticmethod
    def from_field_dict(fields: dict[str, ua.Variant]) -> "Event":
        """The Event of get_event_props_as_fields_dict, as stored by the event history."""
        ev = Event()
        for k, v in fields.items():
            ev.add_property(k, v.Value, v.VariantType)
        return ev

    def select_field(
        self,
        sattr: ua.SimpleAttributeOperand,
        is_subtype: Callable[[ua.NodeId, ua.NodeId], bool] | None = None,
        apply_range: Callable[[Any, str], tuple[int, Any]] | None = None,
    ) -> ua.Variant:
        """
        The value of one SelectClause (OPC 10000-4 v1.05, 7.7.4): a null Variant when the field is missing, the
        clause names a TypeDefinitionId the Event is not of, or it selects another attribute than Value through a
        path. is_subtype decides the TypeDefinitionId; apply_range applies an IndexRange and returns its status.
        """
        if not self._type_definition_matches(sattr.TypeDefinitionId, is_subtype):
            return ua.Variant(None)
        if len(sattr.BrowsePath) == 0:
            name = ua.AttributeIds(sattr.AttributeId).name
        elif sattr.AttributeId != ua.AttributeIds.Value:
            return ua.Variant(None)
        else:
            if any(not isinstance(element.Name, str) for element in sattr.BrowsePath):
                return ua.Variant(None)
            name = self.browse_path_to_attribute_name(sattr.BrowsePath)
        try:
            val = getattr(self, name)
        except AttributeError:
            return ua.Variant(None)
        if val is None:
            return ua.Variant(None)
        val = copy.deepcopy(val)
        if sattr.IndexRange and apply_range is not None:
            code, val = apply_range(val, sattr.IndexRange)
            if code != ua.StatusCodes.Good:
                return ua.Variant(ua.StatusCode(code), ua.VariantType.StatusCode)
        datatype = self.data_types.get(name)
        return ua.Variant(val) if datatype is None else ua.Variant(val, datatype)

    def _type_definition_matches(
        self, type_definition: ua.NodeId, is_subtype: Callable[[ua.NodeId, ua.NodeId], bool] | None
    ) -> bool:
        if is_subtype is None or type_definition.is_null():
            return True
        if type_definition == ua.NodeId(ua.ObjectIds.BaseEventType):
            return True
        event_type = getattr(self, "EventType", None)
        return isinstance(event_type, ua.NodeId) and is_subtype(event_type, type_definition)

    def to_event_fields(
        self,
        select_clauses: list[ua.SimpleAttributeOperand],
        is_subtype: Callable[[ua.NodeId, ua.NodeId], bool] | None = None,
        apply_range: Callable[[Any, str], tuple[int, Any]] | None = None,
    ) -> list[ua.Variant]:
        """The EventFieldList of a notification: select_field for each SelectClause."""
        return [self.select_field(sattr, is_subtype, apply_range) for sattr in select_clauses]

    @staticmethod
    def from_event_fields(select_clauses: list[ua.SimpleAttributeOperand], fields: list[ua.Variant]) -> "Event":
        """The Event of an EventFieldList received for these SelectClauses."""
        ev = Event()
        ev.select_clauses = select_clauses
        ev.event_fields = fields
        if len(fields) < len(select_clauses):
            raise UaError(f"Received {len(fields)} event fields for {len(select_clauses)} select clauses")
        for idx, sattr in enumerate(select_clauses):
            if len(sattr.BrowsePath) == 0:
                name = ua.AttributeIds(sattr.AttributeId).name
            else:
                name = Event.browse_path_to_attribute_name(sattr.BrowsePath)
            ev.add_property(name, fields[idx].Value, fields[idx].VariantType)
        return ev

    @staticmethod
    def browse_path_to_attribute_name(browsePath: list[ua.QualifiedName]) -> str:
        """The field name of a browse path: the names joined by "/", without namespace indexes."""
        return "/".join(str(element.Name) for element in browsePath)


async def get_filter_from_event_type(eventtypes: list["Node"], where_clause_generation: bool = True) -> ua.EventFilter:
    """
    An EventFilter that selects every field the EventTypes and their supertypes declare and, with
    where_clause_generation, lets through only Events of these types (where_clause_from_evtype).
    """
    evfilter = ua.EventFilter()
    evfilter.SelectClauses = await select_clauses_from_evtype(eventtypes)
    if where_clause_generation:
        evfilter.WhereClause = await where_clause_from_evtype(eventtypes)
    return evfilter


def _append_new_attribute_to_select_clauses(
    select_clauses: list[ua.SimpleAttributeOperand],
    already_selected: set[str],
    browse_path: list[ua.QualifiedName],
    type_definition_id: ua.NodeId,
) -> None:
    string_path = "/".join(map(str, browse_path))
    if string_path not in already_selected:
        already_selected.add(string_path)
        op = ua.SimpleAttributeOperand()
        op.AttributeId = ua.AttributeIds.Value
        op.BrowsePath = browse_path
        op.TypeDefinitionId = type_definition_id
        select_clauses.append(op)


async def _aggregated_objects_and_variables(node: "Node") -> list[ua.ReferenceDescription]:
    return await node.get_references(
        ua.ObjectIds.Aggregates, ua.BrowseDirection.Forward, _OBJECTS_AND_VARIABLES, True, _BROWSE_MASK
    )


async def _select_clause_from_childs(
    child: "Node",
    refs: list[ua.ReferenceDescription],
    select_clauses: list[ua.SimpleAttributeOperand],
    already_selected: set[str],
    browse_path: list[ua.QualifiedName],
    type_definition_id: ua.NodeId,
    visited: frozenset[ua.NodeId] = frozenset(),
) -> None:
    visited = visited | {child.nodeid}
    for ref in refs:
        if ref.NodeId in visited:
            continue
        path = [*browse_path, ref.BrowseName]
        if ref.NodeClass == ua.NodeClass.Variable:
            _append_new_attribute_to_select_clauses(select_clauses, already_selected, path, type_definition_id)
            if ref.ReferenceTypeId == ua.NodeId(ua.ObjectIds.HasProperty):
                continue
        elif ref.NodeClass != ua.NodeClass.Object:
            continue
        below = child.new_node(child.session, ref.NodeId)
        await _select_clause_from_childs(
            below,
            await _aggregated_objects_and_variables(below),
            select_clauses,
            already_selected,
            path,
            type_definition_id,
            visited,
        )


async def _supertype_chain(evtype: "Node") -> list["Node"]:
    """evtype and its supertypes up to BaseEventType, evtype first; UaError if the chain branches, ends or loops."""
    chain = [evtype]
    seen = {evtype.nodeid}
    current = evtype
    while current.nodeid != _BASE_EVENT_TYPE:
        parents = await current.get_referenced_nodes(refs=ua.ObjectIds.HasSubtype, direction=ua.BrowseDirection.Inverse)
        if len(parents) != 1 or parents[0].nodeid in seen:
            raise UaError(f"EventType {evtype.nodeid} does not have one chain of supertypes up to BaseEventType")
        current = parents[0]
        seen.add(current.nodeid)
        chain.append(current)
    return chain


async def _event_type_nodes_up_to_base(evtype: "Node") -> list["Node"]:
    """Return EventTypes from BaseEventType to evtype (introducing types first)."""
    return list(reversed(await _supertype_chain(evtype)))


async def select_clauses_from_evtype(
    evtypes: list["Node"],
) -> list[ua.SimpleAttributeOperand]:
    """
    A SelectClause for every Variable the EventTypes and their supertypes aggregate, each path once, with the type
    that introduces it as TypeDefinitionId; for a ConditionType also the ConditionId (OPC 10000-9 v1.05, 5.5.2).
    """
    select_clauses: list[ua.SimpleAttributeOperand] = []
    already_selected: set[str] = set()
    add_condition_id = False
    for evtype in evtypes:
        if not add_condition_id and await is_subtype(evtype, ua.NodeId(ua.ObjectIds.ConditionType)):
            add_condition_id = True
        for type_node in await _event_type_nodes_up_to_base(evtype):
            refs = await _aggregated_objects_and_variables(type_node)
            await _select_clause_from_childs(type_node, refs, select_clauses, already_selected, [], type_node.nodeid)
    if add_condition_id:
        op = ua.SimpleAttributeOperand()
        op.AttributeId = ua.AttributeIds.NodeId
        op.TypeDefinitionId = ua.NodeId(ua.ObjectIds.ConditionType)
        select_clauses.append(op)
    return select_clauses


def _of_type_element(evtype: "Node") -> ua.ContentFilterElement:
    element = ua.ContentFilterElement()
    element.FilterOperator = ua.FilterOperator.OfType
    element.FilterOperands.append(ua.LiteralOperand(Value=ua.Variant(evtype.nodeid)))
    return element


async def where_clause_from_evtype(evtypes: list["Node"]) -> ua.ContentFilter:
    """
    A WhereClause that lets through events of the given types and their subtypes, decided by the server
    with one OfType element per type, combined with Or.
    """
    cf = ua.ContentFilter()
    if not evtypes:
        return cf
    if len(evtypes) == 1:
        cf.Elements.append(_of_type_element(evtypes[0]))
        return cf
    elements: list[ua.ContentFilterElement] = []

    def build(remaining: list["Node"]) -> None:
        if len(remaining) == 1:
            elements.append(_of_type_element(remaining[0]))
            return
        combine = ua.ContentFilterElement()
        combine.FilterOperator = ua.FilterOperator.Or
        elements.append(combine)
        combine.FilterOperands.append(ua.ElementOperand(Index=len(elements)))
        elements.append(_of_type_element(remaining[0]))
        combine.FilterOperands.append(ua.ElementOperand(Index=len(elements)))
        build(remaining[1:])

    build(list(evtypes))
    cf.Elements = elements
    return cf


async def select_event_attributes_from_type_node(
    node: "Node",
    attributeSelector: Callable[["Node"], Awaitable[list[Any]]],
) -> list[Any] | None:
    """
    What attributeSelector returns for the EventType and each of its supertypes up to BaseEventType, the EventType's
    first; None if the type has no single chain of supertypes up to BaseEventType.
    """
    try:
        chain = await _supertype_chain(node)
    except UaError:
        return None
    attributes: list[Any] = []
    for type_node in chain:
        attributes.extend(await attributeSelector(type_node))
    return attributes


async def get_event_properties_from_type_node(node: "Node") -> list[Any] | None:
    """The Properties of the EventType and its supertypes; see select_event_attributes_from_type_node."""
    return await select_event_attributes_from_type_node(node, lambda n: n.get_properties())


async def get_event_variables_from_type_node(node: "Node") -> list[Any] | None:
    """The component Variables of the EventType and its supertypes; see select_event_attributes_from_type_node."""
    return await select_event_attributes_from_type_node(node, lambda n: n.get_variables())


async def get_event_objects_from_type_node(node: "Node") -> list[Any] | None:
    """The component Objects of the EventType and its supertypes; see select_event_attributes_from_type_node."""
    return await select_event_attributes_from_type_node(
        node, lambda n: n.get_children(refs=ua.ObjectIds.HasComponent, nodeclassmask=ua.NodeClass.Object)
    )


def _implemented_event(nodeid: ua.NodeId) -> type[Event] | None:
    from .event_objects import IMPLEMENTED_EVENTS

    if nodeid.NamespaceIndex != 0 or not isinstance(nodeid.Identifier, int):
        return None
    return IMPLEMENTED_EVENTS.get(nodeid.Identifier)


async def get_event_obj_from_type_node(node: "Node") -> Event:
    """
    An Event of the EventType node, to fire. A standard EventType gives its class from event_objects; a custom one
    gives an instance of the nearest standard supertype's class with the Properties and Variables the custom types
    on the way declare, set to their values in the address space. Raises UaError if the type has no single chain of
    supertypes up to BaseEventType.
    """
    implemented = _implemented_event(node.nodeid)
    if implemented is not None:
        return implemented()
    chain = await _supertype_chain(node)
    for position, type_node in enumerate(chain):
        parent_class = _implemented_event(type_node.nodeid)
        if parent_class is not None:
            break
    else:
        raise UaError(f"EventType {node.nodeid} has no standard supertype")
    event = parent_class()
    event.EventType = node.nodeid  # type: ignore[attr-defined]
    for type_node in chain[:position]:
        for prop in await type_node.get_properties():
            await _add_field(event, prop, None)
        for var in await type_node.get_variables():
            await _add_variable_field(event, var)
            for prop in await var.get_properties():
                await _add_field(event, prop, var)
    return event


async def _add_field(event: Event, field: "Node", parent_variable: "Node | None") -> None:
    name = (await field.read_browse_name()).Name
    if parent_variable is not None:
        name = f"{(await parent_variable.read_browse_name()).Name}/{name}"
    value = await field.read_data_value()
    if value.Value is not None:
        event.add_property(name, value.Value.Value, value.Value.VariantType)


async def _add_variable_field(event: Event, variable: "Node") -> None:
    name = (await variable.read_browse_name()).Name
    value = await variable.read_data_value()
    if value.Value is not None:
        event.add_property(name, value.Value.Value, await variable.read_data_type_as_variant_type())
