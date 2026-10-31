"""
The Node object: reading and writing the attributes of a node, browsing, history and adding child nodes.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, overload

from enginir_opcua import ua
from enginir_opcua.common.session_interface import AbstractSession
from enginir_opcua.ua.uaerrors import UaInvalidParameterError

from .events import Event, get_filter_from_event_type
from .manage_nodes import (
    create_data_type,
    create_folder,
    create_method,
    create_object,
    create_object_type,
    create_property,
    create_reference_type,
    create_variable,
    create_variable_type,
    delete_nodes,
)
from .methods import call_method
from .ua_utils import data_type_to_variant_type, value_to_datavalue

_logger = logging.getLogger(__name__)


def _check_results(results: list[ua.StatusCode], reqlen: int = 1) -> None:
    if len(results) != reqlen:
        raise ua.UaError(f"Expected {reqlen} results, the server returned {len(results)}")
    for r in results:
        r.check()


def _to_nodeid(nodeid: Node | ua.NodeId | str | int) -> ua.NodeId:
    if isinstance(nodeid, int):
        return ua.NodeId(nodeid)
    if isinstance(nodeid, Node):
        return nodeid.nodeid
    if isinstance(nodeid, ua.NodeId):
        return nodeid
    if isinstance(nodeid, str):
        return ua.NodeId.from_string(nodeid)
    raise ua.UaError(f"Could not resolve {nodeid!r} of type {type(nodeid)} to a NodeId")


_ALL_ELEMENTS_PROCESSED = 0xFFFFFFFF
_EARLIEST_SPECIFIED_TIME = ua.get_win_epoch() + timedelta(microseconds=1)


def _history_time_domain(
    starttime: datetime | None, endtime: datetime | None, numvalues: int
) -> tuple[datetime, datetime]:
    start = starttime or ua.get_win_epoch()
    end = endtime or ua.get_win_epoch()
    given = sum((starttime is not None, endtime is not None, numvalues > 0))
    if given < 2 and endtime is None:
        end = datetime.now(UTC)
        given += 1
    if given < 2:
        start = _EARLIEST_SPECIFIED_TIME
    return start, end


def _no_history(history: Any, expected: str) -> None:
    if not (isinstance(history, ua.ExtensionObject) and history.Body is None):
        raise ua.UaError(f"Expected {expected} in the HistoryReadResult, got {type(history).__name__}")


def _history_values(history: Any) -> list[ua.DataValue]:
    if isinstance(history, ua.HistoryData):
        return list(history.DataValues or [])
    _no_history(history, "HistoryData")
    return []


def _history_events(history: Any) -> list[ua.HistoryEventFieldList]:
    if isinstance(history, ua.HistoryEvent):
        return list(history.Events or [])
    _no_history(history, "HistoryEvent")
    return []


class Node:
    """
    A node of the address space, seen through a session: a client's UaClient or a server's internal session.
    The nodeid is a NodeId, its text form, an integer of namespace 0 or another Node. Every method is one or a few
    service calls; for many nodes at once, the services of the session are faster. Two Nodes are equal when their
    NodeIds are, whatever the session.
    """

    def __init__(self, session: AbstractSession, nodeid: Node | ua.NodeId | str | int) -> None:
        self.session: AbstractSession = session
        self.nodeid: ua.NodeId = _to_nodeid(nodeid)
        self.basenodeid: ua.NodeId | None = None

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Node) and self.nodeid == other.nodeid

    def __str__(self) -> str:
        return self.nodeid.to_string()

    def __repr__(self) -> str:
        return f"Node({self.nodeid})"

    def __hash__(self) -> int:
        return self.nodeid.__hash__()

    async def _read_attribute_value(self, attr: ua.AttributeIds) -> Any:
        result = await self.read_attribute(attr)
        if result.Value is None:
            raise UaInvalidParameterError(f"The server returned a Good {attr.name} without a value")
        return result.Value.Value

    async def read_browse_name(self) -> ua.QualifiedName:
        """The BrowseName attribute: a name with a namespace index."""
        return await self._read_attribute_value(ua.AttributeIds.BrowseName)

    async def read_display_name(self) -> ua.LocalizedText:
        """The DisplayName attribute."""
        return await self._read_attribute_value(ua.AttributeIds.DisplayName)

    async def read_data_type(self) -> ua.NodeId:
        """The DataType attribute of a Variable or VariableType, as a NodeId."""
        return await self._read_attribute_value(ua.AttributeIds.DataType)

    async def read_data_type_as_variant_type(self) -> ua.VariantType:
        """The VariantType that encodes values of the DataType attribute; see ua_utils.data_type_to_variant_type."""
        return await data_type_to_variant_type(Node(self.session, await self.read_data_type()))

    async def get_access_level(self) -> set[ua.AccessLevel]:
        """The AccessLevel attribute as a set of AccessLevel members."""
        return ua.AccessLevel.parse_bitfield(await self._read_attribute_value(ua.AttributeIds.AccessLevel))

    async def get_user_access_level(self) -> set[ua.AccessLevel]:
        """The UserAccessLevel attribute, the access of the session's user, as a set of AccessLevel members."""
        return ua.AccessLevel.parse_bitfield(await self._read_attribute_value(ua.AttributeIds.UserAccessLevel))

    async def read_event_notifier(self) -> set[ua.EventNotifier]:
        """The EventNotifier attribute as a set of EventNotifier members."""
        return ua.EventNotifier.parse_bitfield(await self._read_attribute_value(ua.AttributeIds.EventNotifier))

    async def set_event_notifier(self, values: Iterable[ua.EventNotifier]) -> None:
        """
        Set the event notifier attribute.

        :param values: an iterable of EventNotifier enum values.
        """
        event_notifier_bitfield = ua.EventNotifier.to_bitfield(values)
        await self.write_attribute(
            ua.AttributeIds.EventNotifier, ua.DataValue(ua.Variant(event_notifier_bitfield, ua.VariantType.Byte))
        )

    async def read_node_class(self) -> ua.NodeClass:
        """The NodeClass attribute."""
        return ua.NodeClass(await self._read_attribute_value(ua.AttributeIds.NodeClass))

    async def read_data_type_definition(self) -> ua.DataTypeDefinition:
        """The DataTypeDefinition attribute of a DataType (OPC 10000-3 v1.05, 5.8.3); servers before 1.04 lack it."""
        return await self._read_attribute_value(ua.AttributeIds.DataTypeDefinition)

    async def write_data_type_definition(self, sdef: ua.DataTypeDefinition) -> None:
        """Write the DataTypeDefinition attribute of a DataType."""
        v = ua.Variant(sdef, ua.VariantType.ExtensionObject)
        await self.write_attribute(ua.AttributeIds.DataTypeDefinition, ua.DataValue(v))

    async def read_description(self) -> ua.LocalizedText:
        """The Description attribute."""
        return await self._read_attribute_value(ua.AttributeIds.Description)

    async def read_value(self) -> Any:
        """
        The Value attribute of a Variable as a Python value; other NodeClasses raise. On the server side this is
        the object stored in the address space: changing a mutable value in place changes the node without a
        data change notification.
        """
        return await self._read_attribute_value(ua.AttributeIds.Value)

    get_value = read_value

    async def read_data_value(self, raise_on_bad_status: bool = True) -> ua.DataValue:
        """
        The Value attribute of a Variable as a DataValue, with the value as a Variant, the StatusCode and the
        timestamps. A Bad StatusCode raises unless raise_on_bad_status is False.
        """
        return await self.read_attribute(ua.AttributeIds.Value, None, raise_on_bad_status)

    async def write_array_dimensions(self, value: int | Iterable[int]) -> None:
        """
        Set attribute ArrayDimensions of node: the maximum length of each dimension, 0 when unknown.
        A single integer is the one-dimensional case.
        """
        dimensions = [value] if isinstance(value, int) else list(value)
        v = ua.Variant(dimensions, ua.VariantType.UInt32)
        await self.write_attribute(ua.AttributeIds.ArrayDimensions, ua.DataValue(v))

    async def read_array_dimensions(self) -> list[int]:
        """The ArrayDimensions attribute: the length of each dimension, 0 when unknown."""
        return await self._read_attribute_value(ua.AttributeIds.ArrayDimensions)

    async def write_value_rank(self, value: int) -> None:
        """Write the ValueRank attribute."""
        v = ua.Variant(value, ua.VariantType.Int32)
        await self.write_attribute(ua.AttributeIds.ValueRank, ua.DataValue(v))

    async def read_value_rank(self) -> int:
        """
        Read and return the ValueRank attribute of the node.
        The result is a ua.ValueRank member when there is one, else the plain integer (more than four dimensions).
        """
        rank = await self._read_attribute_value(ua.AttributeIds.ValueRank)
        try:
            return ua.ValueRank(rank)
        except ValueError:
            return int(rank)

    async def write_value(self, value: Any, varianttype: ua.VariantType | None = None) -> None:
        """
        Write the Value attribute of a Variable. value is a Python value, encoded as varianttype if given, a
        ua.Variant (varianttype is ignored) or a ua.DataValue, which is sent as it is. On the server side the object
        is stored as it is: changing a mutable value afterwards changes the node without a data change notification.
        """
        dv = value_to_datavalue(value, varianttype)
        await self.write_attribute(ua.AttributeIds.Value, dv)

    set_data_value = write_value
    set_value = write_value

    async def set_writable(self, writable: bool = True) -> None:
        """
        Set or clear the CurrentWrite bit of AccessLevel and UserAccessLevel. The server's own internal session
        writes regardless.
        """
        if writable:
            await self.set_attr_bit(ua.AttributeIds.AccessLevel, ua.AccessLevel.CurrentWrite)
            await self.set_attr_bit(ua.AttributeIds.UserAccessLevel, ua.AccessLevel.CurrentWrite)
        else:
            await self.unset_attr_bit(ua.AttributeIds.AccessLevel, ua.AccessLevel.CurrentWrite)
            await self.unset_attr_bit(ua.AttributeIds.UserAccessLevel, ua.AccessLevel.CurrentWrite)

    async def set_attr_bit(self, attr: ua.AttributeIds, bit: ua.AccessLevel | int) -> None:
        """Set one bit of an integer attribute such as AccessLevel, keeping its VariantType."""
        await self._change_attr_bit(attr, bit, ua.ua_binary.set_bit)

    async def unset_attr_bit(self, attr: ua.AttributeIds, bit: ua.AccessLevel | int) -> None:
        """Clear one bit of an integer attribute such as AccessLevel, keeping its VariantType."""
        await self._change_attr_bit(attr, bit, ua.ua_binary.unset_bit)

    async def _change_attr_bit(
        self, attr: ua.AttributeIds, bit: ua.AccessLevel | int, change: Callable[[int, int], int]
    ) -> None:
        dv = await self.read_attribute(attr)
        if dv.Value is None:
            raise UaInvalidParameterError(f"The server returned a Good {attr.name} without a value")
        val = change(dv.Value.Value, bit)
        await self.write_attribute(attr, ua.DataValue(ua.Variant(val, dv.Value.VariantType)))

    async def set_read_only(self) -> None:
        """Clear the CurrentWrite bit of AccessLevel and UserAccessLevel; see set_writable."""
        await self.set_writable(False)

    async def write_attribute(
        self, attributeid: ua.AttributeIds, datavalue: ua.DataValue, indexrange: str | None = None
    ) -> None:
        """
        Set an attribute of a node.

        :param attributeid: a member of ua.AttributeIds
        :param datavalue: a ua.DataValue object
        :param indexrange: a NumericRange, a string such as "1" or "1:3" (OPC 10000-4 v1.05, 7.27)
        """
        attr = ua.WriteValue()
        attr.NodeId = self.nodeid
        attr.AttributeId = attributeid
        attr.Value = datavalue
        attr.IndexRange = indexrange
        params = ua.WriteParameters()
        params.NodesToWrite = [attr]
        result = await self.session.write(params)
        result[0].check()

    async def write_params(self, params: ua.WriteParameters) -> list[ua.StatusCode]:
        """Send a Write request as it is and return the StatusCode of each item, unchecked."""
        return await self.session.write(params)

    async def read_attribute(
        self, attr: ua.AttributeIds, indexrange: str | None = None, raise_on_bad_status: bool = True
    ) -> ua.DataValue:
        """
        Read one attribute of the node; indexrange is a NumericRange such as "1" or "1:3" (OPC 10000-4 v1.05, 7.27).
        A Bad StatusCode raises unless raise_on_bad_status is False.
        """
        rv = ua.ReadValueId()
        rv.NodeId = self.nodeid
        rv.AttributeId = attr
        rv.IndexRange = indexrange
        params = ua.ReadParameters()
        params.NodesToRead.append(rv)
        result = await self.session.read(params)
        res = result[0]
        if res.StatusCode is None:
            raise ua.UaError("No status code received")
        if raise_on_bad_status:
            res.StatusCode.check()
        return res

    async def read_attributes(self, attrs: Iterable[ua.AttributeIds]) -> list[ua.DataValue]:
        """Read several attributes of the node in one request; the DataValues are not checked."""
        params = ua.ReadParameters()
        for attr in attrs:
            rv = ua.ReadValueId()
            rv.NodeId = self.nodeid
            rv.AttributeId = attr
            params.NodesToRead.append(rv)

        return await self.session.read(params)

    async def read_params(self, params: ua.ReadParameters) -> list[ua.DataValue]:
        """Send a Read request as it is and return the DataValues, unchecked."""
        return await self.session.read(params)

    async def get_children(
        self,
        refs: Node | ua.NodeId | str | int = ua.ObjectIds.HierarchicalReferences,
        nodeclassmask: ua.NodeClass = ua.NodeClass.Unspecified,
    ) -> list[Node]:
        """
        The targets of the forward references of type refs and its subtypes, by default all hierarchical ones,
        such as ua.ObjectIds.HasComponent; nodeclassmask keeps only the given NodeClasses.
        """
        return await self.get_referenced_nodes(refs, ua.BrowseDirection.Forward, nodeclassmask)

    async def get_properties(self) -> list[Node]:
        """The Variables the node references with HasProperty."""
        return await self.get_children(refs=ua.ObjectIds.HasProperty, nodeclassmask=ua.NodeClass.Variable)

    async def get_variables(self) -> list[Node]:
        """The Variables the node references with HasComponent."""
        return await self.get_children(refs=ua.ObjectIds.HasComponent, nodeclassmask=ua.NodeClass.Variable)

    async def get_methods(self) -> list[Node]:
        """The Methods the node references with HasComponent."""
        return await self.get_children(refs=ua.ObjectIds.HasComponent, nodeclassmask=ua.NodeClass.Method)

    async def get_children_descriptions(
        self,
        refs: Node | ua.NodeId | str | int = ua.ObjectIds.HierarchicalReferences,
        nodeclassmask: ua.NodeClass = ua.NodeClass.Unspecified,
        includesubtypes: bool = True,
        result_mask: ua.BrowseResultMask = ua.BrowseResultMask.All,
    ) -> list[ua.ReferenceDescription]:
        """Like get_children, but the ReferenceDescriptions, with the fields result_mask asks for."""
        return await self.get_references(refs, ua.BrowseDirection.Forward, nodeclassmask, includesubtypes, result_mask)

    async def get_encoding_refs(self) -> list[Node]:
        """The encoding nodes of a DataType (HasEncoding)."""
        return await self.get_referenced_nodes(ua.ObjectIds.HasEncoding, ua.BrowseDirection.Forward)

    async def get_description_refs(self) -> list[Node]:
        """The description nodes of an encoding (HasDescription)."""
        return await self.get_referenced_nodes(ua.ObjectIds.HasDescription, ua.BrowseDirection.Forward)

    async def get_references(
        self,
        refs: Node | ua.NodeId | str | int = ua.ObjectIds.References,
        direction: ua.BrowseDirection = ua.BrowseDirection.Both,
        nodeclassmask: ua.NodeClass = ua.NodeClass.Unspecified,
        includesubtypes: bool = True,
        result_mask: ua.BrowseResultMask = ua.BrowseResultMask.All,
    ) -> list[ua.ReferenceDescription]:
        """
        Browse the references of the node of type refs (and its subtypes with includesubtypes) in direction, keeping
        targets of the NodeClasses in nodeclassmask, and follow the continuation points until all are read.
        result_mask selects the fields of the ReferenceDescriptions.
        """
        desc = ua.BrowseDescription()
        desc.BrowseDirection = direction
        desc.ReferenceTypeId = _to_nodeid(refs)
        desc.IncludeSubtypes = includesubtypes
        desc.NodeClassMask = nodeclassmask
        desc.ResultMask = result_mask
        desc.NodeId = self.nodeid
        params = ua.BrowseParameters()
        params.View.Timestamp = ua.get_win_epoch()
        params.NodesToBrowse.append(desc)
        params.RequestedMaxReferencesPerNode = 0
        return await self._browse_next(await self.session.browse(params))

    async def _browse_next(self, results: list[ua.BrowseResult]) -> list[ua.ReferenceDescription]:
        if not results:
            raise ua.UaError("The server returned no BrowseResult")
        result = results[0]
        result.StatusCode.check()
        references = list(result.References)
        point = result.ContinuationPoint
        while point:
            try:
                params = ua.BrowseNextParameters()
                params.ContinuationPoints = [point]
                params.ReleaseContinuationPoints = False
                next_results = await self.session.browse_next(params)
                if not next_results:
                    raise ua.UaError("The server returned no BrowseResult for BrowseNext")
                result = next_results[0]
                result.StatusCode.check()
            except BaseException:
                await self._release_browse_point(point)
                raise
            references.extend(result.References)
            if result.ContinuationPoint == point and not result.References:
                await self._release_browse_point(point)
                break
            point = result.ContinuationPoint
        return references

    async def _release_browse_point(self, point: bytes) -> None:
        params = ua.BrowseNextParameters()
        params.ContinuationPoints = [point]
        params.ReleaseContinuationPoints = True
        try:
            await self.session.browse_next(params)
        except Exception:
            _logger.debug("Could not release the browse continuation point", exc_info=True)

    async def get_referenced_nodes(
        self,
        refs: Node | ua.NodeId | str | int = ua.ObjectIds.References,
        direction: ua.BrowseDirection = ua.BrowseDirection.Both,
        nodeclassmask: ua.NodeClass = ua.NodeClass.Unspecified,
        includesubtypes: bool = True,
    ) -> list[Node]:
        """The target nodes of get_references with the same filter."""
        references = await self.get_references(refs, direction, nodeclassmask, includesubtypes)
        return [Node(self.session, desc.NodeId) for desc in references]

    async def read_type_definition(self) -> ua.NodeId | None:
        """The TypeDefinition of an Object or Variable (HasTypeDefinition), None if it has none."""
        references = await self.get_references(
            refs=ua.ObjectIds.HasTypeDefinition, direction=ua.BrowseDirection.Forward
        )
        if len(references) == 0:
            return None
        return references[0].NodeId

    @overload
    async def get_path(self, max_length: int = 20, as_string: Literal[False] = False) -> list[Node]: ...

    @overload
    async def get_path(self, max_length: int = 20, as_string: Literal[True] = True) -> list[str]: ...

    async def get_path(self, max_length: int = 20, as_string: bool = False) -> list[Node] | list[str]:
        """
        Find one path from the Root to this node and return it as a list of Nodes, the Root side first and
        this node last, so the list is never empty. The walk follows the first inverse hierarchical reference
        of each node, so the path starts at the Root only if every node on the way has such a reference.
        Since the address space may have circular references, a max length is specified.
        """
        path = await self._get_path(max_length)
        nodes = [Node(self.session, ref.NodeId) for ref in path]
        nodes.append(self)
        if as_string:
            return [(await el.read_browse_name()).to_string() for el in nodes]
        return nodes

    async def _get_path(self, max_length: int = 20) -> list[ua.ReferenceDescription]:
        """
        References of the walk from the farthest ancestor to the parent of this node, see get_path.
        """
        path: list[ua.ReferenceDescription] = []
        node = self
        while True:
            refs = await node.get_references(
                refs=ua.ObjectIds.HierarchicalReferences, direction=ua.BrowseDirection.Inverse
            )
            if len(refs) > 0:
                path.insert(0, refs[0])
                node = Node(self.session, refs[0].NodeId)
                if len(path) >= (max_length - 1):
                    return path
            else:
                return path

    async def get_parent(self) -> Node | None:
        """
        The source of the first inverse hierarchical reference, None if there is none. A node may have several
        parents; this is the first one the server returns.
        """
        refs = await self.get_references(refs=ua.ObjectIds.HierarchicalReferences, direction=ua.BrowseDirection.Inverse)
        if len(refs) > 0:
            return Node(self.session, refs[0].NodeId)
        return None

    @overload
    async def get_child(
        self,
        path: ua.QualifiedName | str | Iterable[ua.QualifiedName | str],
        return_all: Literal[False] = False,
    ) -> Node: ...

    @overload
    async def get_child(
        self,
        path: ua.QualifiedName | str | Iterable[ua.QualifiedName | str],
        return_all: Literal[True] = True,
    ) -> list[Node]: ...

    async def get_child(
        self, path: ua.QualifiedName | str | Iterable[ua.QualifiedName | str], return_all: bool = False
    ) -> Node | list[Node]:
        """
        The node at a path below this one. A path is a RelativePath text such as "0:Server/0:ServerStatus"
        (OPC 10000-4 v1.05, A.2), a QualifiedName, or a list of QualifiedNames or "ns:Name" texts followed along
        hierarchical references. Raises BadNoMatch if nothing is found; return_all returns every match.
        """
        results = await self.session.translate_browsepaths_to_nodeids([self._browse_path(path)])
        result = results[0]
        targets = self._complete_targets(result)
        if not targets:
            ua.StatusCode(ua.StatusCodes.BadNoMatch).check()
        if return_all:
            return [Node(self.session, target.TargetId) for target in targets]
        return Node(self.session, targets[0].TargetId)

    @staticmethod
    def _complete_targets(result: ua.BrowsePathResult) -> list[ua.BrowsePathTarget]:
        result.StatusCode.check()
        return [target for target in result.Targets if target.RemainingPathIndex == _ALL_ELEMENTS_PROCESSED]

    async def get_children_by_path(
        self,
        paths: Iterable[ua.QualifiedName | str | Iterable[ua.QualifiedName | str]],
        raise_on_partial_error: bool = True,
    ) -> list[list[Node] | None]:
        """
        The nodes at several paths below this one, in one request; a path is as for get_child. A path that does not
        resolve completely gives None at its position, or with raise_on_partial_error raises UaStatusCodeErrors.
        """
        bpaths = [self._browse_path(path) for path in paths]
        results = await self.session.translate_browsepaths_to_nodeids(bpaths)
        found: list[list[Node] | None] = []
        codes: list[int] = []
        for result in results:
            if result.StatusCode.is_good():
                targets = [t for t in result.Targets if t.RemainingPathIndex == _ALL_ELEMENTS_PROCESSED]
            else:
                targets = []
            if targets:
                found.append([Node(self.session, target.TargetId) for target in targets])
                codes.append(ua.StatusCodes.Good)
            else:
                found.append(None)
                codes.append(ua.StatusCodes.BadNoMatch if result.StatusCode.is_good() else result.StatusCode.value)
        if raise_on_partial_error and any(code != ua.StatusCodes.Good for code in codes):
            raise ua.UaStatusCodeErrors(codes)
        return found

    def _browse_path(self, path: ua.QualifiedName | str | Iterable[ua.QualifiedName | str]) -> ua.BrowsePath:
        if isinstance(path, str):
            rpath = ua.RelativePath.from_string(path)
        elif isinstance(path, ua.QualifiedName):
            rpath = self._make_relative_path([path])
        else:
            rpath = self._make_relative_path(path)
        return ua.BrowsePath(StartingNode=self.nodeid, RelativePath=rpath)

    def _make_relative_path(self, path: Iterable[ua.QualifiedName | str]) -> ua.RelativePath:
        rpath = ua.RelativePath()
        for item in path:
            el = ua.RelativePathElement()
            el.ReferenceTypeId = ua.TwoByteNodeId(ua.ObjectIds.HierarchicalReferences)
            el.IsInverse = False
            el.IncludeSubtypes = True
            if isinstance(item, ua.QualifiedName):
                el.TargetName = item
            else:
                el.TargetName = ua.QualifiedName.from_string(item)
            rpath.Elements.append(el)
        return rpath

    async def read_raw_history(
        self,
        starttime: datetime | None = None,
        endtime: datetime | None = None,
        numvalues: int = 0,
        return_bounds: bool = False,
    ) -> list[ua.DataValue]:
        """
        Read raw history of a node, following the continuation points until the server has no more values.
        The result code of every response is checked and an exception is raised in case of error.
        numvalues is the most values returned in total, 0 means all. A continuation point still open
        when the read stops is released.
        """
        details = ua.ReadRawModifiedDetails()
        details.IsReadModified = False
        details.StartTime, details.EndTime = _history_time_domain(starttime, endtime, numvalues)
        details.NumValuesPerNode = numvalues
        details.ReturnBounds = return_bounds
        history: list[ua.DataValue] = []

        def collect(result: ua.HistoryReadResult) -> int:
            history.extend(_history_values(result.HistoryData))
            return len(history)

        await self._read_history_pages(details, collect, numvalues)
        return history[:numvalues] if numvalues > 0 else history

    async def _read_history_pages(
        self, details: ua.HistoryReadDetails, collect: Callable[[ua.HistoryReadResult], int], numvalues: int
    ) -> None:
        point: bytes | None = None
        try:
            while True:
                result = await self.history_read(details, point)
                result.StatusCode.check()
                previous = point
                point = result.ContinuationPoint or None
                count = collect(result)
                if point is None or point == previous or (numvalues > 0 and count >= numvalues):
                    break
        except BaseException:
            if point is not None:
                await self._release_history_point(details, point)
            raise
        if point is not None:
            await self._release_history_point(details, point)

    async def _release_history_point(self, details: ua.HistoryReadDetails, point: bytes) -> None:
        try:
            await self.history_read(details, point, True)
        except Exception:
            _logger.debug("Could not release the history continuation point", exc_info=True)

    async def history_read(
        self,
        details: ua.HistoryReadDetails,
        continuation_point: bytes | None = None,
        release_continuation_point: bool = False,
    ) -> ua.HistoryReadResult:
        """
        One HistoryRead request for this node with any HistoryReadDetails (raw, processed, at time, events).
        The result is returned as it is; the caller checks its StatusCode.
        With release_continuation_point the given continuation point is freed in the server.
        """
        valueid = ua.HistoryReadValueId()
        valueid.NodeId = self.nodeid
        valueid.IndexRange = ""
        valueid.ContinuationPoint = continuation_point
        params = ua.HistoryReadParameters()
        params.HistoryReadDetails = details
        params.TimestampsToReturn = ua.TimestampsToReturn.Both
        params.ReleaseContinuationPoints = release_continuation_point
        params.NodesToRead.append(valueid)
        return (await self.session.history_read(params))[0]

    async def history_update(self, details: ua.HistoryUpdateDetails) -> ua.HistoryUpdateResult:
        """
        Update history of a node, low-level function.
        An exception is raised for a Bad StatusCode of the result or of any of its operation results.
        """
        params = ua.HistoryUpdateParameters()
        params.HistoryUpdateDetails.append(details)
        result = (await self.session.history_update(params))[0]
        result.StatusCode.check()
        for operation_result in result.OperationResults or []:
            operation_result.check()
        return result

    async def read_event_history(
        self,
        starttime: datetime | None = None,
        endtime: datetime | None = None,
        numvalues: int = 0,
        evtypes: Node | ua.NodeId | str | int | Iterable[Node | ua.NodeId | str | int] = ua.ObjectIds.BaseEventType,
    ) -> list[Event]:
        """
        Read event history of a source node, following the continuation points until the server has no more events.
        The result code of every response is checked and an exception is raised in case of error.
        numvalues is the most events returned in total, 0 means all. A continuation point still open
        when the read stops is released.
        """
        details = ua.ReadEventDetails()
        details.StartTime, details.EndTime = _history_time_domain(starttime, endtime, numvalues)
        details.NumValuesPerNode = numvalues
        if isinstance(evtypes, Node | ua.NodeId | str | int):
            evtypes = [evtypes]
        evtype_nodes = [Node(self.session, evtype) for evtype in evtypes]
        evfilter = await get_filter_from_event_type(evtype_nodes)
        details.Filter = evfilter
        event_res: list[Event] = []

        def collect(result: ua.HistoryReadResult) -> int:
            for res in _history_events(result.HistoryData):
                event_res.append(Event.from_event_fields(evfilter.SelectClauses, res.EventFields))
            return len(event_res)

        await self._read_history_pages(details, collect, numvalues)
        return event_res[:numvalues] if numvalues > 0 else event_res

    async def history_read_events(
        self,
        details: ua.ReadEventDetails,
        continuation_point: bytes | None = None,
        release_continuation_point: bool = False,
    ) -> ua.HistoryReadResult:
        """One HistoryRead request for events; the same as history_read."""
        return await self.history_read(details, continuation_point, release_continuation_point)

    async def delete(self, delete_references: bool = True, recursive: bool = False) -> list[Node]:
        """
        Delete the node, with recursive also the nodes it aggregates (see manage_nodes.delete_nodes). Returns the
        nodes deleted; any Bad result raises.
        """
        nodes, results = await delete_nodes(self.session, [self], recursive, delete_references)
        for r in results:
            r.check()
        return nodes

    def _fill_delete_reference_item(
        self, rdesc: ua.ReferenceDescription, bidirectional: bool = False
    ) -> ua.DeleteReferencesItem:
        ditem = ua.DeleteReferencesItem()
        ditem.SourceNodeId = self.nodeid
        ditem.TargetNodeId = rdesc.NodeId
        ditem.ReferenceTypeId = rdesc.ReferenceTypeId
        ditem.IsForward = rdesc.IsForward
        ditem.DeleteBidirectional = bidirectional
        return ditem

    async def delete_reference(
        self,
        target: Node | ua.NodeId | str | int,
        reftype: Node | ua.NodeId | str | int,
        forward: bool = True,
        bidirectional: bool = True,
    ) -> None:
        """
        Delete the reference of type reftype (exactly, not a subtype) to target in the given direction, with
        bidirectional also the inverse reference at the target. Raises BadNotFound if the node has no such reference.
        """
        known_refs = await self.get_references(reftype, includesubtypes=False)
        targetid = _to_nodeid(target)
        for r in known_refs:
            if r.NodeId == targetid and r.IsForward == forward:
                rdesc = r
                break
        else:
            raise ua.UaStatusCodeError(ua.StatusCodes.BadNotFound)
        ditem = self._fill_delete_reference_item(rdesc, bidirectional)
        (await self.session.delete_references([ditem]))[0].check()

    async def add_reference(
        self,
        target: Node | ua.NodeId | str | int,
        reftype: Node | ua.NodeId | str | int,
        forward: bool = True,
        bidirectional: bool = True,
        target_class: ua.NodeClass | None = None,
    ) -> None:
        """
        Add a reference of type reftype to target, with bidirectional also the inverse reference at the target. The
        NodeClass of the target is part of the request; it is read from the target when not given, and left
        unspecified if it cannot be read.
        """
        aitem = ua.AddReferencesItem()
        aitem.SourceNodeId = self.nodeid
        aitem.TargetNodeId = _to_nodeid(target)
        aitem.ReferenceTypeId = _to_nodeid(reftype)
        aitem.IsForward = forward
        if target_class is None:
            try:
                target_class = await Node(self.session, aitem.TargetNodeId).read_node_class()
            except (ua.UaError, ValueError):
                target_class = ua.NodeClass.Unspecified
        aitem.TargetNodeClass = target_class
        params = [aitem]
        if bidirectional:
            aitem2 = ua.AddReferencesItem()
            aitem2.SourceNodeId = aitem.TargetNodeId
            aitem2.TargetNodeId = aitem.SourceNodeId
            aitem2.ReferenceTypeId = aitem.ReferenceTypeId
            aitem2.IsForward = not forward
            aitem2.TargetNodeClass = await self._own_node_class()
            params.append(aitem2)
        results = await self.session.add_references(params)
        _check_results(results, len(params))

    async def _own_node_class(self) -> ua.NodeClass:
        try:
            return await self.read_node_class()
        except (ua.UaError, ValueError):
            return ua.NodeClass.Unspecified

    async def set_modelling_rule(self, mandatory: bool | None) -> None:
        """
        Replace the ModellingRule of an InstanceDeclaration with Mandatory (True) or Optional (False), or remove it
        (None). Children of a type without a ModellingRule are not instantiated.
        """
        rules = await self.get_references(ua.ObjectIds.HasModellingRule)
        if rules:
            results = await self.session.delete_references(list(map(self._fill_delete_reference_item, rules)))
            for result in results:
                result.check()
        if mandatory is not None:
            rule = ua.ObjectIds.ModellingRule_Mandatory if mandatory else ua.ObjectIds.ModellingRule_Optional
            await self.add_reference(rule, ua.ObjectIds.HasModellingRule, True, False, ua.NodeClass.Object)

    async def add_folder(self, nodeid: ua.NodeId | str | int, bname: ua.QualifiedName | str) -> Node:
        """
        Add a FolderType Object below this node. As for every add_ method, nodeid and bname are a NodeId (or its
        text) and a QualifiedName (or "ns:Name"), or a namespace index and a name in that namespace; see
        manage_nodes.
        """
        return await create_folder(self, nodeid, bname)

    async def add_object(
        self,
        nodeid: ua.NodeId | str | int,
        bname: ua.QualifiedName | str,
        objecttype: ua.NodeId | int | None = None,
        instantiate_optional: bool = True,
    ) -> Node:
        """Add an Object below this node, an instance of objecttype with its children if given; see add_folder."""
        return await create_object(self, nodeid, bname, objecttype, instantiate_optional)

    async def add_variable(
        self,
        nodeid: ua.NodeId | str | int,
        bname: ua.QualifiedName | str,
        val: Any,
        varianttype: ua.VariantType | None = None,
        datatype: ua.NodeId | int | None = None,
    ) -> Node:
        """
        Add a BaseDataVariableType Variable below this node with the value val; the DataType is datatype or guessed
        from the value. See add_folder.
        """
        return await create_variable(self, nodeid, bname, val, varianttype, datatype)

    async def add_object_type(
        self, nodeid: ua.NodeId | str | int, bname: ua.QualifiedName | str, is_abstract: bool = False
    ) -> Node:
        """Add an ObjectType as subtype of this one; see add_folder."""
        return await create_object_type(self, nodeid, bname, is_abstract)

    async def add_variable_type(
        self,
        nodeid: ua.NodeId | str | int,
        bname: ua.QualifiedName | str,
        datatype: ua.NodeId | int,
        is_abstract: bool = False,
        value: Any = None,
    ) -> Node:
        """Add a VariableType as subtype of this one, with value as the default Value; see add_folder."""
        return await create_variable_type(self, nodeid, bname, datatype, is_abstract, value)

    async def add_data_type(
        self,
        nodeid: ua.NodeId | str | int,
        bname: ua.QualifiedName | str,
        description: str | None = None,
        is_abstract: bool = False,
    ) -> Node:
        """Add a DataType as subtype of this one; see add_folder and structures104.new_struct."""
        return await create_data_type(self, nodeid, bname, description=description, is_abstract=is_abstract)

    async def add_property(
        self,
        nodeid: ua.NodeId | str | int,
        bname: ua.QualifiedName | str,
        val: Any,
        varianttype: ua.VariantType | None = None,
        datatype: ua.NodeId | int | None = None,
    ) -> Node:
        """Add a PropertyType Variable below this node with HasProperty; see add_variable."""
        return await create_property(self, nodeid, bname, val, varianttype, datatype)

    async def add_method(
        self,
        nodeid: ua.NodeId | str | int,
        bname: ua.QualifiedName | str,
        callback: Callable[..., Any] | None = None,
        inputs: list[Any] | None = None,
        outputs: list[Any] | None = None,
    ) -> Node:
        """Add a Method below this node; see manage_nodes.create_method."""
        return await create_method(self, nodeid, bname, callback, inputs, outputs)

    async def add_reference_type(
        self,
        nodeid: ua.NodeId | str | int,
        bname: ua.QualifiedName | str,
        symmetric: bool = True,
        inversename: str | None = None,
    ) -> Node:
        """Add a ReferenceType as subtype of this one; a non-symmetric one needs an inversename. See add_folder."""
        return await create_reference_type(self, nodeid, bname, symmetric, inversename)

    async def call_method(
        self, methodid: Node | ua.NodeId | ua.QualifiedName | str, *args: Any, timeout: float | None = None
    ) -> Any:
        """Call a Method of this Object; see methods.call_method."""
        return await call_method(self, methodid, *args, timeout=timeout)

    async def register(self) -> None:
        """
        RegisterNodes (OPC 10000-4 v1.05, 5.9.5): the node then uses the NodeId the server returns, which may be
        faster to access; the original one is kept in basenodeid until unregister.
        """
        nodeid = (await self.session.register_nodes([self.nodeid]))[0]
        self.basenodeid = self.nodeid
        self.nodeid = nodeid

    async def unregister(self) -> None:
        """UnregisterNodes for a registered node, which gets its original NodeId back."""
        if self.basenodeid is None:
            return
        await self.session.unregister_nodes([self.nodeid])
        self.nodeid = self.basenodeid
        self.basenodeid = None

    @staticmethod
    def new_node(session: AbstractSession, nodeid: ua.NodeId) -> Node:
        """A Node, for modules that cannot import this one."""
        return Node(session, nodeid)
