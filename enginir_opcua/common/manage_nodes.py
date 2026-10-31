"""
Adding and deleting nodes with the NodeManagement services (OPC 10000-4 v1.05, 5.8).

The create functions take the new node's NodeId and BrowseName in one of two forms: a NodeId (or its text form)
and a QualifiedName (or its "ns:Name" text form), or a namespace index and a plain name, for which the server picks
the NodeId. The new node gets the parent through the reference the NodeClass needs (Organizes below a folder,
HasComponent, HasProperty or HasSubtype).
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable, Iterable
from enum import Enum
from typing import Any

import enginir_opcua
from enginir_opcua import ua
from enginir_opcua.common.session_interface import AbstractSession

from .copy_node_util import aggregated_children
from .instantiate_util import instantiate
from .node_factory import make_node

_logger = logging.getLogger(__name__)


def _parse_nodeid_qname(
    nodeid: ua.NodeId | str | int, bname: ua.QualifiedName | str
) -> tuple[ua.NodeId, ua.QualifiedName]:
    usage = "Give a namespace index and a name, or a NodeId and a QualifiedName"
    if isinstance(nodeid, int):
        if not isinstance(bname, str):
            raise TypeError(f"{usage}; got {nodeid!r} and {bname!r}")
        return ua.NodeId(0, nodeid), ua.QualifiedName(bname, nodeid)
    if isinstance(nodeid, str):
        nodeid = ua.NodeId.from_string(nodeid)
    elif not isinstance(nodeid, ua.NodeId):
        raise TypeError(f"{usage}; got {nodeid!r}")
    if isinstance(bname, str):
        return nodeid, ua.QualifiedName.from_string(bname)
    if not isinstance(bname, ua.QualifiedName):
        raise TypeError(f"{usage}; got {bname!r}")
    return nodeid, bname


async def create_folder(
    parent: enginir_opcua.Node, nodeid: ua.NodeId | str | int, bname: ua.QualifiedName | str
) -> enginir_opcua.Node:
    """Add a FolderType Object below parent."""
    nodeid, qname = _parse_nodeid_qname(nodeid, bname)
    return make_node(
        parent.session, await _create_object(parent.session, parent.nodeid, nodeid, qname, ua.ObjectIds.FolderType)
    )


async def create_object(
    parent: enginir_opcua.Node,
    nodeid: ua.NodeId | str | int,
    bname: ua.QualifiedName | str,
    objecttype: ua.NodeId | int | None = None,
    instantiate_optional: bool = True,
) -> enginir_opcua.Node:
    """
    Add an Object below parent. With objecttype the type is instantiated with its children (see
    instantiate_util.instantiate), else the Object is a BaseObjectType.
    """
    nodeid, qname = _parse_nodeid_qname(nodeid, bname)
    if objecttype is not None:
        objecttype_node = make_node(
            parent.session, ua.NodeId(objecttype) if isinstance(objecttype, int) else objecttype
        )
        dname = ua.LocalizedText(qname.Name)
        nodes = await instantiate(
            parent, objecttype_node, nodeid, bname=qname, dname=dname, instantiate_optional=instantiate_optional
        )
        return nodes[0]
    return make_node(
        parent.session,
        await _create_object(parent.session, parent.nodeid, nodeid, qname, ua.ObjectIds.BaseObjectType),
    )


async def create_property(
    parent: enginir_opcua.Node,
    nodeid: ua.NodeId | str | int,
    bname: ua.QualifiedName | str,
    val: Any,
    varianttype: ua.VariantType | None = None,
    datatype: ua.NodeId | int | None = None,
) -> enginir_opcua.Node:
    """Add a PropertyType Variable below parent with HasProperty; see create_variable."""
    nodeid, qname = _parse_nodeid_qname(nodeid, bname)
    var = ua.Variant(val) if varianttype is None else ua.Variant(val, varianttype)
    checked = _checked_datatype(datatype, val)
    return make_node(
        parent.session,
        await _create_variable(parent.session, parent.nodeid, nodeid, qname, var, datatype=checked, isproperty=True),
    )


async def create_variable(
    parent: enginir_opcua.Node,
    nodeid: ua.NodeId | str | int,
    bname: ua.QualifiedName | str,
    val: Any,
    varianttype: ua.VariantType | None = None,
    datatype: ua.NodeId | int | None = None,
) -> enginir_opcua.Node:
    """
    Add a BaseDataVariableType Variable below parent with the value val, encoded as varianttype if given. The
    DataType is datatype (a NodeId, or an integer of namespace 0), else that of the value's class: the registered
    DataType of a structure or enumeration, the built-in type otherwise. The node is readable, not writable.
    """
    nodeid, qname = _parse_nodeid_qname(nodeid, bname)
    var = ua.Variant(val) if varianttype is None else ua.Variant(val, varianttype)
    checked = _checked_datatype(datatype, val)
    return make_node(
        parent.session,
        await _create_variable(parent.session, parent.nodeid, nodeid, qname, var, datatype=checked, isproperty=False),
    )


def _checked_datatype(datatype: ua.NodeId | int | None, val: Any) -> ua.NodeId | None:
    if datatype is not None and not isinstance(datatype, ua.NodeId | int):
        raise TypeError("datatype argument must be a NodeId or an int referring to a namespace 0 NodeId")
    if isinstance(datatype, int) and datatype:
        return ua.NodeId(datatype, 0)
    if datatype:
        return datatype
    sample = val[0] if isinstance(val, list | tuple) and val else val
    if isinstance(sample, Enum):
        return ua.data_type_of_class(type(sample))
    return None


async def create_variable_type(
    parent: enginir_opcua.Node,
    nodeid: ua.NodeId | str | int,
    bname: ua.QualifiedName | str,
    datatype: ua.NodeId | int,
    is_abstract: bool = False,
    value: Any = None,
) -> enginir_opcua.Node:
    """
    Add a VariableType of the given DataType as subtype of parent; value, a Python value or a Variant, is the
    default Value its instances start with, and an array value makes the type an array type.
    """
    nodeid, qname = _parse_nodeid_qname(nodeid, bname)
    checked = _checked_datatype(datatype, None)
    if checked is None:
        raise TypeError("Data type argument must be a NodeId or an int referring to a NodeId")
    return make_node(
        parent.session,
        await _create_variable_type(parent.session, parent.nodeid, nodeid, qname, checked, value, is_abstract),
    )


async def create_reference_type(
    parent: enginir_opcua.Node,
    nodeid: ua.NodeId | str | int,
    bname: ua.QualifiedName | str,
    symmetric: bool = True,
    inversename: str | None = None,
) -> enginir_opcua.Node:
    """
    Add a concrete ReferenceType as subtype of parent. A symmetric one has no InverseName; a non-symmetric one
    needs it (OPC 10000-3 v1.05, 5.3.3).
    """
    nodeid, qname = _parse_nodeid_qname(nodeid, bname)
    if symmetric and inversename:
        raise ValueError("A symmetric ReferenceType has no InverseName")
    if not symmetric and not inversename:
        raise ValueError("A non-symmetric ReferenceType needs an InverseName")
    return make_node(
        parent.session,
        await _create_reference_type(parent.session, parent.nodeid, nodeid, qname, symmetric, inversename),
    )


async def create_object_type(
    parent: enginir_opcua.Node,
    nodeid: ua.NodeId | str | int,
    bname: ua.QualifiedName | str,
    is_abstract: bool = False,
) -> enginir_opcua.Node:
    """Add an ObjectType as subtype of parent."""
    nodeid, qname = _parse_nodeid_qname(nodeid, bname)
    return make_node(
        parent.session, await _create_object_type(parent.session, parent.nodeid, nodeid, qname, is_abstract)
    )


async def create_method(
    parent: enginir_opcua.Node,
    nodeid: ua.NodeId | str | int,
    bname: ua.QualifiedName | str,
    callback: Callable[..., Any] | None = None,
    inputs: list[Any] | None = None,
    outputs: list[Any] | None = None,
) -> enginir_opcua.Node:
    """
    Add a Method below parent, with InputArguments and OutputArguments Properties for the argument types given.
    An argument type is a ua.Argument, a VariantType, a NodeId, a Node or a class with a DataType; a list of one of
    these declares an array. The callback gets the NodeId of the parent and the input Variants and returns a list of
    Variants (methods.uamethod converts both). A callback can only be bound on a local session (a Server); on any
    other session pass None and the server that holds the node provides the implementation.
    """
    nodeid, qname = _parse_nodeid_qname(nodeid, bname)
    if callback is not None and not hasattr(parent.session, "add_method_callback"):
        raise ua.UaError("A method callback can only be bound on a local server session")
    return make_node(parent.session, await _create_method(parent, nodeid, qname, callback, inputs or [], outputs or []))


async def _create_object(
    session: AbstractSession,
    parentnodeid: ua.NodeId,
    nodeid: ua.NodeId,
    qname: ua.QualifiedName,
    objecttype: ua.NodeId | int,
) -> ua.NodeId:
    addnode = ua.AddNodesItem()
    addnode.RequestedNewNodeId = nodeid
    addnode.BrowseName = qname
    addnode.ParentNodeId = parentnodeid
    if await make_node(session, parentnodeid).read_type_definition() == ua.NodeId(ua.ObjectIds.FolderType):
        addnode.ReferenceTypeId = ua.NodeId(ua.ObjectIds.Organizes)
    else:
        addnode.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasComponent)
    addnode.NodeClass = ua.NodeClass.Object
    if isinstance(objecttype, int):
        addnode.TypeDefinition = ua.NodeId(objecttype)
    else:
        addnode.TypeDefinition = objecttype
    attrs = ua.ObjectAttributes()
    attrs.EventNotifier = 0
    attrs.DisplayName = ua.LocalizedText(qname.Name)
    attrs.WriteMask = 0
    attrs.UserWriteMask = 0
    addnode.NodeAttributes = attrs
    results = await session.add_nodes([addnode])
    results[0].StatusCode.check()
    return results[0].AddedNodeId


async def _create_reference_type(
    session: AbstractSession,
    parentnodeid: ua.NodeId,
    nodeid: ua.NodeId,
    qname: ua.QualifiedName,
    symmetric: bool,
    inversename: str | None,
) -> ua.NodeId:
    addnode = ua.AddNodesItem()
    addnode.RequestedNewNodeId = nodeid
    addnode.BrowseName = qname
    addnode.NodeClass = ua.NodeClass.ReferenceType
    addnode.ParentNodeId = parentnodeid
    addnode.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasSubtype)
    attrs = ua.ReferenceTypeAttributes()
    attrs.IsAbstract = False
    attrs.DisplayName = ua.LocalizedText(qname.Name)
    attrs.Symmetric = symmetric
    if inversename:
        attrs.InverseName = ua.LocalizedText(inversename)
    attrs.UserWriteMask = 0
    addnode.NodeAttributes = attrs

    results = await session.add_nodes([addnode])
    results[0].StatusCode.check()
    return results[0].AddedNodeId


async def _create_object_type(
    session: AbstractSession,
    parentnodeid: ua.NodeId,
    nodeid: ua.NodeId,
    qname: ua.QualifiedName,
    is_abstract: bool = False,
) -> ua.NodeId:
    addnode = ua.AddNodesItem()
    addnode.RequestedNewNodeId = nodeid
    addnode.BrowseName = qname
    addnode.ParentNodeId = parentnodeid
    addnode.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasSubtype)
    addnode.NodeClass = ua.NodeClass.ObjectType
    attrs = ua.ObjectTypeAttributes()
    attrs.IsAbstract = is_abstract
    attrs.DisplayName = ua.LocalizedText(qname.Name)
    attrs.WriteMask = 0
    attrs.UserWriteMask = 0
    addnode.NodeAttributes = attrs
    results = await session.add_nodes([addnode])
    results[0].StatusCode.check()
    return results[0].AddedNodeId


async def _create_variable(
    session: AbstractSession,
    parentnodeid: ua.NodeId,
    nodeid: ua.NodeId,
    qname: ua.QualifiedName,
    var: ua.Variant,
    datatype: ua.NodeId | None = None,
    isproperty: bool = False,
) -> ua.NodeId:
    addnode = ua.AddNodesItem()
    addnode.RequestedNewNodeId = nodeid
    addnode.BrowseName = qname
    addnode.NodeClass = ua.NodeClass.Variable
    addnode.ParentNodeId = parentnodeid
    if isproperty:
        addnode.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasProperty)
        addnode.TypeDefinition = ua.NodeId(ua.ObjectIds.PropertyType)
    else:
        addnode.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasComponent)
        addnode.TypeDefinition = ua.NodeId(ua.ObjectIds.BaseDataVariableType)
    attrs = ua.VariableAttributes()
    attrs.DisplayName = ua.LocalizedText(qname.Name)
    if datatype:
        attrs.DataType = datatype
    else:
        attrs.DataType = _guess_datatype(var)

    attrs.Value = var
    attrs.ValueRank, attrs.ArrayDimensions = _rank_and_dimensions(var)  # type: ignore[assignment]
    attrs.WriteMask = 0
    attrs.UserWriteMask = 0
    attrs.Historizing = False
    attrs.AccessLevel = ua.AccessLevel.CurrentRead.mask
    attrs.UserAccessLevel = ua.AccessLevel.CurrentRead.mask
    addnode.NodeAttributes = attrs
    results = await session.add_nodes([addnode])
    results[0].StatusCode.check()
    return results[0].AddedNodeId


def _rank_and_dimensions(var: ua.Variant) -> tuple[int, list[int] | None]:
    if not isinstance(var.Value, list | tuple):
        return ua.ValueRank.Scalar, None
    rank = len(var.Dimensions) if var.Dimensions else 1
    return rank, [0] * rank


async def _create_variable_type(
    session: AbstractSession,
    parentnodeid: ua.NodeId,
    nodeid: ua.NodeId,
    qname: ua.QualifiedName,
    datatype: ua.NodeId,
    value: Any = None,
    is_abstract: bool = False,
) -> ua.NodeId:
    addnode = ua.AddNodesItem()
    addnode.RequestedNewNodeId = nodeid
    addnode.BrowseName = qname
    addnode.NodeClass = ua.NodeClass.VariableType
    addnode.ParentNodeId = parentnodeid
    addnode.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasSubtype)
    attrs = ua.VariableTypeAttributes()
    attrs.DisplayName = ua.LocalizedText(qname.Name)
    attrs.DataType = datatype
    attrs.IsAbstract = is_abstract
    attrs.ValueRank = ua.ValueRank.Scalar
    attrs.ArrayDimensions = None  # type: ignore[assignment]
    if value is not None:
        variant = value if isinstance(value, ua.Variant) else ua.Variant(value)
        attrs.Value = variant
        attrs.ValueRank, attrs.ArrayDimensions = _rank_and_dimensions(variant)  # type: ignore[assignment]
    attrs.WriteMask = 0
    attrs.UserWriteMask = 0
    addnode.NodeAttributes = attrs
    results = await session.add_nodes([addnode])
    results[0].StatusCode.check()
    return results[0].AddedNodeId


async def create_data_type(
    parent: enginir_opcua.Node,
    nodeid: ua.NodeId | str | int,
    bname: ua.QualifiedName | str,
    description: str | None = None,
    is_abstract: bool = False,
) -> enginir_opcua.Node:
    """
    Add a DataType as subtype of parent. Its DataTypeDefinition is writable, so that new_struct and new_enum
    (structures104) can set it.
    """
    nodeid, qname = _parse_nodeid_qname(nodeid, bname)
    addnode = ua.AddNodesItem()
    addnode.RequestedNewNodeId = nodeid
    addnode.BrowseName = qname
    addnode.NodeClass = ua.NodeClass.DataType
    addnode.ParentNodeId = parent.nodeid
    addnode.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasSubtype)
    attrs = ua.DataTypeAttributes()
    if description is not None:
        attrs.Description = ua.LocalizedText(description)
    attrs.DisplayName = ua.LocalizedText(qname.Name)
    attrs.WriteMask = 1 << ua.WriteMask.DataTypeDefinition
    attrs.UserWriteMask = 1 << ua.WriteMask.DataTypeDefinition
    attrs.IsAbstract = is_abstract
    addnode.NodeAttributes = attrs
    results = await parent.session.add_nodes([addnode])
    results[0].StatusCode.check()
    return make_node(parent.session, results[0].AddedNodeId)


async def create_encoding(
    parent: enginir_opcua.Node, nodeid: ua.NodeId | str | int, bname: ua.QualifiedName | str
) -> enginir_opcua.Node:
    """Add a DataTypeEncodingType Object to the DataType parent with HasEncoding; the BrowseName is in namespace 0."""
    nodeid, qname = _parse_nodeid_qname(nodeid, bname)
    if qname.NamespaceIndex != 0:
        raise ua.UaError("Encoding QualifiedName index must be 0")
    return make_node(parent.session, await _create_encoding(parent.session, parent.nodeid, nodeid, qname))


async def _create_encoding(
    session: AbstractSession,
    parentnodeid: ua.NodeId,
    nodeid: ua.NodeId,
    qname: ua.QualifiedName,
) -> ua.NodeId:
    addnode = ua.AddNodesItem()
    addnode.RequestedNewNodeId = nodeid
    addnode.BrowseName = qname
    addnode.ParentNodeId = parentnodeid
    addnode.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasEncoding)
    addnode.TypeDefinition = ua.NodeId(ua.ObjectIds.DataTypeEncodingType)
    addnode.NodeClass = ua.NodeClass.Object
    attrs = ua.ObjectAttributes()
    attrs.DisplayName = ua.LocalizedText(qname.Name)
    attrs.WriteMask = 0
    attrs.UserWriteMask = 0
    attrs.EventNotifier = 0
    addnode.NodeAttributes = attrs
    results = await session.add_nodes([addnode])
    results[0].StatusCode.check()
    return results[0].AddedNodeId


async def _create_method(
    parent: enginir_opcua.Node,
    nodeid: ua.NodeId,
    qname: ua.QualifiedName,
    callback: Callable[..., Any] | None,
    inputs: list[Any],
    outputs: list[Any],
) -> ua.NodeId:
    addnode = ua.AddNodesItem()
    addnode.RequestedNewNodeId = nodeid
    addnode.BrowseName = qname
    addnode.NodeClass = ua.NodeClass.Method
    addnode.ParentNodeId = parent.nodeid
    addnode.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasComponent)
    attrs = ua.MethodAttributes()
    attrs.DisplayName = ua.LocalizedText(qname.Name)
    attrs.WriteMask = 0
    attrs.UserWriteMask = 0
    attrs.Executable = True
    attrs.UserExecutable = True
    addnode.NodeAttributes = attrs
    results = await parent.session.add_nodes([addnode])
    results[0].StatusCode.check()
    method = make_node(parent.session, results[0].AddedNodeId)
    try:
        for name, types in (("InputArguments", inputs), ("OutputArguments", outputs)):
            if types:
                prob = await create_property(
                    method,
                    ua.NodeId(NamespaceIndex=method.nodeid.NamespaceIndex),
                    ua.QualifiedName(name, 0),
                    [_vtype_to_argument(vtype, f"{name[:-9]}{index}") for index, vtype in enumerate(types)],
                    varianttype=ua.VariantType.ExtensionObject,
                    datatype=ua.ObjectIds.Argument,
                )
                await prob.set_modelling_rule(True)
        if callback is not None:
            parent.session.add_method_callback(method.nodeid, callback)  # type: ignore[attr-defined]
    except BaseException:
        await _remove_quietly(parent.session, method)
        raise
    return results[0].AddedNodeId


async def _remove_quietly(session: AbstractSession, node: enginir_opcua.Node) -> None:
    try:
        await delete_nodes(session, [node], recursive=True)
    except Exception:
        _logger.warning("Could not remove %s after a failure", node, exc_info=True)


def _vtype_to_argument(vtype: Any, name: str = "") -> ua.Argument:
    if isinstance(vtype, ua.Argument):
        return vtype
    arg = ua.Argument()
    arg.Name = name
    arg.ValueRank = ua.ValueRank.Scalar
    arg.ArrayDimensions = None  # type: ignore[assignment]
    if isinstance(vtype, list | tuple) and len(vtype) > 0:
        vtype = vtype[0]
        arg.ValueRank = ua.ValueRank.OneDimension
        arg.ArrayDimensions = [0]
    if hasattr(vtype, "data_type"):
        arg.DataType = vtype.data_type
    elif inspect.isclass(vtype) and issubclass(vtype, Enum):
        data_type = ua.data_type_of_class(vtype)
        if data_type is None:
            raise ua.UaError(f"No DataType is registered for enumeration {vtype.__name__}")
        arg.DataType = data_type
    elif isinstance(vtype, ua.VariantType):
        arg.DataType = ua.NodeId(vtype.value)
    elif isinstance(vtype, ua.NodeId):
        arg.DataType = vtype
    elif hasattr(vtype, "nodeid"):
        arg.DataType = vtype.nodeid
    elif hasattr(vtype, "__name__") and hasattr(ua.VariantType, vtype.__name__):
        arg.DataType = ua.NodeId(ua.VariantType[vtype.__name__].value)
    else:
        arg.DataType = ua.NodeId(vtype)
    return arg


def _guess_datatype(variant: ua.Variant) -> ua.NodeId:
    if variant.VariantType == ua.VariantType.Null:
        raise ua.UaError("Cannot guess the DataType of a null value, give the datatype")
    if variant.VariantType == ua.VariantType.ExtensionObject:
        if variant.Value is None:
            raise ua.UaError("Cannot guess DataType from Null ExtensionObject")
        if isinstance(variant.Value, list | tuple):
            if len(variant.Value) == 0:
                raise ua.UaError("Cannot guess the DataType of an empty ExtensionObject array, give the datatype")
            extobj = variant.Value[0]
        else:
            extobj = variant.Value
        data_type = ua.data_type_of_class(extobj.__class__)
        if data_type is not None:
            return data_type
        classname = extobj.__class__.__name__
        if hasattr(ua.ObjectIds, classname):
            return ua.NodeId(getattr(ua.ObjectIds, classname))
        raise ua.UaError(f"Cannot guess the DataType of {extobj!r} of Python type {type(extobj).__name__}")
    return ua.NodeId(getattr(ua.ObjectIds, variant.VariantType.name))


async def delete_nodes(
    session: AbstractSession,
    nodes: Iterable[enginir_opcua.Node],
    recursive: bool = False,
    delete_target_references: bool = True,
) -> tuple[list[enginir_opcua.Node], list[ua.StatusCode]]:
    """
    Delete specified nodes. With recursive, also the nodes below them along forward aggregating references
    (HasComponent, HasProperty, HasOrderedComponent and their subtypes), children first. A node that another
    node outside the deleted set still aggregates is kept.
    return the list of nodes the request deleted and their results
    """
    requested = list(nodes)
    ordered = await _with_aggregated_children(requested) if recursive else requested
    nodestodelete: list[ua.DeleteNodesItem] = []
    for mynode in ordered:
        it = ua.DeleteNodesItem()
        it.NodeId = mynode.nodeid
        it.DeleteTargetReferences = delete_target_references
        nodestodelete.append(it)
    params = ua.DeleteNodesParameters()
    params.NodesToDelete = nodestodelete
    return ordered, await session.delete_nodes(params)


async def _aggregation_neighbours(node: enginir_opcua.Node, direction: ua.BrowseDirection) -> list[enginir_opcua.Node]:
    if direction == ua.BrowseDirection.Forward:
        references = await aggregated_children(node)
    else:
        references = await node.get_references(
            ua.ObjectIds.Aggregates, direction, ua.NodeClass.Unspecified, True, ua.BrowseResultMask.None_
        )
    return [make_node(node.session, reference.NodeId) for reference in references]


async def _with_aggregated_children(roots: list[enginir_opcua.Node]) -> list[enginir_opcua.Node]:
    root_ids = {root.nodeid for root in roots}
    children: dict[ua.NodeId, list[enginir_opcua.Node]] = {}
    found: dict[ua.NodeId, enginir_opcua.Node] = {root.nodeid: root for root in roots}
    pending = list(roots)
    while pending:
        current = pending.pop(0)
        below = await _aggregation_neighbours(current, ua.BrowseDirection.Forward)
        children[current.nodeid] = below
        for child in below:
            if child.nodeid not in found:
                found[child.nodeid] = child
                pending.append(child)
    parents = {
        nid: {p.nodeid for p in await _aggregation_neighbours(found[nid], ua.BrowseDirection.Inverse)}
        for nid in found
        if nid not in root_ids
    }
    kept = set(found)
    changed = True
    while changed:
        changed = False
        for nid in list(kept - root_ids):
            if not parents[nid] <= kept:
                kept.discard(nid)
                changed = True
    ordered: list[enginir_opcua.Node] = []
    emitted: set[ua.NodeId] = set()

    def visit(nid: ua.NodeId) -> None:
        if nid in emitted or nid not in kept:
            return
        emitted.add(nid)
        for child in children.get(nid, []):
            visit(child.nodeid)
        ordered.append(found[nid])

    for root in roots:
        visit(root.nodeid)
    return ordered
