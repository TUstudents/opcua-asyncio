"""
Copying nodes, alone or with everything they aggregate, and the shared steps of copying and instantiating.
"""

from __future__ import annotations

import logging
from dataclasses import fields
from typing import Any

import enginir_opcua
from enginir_opcua import ua
from enginir_opcua.common.session_interface import AbstractSession
from enginir_opcua.ua.uaerrors import UaInvalidParameterError

from .node_factory import make_node

_logger = logging.getLogger(__name__)

_SKIPPED_FIELDS = ("BodyLength", "TypeId", "SpecifiedAttributes", "Encoding")
_QUIET_STATUS = (
    ua.StatusCodes.BadAttributeIdInvalid,
    ua.StatusCodes.BadNodeAttributesInvalid,
    ua.StatusCodes.BadNoValue,
)


async def aggregated_children(node: enginir_opcua.Node) -> list[ua.ReferenceDescription]:
    """Forward references of the node along Aggregates and its subtypes, with the target's description."""
    return await node.get_references(
        ua.ObjectIds.Aggregates, ua.BrowseDirection.Forward, ua.NodeClass.Unspecified, True, ua.BrowseResultMask.All
    )


async def remove_created(session: AbstractSession, created: list[ua.NodeId]) -> None:
    """Best-effort removal of nodes made by a failed helper, the last made first."""
    if not created:
        return
    params = ua.DeleteNodesParameters()
    for nodeid in reversed(created):
        item = ua.DeleteNodesItem()
        item.NodeId = nodeid
        item.DeleteTargetReferences = True
        params.NodesToDelete.append(item)
    try:
        results = await session.delete_nodes(params)
        if any(not result.is_good() for result in results):
            _logger.warning("Some nodes of a failed operation could not be removed: %s", created)
    except Exception:
        _logger.warning("Could not remove the nodes of a failed operation: %s", created, exc_info=True)


async def _added_node(session: AbstractSession, addnode: ua.AddNodesItem, created: list[ua.NodeId]) -> ua.NodeId:
    result = (await session.add_nodes([addnode]))[0]
    result.StatusCode.check()
    if result.AddedNodeId.is_null():
        raise ua.UaError(f"The server returned no NodeId for {addnode.BrowseName}")
    created.append(result.AddedNodeId)
    return result.AddedNodeId


async def _copy_modelling_rule(session: AbstractSession, source: enginir_opcua.Node, target: ua.NodeId) -> None:
    for rule in await source.get_referenced_nodes(ua.ObjectIds.HasModellingRule, ua.BrowseDirection.Forward):
        await make_node(session, target).add_reference(
            rule, ua.ObjectIds.HasModellingRule, True, False, ua.NodeClass.Object
        )


async def copy_node(
    parent: enginir_opcua.Node,
    node: enginir_opcua.Node,
    nodeid: ua.NodeId | None = None,
    recursive: bool = True,
    referenceType: ua.NodeId | None = None,
) -> list[enginir_opcua.Node]:
    """
    Copy a node, or the node and everything it aggregates, as child of parent node.
    The copy is attached with referenceType, by default the reference through which the source hangs
    below its own parent (HasComponent if it has none). Nodes reached only through Organizes, HasNotifier,
    HasEventSource or HasSubtype are not copied. If a step fails the nodes copied so far are removed.
    """
    if referenceType is None:
        inverse = await node.get_references(
            ua.ObjectIds.HierarchicalReferences,
            ua.BrowseDirection.Inverse,
            ua.NodeClass.Unspecified,
            True,
            ua.BrowseResultMask.ReferenceTypeId,
        )
        referenceType = inverse[0].ReferenceTypeId if inverse else ua.NodeId(ua.ObjectIds.HasComponent)
    rdesc = await _rdesc_from_node(parent, node, referenceType)
    if nodeid is None:
        nodeid = ua.NodeId(NamespaceIndex=node.nodeid.NamespaceIndex)
    created: list[ua.NodeId] = []
    try:
        copied: dict[ua.NodeId, ua.NodeId] = {}
        await _copy_node(parent.session, parent.nodeid, rdesc, nodeid, recursive, created, copied)
    except BaseException:
        await remove_created(parent.session, created)
        raise
    return [make_node(parent.session, nid) for nid in created]


async def _copy_node(
    session: AbstractSession,
    parent_nodeid: ua.NodeId,
    rdesc: ua.ReferenceDescription,
    nodeid: ua.NodeId,
    recursive: bool,
    created: list[ua.NodeId],
    copied: dict[ua.NodeId, ua.NodeId],
) -> None:
    addnode = ua.AddNodesItem()
    addnode.RequestedNewNodeId = nodeid
    addnode.BrowseName = rdesc.BrowseName
    addnode.ParentNodeId = parent_nodeid
    addnode.ReferenceTypeId = rdesc.ReferenceTypeId
    addnode.TypeDefinition = rdesc.TypeDefinition
    addnode.NodeClass = rdesc.NodeClass
    node_to_copy = make_node(session, rdesc.NodeId)
    attr_obj = getattr(ua, ua.NodeClass(rdesc.NodeClass).name + "Attributes")
    await _read_and_copy_attrs(node_to_copy, attr_obj(), addnode)
    new_id = await _added_node(session, addnode, created)
    copied[rdesc.NodeId] = new_id
    await _copy_modelling_rule(session, node_to_copy, new_id)
    if not recursive:
        return
    for desc in await aggregated_children(node_to_copy):
        if desc.NodeId in copied:
            await make_node(session, new_id).add_reference(
                copied[desc.NodeId], desc.ReferenceTypeId, True, True, desc.NodeClass
            )
            continue
        await _copy_node(
            session, new_id, desc, ua.NodeId(NamespaceIndex=desc.NodeId.NamespaceIndex), True, created, copied
        )


async def _rdesc_from_node(
    parent: enginir_opcua.Node, node: enginir_opcua.Node, reference_type: ua.NodeId | None = None
) -> ua.ReferenceDescription:
    results = await node.read_attributes(
        [
            ua.AttributeIds.NodeClass,
            ua.AttributeIds.BrowseName,
            ua.AttributeIds.DisplayName,
        ]
    )
    variants: list[ua.Variant] = []
    for res in results:
        assert res.StatusCode is not None
        res.StatusCode.check()
        if res.Value is None:
            raise UaInvalidParameterError("Value must not be None if the result is in Good status")
        variants.append(res.Value)
    nclass, qname, dname = (v.Value for v in variants)
    rdesc = ua.ReferenceDescription()
    rdesc.NodeId = node.nodeid
    rdesc.BrowseName = qname
    rdesc.DisplayName = dname
    rdesc.NodeClass = nclass
    if reference_type is not None:
        rdesc.ReferenceTypeId = reference_type
    elif await parent.read_type_definition() == ua.NodeId(ua.ObjectIds.FolderType):
        rdesc.ReferenceTypeId = ua.NodeId(ua.ObjectIds.Organizes)
    else:
        rdesc.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasComponent)
    typedef = await node.read_type_definition()
    if typedef:
        rdesc.TypeDefinition = typedef
    return rdesc


async def _read_and_copy_attrs(node_type: enginir_opcua.Node, struct: Any, addnode: ua.AddNodesItem) -> None:
    names = [f.name for f in fields(struct) if not f.name.startswith("_") and f.name not in _SKIPPED_FIELDS]
    attrs = [getattr(ua.AttributeIds, name) for name in names]
    results = await node_type.read_attributes(attrs)
    for idx, name in enumerate(names):
        res = results[idx]
        assert res.StatusCode is not None
        if res.StatusCode.is_good():
            variant = res.Value
            if variant is None:
                raise UaInvalidParameterError("Value must not be None if the result is in Good status")
            if name == "Value":
                setattr(struct, name, variant)
            else:
                setattr(struct, name, variant.Value)
        elif res.StatusCode.value in _QUIET_STATUS:
            _logger.debug("Node %s has no attribute %s", node_type, name)
        else:
            _logger.warning(
                "Copying attributes from node %s, attribute %s, statuscode is %s",
                str(node_type),
                str(name),
                str(res.StatusCode),
            )
    addnode.NodeAttributes = struct
