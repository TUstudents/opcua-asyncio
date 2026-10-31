from __future__ import annotations

import asyncio
import copy
import keyword
import logging
import re
import typing
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field, make_dataclass
from enum import Enum, IntEnum, IntFlag
from typing import TYPE_CHECKING, Any

from enginir_opcua import Node, ua
from enginir_opcua.common.manage_nodes import create_data_type, create_encoding
from enginir_opcua.ua.uaerrors import UaInvalidParameterError
from enginir_opcua.ua.uatypes import _set_ua_attribute

if TYPE_CHECKING:
    from enginir_opcua import Client, Server

_logger = logging.getLogger(__name__)


def new_struct_field(
    name: str,
    dtype: ua.NodeId | Node | ua.VariantType,
    array: bool = False,
    optional: bool = False,
    description: str = "",
) -> ua.StructureField:
    """
    A StructureField for new_struct; dtype is the DataType of the field, given as its NodeId, its Node or, for a
    built-in type, its VariantType. The description defaults to the name.
    """
    field = ua.StructureField()
    field.Name = name
    field.IsOptional = optional
    if description:
        field.Description = ua.LocalizedText(Text=description)
    else:
        field.Description = ua.LocalizedText(Text=name)
    if isinstance(dtype, ua.VariantType):
        field.DataType = ua.NodeId(dtype.value, 0)
    elif isinstance(dtype, ua.NodeId):
        field.DataType = dtype
    elif isinstance(dtype, Node):
        field.DataType = dtype.nodeid
    else:
        raise ValueError(f"DataType of a field must be a NodeId, not {dtype} of type {type(dtype)}")
    if array:
        field.ValueRank = ua.ValueRank.OneDimension
        field.ArrayDimensions = [0]
    else:
        field.ValueRank = ua.ValueRank.Scalar
        field.ArrayDimensions = None  # type: ignore[assignment]
    return field


async def new_struct(
    server: Server | Client,
    idx: int | ua.NodeId,
    name: str | ua.QualifiedName,
    fields: list[ua.StructureField],
    is_union: bool = False,
) -> tuple[Node, list[Node]]:
    """
    Add a Structure DataType (or a Union with is_union) with its Default Binary encoding node and write its
    DataTypeDefinition. idx is the namespace index or the requested NodeId. Returns the DataType node and the
    encoding nodes.
    """

    type_name = server.nodes.base_structure_type
    if is_union:
        type_name = server.nodes.base_union_type

    dtype = await create_data_type(type_name, idx, name)

    if isinstance(idx, ua.NodeId):
        idx = idx.NamespaceIndex
    enc = await create_encoding(dtype, ua.NodeId(0, idx), ua.QualifiedName("Default Binary", 0))

    sdef = ua.StructureDefinition()
    if is_union:
        sdef.StructureType = ua.StructureType.Union
        sdef.BaseDataType = server.nodes.base_union_type.nodeid
    else:
        sdef.BaseDataType = server.nodes.base_structure_type.nodeid
        sdef.StructureType = ua.StructureType.Structure
        for sfield in fields:
            if sfield.IsOptional:
                sdef.StructureType = ua.StructureType.StructureWithOptionalFields
                break
    sdef.Fields = fields
    sdef.DefaultEncodingId = enc.nodeid

    await dtype.write_data_type_definition(sdef)
    return dtype, [enc]


def new_enum_field(
    name: str,
    description: str = "",
) -> ua.EnumField:
    """An EnumField for new_enum; the description defaults to the name. The Value is set by new_enum."""
    field = ua.EnumField()
    field.DisplayName = ua.LocalizedText(Text=name)
    field.Name = name
    if description:
        field.Description = ua.LocalizedText(Text=description)
    else:
        field.Description = ua.LocalizedText(Text=name)
    return field


async def new_enum(
    server: Server | Client,
    idx: int | ua.NodeId,
    name: str | ua.QualifiedName,
    fields: list[str | ua.EnumField],
    option_set: bool = False,
) -> Node:
    """
    Add an Enumeration DataType, or an OptionSet with option_set, and write its EnumDefinition. Plain names are
    numbered from 0, or from one past the Value of the EnumField before them. For an OptionSet a Value is a bit
    number.
    """
    edef = ua.EnumDefinition()
    counter = 0
    for item in fields:
        if isinstance(item, ua.EnumField):
            field = copy.copy(item)
            counter = field.Value
        else:
            field = new_enum_field(item)
            field.Value = counter
        counter += 1
        edef.Fields.append(field)
    if option_set:
        dtype = await server.nodes.option_set_type.add_data_type(idx, name)
    else:
        dtype = await server.nodes.enum_data_type.add_data_type(idx, name)
    await dtype.write_data_type_definition(edef)
    return dtype


def clean_name(name: str) -> str:
    """
    A Python identifier for an OPC UA name: other characters become '_', a leading digit gets a '_' before it,
    a keyword gets one after it, and an empty name, which some servers give their DataTypes, becomes '_'.
    """
    if not name:
        return "_"
    if keyword.iskeyword(name):
        return name + "_"
    if name.isidentifier():
        return name
    newname = re.sub(r"\W+", "_", name)
    newname = re.sub(r"^[0-9]+", r"_\g<0>", newname)
    _logger.info("renamed %s to %s due to Python syntax", name, newname)
    return newname


_NUMERIC_TYPES = frozenset(
    ("Int16", "Int32", "Int64", "UInt16", "UInt32", "UInt64", "Double", "Float", "Byte", "SByte")
)


def _first_member_or_zero(enum_type: type[Enum]) -> Any:
    return next(iter(enum_type.__members__.values()), 0)


def _default_value_for(uatype: str, optional: bool = False) -> Any:
    """The default of a field of this built-in type, or a dataclass field with a factory for other types."""
    if optional:
        return None
    cls = getattr(ua, uatype, None)
    if isinstance(cls, type):
        uatype = cls.__name__
    if uatype == "String":
        return ua.String()
    if uatype == "Guid":
        return uuid.UUID(int=0)
    if uatype in ("ByteString", "CharArray", "Char"):
        return b""
    if uatype == "Boolean":
        return False
    if uatype == "DateTime":
        return ua.get_win_epoch()
    if uatype in _NUMERIC_TYPES:
        return getattr(ua, uatype)(0)
    if isinstance(cls, type) and issubclass(cls, Enum):
        return _first_member_or_zero(cls)
    if cls is not None:
        return field(default_factory=cls)
    return field(default_factory=list)


def _make_union_property(name: str, idx: int) -> property:
    def getter(self: Any) -> Any:
        if getattr(self, "Encoding", 0) == idx:
            return getattr(self, "Value", None)
        return None

    def setter(self: Any, value: Any) -> None:
        self.Encoding = idx
        self.Value = value

    return property(getter, setter)


def make_structure(
    data_type: ua.NodeId,
    struct_name: str,
    sdef: ua.StructureDefinition,
    log_error: bool = True,
    types: ua.TypeRegistry | None = None,
) -> dict[str, type]:
    """
    Build the dataclass for a StructureDefinition (OPC 10000-3 v1.05, 8.48) and bind it in the ua module.
    Field types are looked up in types (default: ua.default_types); a field of the structure's own type refers to
    the class itself. Returns {struct_name: class}. Raises RuntimeError for an unknown field type,
    NotImplementedError for an unsupported StructureType and TypeError or ValueError if the class cannot be built.
    """
    if sdef.StructureType not in (
        ua.StructureType.Structure,
        ua.StructureType.StructureWithOptionalFields,
        ua.StructureType.Union,
        ua.StructureType.StructureWithSubtypedValues,
        ua.StructureType.UnionWithSubtypedValues,
    ):
        raise NotImplementedError(
            f"Only StructureType implemented, not {ua.StructureType(sdef.StructureType).name} for node {struct_name} with DataTypeDefinition {sdef}"
        )
    is_union = sdef.StructureType in (ua.StructureType.Union, ua.StructureType.UnionWithSubtypedValues)
    allows_subtypes = sdef.StructureType in (
        ua.StructureType.StructureWithSubtypedValues,
        ua.StructureType.UnionWithSubtypedValues,
    )
    bases = (ua.UaUnion,) if is_union else ()

    fields: list[tuple[str, Any, Any]] = []
    union_fields: list[tuple[str, int]] = []
    union_type_hints: list[str] = []
    union_resolved_types: list[Any] = []
    deps: dict[str, type] = {}
    if sdef.StructureType == ua.StructureType.StructureWithOptionalFields:
        fields.append(("Encoding", ua.UInt32, field(default=0, repr=False, init=True, compare=False)))

    def _alias(cls: type) -> str:
        alias = f"_dep_{len(deps)}"
        deps[alias] = cls
        return alias

    for idx, sfield in enumerate(sdef.Fields, start=1):
        fname = clean_name(sfield.Name)
        dep_cls: type | None = None
        is_self_ref = False
        if sfield.DataType.NamespaceIndex == 0 and sfield.DataType.Identifier in ua.ObjectIdNames:
            if sfield.DataType.Identifier == ua.ObjectIds.BaseDataType:
                uatype_name = "Variant"
            elif sfield.DataType.Identifier == ua.ObjectIds.Structure:
                uatype_name = "ExtensionObject"
            else:
                uatype_name = ua.ObjectIdNames[sfield.DataType.Identifier]
        elif (registered := (types or ua.default_types).find(sfield.DataType)) is not None:
            dep_cls = registered
            uatype_name = registered.__name__
        elif sfield.DataType == data_type:
            is_self_ref = True
            uatype_name = struct_name
        else:
            if log_error:
                _logger.error("Unknown datatype for field: %s in structure:%s, please report", sfield, struct_name)
            raise RuntimeError(f"Unknown datatype for field: {sfield} in structure:{struct_name}, please report")

        if is_self_ref:
            element_type = "__SELF__"
            union_resolved_element: Any = None
        elif dep_cls is not None:
            element_type = _alias(dep_cls)
            union_resolved_element = dep_cls
        else:
            element_type = f"ua.{uatype_name}"
            union_resolved_element = getattr(ua, uatype_name, None)

        if sfield.ValueRank >= 1 and uatype_name == "Char":
            element_type = "ua.String"
            union_resolved_element = ua.String

        rank = max(sfield.ValueRank, 1) if sfield.ValueRank >= 1 or sfield.ArrayDimensions else 0
        uatype = "list[" * rank + element_type + "]" * rank
        resolved_for_union: Any = union_resolved_element
        if resolved_for_union is not None:
            for _ in range(rank):
                resolved_for_union = list[resolved_for_union]
        elif rank:
            resolved_for_union = list

        subtyped = allows_subtypes and sfield.IsOptional
        prop_uatype = uatype
        if sfield.IsOptional or is_union:
            if subtyped:
                prop_uatype = f"typing.Annotated[{uatype}, 'AllowSubtypes']"
            else:
                prop_uatype = f"typing.Optional[{uatype}]"

        if is_union:
            union_fields.append((fname, idx))
            union_type_hints.append(prop_uatype if subtyped else uatype)
            union_resolved_types.append(
                typing.Annotated[resolved_for_union, "AllowSubtypes"]
                if subtyped and resolved_for_union is not None
                else resolved_for_union
            )
            continue

        default_val: Any
        if sfield.ValueRank >= 0 and not sfield.IsOptional:
            default_val = field(default_factory=list)
        elif dep_cls is not None and not sfield.IsOptional:
            if issubclass(dep_cls, Enum):
                default_val = _first_member_or_zero(dep_cls)
            else:
                default_val = field(default_factory=dep_cls)
        else:
            default_val = _default_value_for(uatype_name, optional=sfield.IsOptional)

        fields.append((fname, prop_uatype, default_val))

    namespace: dict[str, Any] = {
        "ua": ua,
        "typing": typing,
        "field": field,
        "dataclass": dataclass,
        **deps,
    }

    if is_union:
        fields.append(("Encoding", "ua.UInt32", field(default=0, init=True)))
        value_type = f"typing.Optional[typing.Union[{', '.join(union_type_hints)}]]"
        fields.append(("Value", value_type, field(default=None, init=True)))
        for fname, idx in union_fields:
            namespace[fname] = _make_union_property(fname, idx)

    try:
        cls = make_dataclass(struct_name, fields, bases=bases, namespace=namespace, slots=True)
    except (TypeError, ValueError):
        if log_error:
            _logger.warning(
                "Failed to create dataclass for struct %s with fields %s and origin sdef: %s",
                struct_name,
                fields,
                sdef,
            )
        raise
    cls.__module__ = __name__
    cls.data_type = data_type  # type: ignore[attr-defined]
    cls.__SELF__ = cls  # type: ignore[attr-defined]
    cls.__doc__ = f"{struct_name} structure autogenerated from StructureDefinition object"

    _set_ua_attribute(struct_name, cls, data_type)

    if is_union:
        cls._union_types = [cls if t is None else t for t in union_resolved_types]  # type: ignore[attr-defined]

    return {struct_name: cls}


@dataclass
class DataTypeInfo:
    """Holds parsed metadata for a single structure DataType node."""

    data_type: ua.NodeId
    name: str
    desc: ua.ReferenceDescription
    sdef: ua.StructureDefinition
    encoding_id: ua.NodeId = field(init=False)
    deps: list[ua.NodeId] = field(init=False)

    def __post_init__(self) -> None:
        self.encoding_id = self.sdef.DefaultEncodingId
        self.deps = [f.DataType for f in self.sdef.Fields]


def _topological_sort_dtypes(dtypes: list[DataTypeInfo]) -> list[DataTypeInfo]:
    """Sort data types using Kahn's algorithm so dependencies come before dependents."""
    node_map: dict[ua.NodeId, DataTypeInfo] = {dt.desc.NodeId: dt for dt in dtypes}
    known_ids = node_map.keys()
    in_degree: dict[ua.NodeId, int] = {nid: 0 for nid in known_ids}
    dependents: dict[ua.NodeId, list[ua.NodeId]] = defaultdict(list)

    for dt in dtypes:
        for dep_nid in dt.deps:
            if dep_nid in known_ids and dep_nid != dt.desc.NodeId:
                in_degree[dt.desc.NodeId] += 1
                dependents[dep_nid].append(dt.desc.NodeId)

    queue = deque(nid for nid, deg in in_degree.items() if deg == 0)
    result: list[DataTypeInfo] = []

    while queue:
        nid = queue.popleft()
        result.append(node_map[nid])
        for dependent_nid in dependents[nid]:
            in_degree[dependent_nid] -= 1
            if in_degree[dependent_nid] == 0:
                queue.append(dependent_nid)

    if len(result) < len(dtypes):
        seen = {dt.desc.NodeId for dt in result}
        for dt in dtypes:
            if dt.desc.NodeId not in seen:
                result.append(dt)
    return result


async def _all_subtype_descriptions(server: Server | Client, base_node: Node) -> list[ua.ReferenceDescription]:
    found: list[ua.ReferenceDescription] = []
    seen = {base_node.nodeid}
    pending = [base_node]
    while pending:
        node = pending.pop(0)
        for desc in await node.get_children_descriptions(refs=ua.ObjectIds.HasSubtype):
            if desc.NodeId not in seen:
                seen.add(desc.NodeId)
                found.append(desc)
                pending.append(server.get_node(desc.NodeId))
    return found


async def get_children_descriptions_type_definitions(
    server: Server | Client, base_node: Node, overwrite_existing: bool = False, recursive: bool = False
) -> tuple[list[ua.ReferenceDescription], list[Any]]:
    """
    The subtypes of base_node (all levels with recursive) and, at the same positions, their DataTypeDefinition, or
    None for a subtype that is already registered (unless overwrite_existing) or has no definition.
    """
    if recursive:
        descs = await _all_subtype_descriptions(server, base_node)
    else:
        descs = await base_node.get_children_descriptions(refs=ua.ObjectIds.HasSubtype)
    nodes = []
    idxs = []
    for idx, desc in enumerate(descs):
        if not overwrite_existing and server.types.find_own(desc.NodeId) is not None:
            continue
        idxs.append(idx)
        nodes.append(server.get_node(desc.NodeId))

    if nodes:
        results = [
            dv.Value.Value if dv.Value is not None else None
            for dv in await server.read_attributes(nodes, ua.AttributeIds.DataTypeDefinition)
        ]
    else:
        results = []
    sdefs: list[Any] = [None for _ in descs]
    for i, sdef in zip(idxs, results):
        sdefs[i] = sdef
    return descs, sdefs


async def _get_parent_types(node: Node) -> list[Node]:
    parents: list[Node] = []
    tmp_node = node
    for _ in range(10):
        refs = await tmp_node.get_references(refs=ua.ObjectIds.HasSubtype, direction=ua.BrowseDirection.Inverse)
        if not refs or refs[0].NodeId == ua.NodeId(ua.ObjectIds.Structure):
            return parents
        tmp_node = Node(tmp_node.session, refs[0].NodeId)
        parents.append(tmp_node)
    _logger.warning("Went 10 layers up while look of subtype of given node %s, something is wrong: %s", node, parents)
    return parents


async def load_custom_struct(node: Node, types: ua.TypeRegistry | None = None) -> Any:
    """
    Build and register the class of one Structure DataType node; fields of supertypes that the definition lacks
    are put in front. Returns the class already registered for the node if there is one.
    """
    sdef = await node.read_data_type_definition()
    if not isinstance(sdef, ua.StructureDefinition):
        raise UaInvalidParameterError(f"Expected StructureDefinition, got: {type(sdef)}")
    name = (await node.read_browse_name()).Name
    for parent in await _get_parent_types(node):
        parent_sdef = await parent.read_data_type_definition()
        if isinstance(parent_sdef, ua.StructureDefinition):
            names = [f.Name for f in sdef.Fields]
            for f in reversed(parent_sdef.Fields):
                if f.Name not in names:
                    sdef.Fields.insert(0, f)
    types = types or ua.default_types
    existing = types.find_own(node.nodeid)
    if existing is not None:
        return existing
    struct = make_structure(node.nodeid, name, sdef, types=types)[name]
    types.register_struct(node.nodeid, sdef.DefaultEncodingId, struct, name)
    return struct


async def load_custom_struct_xml_import(
    types: ua.TypeRegistry, node_id: ua.NodeId, name: str, sdef: ua.StructureDefinition
) -> Any:
    """Build and register the class of a Structure DataType imported from a NodeSet (used by XmlImporter)."""
    name = clean_name(name)
    existing = types.find_own(node_id)
    if existing is not None:
        return existing
    struct = make_structure(node_id, name, sdef, types=types)[name]
    types.register_struct(node_id, sdef.DefaultEncodingId, struct, name)
    return struct


async def _recursive_parse_basedatatypes(
    server: Server | Client, base_node: Node, parent_datatype: str, new_alias: dict[str, Any]
) -> None:
    descs = await base_node.get_children_descriptions(refs=ua.ObjectIds.HasSubtype)
    for desc in descs:
        name = clean_name(desc.BrowseName.Name)
        if parent_datatype == "Number" or desc.NodeId.NamespaceIndex == 0:
            continue
        if server.types.find_own(desc.NodeId) is None:
            env = make_basetype(name, parent_datatype)
            server.types.register_alias(desc.NodeId, env[name], name)
            new_alias[name] = env[name]
    if descs:
        await asyncio.gather(
            *[
                _recursive_parse_basedatatypes(
                    server, server.get_node(desc.NodeId), clean_name(desc.BrowseName.Name), new_alias
                )
                for desc in descs
            ]
        )


async def load_basetype_alias_xml_import(
    server: Server | Client, name: str, nodeid: ua.NodeId, parent_datatype_nid: ua.NodeId
) -> Any:
    """Register a DataType imported from a NodeSet as an alias of the class of its parent DataType."""
    existing = server.types.find_own(nodeid)
    if existing is not None:
        return existing
    parent = server.get_node(parent_datatype_nid)
    bname = await parent.read_browse_name()
    parent_datatype = clean_name(bname.Name)
    env = make_basetype(name, parent_datatype)
    server.types.register_alias(nodeid, env[name], name)
    return env[name]


def make_basetype(name: str, parent_datatype: str) -> dict[str, Any]:
    """{name: the ua class called parent_datatype}, for a DataType that is a subtype of a built-in one."""
    return {name: getattr(ua, parent_datatype)}


async def _load_base_datatypes(server: Server | Client) -> dict[str, Any]:
    new_alias: dict[str, Any] = {}
    descriptions = await server.nodes.base_data_type.get_children_descriptions()
    for desc in descriptions:
        name = clean_name(desc.BrowseName.Name)
        if name not in ["Structure", "Enumeration"]:
            await _recursive_parse_basedatatypes(server, server.get_node(desc.NodeId), name, new_alias)
    return new_alias


class RecursiveParser:
    """Collects the Structure DataTypes below a node, each with the fields of its supertypes put in front."""

    def __init__(self, server: Server | Client) -> None:
        self.server = server
        self._visited: set[ua.NodeId] = set()
        self._dtypes: list[DataTypeInfo] = []

    async def parse(self, base_node: Node, overwrite_existing: bool = False) -> list[DataTypeInfo]:
        await self._parse_node(
            node=base_node,
            parent_sdef=None,
            overwrite_existing=overwrite_existing,
        )
        return self._dtypes

    async def _parse_node(
        self, node: Node, parent_sdef: ua.StructureDefinition | None, overwrite_existing: bool
    ) -> None:
        if node.nodeid in self._visited:
            return

        self._visited.add(node.nodeid)

        descs, sdefs = await get_children_descriptions_type_definitions(self.server, node, overwrite_existing)
        await asyncio.gather(
            *[self._process_child(desc, sdef, parent_sdef, overwrite_existing) for desc, sdef in zip(descs, sdefs)]
        )

    async def _process_child(
        self,
        desc: ua.ReferenceDescription,
        sdef: ua.StructureDefinition | None,
        parent_sdef: ua.StructureDefinition | None,
        overwrite_existing: bool,
    ) -> None:
        next_parent = parent_sdef

        if isinstance(sdef, ua.StructureDefinition):
            try:
                name = clean_name(desc.BrowseName.Name)

                if parent_sdef:
                    existing = {f.Name for f in sdef.Fields}
                    inherited = [f for f in parent_sdef.Fields if f.Name not in existing]
                    if inherited:
                        sdef.Fields = inherited + list(sdef.Fields)

                self._dtypes.append(DataTypeInfo(desc.NodeId, name, desc, sdef))
                next_parent = sdef
            except Exception:
                _logger.exception("Failed to process DataType node %s (%s), skipping it", desc.NodeId, desc.BrowseName)
                next_parent = parent_sdef

        child_node = self.server.get_node(desc.NodeId)

        await self._parse_node(
            node=child_node,
            parent_sdef=next_parent,
            overwrite_existing=overwrite_existing,
        )


async def load_data_type_definitions(
    server: Server | Client, base_node: Node | None = None, overwrite_existing: bool = False
) -> dict[str, type]:
    """
    Build and register classes for the custom DataTypes of the server: aliases of built-in types, OptionSets,
    Enumerations and the Structures below base_node (default: Structure), from their DataTypeDefinition
    Attribute (OPC 10000-3 v1.05, 5.8.3). Returns {name: class} of everything that was built.
    """
    await server.get_namespace_array()
    option_set_loads = [
        load_enums(server, server.nodes.option_set_type, True, overwrite_existing),
        *(
            load_enums(server, server.get_node(ua.NodeId(base_id)), True, overwrite_existing, base_name, True)
            for base_id, base_name in _OPTION_SET_BASES.items()
        ),
    ]
    option_set_results = await asyncio.gather(*option_set_loads)
    new_objects = await _load_base_datatypes(server)
    for option_sets in option_set_results:
        new_objects.update(option_sets)
    new_objects.update(await load_enums(server, overwrite_existing=overwrite_existing))

    if base_node is None:
        base_node = server.nodes.base_structure_type

    parser = RecursiveParser(server)
    dtypes = _topological_sort_dtypes(await parser.parse(base_node, overwrite_existing))

    retries = 3
    for cnt in range(retries):
        failed_types = []
        log_ex = retries == cnt + 1
        for dts in dtypes:
            if not overwrite_existing and server.types.find_own(dts.data_type) is not None:
                continue
            try:
                cls = make_structure(dts.data_type, dts.name, dts.sdef, log_error=log_ex, types=server.types)[dts.name]
                server.types.register_struct(dts.data_type, dts.encoding_id, cls, dts.name)
                new_objects[dts.name] = cls
            except NotImplementedError:
                _logger.exception("Structure type %s not implemented", dts.sdef)
            except (AttributeError, RuntimeError, KeyError, TypeError, ValueError, ua.UaError):
                if log_ex:
                    _logger.exception("Failed to resolve datatype %s", dts.sdef)
                failed_types.append(dts)
        if not failed_types:
            break
        dtypes = failed_types
    return new_objects


_OPTION_SET_BASES: dict[int, str] = {
    ua.ObjectIds.Byte: "Byte",
    ua.ObjectIds.UInt16: "UInt16",
    ua.ObjectIds.UInt32: "UInt32",
    ua.ObjectIds.UInt64: "UInt64",
}


def option_set_base_name(parent: ua.NodeId | None) -> str:
    """The integer type an OptionSet that is a subtype of parent encodes as; UInt32 unless parent is Byte to UInt64."""
    if parent is not None and parent.NamespaceIndex == 0:
        return _OPTION_SET_BASES.get(parent.Identifier, "UInt32") if isinstance(parent.Identifier, int) else "UInt32"
    return "UInt32"


def make_enum(
    name: str, edef: ua.EnumDefinition | ua.StructureDefinition, option_set: bool, base_type: str = "UInt32"
) -> dict[str, type]:
    """
    Build an IntEnum, or an IntFlag with option_set, from an EnumDefinition; for an OptionSet the Value of a field
    is its bit number and base_type the integer type it encodes as. Some servers give a StructureDefinition
    instead; its fields are then numbered from 1 (bits from 0) and a warning is logged. An empty definition gives an
    empty class and an error in the log. Returns {name: class}.
    """
    members: dict[str, int] = {}
    if not edef.Fields:
        _logger.error("Enum %s (NodeId: unknown): Failed to generate class from UA datatype", name)
    for n, sfield in enumerate(edef.Fields):
        fieldname = clean_name(sfield.Name)
        if fieldname in members:
            raise ua.UaError(
                f"Enumeration {name}: the fields '{sfield.Name}' and another one both become '{fieldname}'"
            )
        if isinstance(sfield, ua.EnumField):
            value = sfield.Value if not option_set else (1 << sfield.Value)
        else:
            value = n + 1 if not option_set else (1 << n)
            if n == 0:
                _logger.warning(
                    "%s type %s: guessing field values since the server does not provide them.",
                    "OptionSet" if option_set else "Enumeration",
                    name,
                )
        members[fieldname] = value
    cls = typing.cast(Any, IntFlag if option_set else IntEnum)(name, members)
    empty = "" if members else " (empty)"
    cls.__doc__ = f"{name} {'IntFlag' if option_set else 'IntEnum'}{empty} autogenerated from EnumDefinition"
    if option_set:
        cls.datatype = staticmethod(lambda: base_type)
    return {name: cls}


async def _read_enum_property(node: Node, name: str) -> list[Any] | None:
    try:
        child = await node.get_child(f"0:{name}")
        value = await child.read_value()
    except ua.UaError:
        return None
    return list(value) if value else None


async def _enum_definition_from_properties(server: Server | Client, nodeid: ua.NodeId) -> ua.EnumDefinition | None:
    """The EnumValues and EnumStrings Properties of an enumeration without DataTypeDefinition (OPC 10000-3, 8.14)."""
    node = server.get_node(nodeid)
    definition = ua.EnumDefinition()
    values = await _read_enum_property(node, "EnumValues")
    if values:
        for item in values:
            entry = ua.EnumField(Value=item.Value, DisplayName=item.DisplayName, Description=item.Description)
            entry.Name = item.DisplayName.Text or ""
            definition.Fields.append(entry)
        return definition
    strings = await _read_enum_property(node, "EnumStrings")
    if strings:
        for position, text in enumerate(strings):
            definition.Fields.append(ua.EnumField(Value=position, DisplayName=text, Name=text.Text or ""))
        return definition
    return None


async def load_enums(
    server: Server | Client,
    base_node: Node | None = None,
    option_set: bool = False,
    overwrite_existing: bool = False,
    option_set_base: str = "UInt32",
    recursive: bool = False,
) -> dict[str, type]:
    """
    Build and register an IntEnum, or an IntFlag with option_set, for the subtypes of base_node (default:
    Enumeration; all levels with recursive) from their EnumDefinition, or for enumerations without one from their
    EnumValues or EnumStrings Property. Returns {name: class} of what was built.
    """
    typename = "OptionSet" if option_set else "Enum"
    if base_node is None:
        base_node = server.nodes.enum_data_type
    descs, sdefs = await get_children_descriptions_type_definitions(server, base_node, overwrite_existing, recursive)
    new_enums = {}
    for idx, desc in enumerate(descs):
        name = clean_name(desc.BrowseName.Name)
        if not overwrite_existing and server.types.find_own(desc.NodeId) is not None:
            continue
        _logger.info("Registering %s %s %s", typename, desc.NodeId, name)
        edef = sdefs[idx]
        if not edef and not option_set:
            edef = await _enum_definition_from_properties(server, desc.NodeId)
        if not edef:
            continue
        try:
            cls = make_enum(name, edef, option_set, option_set_base)[name]
        except Exception:
            _logger.exception(
                "%s %s (NodeId: %s): Failed to generate class from UA datatype", typename, name, desc.NodeId
            )
            continue
        server.types.register_enum(desc.NodeId, cls, name)
        new_enums[name] = cls
    return new_enums


async def load_enum_xml_import(
    types: ua.TypeRegistry,
    node_id: ua.NodeId,
    name: str,
    edef: ua.EnumDefinition,
    option_set: bool,
    option_set_base: str = "UInt32",
) -> Any:
    """Build and register the class of an Enumeration or OptionSet imported from a NodeSet (used by XmlImporter)."""
    name = clean_name(name)
    existing = types.find_own(node_id)
    if existing is not None:
        return existing
    cls = make_enum(name, edef, option_set, option_set_base)[name]
    types.register_enum(node_id, cls, name)
    return cls
