"""
Helpers on top of the ua types and the Node API: values as text and back, type hierarchies, DataTypes.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import fields
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from dateutil import parser  # type: ignore[attr-defined]
from dateutil.tz import tzutc

from enginir_opcua import ua

from ..ua.ua_binary import get_string_encoding

if TYPE_CHECKING:
    from enginir_opcua import Server
    from enginir_opcua.common.node import Node

_logger = logging.getLogger(__name__)


def value_to_datavalue(val: Any, varianttype: ua.VariantType | None = None) -> ua.DataValue:
    """A DataValue as it is, a Variant wrapped in a DataValue, or any other value as a Variant of varianttype."""
    if isinstance(val, ua.DataValue):
        return val
    if isinstance(val, ua.Variant):
        return ua.DataValue(val)
    return ua.DataValue(ua.Variant(val) if varianttype is None else ua.Variant(val, varianttype))


INTEGER_RANGES = {
    ua.VariantType.SByte: (-(2**7), 2**7 - 1),
    ua.VariantType.Byte: (0, 2**8 - 1),
    ua.VariantType.Int16: (-(2**15), 2**15 - 1),
    ua.VariantType.UInt16: (0, 2**16 - 1),
    ua.VariantType.Int32: (-(2**31), 2**31 - 1),
    ua.VariantType.UInt32: (0, 2**32 - 1),
    ua.VariantType.Int64: (-(2**63), 2**63 - 1),
    ua.VariantType.UInt64: (0, 2**64 - 1),
}
_ABSTRACT_NUMBER_TYPES = (
    ua.ObjectIds.BaseDataType,
    ua.ObjectIds.Number,
    ua.ObjectIds.Integer,
    ua.ObjectIds.UInteger,
)
_BOOLEANS = {"true": True, "false": False, "1": True, "0": False}
_QUOTE_TRIGGERS = ('"', ",", "[", "]")


def _quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _element_to_string(val: Any, truncate: bool) -> str:
    if isinstance(val, list | tuple):
        return val_to_string(val, truncate)
    text = _text_of(val, truncate)
    if text == "" or text != text.strip() or any(c in text for c in _QUOTE_TRIGGERS):
        return _quote(text)
    return text


def val_to_string(val: Any, truncate: bool = False) -> str:
    """
    Convert a python object or enginir-opcua object to a text a human can read and edit.
    string_to_val reads it back. A list is written as [a, b]; an element that contains a comma,
    a quote or a bracket, or is empty, is written in double quotes.
    If truncate is true then huge strings or bytes are truncated.
    """
    if isinstance(val, list | tuple):
        return "[{}]".format(", ".join(_element_to_string(v, truncate) for v in val))
    text = _text_of(val, truncate)
    if text[:1] in ('"', "["):
        return _quote(text)
    return text


def _text_of(val: Any, truncate: bool) -> str:
    if hasattr(val, "to_string"):
        val = val.to_string()
    elif isinstance(val, ua.StatusCode):
        val = val.name
    elif isinstance(val, Enum):
        val = val.name
    elif isinstance(val, ua.DataValue):
        val = variant_to_string(val.Value) if val.Value is not None else ""
    elif isinstance(val, ua.XmlElement):
        val = val.Value
    elif isinstance(val, str):
        if truncate and len(val) > 100:
            val = val[:10] + "...." + val[-10:]
    elif isinstance(val, bytes):
        if truncate and len(val) > 100:
            val = (
                val[:10].decode(get_string_encoding(), errors="surrogateescape")
                + "...."
                + val[-10:].decode(get_string_encoding(), errors="surrogateescape")
            )
        else:
            val = val.decode(get_string_encoding(), errors="surrogateescape")
    elif isinstance(val, datetime):
        val = val.isoformat()
    else:
        val = str(val)
    return val


def variant_to_string(var: ua.Variant) -> str:
    """
    Convert a variant to a text a human can read, see val_to_string.
    """
    return val_to_string(var.Value)


def _split_list(text: str) -> list[str]:
    items: list[str] = []
    depth = 0
    quoted = False
    escaped = False
    start = 0
    for position, char in enumerate(text):
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth < 0:
                raise ValueError(f"Unbalanced brackets in {text!r}")
        elif char == "," and depth == 0:
            items.append(text[start:position])
            start = position + 1
    if quoted or depth != 0:
        raise ValueError(f"Unterminated quote or bracket in {text!r}")
    items.append(text[start:])
    return items


def _unquote(text: str) -> str:
    body = text[1:-1]
    result = []
    escaped = False
    for char in body:
        if escaped:
            result.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        else:
            result.append(char)
    return "".join(result)


def _is_quoted(text: str) -> bool:
    return len(text) >= 2 and text[0] == '"' and text[-1] == '"'


def string_to_val(string: str, vtype: Any) -> Any:
    """
    Convert a text back to a python or enginir-opcua object, the inverse of val_to_string.
    Text that cannot be read raises ValueError; a type without a text form raises NotImplementedError.
    """
    string = string.strip()
    if string.startswith("[") and string.endswith("]"):
        inner = string[1:-1].strip()
        if not inner:
            return []
        return [_element_from_string(item, vtype) for item in _split_list(inner)]
    if _is_quoted(string):
        return _scalar_from_string(_unquote(string), vtype)
    return _scalar_from_string(string, vtype)


def _element_from_string(item: str, vtype: Any) -> Any:
    item = item.strip()
    if item.startswith("["):
        return string_to_val(item, vtype)
    if _is_quoted(item):
        return _scalar_from_string(_unquote(item), vtype)
    return _scalar_from_string(item, vtype)


def _scalar_from_string(string: str, vtype: Any) -> Any:
    if vtype in (
        ua.VariantType.ExtensionObject,
        ua.VariantType.DataValue,
        ua.VariantType.Variant,
        ua.VariantType.DiagnosticInfo,
    ):
        raise NotImplementedError(f"No text form for {vtype}")
    try:
        return _convert_scalar_text(string, vtype)
    except (ValueError, NotImplementedError):
        raise
    except Exception as ex:
        raise ValueError(f"Cannot read {string!r} as {vtype}: {ex}") from ex


def _convert_scalar_text(string: str, vtype: Any) -> Any:
    if vtype == ua.VariantType.Null:
        return None
    if vtype == ua.VariantType.Boolean:
        try:
            return _BOOLEANS[string.lower()]
        except KeyError:
            raise ValueError(f"Cannot read {string!r} as a Boolean") from None
    if vtype in INTEGER_RANGES:
        number = int(string)
        low, high = INTEGER_RANGES[vtype]
        if not low <= number <= high:
            raise ValueError(f"{number} is outside the range of {vtype.name}")
        return number
    if vtype in (ua.VariantType.Float, ua.VariantType.Double):
        return float(string)
    if vtype == ua.VariantType.XmlElement:
        return ua.XmlElement(string)
    if vtype == ua.VariantType.String:
        return string
    if vtype == ua.VariantType.ByteString:
        return string.encode(get_string_encoding(), errors="surrogateescape")
    if vtype in (ua.VariantType.NodeId, ua.VariantType.ExpandedNodeId):
        return ua.NodeId.from_string(string)
    if vtype == ua.VariantType.QualifiedName:
        return ua.QualifiedName.from_string(string)
    if vtype == ua.VariantType.DateTime:
        value = parser.parse(string)
        if value.tzinfo is not None:
            value = value.astimezone(tzutc())
        return value
    if vtype == ua.VariantType.LocalizedText:
        return ua.LocalizedText.from_string(string)
    if vtype == ua.VariantType.StatusCode:
        return ua.StatusCode(int(string)) if string.isdigit() else ua.StatusCode(getattr(ua.StatusCodes, string))
    if vtype == ua.VariantType.Guid:
        return uuid.UUID(string)
    if isinstance(vtype, type) and issubclass(vtype, Enum):
        return _enum_from_string(string, vtype)
    raise NotImplementedError(f"No text form for {vtype}")


def _enum_from_string(string: str, vtype: Any) -> Any:
    if string.isdigit():
        return vtype(int(string))
    if string in vtype.__members__:
        return vtype[string]
    _, separator, number = string.rpartition("_")
    if separator and number.isdigit():
        return vtype(int(number))
    raise ValueError(f"{string!r} is not a member of {vtype.__name__}")


def string_to_variant(string: str, vtype: Any) -> ua.Variant:
    """The Variant of vtype for a text written by variant_to_string."""
    return ua.Variant(string_to_val(string, vtype), vtype)


async def get_node_children(node: Node, nodes: list[Node] | None = None) -> list[Node]:
    """
    Get the node and all its descendants along forward hierarchical references, each node once.
    """
    result = nodes if nodes is not None else []
    seen = {n.nodeid for n in result}
    pending = [node]
    while pending:
        current = pending.pop(0)
        if current.nodeid in seen:
            continue
        seen.add(current.nodeid)
        result.append(current)
        pending.extend(await current.get_children())
    return result


async def get_node_subtypes(node: Node, nodes: list[Node] | None = None) -> list[Node]:
    """
    Get the type and all its subtypes, each once.
    """
    result = nodes if nodes is not None else []
    seen = {n.nodeid for n in result}
    pending = [node]
    while pending:
        current = pending.pop(0)
        if current.nodeid in seen:
            continue
        seen.add(current.nodeid)
        result.append(current)
        pending.extend(await current.get_children(refs=ua.ObjectIds.HasSubtype))
    return result


async def get_node_supertypes(node: Node, includeitself: bool = False, skipbase: bool = True) -> list[Node]:
    """
    Return all supertypes of a type, following HasSubtype upwards.
    :param node: a Node
    :param includeitself: put the node itself first in the list
    :param skipbase: drop the last element of the chain, the top type
    :returns list of Nodes, the nearest supertype first
    """
    parents = [node] if includeitself else []
    seen = {node.nodeid}
    parent = await get_node_supertype(node)
    while parent is not None and parent.nodeid not in seen:
        seen.add(parent.nodeid)
        parents.append(parent)
        parent = await get_node_supertype(parent)
    if skipbase and len(parents) > 1:
        parents = parents[:-1]
    return parents


async def get_node_supertype(node: Node) -> Node | None:
    """The supertype of a type (the first inverse HasSubtype reference), None for a top type."""
    supertypes = await node.get_referenced_nodes(refs=ua.ObjectIds.HasSubtype, direction=ua.BrowseDirection.Inverse)
    if supertypes:
        return supertypes[0]
    return None


async def is_subtype(node: Node, supertype: ua.NodeId) -> bool:
    """Whether the type node is supertype or one of its subtypes."""
    current: Node | None = node
    seen: set[ua.NodeId] = set()
    while current is not None and current.nodeid not in seen:
        if current.nodeid == supertype:
            return True
        seen.add(current.nodeid)
        current = await get_node_supertype(current)
    return False


async def is_child_present(node: Node, browsename: ua.QualifiedName) -> bool:
    """Whether the node has a child (along hierarchical references) with this BrowseName."""
    return any(desc.BrowseName == browsename for desc in await node.get_children_descriptions())


async def data_type_to_variant_type(dtype_node: Node) -> ua.VariantType:
    """
    The VariantType that encodes values of a DataType: that of its built-in base type, Int32 for an
    Enumeration, and Variant for the abstract BaseDataType, Number, Integer and UInteger.
    """
    base = await get_base_data_type(dtype_node)
    identifier = base.nodeid.Identifier
    if not isinstance(identifier, int):
        raise ua.UaError(f"{base.nodeid} is not a built-in DataType")
    if identifier == ua.ObjectIds.Enumeration:
        return ua.VariantType.Int32
    if identifier in _ABSTRACT_NUMBER_TYPES:
        return ua.VariantType.Variant
    return ua.VariantType(identifier)


async def get_base_data_type(datatype: Node) -> Node:
    """
    The nearest built-in DataType of namespace 0 that the DataType is or derives from: a built-in type (i=1 to 25),
    Number, Integer, UInteger or Enumeration (up to i=29). Raises UaError if there is none.
    """
    base: Node | None = datatype
    seen: set[ua.NodeId] = set()
    while base is not None and base.nodeid not in seen:
        seen.add(base.nodeid)
        if base.nodeid.NamespaceIndex == 0 and isinstance(base.nodeid.Identifier, int) and base.nodeid.Identifier < 30:
            return base
        base = await get_node_supertype(base)
    raise ua.UaError(f"Datatype must be a subtype of builtin types {datatype!s}")


async def get_nodes_of_namespace(server: Server, namespaces: list[str | int] | str | int | None = None) -> list[Node]:
    """
    Get the nodes of one or more namespaces from a local Server.

    :param server: the Server whose address space is used
    :param namespaces: namespace URIs or indexes; none means every namespace except 0
    :return: List of nodes that are part of the namespaces
    :raises UaError: a namespace URI is not in the namespace array
    """
    ns_available = await server.get_namespace_array()
    if namespaces is None or (not isinstance(namespaces, str | int) and not namespaces):
        namespaces = list(range(1, len(ns_available)))
    elif isinstance(namespaces, str | int):
        namespaces = [namespaces]

    namespace_indexes: set[int] = set()
    for namespace in namespaces:
        if isinstance(namespace, int):
            namespace_indexes.add(namespace)
        elif namespace in ns_available:
            namespace_indexes.add(ns_available.index(namespace))
        else:
            raise ua.UaError(f"Namespace {namespace!r} is not in the namespace array")

    return [
        server.get_node(nodeid) for nodeid in server.iserver.aspace.keys() if nodeid.NamespaceIndex in namespace_indexes
    ]


def data_type_to_string(dtype: ua.NodeId) -> str:
    """The name of a DataType of namespace 0 without a service call, the NodeId text for other DataTypes."""
    if dtype.NamespaceIndex == 0 and isinstance(dtype.Identifier, int) and dtype.Identifier in ua.ObjectIdNames:
        return ua.ObjectIdNames[dtype.Identifier]
    return dtype.to_string()


def copy_dataclass_attr(dc_source: Any, dc_dest: Any) -> None:
    """
    Copy the common attributes of dc_source to dc_dest
    """
    common_params = set(f.name for f in fields(dc_source)) & set(f.name for f in fields(dc_dest))
    for c in common_params:
        setattr(dc_dest, c, getattr(dc_source, c))
