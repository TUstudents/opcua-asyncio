"""
Building an OPC Binary DataTypeDictionary on a server (OPC 10000-5 v1.05, Annexes B and C).

The DataTypeDictionary is deprecated since OPC UA 1.04; new structures should be added with structures104.new_struct,
which writes the DataTypeDefinition Attribute. This module serves clients that only read dictionaries.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as Et
from enum import Enum
from typing import TYPE_CHECKING

from enginir_opcua import ua

if TYPE_CHECKING:
    from enginir_opcua import Server

_logger = logging.getLogger(__name__)

_OPC_BINARY_TYPES = frozenset(
    (
        "Bit",
        "Boolean",
        "SByte",
        "Byte",
        "Int16",
        "UInt16",
        "Int32",
        "UInt32",
        "Int64",
        "UInt64",
        "Float",
        "Double",
        "Char",
        "String",
        "WideString",
        "DateTime",
        "ByteString",
        "Guid",
    )
)
_UA_BUILT_IN_TYPES = frozenset(ua.VariantType.__members__) - _OPC_BINARY_TYPES


class OPCTypeDictionaryBuilder:
    """The XML of one TypeDictionary with StructuredTypes in the namespace ns_urn."""

    def __init__(self, ns_urn: str) -> None:
        head_attributes = {
            "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "xmlns:tns": ns_urn,
            "DefaultByteOrder": "LittleEndian",
            "xmlns:opc": "http://opcfoundation.org/BinarySchema/",
            "xmlns:ua": "http://opcfoundation.org/UA/",
            "TargetNamespace": ns_urn,
        }
        self._root = Et.Element("opc:TypeDictionary", head_attributes)
        self.etree = Et.ElementTree(self._root)
        name_space = Et.SubElement(self._root, "opc:Import")
        name_space.attrib["Namespace"] = "http://opcfoundation.org/UA/"
        self._structs_dict: dict[str, Et.Element] = {}

    @staticmethod
    def _process_type(data_type: str) -> str:
        if data_type in _OPC_BINARY_TYPES:
            return "opc:" + data_type
        if data_type in _UA_BUILT_IN_TYPES:
            return "ua:" + data_type
        return "tns:" + data_type

    def _add_field(self, variable_name: str, data_type: str, struct_name: str) -> None:
        field = Et.SubElement(self._structs_dict[struct_name], "opc:Field")
        field.attrib["Name"] = variable_name
        field.attrib["TypeName"] = self._process_type(data_type)

    def _add_array_field(self, variable_name: str, data_type: str, struct_name: str) -> None:
        array_len = "NoOf" + variable_name
        field = Et.SubElement(self._structs_dict[struct_name], "opc:Field")
        field.attrib["Name"] = array_len
        field.attrib["TypeName"] = "opc:Int32"
        field = Et.SubElement(self._structs_dict[struct_name], "opc:Field")
        field.attrib["Name"] = variable_name
        field.attrib["TypeName"] = self._process_type(data_type)
        field.attrib["LengthField"] = array_len

    def add_field(self, type_name: str | Enum, variable_name: str, struct_name: str, is_array: bool = False) -> None:
        """
        Add a field to the StructuredType struct_name. type_name is a built-in type (its name or a VariantType) or
        another StructuredType of this dictionary; an array gets an Int32 'NoOf' length field before it.
        """
        if isinstance(type_name, Enum):
            type_name = type_name.name
        if is_array:
            self._add_array_field(variable_name, type_name, struct_name)
        else:
            self._add_field(variable_name, type_name, struct_name)

    def append_struct(self, name: str) -> Et.Element:
        """Add an empty StructuredType that derives from ExtensionObject."""
        appended_struct = Et.SubElement(self._root, "opc:StructuredType")
        appended_struct.attrib["BaseType"] = "ua:ExtensionObject"
        appended_struct.attrib["Name"] = name
        self._structs_dict[name] = appended_struct
        return appended_struct

    def get_dict_value(self) -> bytes:
        """The dictionary as indented UTF-8 XML."""
        Et.indent(self._root)
        return Et.tostring(self._root, encoding="utf-8")


def _reference_generator(
    source_id: ua.NodeId, target_id: ua.NodeId, reference_type: ua.NodeId, is_forward: bool = True
) -> ua.AddReferencesItem:
    ref = ua.AddReferencesItem()
    ref.IsForward = is_forward
    ref.ReferenceTypeId = reference_type
    ref.SourceNodeId = source_id
    ref.TargetNodeId = target_id
    return ref


class DataTypeDictionaryBuilder:
    """
    Adds a DataTypeDictionary variable under 'OPC Binary' and, for each structure, the DataType node, its
    DataTypeDescription and its Default Binary encoding. Call init() first and set_dict_byte_string() at the end.
    An existing dictionary called dict_name, or the one dict_node_id names, is overwritten.
    """

    def __init__(
        self,
        server: Server,
        idx: int,
        ns_urn: str,
        dict_name: str,
        dict_node_id: ua.NodeId | None = None,
    ) -> None:
        self._server = server
        self._session_server = server.get_node(ua.ObjectIds.RootFolder).session
        self._idx = idx
        self.ns_urn = ns_urn
        self.dict_name = dict_name
        self._type_dictionary = OPCTypeDictionaryBuilder(ns_urn)
        self.dict_id: ua.NodeId | None = dict_node_id

    async def init(self) -> None:
        """Add the dictionary variable unless a dict_node_id was given."""
        if self.dict_id is None:
            self.dict_id = await self._add_dictionary(self.dict_name)

    def _dictionary(self) -> ua.NodeId:
        if self.dict_id is None:
            raise ua.UaError("DataTypeDictionaryBuilder.init() was not called")
        return self.dict_id

    async def _add_dictionary(self, name: str) -> ua.NodeId:
        try:
            existing_node = await self._server.nodes.opc_binary.get_child(f"{self._idx}:{name}")
        except ua.uaerrors.BadNoMatch:
            new_node = ua.AddNodesItem()
            new_node.RequestedNewNodeId = ua.NodeId(0, self._idx)
            new_node.BrowseName = ua.QualifiedName(name, self._idx)
            new_node.NodeClass = ua.NodeClass.Variable
            new_node.ParentNodeId = ua.NodeId(ua.ObjectIds.OPCBinarySchema_TypeSystem, 0)
            new_node.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasComponent, 0)
            new_node.TypeDefinition = ua.NodeId(ua.ObjectIds.DataTypeDictionaryType, 0)
            attrs = ua.VariableAttributes()
            attrs.DisplayName = ua.LocalizedText(name)
            attrs.DataType = ua.NodeId(ua.ObjectIds.ByteString)
            attrs.Value = ua.Variant(None, ua.VariantType.Null)
            attrs.ValueRank = -1
            new_node.NodeAttributes = attrs
            res = await self._session_server.add_nodes([new_node])
            res[0].StatusCode.check()
            return res[0].AddedNodeId
        _logger.warning(
            "Making %s object for node %s which already exist, its data will be overriden", self, existing_node
        )
        return existing_node.nodeid

    async def _link_nodes(
        self, linked_obj_node_id: ua.NodeId, data_type_node_id: ua.NodeId, description_node_id: ua.NodeId
    ) -> None:
        """
        The references between the DataType, its encoding, its description and the dictionary (OPC 10000-5 v1.05,
        Annex B); those that exist already are kept.
        """
        dict_id = self._dictionary()
        has_subtype = ua.NodeId(ua.ObjectIds.HasSubtype, 0)
        has_encoding = ua.NodeId(ua.ObjectIds.HasEncoding, 0)
        has_description = ua.NodeId(ua.ObjectIds.HasDescription, 0)
        has_type_definition = ua.NodeId(ua.ObjectIds.HasTypeDefinition, 0)
        has_component = ua.NodeId(ua.ObjectIds.HasComponent, 0)
        refs = [
            _reference_generator(data_type_node_id, ua.NodeId(ua.ObjectIds.Structure, 0), has_subtype, False),
            _reference_generator(linked_obj_node_id, data_type_node_id, has_encoding, False),
            _reference_generator(linked_obj_node_id, description_node_id, has_description),
            _reference_generator(description_node_id, linked_obj_node_id, has_description, False),
            _reference_generator(
                linked_obj_node_id, ua.NodeId(ua.ObjectIds.DataTypeEncodingType, 0), has_type_definition
            ),
            _reference_generator(
                description_node_id, ua.NodeId(ua.ObjectIds.DataTypeDescriptionType, 0), has_type_definition
            ),
            _reference_generator(dict_id, description_node_id, has_component),
            _reference_generator(description_node_id, dict_id, has_component, False),
        ]
        results = await self._session_server.add_references(refs)
        for status in results:
            if status.is_bad() and status.value != ua.StatusCodes.BadDuplicateReferenceNotAllowed:
                status.check()

    async def create_data_type(self, type_name: str, nodeid: ua.NodeId | None = None, init: bool = True) -> StructNode:
        """
        Add a structure called type_name: a new DataType node under Structure, or the existing one nodeid names,
        and with init its DataTypeDescription and Default Binary encoding. Returns the StructNode to add fields to.
        """
        if nodeid is None:
            dt_node = ua.AddNodesItem()
            dt_node.RequestedNewNodeId = ua.NodeId(0, self._idx)
            dt_node.BrowseName = ua.QualifiedName(type_name, self._idx)
            dt_node.NodeClass = ua.NodeClass.DataType
            dt_node.ParentNodeId = ua.NodeId(ua.ObjectIds.Structure, 0)
            dt_node.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasSubtype, 0)
            dt_attributes = ua.DataTypeAttributes()
            dt_attributes.DisplayName = ua.LocalizedText(type_name)
            dt_node.NodeAttributes = dt_attributes

            res = await self._session_server.add_nodes([dt_node])
            res[0].StatusCode.check()
            data_type_node_id = res[0].AddedNodeId
        else:
            data_type_node_id = nodeid

        added = [data_type_node_id]

        if init:
            desc_node = ua.AddNodesItem()
            desc_node.RequestedNewNodeId = ua.NodeId(0, self._idx)
            desc_node.BrowseName = ua.QualifiedName(type_name, self._idx)
            desc_node.NodeClass = ua.NodeClass.Variable
            desc_node.ParentNodeId = self._dictionary()
            desc_node.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasComponent, 0)
            desc_node.TypeDefinition = ua.NodeId(ua.ObjectIds.DataTypeDescriptionType, 0)
            desc_attributes = ua.VariableAttributes()
            desc_attributes.DisplayName = ua.LocalizedText(type_name)
            desc_attributes.DataType = ua.NodeId(ua.ObjectIds.String)
            desc_attributes.Value = ua.Variant(type_name, ua.VariantType.String)
            desc_attributes.ValueRank = -1
            desc_node.NodeAttributes = desc_attributes

            res = await self._session_server.add_nodes([desc_node])
            res[0].StatusCode.check()
            description_node_id = res[0].AddedNodeId
            added.append(description_node_id)

            obj_node = ua.AddNodesItem()
            obj_node.RequestedNewNodeId = ua.NodeId(0, self._idx)
            obj_node.BrowseName = ua.QualifiedName("Default Binary", 0)
            obj_node.NodeClass = ua.NodeClass.Object
            obj_node.ParentNodeId = data_type_node_id
            obj_node.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasEncoding, 0)
            obj_node.TypeDefinition = ua.NodeId(ua.ObjectIds.DataTypeEncodingType, 0)
            obj_attributes = ua.ObjectAttributes()
            obj_attributes.DisplayName = ua.LocalizedText("Default Binary")
            obj_attributes.EventNotifier = 0
            obj_node.NodeAttributes = obj_attributes

            res = await self._session_server.add_nodes([obj_node])
            res[0].StatusCode.check()
            bind_obj_node_id = res[0].AddedNodeId
            added.append(bind_obj_node_id)

            await self._link_nodes(bind_obj_node_id, data_type_node_id, description_node_id)

        self._type_dictionary.append_struct(type_name)
        return StructNode(self, data_type_node_id, type_name, added)

    def add_field(self, type_name: str | Enum, variable_name: str, struct_name: str, is_array: bool = False) -> None:
        """Add a field to the structure struct_name; see OPCTypeDictionaryBuilder.add_field."""
        self._type_dictionary.add_field(type_name, variable_name, struct_name, is_array)

    async def set_dict_byte_string(self) -> None:
        """Write the dictionary XML into the value of the dictionary variable."""
        dict_node = self._server.get_node(self._dictionary())
        await dict_node.write_value(self._type_dictionary.get_dict_value(), ua.VariantType.ByteString)


class StructNode:
    """A structure created by DataTypeDictionaryBuilder.create_data_type, with the NodeIds of the nodes it added."""

    def __init__(
        self, type_dict: DataTypeDictionaryBuilder, data_type: ua.NodeId, name: str, node_ids: list[ua.NodeId]
    ) -> None:
        self._type_dict = type_dict
        self.data_type = data_type
        self.name = name
        self.node_ids = node_ids

    def add_field(self, field_name: str, field_type: str | Enum | StructNode, is_array: bool = False) -> None:
        """Add a field of a built-in type or of another structure of the same dictionary."""
        if isinstance(field_type, StructNode):
            field_type = field_type.name
        self._type_dict.add_field(field_type, field_name, self.name, is_array)
