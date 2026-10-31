import contextlib
import tempfile
from pathlib import Path

import pytest

from enginir_opcua import ua
from enginir_opcua.common.structures104 import new_enum, new_struct, new_struct_field
from enginir_opcua.ua.ua_binary import struct_from_binary, struct_to_binary
from tests.access_rig import declare_writable

pytestmark = pytest.mark.asyncio


@contextlib.contextmanager
def expect_file_creation(filename: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / filename
        yield path
        assert Path.is_file(path), f"File {path} should have been created"


async def test_custom_struct_with_null_browsename_sibling(opc, caplog):
    """A DataType node with a null/empty BrowseName (seen on some real servers, see
    https://github.com/FreeOpcUa/opcua-asyncio/issues/1990) must not abort parsing of
    the rest of the type hierarchy.
    """
    caplog.set_level("ERROR")
    idx = 4

    # A well-formed struct that should still be loaded despite its malformed sibling.
    await new_struct(
        opc.opc,
        idx,
        "MyGoodStruct",
        [new_struct_field("MyBool", ua.VariantType.Boolean)],
    )

    # A struct DataType node with a null BrowseName.Name, as reported by some servers.
    bad_attributes = ua.DataTypeAttributes()
    bad_attributes.DisplayName = ua.LocalizedText("MyBadStructType")
    bad_item = ua.AddNodesItem(
        ParentNodeId=ua.NodeId(ua.ObjectIds.Structure),
        ReferenceTypeId=ua.NodeId(ua.ObjectIds.HasSubtype),
        RequestedNewNodeId=ua.NodeId("MyBadStructType", idx),
        BrowseName=ua.QualifiedName(None, idx),
        NodeClass=ua.NodeClass.DataType,
        NodeAttributes=bad_attributes,
    )
    assert not list(opc.server.iserver.node_mgt_service.try_add_nodes([bad_item], check=False))
    dtype = opc.server.get_node(bad_item.RequestedNewNodeId)
    sdef = ua.StructureDefinition()
    sdef.StructureType = ua.StructureType.Structure
    sdef.Fields = [new_struct_field("MyInt32", ua.VariantType.Int32)]
    await dtype.write_data_type_definition(sdef)

    for name in ("MyGoodStruct",):
        try:
            delattr(ua, name)
        except AttributeError:
            pass

    # Does not raise
    await opc.opc.load_data_type_definitions()

    assert hasattr(ua, "MyGoodStruct")


async def test_custom_struct_(opc):
    idx = 4

    await new_struct(
        opc.opc,
        idx,
        "MyMyStruct",
        [
            new_struct_field("MyBool", ua.VariantType.Boolean),
            new_struct_field("MyUInt32", ua.VariantType.UInt32, array=True),
        ],
    )

    await opc.opc.load_data_type_definitions()
    mystruct = ua.MyMyStruct()
    mystruct.MyUInt32 = [78, 79]
    var = await opc.opc.nodes.objects.add_variable(
        idx, "my_struct", ua.Variant(mystruct, ua.VariantType.ExtensionObject)
    )
    val = await var.read_value()
    assert val.MyUInt32 == [78, 79]


async def test_variable_of_a_custom_struct_named_like_a_standard_type_gets_its_own_data_type(
    server, restore_ua_registry
):
    idx = await server.register_namespace("urn:test:guess-data-type")
    dtype, _ = await new_struct(server, idx, "Range", [new_struct_field("Width", ua.VariantType.Double)])
    await server.load_data_type_definitions()
    cls = server.types.find_own(dtype.nodeid)
    value = ua.Variant(cls(Width=2.0), ua.VariantType.ExtensionObject)
    var = await server.nodes.objects.add_variable(idx, "CustomRange", value)
    assert await var.read_data_type() == dtype.nodeid


async def test_custom_struct_with_optional_fields(opc):
    idx = 4

    await new_struct(
        opc.opc,
        idx,
        "MyOptionalStruct",
        [
            new_struct_field("MyBool", ua.VariantType.Boolean),
            new_struct_field("MyUInt32", ua.VariantType.UInt32),
            new_struct_field("MyString", ua.VariantType.String, optional=True),
            new_struct_field("MyInt64", ua.VariantType.Int64, optional=True),
        ],
    )

    await opc.opc.load_data_type_definitions()

    my_struct_optional = ua.MyOptionalStruct()
    assert my_struct_optional.MyBool is not None
    assert my_struct_optional.MyUInt32 is not None
    assert my_struct_optional.MyString is None
    assert my_struct_optional.MyInt64 is None

    my_struct_optional.MyUInt32 = 45
    my_struct_optional.MyInt64 = -67
    var = await opc.opc.nodes.objects.add_variable(
        idx,
        "my_struct_optional",
        ua.Variant(my_struct_optional, ua.VariantType.ExtensionObject),
    )
    await declare_writable(opc, var)

    val = await var.read_value()
    assert val.MyUInt32 == 45
    assert val.MyInt64 == -67
    assert val.MyString is None

    my_struct_optional = ua.MyOptionalStruct()
    my_struct_optional.MyUInt32 = 45
    my_struct_optional.MyInt64 = -67
    my_struct_optional.MyString = "abc"
    await var.write_value(my_struct_optional)
    val = await var.read_value()
    assert val.MyUInt32 == 45
    assert val.MyInt64 == -67
    assert val.MyString == "abc"


async def test_custom_struct_union(opc):
    idx = 4
    await new_struct(
        opc.opc,
        idx,
        "MyUnionStruct",
        [
            new_struct_field("MyString", ua.VariantType.String),
            new_struct_field("MyInt64", ua.VariantType.Int64),
        ],
        is_union=True,
    )
    await opc.opc.load_data_type_definitions()
    my_union = ua.MyUnionStruct()
    my_union.MyInt64 = 555
    var = await opc.opc.nodes.objects.add_variable(
        idx, "my_union_struct", ua.Variant(my_union, ua.VariantType.ExtensionObject)
    )
    await declare_writable(opc, var)
    val = await var.read_value()
    assert val.MyInt64 == 555
    assert val.MyString is None
    my_union.MyString = "1234"
    await var.write_value(my_union)
    val = await var.read_value()
    assert val.MyInt64 is None
    assert val.MyString == "1234"

    # test for union with the same type and multiple fields
    await new_struct(
        opc.opc,
        idx,
        "MyDuplicateTypeUnionStruct",
        [
            new_struct_field("MyString", ua.VariantType.String),
            new_struct_field("MyInt64", ua.VariantType.Int64),
            new_struct_field("MySecondString", ua.VariantType.String),
        ],
        is_union=True,
    )
    await opc.opc.load_data_type_definitions()
    my_union = ua.MyDuplicateTypeUnionStruct()
    my_union.MyInt64 = 555
    var = await opc.opc.nodes.objects.add_variable(
        idx,
        "my_duplicate_union_struct",
        ua.Variant(my_union, ua.VariantType.ExtensionObject),
    )
    await declare_writable(opc, var)
    val = await var.read_value()
    assert val.MyInt64 == 555
    assert val.MyString is None
    assert val.MySecondString is None
    my_union.MyString = "1234"
    await var.write_value(my_union)
    val = await var.read_value()
    assert val.MyInt64 is None
    assert val.MyString == "1234"
    assert val.MySecondString is None
    my_union.MySecondString = "ABC"
    await var.write_value(my_union)
    val = await var.read_value()
    assert val.MyInt64 is None
    assert val.MyString is None
    assert val.MySecondString == "ABC"


async def test_custom_struct_of_struct(opc):
    idx = 4

    dtype, _encs = await new_struct(
        opc.opc,
        idx,
        "MySubStruct2",
        [
            new_struct_field("MyBool", ua.VariantType.Boolean),
            new_struct_field("MyUInt32", ua.VariantType.UInt32),
        ],
    )

    await new_struct(
        opc.opc,
        idx,
        "MyMotherStruct2",
        [
            new_struct_field("MyBool", ua.VariantType.Boolean),
            new_struct_field("MySubStruct", dtype),
        ],
    )

    await opc.opc.load_data_type_definitions()

    mystruct = ua.MyMotherStruct2()
    mystruct.MySubStruct = ua.MySubStruct2()
    mystruct.MySubStruct.MyUInt32 = 78
    var = await opc.opc.nodes.objects.add_variable(idx, "my_mother_struct", mystruct)
    val = await var.read_value()
    assert val.MySubStruct.MyUInt32 == 78


async def test_custom_list_of_struct(opc):
    idx = 4

    dtype, _encs = await new_struct(
        opc.opc,
        idx,
        "MySubStruct3",
        [
            new_struct_field("MyBool", ua.VariantType.Boolean),
            new_struct_field("MyUInt32", ua.VariantType.UInt32),
        ],
    )

    await new_struct(
        opc.opc,
        idx,
        "MyMotherStruct3",
        [
            new_struct_field("MyBool", ua.VariantType.Boolean),
            new_struct_field("MySubStruct", dtype, array=True),
        ],
    )

    await opc.opc.load_data_type_definitions()

    mystruct = ua.MyMotherStruct3()
    mystruct.MySubStruct = [ua.MySubStruct3()]
    mystruct.MySubStruct[0].MyUInt32 = 78
    var = await opc.opc.nodes.objects.add_variable(
        idx, "my_mother_struct3", ua.Variant(mystruct, ua.VariantType.ExtensionObject)
    )
    val = await var.read_value()
    assert val.MySubStruct[0].MyUInt32 == 78


async def test_custom_struct_with_enum(opc):
    idx = 4

    dtype = await new_enum(
        opc.opc,
        idx,
        "MyCustEnum2",
        [
            "titi",
            "toto",
            "tutu",
        ],
    )

    await new_struct(
        opc.opc,
        idx,
        "MyStructEnum",
        [
            new_struct_field("MyBool", ua.VariantType.Boolean),
            new_struct_field("MyEnum", dtype),
        ],
    )

    await opc.opc.load_data_type_definitions()

    mystruct = ua.MyStructEnum()
    mystruct.MyEnum = ua.MyCustEnum2.tutu
    var = await opc.opc.nodes.objects.add_variable(
        idx, "my_struct2", ua.Variant(mystruct, ua.VariantType.ExtensionObject)
    )
    val = await var.read_value()
    assert val.MyEnum == ua.MyCustEnum2.tutu
    assert isinstance(val.MyEnum, ua.MyCustEnum2)


async def test_nested_struct_arrays(opc):
    idx = 4

    snode1, _ = await new_struct(
        opc.opc,
        idx,
        "MyStruct4",
        [
            new_struct_field("MyBool", ua.VariantType.Boolean),
            new_struct_field("MyUInt32List", ua.VariantType.UInt32, array=True),
        ],
    )

    _snode2, _ = await new_struct(
        opc.opc,
        idx,
        "MyNestedStruct",
        [
            new_struct_field("MyStructArray", snode1, array=True),
        ],
    )

    await opc.opc.load_data_type_definitions()

    mystruct = ua.MyNestedStruct()
    mystruct.MyStructArray = [ua.MyStruct4(), ua.MyStruct4()]
    var = await opc.opc.nodes.objects.add_variable(idx, "nested", ua.Variant(mystruct, ua.VariantType.ExtensionObject))
    val = await var.read_value()
    assert len(val.MyStructArray) == 2
    assert mystruct.MyStructArray == val.MyStructArray


async def test_custom_struct_export(opc):
    idx = 1

    dtype, encs = await new_struct(
        opc.opc,
        idx,
        "MyMyStructExport",
        [
            new_struct_field("MyBool", ua.VariantType.Boolean),
            new_struct_field("MyUInt32", ua.VariantType.UInt32, array=True),
        ],
    )
    with expect_file_creation("custom_struct_export.xml") as path:
        await opc.opc.export_xml([dtype, *encs], path)


async def test_custom_enum_export(opc):
    idx = 1

    dtype = await new_enum(
        opc.opc,
        idx,
        "MyCustEnumExport",
        [
            "titi",
            "toto",
            "tutu",
        ],
    )
    with expect_file_creation("custom_enum_export.xml") as path:
        await opc.opc.export_xml([dtype], path)


async def test_custom_enum_import(opc):
    nodes = await opc.opc.import_xml("tests/custom_enum.xml")
    nodes = [opc.opc.get_node(node) for node in nodes]  # FIXME why does it return nodeids and not nodes?
    node = nodes[0]
    sdef = await node.read_data_type_definition()
    assert sdef.Fields[0].Name == "titi"
    assert sdef.Fields[0].Description.Text == "Description for titi."
    with expect_file_creation("custom_enum_v2.xml") as path:
        await opc.opc.export_xml(nodes, path)


async def test_custom_struct_import(opc):
    nodes = await opc.opc.import_xml("tests/model/custom_struct.xml")
    nodes = [opc.opc.get_node(node) for node in nodes]  # FIXME why does it return nodeids and not nodes?
    node = nodes[0]  # FIXME: make that more robust
    sdef = await node.read_data_type_definition()
    assert sdef.StructureType == ua.StructureType.Structure
    assert sdef.Fields[0].Name == "MyBool"
    assert sdef.Fields[0].DataType == ua.NodeId(ua.ObjectIds.Boolean)
    assert sdef.Fields[0].Description.Text == "Description for MyBool."
    with expect_file_creation("custom_enum_v2.xml") as path:
        await opc.opc.export_xml(nodes, path)


async def test_custom_struct_recursive(opc):
    nodes = await opc.opc.import_xml("tests/model/custom_struct_recursive.xml")
    await opc.opc.load_data_type_definitions()

    nodes = [opc.opc.get_node(node) for node in nodes]  # FIXME why does it return nodeids and not nodes?
    node = nodes[0]  # FIXME: make that more robust
    sdef = await node.read_data_type_definition()
    assert sdef.StructureType == ua.StructureType.Structure
    assert sdef.Fields[0].Name == "Subparameters"

    # Check encoding / decoding
    param = ua.MyParameterType(Value=2)
    param.Subparameters.append(ua.MyParameterType(Value=1))
    bin = struct_to_binary(param)
    res = struct_from_binary(ua.MyParameterType, ua.utils.Buffer(bin))
    assert param == res

    with expect_file_creation("custom_struct_recursive_export.xml") as path:
        await opc.opc.export_xml(nodes, path)


async def test_custom_struct_of_struct_with_spaces(opc):
    idx = 6

    nodeid = ua.NodeId("toto.My Identifier", idx)
    qname = ua.QualifiedName("My Sub Struct 1", idx)
    dtype, _encs = await new_struct(
        opc.opc,
        nodeid,
        qname,
        [
            new_struct_field("My Bool", ua.VariantType.Boolean),
            new_struct_field("My UInt32", ua.VariantType.UInt32),
        ],
    )

    await new_struct(
        opc.opc,
        idx,
        "My Mother Struct",
        [
            new_struct_field("My Bool", ua.VariantType.Boolean),
            new_struct_field("My Sub Struct", dtype),
        ],
    )

    await opc.opc.load_data_type_definitions()

    mystruct = ua.My_Mother_Struct()
    mystruct.My_Sub_Struct = ua.My_Sub_Struct_1()
    mystruct.My_Sub_Struct.My_UInt32 = 78
    var = await opc.opc.nodes.objects.add_variable(idx, "my mother struct", mystruct)
    val = await var.read_value()
    assert val.My_Sub_Struct.My_UInt32 == 78


async def test_custom_struct_with_strange_chars(opc):
    idx = 4

    await new_struct(
        opc.opc,
        ua.StringNodeId('Toto"æ', 99),
        ua.QualifiedName("Siemens", 99),
        [
            new_struct_field('My"Bool', ua.VariantType.Boolean),
            new_struct_field("My'UInt32", ua.VariantType.UInt32, array=True),
            new_struct_field("List", ua.VariantType.UInt32, array=True),
        ],
    )

    await opc.opc.load_data_type_definitions()
    mystruct = ua.Siemens()
    mystruct.My_UInt32 = [78, 79]
    mystruct.My_Bool = False
    var = await opc.opc.nodes.objects.add_variable(
        idx, "my_siemens_struct", ua.Variant(mystruct, ua.VariantType.ExtensionObject)
    )
    val = await var.read_value()
    assert val.My_UInt32 == [78, 79]
