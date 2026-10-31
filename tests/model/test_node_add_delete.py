from base64 import b64encode
from typing import Any

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common import manage_nodes
from enginir_opcua.common.copy_node_util import copy_node
from enginir_opcua.common.node import Node

pytestmark = pytest.mark.asyncio


async def test_add_node_bad_args(opc):
    obj = opc.opc.nodes.objects

    with pytest.raises(TypeError):
        await obj.add_folder(1.2, "kk")

    with pytest.raises(TypeError):
        await obj.add_folder(ua.UaError, "khjh")

    with pytest.raises(ua.UaError):
        await obj.add_folder("kjk", 1.2)

    with pytest.raises(TypeError):
        await obj.add_folder("s='oooo'", 1.2)

    with pytest.raises(ua.UaError):
        await obj.add_folder("i=0;s='oooo'", "tt:oioi")


async def test_delete_nodes(opc):
    obj = opc.opc.nodes.objects
    fold = await obj.add_folder(2, "FolderToDelete")
    var = await fold.add_variable(2, "VarToDelete", 9.1)
    childs = await fold.get_children()
    assert var in childs
    await opc.opc.delete_nodes([var])
    with pytest.raises(ua.UaStatusCodeError):
        await var.write_value(7.8)
    with pytest.raises(ua.UaStatusCodeError):
        await obj.get_child(["2:FolderToDelete", "2:VarToDelete"])
    childs = await fold.get_children()
    assert var not in childs
    await opc.opc.delete_nodes([fold])


async def test_node_bytestring(opc):
    obj = opc.opc.nodes.objects
    var = await obj.add_variable(
        ua.ByteStringNodeId(b"VarByteString", 2),
        ua.QualifiedName("toto", 2),
        ua.UInt16(9),
    )
    node = opc.opc.get_node(f"ns=2;b={b64encode(b'VarByteString').decode()}")
    assert node == var


async def test_delete_nodes_with_inverse_references(opc):
    obj = opc.opc.nodes.objects
    fold = await obj.add_folder(2, "FolderToDelete")
    var = await fold.add_variable(2, "VarToDelete", 9.1)
    var2 = await fold.add_variable(2, "VarWithReference", 9.2)
    childs = await fold.get_children()
    assert var in childs
    assert var2 in childs
    # add two references to var, this includes adding the inverse references to var2
    await var.add_reference(
        var2.nodeid,
        reftype=ua.ObjectIds.HasDescription,
        forward=True,
        bidirectional=True,
    )
    await var.add_reference(var2.nodeid, reftype=ua.ObjectIds.HasEffect, forward=True, bidirectional=True)
    await opc.opc.delete_nodes([var])
    childs = await fold.get_children()
    assert var not in childs
    has_desc_refs = await var2.get_referenced_nodes(
        refs=ua.ObjectIds.HasDescription, direction=ua.BrowseDirection.Inverse
    )
    assert len(has_desc_refs) == 0
    has_effect_refs = await var2.get_referenced_nodes(refs=ua.ObjectIds.HasEffect, direction=ua.BrowseDirection.Inverse)
    assert len(has_effect_refs) == 0
    await opc.opc.delete_nodes([fold])


async def test_delete_nodes_removes_one_way_references(opc):
    fold = await opc.opc.nodes.objects.add_folder(2, "FolderOneWayRefs")
    target = await fold.add_variable(2, "OneWayTarget", 1.0)
    source = await fold.add_variable(2, "OneWaySource", 2.0)
    await source.add_reference(target.nodeid, reftype=ua.ObjectIds.HasEffect, forward=True, bidirectional=False)
    assert [target] == await source.get_referenced_nodes(refs=ua.ObjectIds.HasEffect)
    await opc.opc.delete_nodes([target])
    assert [] == await source.get_referenced_nodes(refs=ua.ObjectIds.HasEffect)
    await opc.opc.delete_nodes([fold], recursive=True)


async def test_delete_nodes_recursive(opc):
    obj = opc.opc.nodes.objects
    fold = await obj.add_folder(2, "FolderToDeleteR")
    var = await fold.add_variable(2, "VarToDeleteR", 9.1)
    await opc.opc.delete_nodes([fold, var])
    with pytest.raises(ua.UaStatusCodeError):
        await var.write_value(7.8)
    with pytest.raises(ua.UaStatusCodeError):
        await obj.get_child(["2:FolderToDelete", "2:VarToDelete"])


async def test_delete_nodes_recursive2(opc):
    obj = opc.opc.nodes.objects
    fold = await obj.add_object(2, "FolderToDeleteRoot")
    mynodes = []
    for i in range(7):
        nfold = await fold.add_object(2, f"FolderToDeleteRoot{i}")
        var = await nfold.add_variable(2, "VarToDeleteR", 9.1)
        var = await nfold.add_property(2, "ProToDeleteR", 9.1)
        prop = await nfold.add_property(2, "ProToDeleteR2", 9.1)
        o = await nfold.add_object(3, "ObjToDeleteR")
        mynodes.append(nfold)
        mynodes.append(var)
        mynodes.append(prop)
        mynodes.append(o)
    await opc.opc.delete_nodes([fold], recursive=True)
    for node in mynodes:
        with pytest.raises(ua.UaStatusCodeError):
            await node.read_browse_name()
    await opc.opc.delete_nodes([fold])


async def test_delete_references(opc):
    newtype = await opc.opc.get_node(ua.ObjectIds.HierarchicalReferences).add_reference_type(
        ua.NodeId(NamespaceIndex=2), "0:HasSuperSecretVariable", symmetric=False, inversename="IsSuperSecretVariableOf"
    )

    obj = opc.opc.nodes.objects
    fold = await obj.add_folder(2, "FolderToRef")
    var = await fold.add_variable(2, "VarToRef", 42)

    await fold.add_reference(var, newtype)

    assert [fold] == await var.get_referenced_nodes(newtype)
    assert [var] == await fold.get_referenced_nodes(newtype)

    await fold.delete_reference(var, newtype)

    assert [] == await var.get_referenced_nodes(newtype)
    assert [] == await fold.get_referenced_nodes(newtype)

    await fold.add_reference(var, newtype, bidirectional=False)

    assert [] == await var.get_referenced_nodes(newtype)
    assert [var] == await fold.get_referenced_nodes(newtype)

    await fold.delete_reference(var, newtype)

    assert [] == await var.get_referenced_nodes(newtype)
    assert [] == await fold.get_referenced_nodes(newtype)

    await var.add_reference(fold, newtype, forward=False, bidirectional=False)

    assert [fold] == await var.get_referenced_nodes(newtype)
    assert [] == await fold.get_referenced_nodes(newtype)

    with pytest.raises(ua.UaStatusCodeError):
        await fold.delete_reference(var, newtype)

    assert [fold] == await var.get_referenced_nodes(newtype)
    assert [] == await fold.get_referenced_nodes(newtype)

    with pytest.raises(ua.UaStatusCodeError):
        await var.delete_reference(fold, newtype)

    assert [fold] == await var.get_referenced_nodes(newtype)
    assert [] == await fold.get_referenced_nodes(newtype)

    await var.delete_reference(fold, newtype, forward=False)

    assert [] == await var.get_referenced_nodes(newtype)
    assert [] == await fold.get_referenced_nodes(newtype)

    # clean-up
    await opc.opc.delete_nodes([fold, newtype], recursive=True)


async def test_readded_reference_preserves_target_type_definition(opc):
    parent = await opc.opc.nodes.objects.add_folder(2, "TypeDefinitionParent")
    obj_type = await opc.opc.nodes.base_object_type.add_object_type(2, "ReferenceTargetType")
    obj = await parent.add_object(2, "ReferenceTarget", obj_type.nodeid)
    var = await parent.add_variable(2, "ReferenceVariable", 42)

    for target, reference_type, expected_type in (
        (obj, ua.ObjectIds.Organizes, obj_type.nodeid),
        (var, ua.ObjectIds.HasComponent, ua.NodeId(ua.ObjectIds.BaseDataVariableType)),
    ):
        await parent.delete_reference(target, reference_type)
        await parent.add_reference(target, reference_type)
        refs = await parent.get_references(
            refs=reference_type,
            direction=ua.BrowseDirection.Forward,
        )
        ref = next(ref for ref in refs if ref.NodeId == target.nodeid)
        assert ref.TypeDefinition == expected_type
        inverse_refs = await target.get_references(
            refs=reference_type,
            direction=ua.BrowseDirection.Inverse,
        )
        inverse_ref = next(ref for ref in inverse_refs if ref.NodeId == parent.nodeid)
        assert inverse_ref.TypeDefinition == ua.NodeId(ua.ObjectIds.FolderType)

    await opc.opc.delete_nodes([parent, obj_type], recursive=True)


async def test_reference_with_nodeid_reftype(opc):
    """Test that add_reference/get_referenced_nodes/delete_reference accept ua.NodeId as reftype.

    Regression test for https://github.com/FreeOpcUa/opcua-asyncio/issues/1896
    where the type annotation enforced int, but _to_nodeid() already supports
    Node, ua.NodeId, str, and int at runtime.
    """
    newtype = await opc.opc.get_node(ua.ObjectIds.HierarchicalReferences).add_reference_type(
        ua.NodeId(NamespaceIndex=2), "0:HasNodeIdRefType"
    )
    reftype_nodeid = newtype.nodeid  # ua.NodeId, not int

    obj = opc.opc.nodes.objects
    fold = await obj.add_folder(2, "FolderNodeIdRef")
    var = await fold.add_variable(2, "VarNodeIdRef", 42)

    # Use ua.NodeId as reftype (this is what issue #1896 requests)
    await fold.add_reference(var, reftype_nodeid)
    assert [var] == await fold.get_referenced_nodes(reftype_nodeid)
    assert [fold] == await var.get_referenced_nodes(reftype_nodeid)

    await fold.delete_reference(var, reftype_nodeid)
    assert [] == await fold.get_referenced_nodes(reftype_nodeid)

    # clean-up
    await opc.opc.delete_nodes([fold, newtype], recursive=True)


@pytest.mark.parametrize(
    ("nid", "browse_name"),
    [(ua.NodeId(9999, 3), "AddNodeVar1"), (ua.NodeId("AddNodeVar2Id", 3), "AddNodeVar2")],
    ids=["numeric", "string"],
)
async def test_add_node_with_a_nodeid(opc, nid, browse_name):
    objects = opc.opc.nodes.objects
    qn = ua.QualifiedName(browse_name, 3)
    v = await objects.add_variable(nid, qn, 0)
    assert nid == v.nodeid
    assert qn == await v.read_browse_name()
    await opc.opc.delete_nodes([v])


async def test_add_find_node_(opc):
    objects = opc.opc.nodes.objects
    o = await objects.add_object("ns=2;i=101;", "2:AddFindObject")
    o2 = await objects.get_child("2:AddFindObject")
    assert o == o2
    await opc.opc.delete_nodes([o, o2])


async def test_same_browse_name(opc):
    objects = opc.opc.nodes.objects
    f = await objects.add_folder("ns=2;i=201;", "2:MyBNameFolder")
    o = await f.add_object("ns=2;i=202;", "2:MyBName")
    v = await o.add_variable("ns=2;i=203;", "2:MyBNameTarget", 2.0)
    if opc.opc is not opc.server:
        with pytest.raises(ua.uaerrors.BadBrowseNameDuplicated):
            await f.add_object("ns=2;i=206;", "2:MyBName")
    attrs = ua.ObjectAttributes()
    attrs.DisplayName = ua.LocalizedText("MyBName")
    item = ua.AddNodesItem(
        ParentNodeId=f.nodeid,
        ReferenceTypeId=ua.NodeId(ua.ObjectIds.HasComponent),
        RequestedNewNodeId=ua.NodeId.from_string("ns=2;i=204;"),
        BrowseName=ua.QualifiedName("MyBName", 2),
        NodeClass=ua.NodeClass.Object,
        NodeAttributes=attrs,
        TypeDefinition=ua.NodeId(ua.ObjectIds.BaseObjectType),
    )
    (await f.session.add_nodes([item]))[0].StatusCode.check()
    o2 = opc.opc.get_node(item.RequestedNewNodeId)
    v2 = await o2.add_variable("ns=2;i=205;", "2:MyBNameTarget", 2.0)
    nodes = await objects.get_child("/2:MyBNameFolder/2:MyBName/2:MyBNameTarget", return_all=True)
    assert len(nodes) == 2
    assert nodes[0] == v
    assert nodes[1] == v2
    [nodes] = await objects.get_children_by_path(["/2:MyBNameFolder/2:MyBName/2:MyBNameTarget"])
    assert len(nodes) == 2
    assert nodes[0] == v
    assert nodes[1] == v2
    await opc.opc.delete_nodes([f, o, o2, v, v2])


async def test_use_namespace(opc):
    idx = await opc.opc.get_namespace_index("urn:enginir:opcua:server")
    assert 1 == idx
    root = opc.opc.nodes.root
    myvar = await root.add_variable(idx, "var_in_custom_namespace", [5])
    myid = myvar.nodeid
    assert idx == myid.NamespaceIndex
    await opc.opc.delete_nodes([myvar])


async def test_add_nodes(opc):
    objects = opc.opc.nodes.objects
    f = await objects.add_folder(3, "MyFolder")
    child = await objects.get_child("3:MyFolder")
    assert child == f
    o = await f.add_object(3, "MyObject")
    child = await f.get_child("3:MyObject")
    assert child == o
    v = await f.add_variable(3, "MyVariable", 6)
    child = await f.get_child("3:MyVariable")
    assert child == v
    p = await f.add_property(3, "MyProperty", 10)
    child = await f.get_child("3:MyProperty")
    assert child == p
    childs = await f.get_children()
    assert o in childs
    assert v in childs
    assert p in childs
    await opc.opc.delete_nodes([f, o, v, p, child])


async def test_add_node_with_type(opc):
    objects = opc.opc.nodes.objects
    f = await objects.add_folder(3, "MyFolder_TypeTest")

    o = await f.add_object(3, "MyObject1", ua.ObjectIds.BaseObjectType)
    assert ua.NodeId(ua.ObjectIds.BaseObjectType) == await o.read_type_definition()

    o = await f.add_object(3, "MyObject2", ua.NodeId(ua.ObjectIds.BaseObjectType, 0))
    assert ua.NodeId(ua.ObjectIds.BaseObjectType) == await o.read_type_definition()

    base_otype = opc.opc.get_node(ua.ObjectIds.BaseObjectType)
    custom_otype = await base_otype.add_object_type(2, "MyFooObjectType2")

    o = await f.add_object(3, "MyObject3", custom_otype.nodeid)
    assert custom_otype.nodeid == await o.read_type_definition()

    references = await o.get_references(refs=ua.ObjectIds.HasTypeDefinition, direction=ua.BrowseDirection.Forward)
    assert 1 == len(references)
    assert custom_otype.nodeid == references[0].NodeId
    await opc.opc.delete_nodes([f, o])


async def test_references_for_added_nodes(opc):
    objects = opc.opc.nodes.objects
    o = await objects.add_object(3, "MyObject4")
    nodes = await objects.get_referenced_nodes(
        refs=ua.ObjectIds.Organizes,
        direction=ua.BrowseDirection.Forward,
        includesubtypes=False,
    )
    assert o in nodes
    nodes = await o.get_referenced_nodes(
        refs=ua.ObjectIds.Organizes,
        direction=ua.BrowseDirection.Inverse,
        includesubtypes=False,
    )
    assert objects in nodes
    assert objects == await o.get_parent()
    assert ua.NodeId(ua.ObjectIds.BaseObjectType) == await o.read_type_definition()
    assert [] == await o.get_references(ua.ObjectIds.HasModellingRule)

    o2 = await o.add_object(3, "MySecondObject")
    nodes = await o.get_referenced_nodes(
        refs=ua.ObjectIds.HasComponent,
        direction=ua.BrowseDirection.Forward,
        includesubtypes=False,
    )
    assert o2 in nodes
    nodes = await o2.get_referenced_nodes(
        refs=ua.ObjectIds.HasComponent,
        direction=ua.BrowseDirection.Inverse,
        includesubtypes=False,
    )
    assert o in nodes
    assert o == await o2.get_parent()
    assert ua.NodeId(ua.ObjectIds.BaseObjectType) == await o2.read_type_definition()
    assert [] == await o2.get_references(ua.ObjectIds.HasModellingRule)

    v = await o.add_variable(3, "MyVariable", 6)
    nodes = await o.get_referenced_nodes(
        refs=ua.ObjectIds.HasComponent,
        direction=ua.BrowseDirection.Forward,
        includesubtypes=False,
    )
    assert v in nodes
    nodes = await v.get_referenced_nodes(
        refs=ua.ObjectIds.HasComponent,
        direction=ua.BrowseDirection.Inverse,
        includesubtypes=False,
    )
    assert o in nodes
    assert o == await v.get_parent()
    assert ua.NodeId(ua.ObjectIds.BaseDataVariableType) == await v.read_type_definition()
    assert [] == await v.get_references(ua.ObjectIds.HasModellingRule)

    p = await o.add_property(3, "MyProperty", 2)
    nodes = await o.get_referenced_nodes(
        refs=ua.ObjectIds.HasProperty,
        direction=ua.BrowseDirection.Forward,
        includesubtypes=False,
    )
    assert p in nodes
    nodes = await p.get_referenced_nodes(
        refs=ua.ObjectIds.HasProperty,
        direction=ua.BrowseDirection.Inverse,
        includesubtypes=False,
    )
    assert o in nodes
    assert o == await p.get_parent()
    assert ua.NodeId(ua.ObjectIds.PropertyType) == await p.read_type_definition()
    assert [] == await p.get_references(ua.ObjectIds.HasModellingRule)

    m = await objects.get_child("2:ServerMethod")
    assert [] == await m.get_references(ua.ObjectIds.HasModellingRule)


async def test_copy_node(opc):
    dev_t = await opc.opc.nodes.base_structure_type.add_object_type(ua.NodeId(NamespaceIndex=2), "0:MyDevice")
    _ = await dev_t.add_variable(ua.NodeId(NamespaceIndex=2), "0:sensor", 1.0)
    _ = await dev_t.add_property(ua.NodeId(NamespaceIndex=2), "0:sensor_id", "0340")
    ctrl_t = await dev_t.add_object(ua.NodeId(NamespaceIndex=2), "0:controller")
    prop_t = await ctrl_t.add_property(ua.NodeId(NamespaceIndex=2), "0:state", "Running")
    # Create device sutype
    devd_t = await dev_t.add_object_type(ua.NodeId(NamespaceIndex=2), "0:MyDeviceDerived")
    _ = await devd_t.add_variable(ua.NodeId(NamespaceIndex=2), "0:childparam", 1.0)
    _ = await devd_t.add_property(ua.NodeId(NamespaceIndex=2), "0:sensorx_id", "0340")
    nodes = await copy_node(opc.opc.nodes.objects, dev_t)
    mydevice = nodes[0]
    assert ua.NodeClass.ObjectType == await mydevice.read_node_class()
    assert 3 == len(await mydevice.get_children())
    _ = await mydevice.get_child(["0:controller"])
    prop = await mydevice.get_child(["0:controller", "0:state"])
    assert ua.NodeId(ua.ObjectIds.PropertyType) == await prop.read_type_definition()
    assert "Running" == await prop.read_value()
    assert prop.nodeid != prop_t.nodeid


async def test_duplicated_browsenames_same_ns_protperties(opc):
    parentfolder = await opc.opc.nodes.objects.add_folder(2, "parent_folder")
    _ = await parentfolder.add_property(2, "Myproperty", 123)
    try:
        _ = await parentfolder.add_property(2, "Myproperty", 456)
        await opc.opc.delete_nodes([parentfolder])
        pytest.fail("childproperty2 should never be created!")
    except Exception:
        await opc.opc.delete_nodes([parentfolder])
        return


@pytest.fixture(scope="module")
async def srv() -> Any:
    server = Server()
    await server.init()
    await server.register_namespace("urn:test:manage")
    yield server


def new_id(name: str) -> ua.NodeId:
    return ua.NodeId(name, 2)


async def value_of(node: Node, attribute: ua.AttributeIds) -> Any:
    variant = (await node.read_attribute(attribute)).Value
    assert variant is not None
    return variant.Value


async def exists(node: Node) -> bool:
    try:
        await node.read_browse_name()
    except ua.UaStatusCodeError:
        return False
    return True


async def test_com20_scalar_defaults(srv: Server) -> None:
    """Part 3, 5.6.2: a scalar has ValueRank -1 and no ArrayDimensions."""
    node = await srv.nodes.objects.add_variable(new_id("s"), "2:s", 5)
    assert await node.read_value_rank() == ua.ValueRank.Scalar
    assert (await value_of(node, ua.AttributeIds.ArrayDimensions)) is None
    assert (await node.read_description()).Text is None
    assert (await node.read_display_name()).Text == "s"
    assert await node.get_access_level() == {ua.AccessLevel.CurrentRead}


async def test_com20_one_dimensional_list_has_value_rank_one(srv: Server) -> None:
    node = await srv.nodes.objects.add_variable(new_id("a"), "2:a", [1, 2, 3])
    assert await node.read_value_rank() == ua.ValueRank.OneDimension


async def test_com20_array_dimensions_are_unknown_maximums(srv: Server) -> None:
    """Part 3, 5.6.2: the maximum length per dimension, 0 when unknown; the present shape is not a maximum."""
    one = await srv.nodes.objects.add_variable(new_id("a1"), "2:a1", [1, 2, 3])
    two = await srv.nodes.objects.add_variable(new_id("a2"), "2:a2", [[1, 2], [3, 4]])
    assert await one.read_array_dimensions() == [0]
    assert await two.read_value_rank() == ua.ValueRank.TwoDimensions
    assert await two.read_array_dimensions() == [0, 0]
    await two.write_value([[1, 2, 3], [4, 5, 6], [7, 8, 9]])


async def test_com20_falsy_initial_value_of_variable_type_is_kept(srv: Server) -> None:
    parent = srv.get_node(ua.ObjectIds.BaseDataVariableType)
    node = await parent.add_variable_type(new_id("vt0"), "2:vt0", ua.NodeId(ua.ObjectIds.Int32), value=0)
    assert (await node.read_value()) == 0


async def test_com98_scalar_variable_type_has_scalar_value_rank(srv: Server) -> None:
    node = await srv.nodes.base_variable_type.add_variable_type(new_id("vt"), "2:vt", ua.NodeId(ua.ObjectIds.Int32))
    assert await node.read_value_rank() == ua.ValueRank.Scalar


async def test_types_can_be_created_abstract(srv: Server) -> None:
    object_type = await srv.nodes.base_object_type.add_object_type(new_id("ot"), "2:ot", is_abstract=True)
    variable_type = await srv.nodes.base_variable_type.add_variable_type(
        new_id("vt2"), "2:vt2", ua.NodeId(ua.ObjectIds.Int32), is_abstract=True
    )
    data_type = await srv.nodes.base_structure_type.add_data_type(new_id("dt"), "2:dt", is_abstract=True)
    for node in (object_type, variable_type, data_type):
        assert (await value_of(node, ua.AttributeIds.IsAbstract)) is True
    concrete = await srv.nodes.base_object_type.add_object_type(new_id("ot2"), "2:ot2")
    assert (await value_of(concrete, ua.AttributeIds.IsAbstract)) is False


async def test_com21_non_symmetric_reference_type_needs_inverse_name(srv: Server) -> None:
    parent = srv.get_node(ua.ObjectIds.NonHierarchicalReferences)
    with pytest.raises(ValueError):
        await parent.add_reference_type(new_id("r1"), "2:r1", symmetric=False)
    with pytest.raises(ValueError):
        await parent.add_reference_type(new_id("r2"), "2:r2", symmetric=True, inversename="Back")
    node = await parent.add_reference_type(new_id("r3"), "2:r3", symmetric=False, inversename="Back")
    assert (await value_of(node, ua.AttributeIds.InverseName)).Text == "Back"
    symmetric = await parent.add_reference_type(new_id("r4"), "2:r4")
    assert (await value_of(symmetric, ua.AttributeIds.InverseName)).Text is None


async def test_com19_create_data_type_adds_one_reference(srv: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    session = srv.iserver.isession
    calls: list[Any] = []
    original = session.add_references

    async def spy(items: Any) -> Any:
        calls.append(items)
        return await original(items)

    monkeypatch.setattr(session, "add_references", spy)
    node = await srv.nodes.base_structure_type.add_data_type(new_id("dt1"), "2:dt1")
    assert calls == []
    parents = await node.get_referenced_nodes(ua.ObjectIds.HasSubtype, ua.BrowseDirection.Inverse)
    assert parents == [srv.nodes.base_structure_type]


async def test_com96_encoding_has_data_type_encoding_type(srv: Server) -> None:
    data_type = await srv.nodes.base_structure_type.add_data_type(new_id("dt2"), "2:dt2")
    encoding = await manage_nodes.create_encoding(data_type, new_id("enc"), ua.QualifiedName("Default Binary", 0))
    assert await encoding.read_type_definition() == ua.NodeId(ua.ObjectIds.DataTypeEncodingType)
    assert await data_type.get_encoding_refs() == [encoding]
    with pytest.raises(ua.UaError):
        await manage_nodes.create_encoding(data_type, new_id("enc2"), ua.QualifiedName("Default Binary", 2))


async def test_com21_arguments_have_names_and_array_arguments_are_arrays(srv: Server) -> None:
    def callback(parent: ua.NodeId, *arguments: ua.Variant) -> list[ua.Variant]:
        return []

    method = await srv.nodes.objects.add_method(
        new_id("m"), "2:m", callback, [ua.VariantType.Int32, [ua.VariantType.Double]], [ua.VariantType.String]
    )
    inputs = await (await method.get_child("0:InputArguments")).read_value()
    assert [a.Name for a in inputs] == ["Input0", "Input1"]
    assert inputs[0].ValueRank == ua.ValueRank.Scalar and not inputs[0].ArrayDimensions
    assert inputs[1].ValueRank == ua.ValueRank.OneDimension and inputs[1].ArrayDimensions == [0]
    outputs = await (await method.get_child("0:OutputArguments")).read_value()
    assert [a.Name for a in outputs] == ["Output0"]


async def test_create_method_with_callback_on_session_without_callbacks_raises() -> None:
    class Session:
        async def add_nodes(self, items: Any) -> Any:
            raise AssertionError("nothing may be sent")

    parent = Node(Session(), ua.NodeId(85))  # type: ignore[arg-type]
    with pytest.raises(ua.UaError):
        await parent.add_method(new_id("m2"), "2:m2", lambda parent: None)


async def test_failed_argument_properties_remove_the_method(srv: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    async def failing(*args: Any, **kwargs: Any) -> Any:
        raise ua.UaError("no")

    monkeypatch.setattr(manage_nodes, "create_property", failing)
    with pytest.raises(ua.UaError):
        await srv.nodes.objects.add_method(new_id("m3"), "2:m3", lambda parent, *a: [], [ua.VariantType.Int32])
    assert not await exists(srv.get_node(new_id("m3")))


async def test_com101_delete_nodes_accepts_a_generator(srv: Server) -> None:
    folder = await srv.nodes.objects.add_folder(new_id("g"), "2:g")
    nodes, results = await manage_nodes.delete_nodes(srv.iserver.isession, (n for n in [folder]))
    assert nodes == [folder]
    assert [r.is_good() for r in results] == [True]


async def test_com18_recursive_delete_keeps_organized_nodes(srv: Server) -> None:
    other = await srv.nodes.objects.add_folder(new_id("other"), "2:other")
    mine = await srv.nodes.objects.add_object(new_id("mine"), "2:mine")
    await mine.add_reference(other, ua.ObjectIds.Organizes, True, True)
    own = await mine.add_object(new_id("own"), "2:own")
    await mine.delete(recursive=True)
    assert await exists(other)
    assert not await exists(own)
    assert not await exists(mine)


async def test_com18_recursive_delete_survives_a_cycle(srv: Server) -> None:
    top = await srv.nodes.objects.add_object(new_id("top"), "2:top")
    below = await top.add_object(new_id("below"), "2:below")
    await below.add_reference(top, ua.ObjectIds.HasNotifier, True, True)
    nodes = await top.delete(recursive=True)
    assert sorted(n.nodeid.to_string() for n in nodes) == sorted([top.nodeid.to_string(), below.nodeid.to_string()])
    assert not await exists(top) and not await exists(below)


async def test_com18_node_with_another_aggregating_parent_is_kept(srv: Server) -> None:
    first = await srv.nodes.objects.add_object(new_id("first"), "2:first")
    second = await srv.nodes.objects.add_object(new_id("second"), "2:second")
    shared = await first.add_object(new_id("shared"), "2:shared")
    inside = await shared.add_variable(new_id("inside"), "2:inside", 1)
    await second.add_reference(shared, ua.ObjectIds.HasComponent, True, True)
    await first.delete(recursive=True)
    assert not await exists(first)
    assert await exists(shared) and await exists(inside)


async def test_com18_children_are_deleted_before_their_parent(srv: Server) -> None:
    parent = await srv.nodes.objects.add_object(new_id("p"), "2:p")
    child = await parent.add_variable(new_id("c"), "2:c", 1)
    nodes, results = await manage_nodes.delete_nodes(srv.iserver.isession, [parent], recursive=True)
    assert nodes == [child, parent]
    assert all(r.is_good() for r in results)
