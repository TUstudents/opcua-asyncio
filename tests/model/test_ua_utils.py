import math
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common import ua_utils


@pytest.fixture(scope="module")
async def server() -> Any:
    srv = Server()
    await srv.init()
    yield srv


ROUND_TRIPS = [
    (ua.VariantType.Boolean, True),
    (ua.VariantType.Boolean, False),
    (ua.VariantType.SByte, -5),
    (ua.VariantType.Byte, 200),
    (ua.VariantType.Int16, -300),
    (ua.VariantType.UInt16, 60000),
    (ua.VariantType.Int32, -70000),
    (ua.VariantType.UInt32, 4000000000),
    (ua.VariantType.Int64, -(2**40)),
    (ua.VariantType.UInt64, 2**63),
    (ua.VariantType.Float, 1.5),
    (ua.VariantType.Double, -2.25e100),
    (ua.VariantType.String, "plain"),
    (ua.VariantType.String, ""),
    (ua.VariantType.String, "[bracketed]"),
    (ua.VariantType.String, 'say "hi", please'),
    (ua.VariantType.DateTime, datetime(2024, 5, 6, 7, 8, 9, 123456, tzinfo=UTC)),
    (ua.VariantType.Guid, uuid.UUID("12345678-1234-5678-1234-567812345678")),
    (ua.VariantType.ByteString, b"abc"),
    (ua.VariantType.NodeId, ua.NodeId(5, 2)),
    (ua.VariantType.NodeId, ua.NodeId("Name", 3)),
    (ua.VariantType.QualifiedName, ua.QualifiedName("Name", 2)),
    (ua.VariantType.LocalizedText, ua.LocalizedText("Text", "en")),
    (ua.VariantType.StatusCode, ua.StatusCode(ua.StatusCodes.BadNodeIdUnknown)),
    (ua.VariantType.XmlElement, ua.XmlElement("<a/>")),
]


@pytest.mark.parametrize(("vtype", "value"), ROUND_TRIPS)
def test_com9_string_round_trip_for_every_builtin_type(vtype: ua.VariantType, value: Any) -> None:
    assert ua_utils.string_to_val(ua_utils.val_to_string(value), vtype) == value
    assert ua_utils.string_to_val(ua_utils.val_to_string([value, value]), vtype) == [value, value]


def test_com9_float_nan_round_trip() -> None:
    assert math.isnan(ua_utils.string_to_val(ua_utils.val_to_string(float("nan")), ua.VariantType.Double))


def test_com9_enum_name_round_trip() -> None:
    text = ua_utils.val_to_string(ua.NodeClass.Object)
    assert ua_utils.string_to_val(text, ua.NodeClass) == ua.NodeClass.Object
    assert ua_utils.string_to_val("Object_1", ua.NodeClass) == ua.NodeClass.Object
    assert ua_utils.string_to_val("1", ua.NodeClass) == ua.NodeClass.Object
    with pytest.raises(ValueError):
        ua_utils.string_to_val("Nonsense", ua.NodeClass)


def test_com9_string_list_with_commas() -> None:
    value = ["a,b", "c", "d]"]
    assert ua_utils.string_to_val(ua_utils.val_to_string(value), ua.VariantType.String) == value


def test_com100_empty_list_round_trip() -> None:
    assert ua_utils.string_to_val(ua_utils.val_to_string([]), ua.VariantType.Int32) == []
    assert ua_utils.string_to_val(ua_utils.val_to_string([]), ua.VariantType.String) == []
    assert ua_utils.string_to_val(ua_utils.val_to_string([""]), ua.VariantType.String) == [""]


def test_com100_nested_list_round_trip() -> None:
    value = [[1, 2], [3, 4]]
    assert ua_utils.string_to_val(ua_utils.val_to_string(value), ua.VariantType.Int32) == value


@pytest.mark.parametrize("text", ["TRUE", "True", "true", "1"])
def test_com10_boolean_true_forms(text: str) -> None:
    assert ua_utils.string_to_val(text, ua.VariantType.Boolean) is True


@pytest.mark.parametrize("text", ["yes", "on", "", "2", "tru"])
def test_com10_invalid_boolean_raises(text: str) -> None:
    with pytest.raises(ValueError):
        ua_utils.string_to_val(text, ua.VariantType.Boolean)


@pytest.mark.parametrize(
    ("vtype", "text"),
    [
        (ua.VariantType.Byte, "300"),
        (ua.VariantType.Byte, "-1"),
        (ua.VariantType.SByte, "128"),
        (ua.VariantType.Int32, "2147483648"),
        (ua.VariantType.UInt64, "-1"),
        (ua.VariantType.Int32, "abc"),
        (ua.VariantType.Int32, ""),
        (ua.VariantType.Guid, ""),
        (ua.VariantType.DateTime, ""),
    ],
)
def test_com10_invalid_numbers_raise(vtype: ua.VariantType, text: str) -> None:
    with pytest.raises(ValueError):
        ua_utils.string_to_val(text, vtype)


@pytest.mark.parametrize(
    "vtype",
    [ua.VariantType.ExtensionObject, ua.VariantType.DataValue, ua.VariantType.Variant, ua.VariantType.DiagnosticInfo],
)
def test_com9_unsupported_type_raises_not_implemented(vtype: ua.VariantType) -> None:
    with pytest.raises(NotImplementedError):
        ua_utils.string_to_val("x", vtype)


async def test_com11_supertype_order_and_skipbase(server: Server) -> None:
    fsm = server.get_node(ua.NodeId(ua.ObjectIds.FiniteStateMachineType))
    chain = await ua_utils.get_node_supertypes(fsm, includeitself=True, skipbase=False)
    assert [n.nodeid.Identifier for n in chain] == [
        ua.ObjectIds.FiniteStateMachineType,
        ua.ObjectIds.StateMachineType,
        ua.ObjectIds.BaseObjectType,
    ]
    trimmed = await ua_utils.get_node_supertypes(fsm, includeitself=True)
    assert [n.nodeid.Identifier for n in trimmed] == [
        ua.ObjectIds.FiniteStateMachineType,
        ua.ObjectIds.StateMachineType,
    ]


async def test_supertypes_stop_at_a_cycle(server: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    first, second = server.get_node(ua.NodeId(1, 9)), server.get_node(ua.NodeId(2, 9))
    loop = {first.nodeid: second, second.nodeid: first}

    async def supertype(node: Any) -> Any:
        return loop[node.nodeid]

    monkeypatch.setattr(ua_utils, "get_node_supertype", supertype)
    chain = await ua_utils.get_node_supertypes(first, includeitself=True, skipbase=False)
    assert [n.nodeid for n in chain] == [first.nodeid, second.nodeid]


async def test_com107_get_node_children_stops_at_cycle(server: Server) -> None:
    idx = await server.register_namespace("urn:test:cycle")
    top = await server.nodes.objects.add_folder(idx, "Top")
    below = await top.add_folder(idx, "Below")
    await below.add_reference(top, ua.ObjectIds.HasNotifier, True, True)
    nodes = await ua_utils.get_node_children(top)
    assert [n.nodeid for n in nodes] == [top.nodeid, below.nodeid]


async def test_com108_namespace_zero_can_be_requested(server: Server) -> None:
    nodes = await ua_utils.get_nodes_of_namespace(server, [0])
    assert server.get_node(ua.NodeId(ua.ObjectIds.RootFolder)) in nodes


async def test_com11_unknown_namespace_uri_raises_ua_error(server: Server) -> None:
    with pytest.raises(ua.UaError):
        await ua_utils.get_nodes_of_namespace(server, ["urn:not:there"])
