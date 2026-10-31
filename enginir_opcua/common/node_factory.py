from __future__ import annotations

import enginir_opcua
from enginir_opcua import ua
from enginir_opcua.common.session_interface import AbstractSession


def make_node(session: AbstractSession, nodeid: ua.NodeId) -> enginir_opcua.Node:
    """A Node, for modules that node.py imports and that therefore cannot import it at load time."""
    from .node import Node

    return Node(session, nodeid)
