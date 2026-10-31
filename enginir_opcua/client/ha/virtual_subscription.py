"""
The subscriptions of the HaClient as configuration: what each server should have, compared by the Reconciliator.
"""

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sortedcontainers import SortedDict  # type: ignore

from enginir_opcua import ua

TypeSubHandler = Any


@dataclass(frozen=True)
class NodeAttr:
    """How one node is monitored: the attribute and the queue size."""

    attr: ua.AttributeIds | None = None
    queuesize: int = 0


@dataclass
class VirtualSubscription:
    """One Subscription as it should be on one server; nodes maps NodeId texts to their NodeAttr, sorted."""

    period: int
    handler: TypeSubHandler
    publishing: bool
    monitoring: ua.MonitoringMode
    nodes: SortedDict = field(default_factory=SortedDict)

    def subscribe_data_change(self, nodes: Iterable[str], attr: ua.AttributeIds, queuesize: int) -> None:
        """Monitor the nodes with this attribute and queue size."""
        for node in nodes:
            self.nodes[node] = NodeAttr(attr, queuesize)

    def unsubscribe(self, nodes: Iterable[str]) -> None:
        """Stop monitoring the nodes; unknown ones are ignored."""
        for node in nodes:
            self.nodes.pop(node, None)

    def set_monitoring_mode(self, mode: ua.MonitoringMode) -> None:
        """Set the monitoring mode of all its MonitoredItems."""
        self.monitoring = mode

    def set_publishing_mode(self, mode: bool) -> None:
        """Set whether the Subscription publishes."""
        self.publishing = mode

    def get_nodes(self) -> set[str]:
        """The NodeId texts it monitors."""
        return set(self.nodes)
