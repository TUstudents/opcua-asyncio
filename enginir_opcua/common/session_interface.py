from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from enginir_opcua import ua
from enginir_opcua.observer import NULL_OBSERVER, Observer


class AbstractSession(ABC):
    """
    An abstract interface for the sessionbased Service Sets like:
    NodeManagement, View, Attribute, Method, MonitoredItem and Subscription
    """

    @property
    def observer(self) -> Observer:
        """The observer that sees the requests of the session; by default one that ignores them."""
        return NULL_OBSERVER

    @abstractmethod
    async def browse(self, parameters: ua.BrowseParameters) -> list[ua.BrowseResult]:
        """
        OPC 10000-4 v1.05, 5.9.2.
        Browse: discover the References of a Node, optionally through a View and with a filter.
        """

    @abstractmethod
    async def browse_next(self, parameters: ua.BrowseNextParameters) -> list[ua.BrowseResult]:
        """
        OPC 10000-4 v1.05, 5.9.3.
        BrowseNext: continue a Browse or BrowseNext whose result did not fit one response, on the same Session.
        """

    @abstractmethod
    async def translate_browsepaths_to_nodeids(self, browse_paths: list[ua.BrowsePath]) -> list[ua.BrowsePathResult]:
        """
        OPC 10000-4 v1.05, 5.9.4.
        TranslateBrowsePathsToNodeIds: turn browse paths (a starting Node and a RelativePath) into NodeIds.
        """

    @abstractmethod
    async def register_nodes(self, nodes: list[ua.NodeId]) -> list[ua.NodeId]:
        """
        OPC 10000-4 v1.05, 5.9.5.
        RegisterNodes: tell the Server which Nodes will be accessed repeatedly, so that it can prepare for it.
        """

    @abstractmethod
    async def unregister_nodes(self, nodes: list[ua.NodeId]) -> None:
        """
        OPC 10000-4 v1.05, 5.9.6.
        UnregisterNodes: release NodeIds obtained with RegisterNodes.
        """

    @abstractmethod
    async def read(self, parameters: ua.ReadParameters) -> list[ua.DataValue]:
        """
        OPC 10000-4 v1.05, 5.11.2.
        Read: read Attributes of Nodes, whole values or ranges of an indexed value.
        """

    @abstractmethod
    async def write(self, parameters: ua.WriteParameters) -> list[ua.StatusCode]:
        """
        OPC 10000-4 v1.05, 5.11.4.
        Write: write Attributes of Nodes, whole values or ranges of an indexed value.
        """

    @abstractmethod
    async def history_read(self, params: ua.HistoryReadParameters) -> list[ua.HistoryReadResult]:
        """
        OPC 10000-4 v1.05, 5.11.3.
        HistoryRead: read the historical values or Events of Nodes.
        """

    @abstractmethod
    async def history_update(self, params: ua.HistoryUpdateParameters) -> list[ua.HistoryUpdateResult]:
        """
        OPC 10000-4 v1.05, 5.11.5.
        HistoryUpdate: update the historical values or Events of Nodes.
        """

    @abstractmethod
    async def add_nodes(self, nodestoadd: list[ua.AddNodesItem]) -> list[ua.AddNodesResult]:
        """
        OPC 10000-4 v1.05, 5.8.2.
        AddNodes: add Nodes to the AddressSpace, each below a parent through a hierarchical Reference.
        """

    @abstractmethod
    async def add_references(self, refs: list[ua.AddReferencesItem]) -> list[ua.StatusCode]:
        """
        OPC 10000-4 v1.05, 5.8.3.
        AddReferences: add References to Nodes.
        """

    @abstractmethod
    async def delete_nodes(self, params: ua.DeleteNodesParameters) -> list[ua.StatusCode]:
        """
        OPC 10000-4 v1.05, 5.8.4.
        DeleteNodes: delete Nodes from the AddressSpace.
        """

    @abstractmethod
    async def delete_references(self, refs: list[ua.DeleteReferencesItem]) -> list[ua.StatusCode]:
        """
        OPC 10000-4 v1.05, 5.8.5.
        DeleteReferences: delete References of Nodes.
        """

    @abstractmethod
    async def call(self, methodstocall: list[ua.CallMethodRequest]) -> list[ua.CallMethodResult]:
        """
        OPC 10000-4 v1.05, 5.12.2.
        Call: invoke Methods.
        """

    @abstractmethod
    async def create_subscription(
        self,
        params: ua.CreateSubscriptionParameters,
        callback: Callable[..., Any],
    ) -> ua.CreateSubscriptionResult:
        """
        OPC 10000-4 v1.05, 5.14.2.
        CreateSubscription: create a Subscription and register `callback` for its PublishResults. Server-side
        implementations may accept more optional parameters.
        """

    @abstractmethod
    async def delete_subscriptions(self, subscription_ids: list[int]) -> list[ua.StatusCode]:
        """
        OPC 10000-4 v1.05, 5.14.8.
        DeleteSubscriptions: delete Subscriptions by SubscriptionId.
        """

    @abstractmethod
    async def create_monitored_items(
        self, params: ua.CreateMonitoredItemsParameters
    ) -> list[ua.MonitoredItemCreateResult]:
        """
        OPC 10000-4 v1.05, 5.13.2.
        CreateMonitoredItems: add MonitoredItems to a Subscription.
        """

    @abstractmethod
    async def modify_monitored_items(
        self, params: ua.ModifyMonitoredItemsParameters
    ) -> list[ua.MonitoredItemModifyResult]:
        """
        OPC 10000-4 v1.05, 5.13.3.
        ModifyMonitoredItems: change the settings of MonitoredItems of a Subscription.
        """

    @abstractmethod
    async def delete_monitored_items(self, params: ua.DeleteMonitoredItemsParameters) -> list[ua.StatusCode]:
        """
        OPC 10000-4 v1.05, 5.13.6.
        DeleteMonitoredItems: remove MonitoredItems from a Subscription.
        """

    @abstractmethod
    async def transfer_subscriptions(self, params: ua.TransferSubscriptionsParameters) -> list[ua.TransferResult]:
        """
        OPC 10000-4 v1.05, 5.14.7.
        TransferSubscriptions: move Subscriptions and their MonitoredItems to this Session.
        """
