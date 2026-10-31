"""
The high-availability client: one logical client over a set of redundant servers (non-transparent redundancy,
OPC 10000-4 v1.05, 6.6.2.4), with the Warm failover mode.
"""

from .ha_client import ConnectionStates, HaClient, HaConfig, HaMode, HaSecurityConfig
