"""Pure validation for non-provisioning disposable-range topology declarations."""

from __future__ import annotations

from nimrod_simulator.errors import RangeTopologyError
from nimrod_simulator.jsonio import require_boolean, require_integer, require_list, require_object, require_string, sha256_digest
from nimrod_simulator.model import JsonObject


EXPECTED_ZONE_ROLES = {"target", "telemetry", "control"}
EXPECTED_NODE_ROLES = {"sacrificial_target", "telemetry_collector", "kill_switch"}
EXPECTED_ROUTE_SHAPES = {
    ("target", "telemetry", "telemetry_export"),
    ("control", "target", "out_of_band_kill"),
}
REQUIRED_CONTROLS = {
    "default_deny_egress": True,
    "internet_egress_permitted": False,
    "target_to_control_plane_permitted": False,
    "telemetry_write_only": True,
    "out_of_band_kill_independent": True,
    "credential_reuse_permitted": False,
}


def _unique(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise RangeTopologyError(f"Range topology repeats {label}.")


def validate_range_topology(topology: JsonObject) -> JsonObject:
    if topology.get("topology_version") != "0.1.0" or topology.get("origin") != "simulated":
        raise RangeTopologyError("Range topology must be version 0.1.0 and simulated.")
    if topology.get("environment_class") != "isolated_range":
        raise RangeTopologyError("Range topology environment must be isolated_range.")
    generation = require_integer(topology.get("generation"), "topology.generation")
    if generation <= 0:
        raise RangeTopologyError("Range topology generation must be positive.")
    authority = require_object(topology.get("authority"), "topology.authority")
    if authority != {"can_provision": False, "can_connect": False, "can_execute": False}:
        raise RangeTopologyError("Range topology cannot provision, connect, or execute.")
    controls = require_object(topology.get("controls"), "topology.controls")
    if set(controls) != set(REQUIRED_CONTROLS):
        raise RangeTopologyError("Range topology controls must use the exact constitutional control set.")
    for field, expected in REQUIRED_CONTROLS.items():
        if require_boolean(controls.get(field), f"topology.controls.{field}") is not expected:
            raise RangeTopologyError(f"Range topology control '{field}' violates the required value.")

    zone_values = require_list(topology.get("zones"), "topology.zones")
    zones: list[JsonObject] = [require_object(value, f"topology.zones[{index}]") for index, value in enumerate(zone_values)]
    zone_ids = [require_string(zone.get("zone_id"), "zone.zone_id") for zone in zones]
    _unique(zone_ids, "zone ID")
    zone_roles = [require_string(zone.get("role"), "zone.role") for zone in zones]
    if len(zones) != 3 or set(zone_roles) != EXPECTED_ZONE_ROLES or len(set(zone_roles)) != 3:
        raise RangeTopologyError("Range topology requires exactly one target, telemetry, and control zone.")
    for zone in zones:
        if require_boolean(zone.get("internet_access"), "zone.internet_access"):
            raise RangeTopologyError("Range topology zones cannot declare internet access.")
    role_by_zone = dict(zip(zone_ids, zone_roles, strict=True))

    node_values = require_list(topology.get("nodes"), "topology.nodes")
    nodes: list[JsonObject] = [require_object(value, f"topology.nodes[{index}]") for index, value in enumerate(node_values)]
    node_ids = [require_string(node.get("node_id"), "node.node_id") for node in nodes]
    _unique(node_ids, "node ID")
    node_roles = [require_string(node.get("role"), "node.role") for node in nodes]
    if len(nodes) != 3 or set(node_roles) != EXPECTED_NODE_ROLES or len(set(node_roles)) != 3:
        raise RangeTopologyError(
            "Range topology requires exactly one sacrificial target, telemetry collector, and kill switch."
        )
    credential_scopes: list[str] = []
    expected_zone_by_node_role = {
        "sacrificial_target": "target",
        "telemetry_collector": "telemetry",
        "kill_switch": "control",
    }
    for node in nodes:
        node_role = require_string(node.get("role"), "node.role")
        zone_id = require_string(node.get("zone_id"), "node.zone_id")
        if role_by_zone.get(zone_id) != expected_zone_by_node_role[node_role]:
            raise RangeTopologyError(f"Range topology node role '{node_role}' is assigned to the wrong zone.")
        if not require_boolean(node.get("disposable"), "node.disposable"):
            raise RangeTopologyError(f"Range topology node '{node.get('node_id')}' must be disposable.")
        if not require_boolean(node.get("dedicated_credentials"), "node.dedicated_credentials"):
            raise RangeTopologyError(f"Range topology node '{node.get('node_id')}' lacks dedicated credentials.")
        credential_scopes.append(require_string(node.get("credential_scope"), "node.credential_scope"))
    _unique(credential_scopes, "credential scope")

    route_values = require_list(topology.get("routes"), "topology.routes")
    routes: list[JsonObject] = [require_object(value, f"topology.routes[{index}]") for index, value in enumerate(route_values)]
    route_ids = [require_string(route.get("route_id"), "route.route_id") for route in routes]
    _unique(route_ids, "route ID")
    route_shapes: set[tuple[str, str, str]] = set()
    for route in routes:
        source_zone = require_string(route.get("source_zone_id"), "route.source_zone_id")
        destination_zone = require_string(route.get("destination_zone_id"), "route.destination_zone_id")
        if source_zone not in role_by_zone or destination_zone not in role_by_zone:
            raise RangeTopologyError("Range topology route references an unknown zone.")
        if route.get("direction") != "one_way":
            raise RangeTopologyError("Range topology routes must be one-way.")
        purpose = require_string(route.get("purpose"), "route.purpose")
        route_shapes.add((role_by_zone[source_zone], role_by_zone[destination_zone], purpose))
    if len(routes) != 2 or route_shapes != EXPECTED_ROUTE_SHAPES:
        raise RangeTopologyError(
            "Range topology permits only target-to-telemetry export and control-to-target kill routes."
        )

    return {
        "verdict_version": "0.1.0",
        "origin": "simulated",
        "topology_id": topology["topology_id"],
        "topology_digest": sha256_digest(topology),
        "generation": generation,
        "status": "declared_contract_valid_environment_unproven",
        "zone_count": len(zones),
        "node_count": len(nodes),
        "route_count": len(routes),
        "default_deny_declared": True,
        "internet_egress_declared": False,
        "out_of_band_kill_declared": True,
        "environment_verified": False,
        "provisioning_performed": False,
        "network_contact_performed": False,
        "authority": {"can_provision": False, "can_connect": False, "can_execute": False},
    }
