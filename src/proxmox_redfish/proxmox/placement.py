"""Finding the node a guest lives on.

Redfish addresses a system by its VM id, and Proxmox ids are unique across
a cluster, so an id identifies one guest wherever it runs. The node it runs
on is a property of the guest that Proxmox reports, not something an
operator should have to configure -- and configuring it cannot survive a
migration, which moves a guest without changing its id.

Placement therefore comes from /cluster/resources, which is available on a
standalone installation as well as a cluster, so one path serves both.
"""

import weakref
from typing import Any, Dict, List, MutableMapping

from proxmoxer import ProxmoxAPI

from ..config.logging_config import logger
from ..config.settings import PROXMOX_NODE
from ..utils.error_handling import VMNotFound

__all__ = ["VMNotFound", "list_vm_ids", "node_for", "vm"]

# Resolved placements are cached against the connection that fetched them. A
# connection is built for one request and discarded afterwards, so this is a
# per-request cache: it spares repeated lookups within a request without
# letting a migration go unnoticed between them. The cache holds weak
# references, so entries disappear with the connection rather than being
# stored on it.
_PLACEMENTS: MutableMapping[Any, Dict[int, str]] = weakref.WeakKeyDictionary()


def _guests(proxmox: ProxmoxAPI) -> List[Dict[str, Any]]:
    """Every qemu guest the caller may see, with the node it runs on.

    `type="vm"` also returns LXC containers. They share the id namespace with
    virtual machines but are not addressable through the qemu endpoints this
    daemon uses, so publishing them as systems would produce ids that fail on
    every subsequent call.
    """
    resources = proxmox.cluster.resources.get(type="vm")
    if not isinstance(resources, list):
        raise TypeError("Unexpected response listing cluster resources")

    guests = [r for r in resources if r.get("type") == "qemu"]

    # PROXMOX_NODE, when set, narrows the daemon to a single node. That keeps
    # an existing single-node deployment behaving exactly as it did, and lets
    # an operator deliberately limit scope on a cluster.
    if PROXMOX_NODE:
        guests = [g for g in guests if g.get("node") == PROXMOX_NODE]

    return guests


def _placements(proxmox: ProxmoxAPI) -> Dict[int, str]:
    try:
        cached = _PLACEMENTS[proxmox]
    except (KeyError, TypeError):
        cached = {int(g["vmid"]): str(g["node"]) for g in _guests(proxmox) if g.get("node")}
        try:
            _PLACEMENTS[proxmox] = cached
        except TypeError:  # pragma: no cover - object cannot be weakly referenced
            pass
    return cached


def node_for(proxmox: ProxmoxAPI, vm_id: Any) -> str:
    """Return the node a guest runs on."""
    placements = _placements(proxmox)
    try:
        key = int(vm_id)
    except (TypeError, ValueError):
        raise VMNotFound(f"{vm_id} is not a VM id")

    node = placements.get(key)
    if node is None:
        raise VMNotFound(f"No such system: {key}")

    logger.debug("VM %s is on node %s", key, node)
    return node


def vm(proxmox: ProxmoxAPI, vm_id: Any) -> Any:
    """The qemu endpoint for a guest, on whichever node it runs."""
    return proxmox.nodes(node_for(proxmox, vm_id)).qemu(int(vm_id))


def list_vm_ids(proxmox: ProxmoxAPI) -> List[int]:
    """Ids of every qemu guest the caller may see, in a stable order."""
    return sorted(int(g["vmid"]) for g in _guests(proxmox) if g.get("vmid") is not None)
