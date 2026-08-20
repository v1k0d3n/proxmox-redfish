"""The catalog of Redfish endpoints exercised by the contract harness.

Split into a read-only set (safe against any host, including production)
and a mutating set that must only ever be pointed at a disposable VM.
"""

from typing import Any, Dict, List, NamedTuple, Optional


class Endpoint(NamedTuple):
    """A single request in the catalog."""

    name: str
    method: str
    path: str
    body: Optional[Dict[str, Any]] = None


def read_only(vm_id: int, storage_id: str = "0", nic_id: str = "0") -> List[Endpoint]:
    """Endpoints that only read state. Safe to run against production."""
    sys_root = f"/redfish/v1/Systems/{vm_id}"
    mgr_root = f"/redfish/v1/Managers/{vm_id}"
    return [
        Endpoint("service_root", "GET", "/redfish/v1"),
        Endpoint("systems_collection", "GET", "/redfish/v1/Systems"),
        Endpoint("system", "GET", sys_root),
        Endpoint("bios", "GET", f"{sys_root}/Bios"),
        Endpoint("processors", "GET", f"{sys_root}/Processors"),
        Endpoint("processor_detail", "GET", f"{sys_root}/Processors/0"),
        Endpoint("storage_collection", "GET", f"{sys_root}/Storage"),
        Endpoint("storage_detail", "GET", f"{sys_root}/Storage/{storage_id}"),
        Endpoint("volumes", "GET", f"{sys_root}/Storage/{storage_id}/Volumes"),
        Endpoint("controllers", "GET", f"{sys_root}/Storage/{storage_id}/Controllers"),
        Endpoint("ethernet_collection", "GET", f"{sys_root}/EthernetInterfaces"),
        Endpoint("ethernet_detail", "GET", f"{sys_root}/EthernetInterfaces/{nic_id}"),
        Endpoint("manager", "GET", mgr_root),
        Endpoint("virtual_media_collection", "GET", f"{mgr_root}/VirtualMedia"),
        Endpoint("virtual_media_cd", "GET", f"{mgr_root}/VirtualMedia/Cd"),
        # Error paths are part of the contract too.
        Endpoint("unknown_path", "GET", "/redfish/v1/NoSuchThing"),
        Endpoint("system_bad_id", "GET", "/redfish/v1/Systems/99999999"),
    ]


def unauthenticated() -> List[Endpoint]:
    """Requests issued with no credentials, to pin the 401 contract."""
    return [
        Endpoint("noauth_service_root", "GET", "/redfish/v1"),
        Endpoint("noauth_systems", "GET", "/redfish/v1/Systems"),
    ]


def mutating(vm_id: int, iso_url: str) -> List[Endpoint]:
    """Endpoints that change VM state. DISPOSABLE VMs ONLY."""
    sys_root = f"/redfish/v1/Systems/{vm_id}"
    mgr_cd = f"/redfish/v1/Managers/{vm_id}/VirtualMedia/Cd"
    return [
        Endpoint(
            "eject_media",
            "POST",
            f"{mgr_cd}/Actions/VirtualMedia.EjectMedia",
            {},
        ),
        Endpoint(
            "insert_media",
            "POST",
            f"{mgr_cd}/Actions/VirtualMedia.InsertMedia",
            {"Image": iso_url, "Inserted": True},
        ),
        Endpoint(
            "boot_override_cd",
            "PATCH",
            sys_root,
            {"Boot": {"BootSourceOverrideTarget": "Cd", "BootSourceOverrideEnabled": "Once"}},
        ),
        Endpoint(
            "power_on",
            "POST",
            f"{sys_root}/Actions/ComputerSystem.Reset",
            {"ResetType": "On"},
        ),
        Endpoint(
            "power_off",
            "POST",
            f"{sys_root}/Actions/ComputerSystem.Reset",
            {"ResetType": "ForceOff"},
        ),
    ]
