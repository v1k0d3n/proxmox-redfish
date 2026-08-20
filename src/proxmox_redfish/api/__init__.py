"""Redfish API endpoints for the Proxmox Redfish daemon."""

from .power_operations import (
    power_off,
    power_on,
    reboot,
    reset_vm,
    resume_vm,
    stop_vm,
    suspend_vm,
)
from .redfish_endpoints import (
    get_bios,
    get_controller_collection,
    get_drive_detail,
    get_ethernet_interface_collection,
    get_ethernet_interface_detail,
    get_manager,
    get_processor_collection,
    get_processor_detail,
    get_storage_collection,
    get_storage_detail,
    get_virtual_media,
    get_vm_config,
    get_vm_status,
    get_volume_collection,
)
from .virtual_media import manage_virtual_media

__all__ = [
    "get_vm_status",
    "get_bios",
    "get_vm_config",
    "get_processor_collection",
    "get_processor_detail",
    "get_storage_collection",
    "get_storage_detail",
    "get_drive_detail",
    "get_volume_collection",
    "get_controller_collection",
    "get_ethernet_interface_collection",
    "get_ethernet_interface_detail",
    "get_virtual_media",
    "get_manager",
    "power_on",
    "power_off",
    "reboot",
    "reset_vm",
    "suspend_vm",
    "resume_vm",
    "stop_vm",
    "manage_virtual_media",
]
