"""VM operations for the Proxmox Redfish daemon."""

from typing import Any, Dict, Tuple

from proxmoxer import ProxmoxAPI

from ..config.settings import PROXMOX_NODE
from ..utils.error_handling import handle_proxmox_error


def update_vm_config(proxmox: ProxmoxAPI, vm_id: int, config_data: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
    """Update VM configuration."""
    try:
        task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.post(**config_data)
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Update Configuration for VM {vm_id}",
            "TaskState": "Running",  # Initial state; client can poll for updates
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Configuration update initiated for VM {vm_id}"}],
        }, 202  # 202 Accepted indicates an asynchronous task
    except Exception as e:
        return handle_proxmox_error("Update Configuration", e, vm_id)
