"""Virtual media operations for the Proxmox Redfish daemon."""

from typing import Any, Dict, Optional, Tuple

from proxmoxer import ProxmoxAPI

from ..config.logging_config import logger
from ..config.settings import PROXMOX_NODE
from ..proxmox.iso_manager import _ensure_iso_available
from ..utils.error_handling import handle_proxmox_error


def manage_virtual_media(
    proxmox: ProxmoxAPI, vm_id: int, action: str, iso_path: Optional[str] = None
) -> Tuple[Dict[str, Any], int]:
    """
    Manage virtual media for a Proxmox VM, mapped to Redfish VirtualMedia actions.

    Args:
        proxmox: ProxmoxAPI instance
        vm_id: VM ID
        action: "InsertMedia" or "EjectMedia"
        iso_path: Path to ISO (for InsertMedia)

    Returns:
        Tuple of (response_dict, status_code)
    """
    logger.info("VirtualMedia operation: action=%s, vm_id=%s, iso_path=%s", action, vm_id, iso_path)

    try:
        vm_config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config

        if action == "InsertMedia":
            if not iso_path:
                logger.error("InsertMedia failed: No ISO path provided for VM %s", vm_id)
                return {
                    "error": {"code": "Base.1.0.InvalidRequest", "message": "ISO path is required for InsertMedia"}
                }, 400

            logger.info("Processing InsertMedia for VM %s with ISO: %s", vm_id, iso_path)
            iso_path = _ensure_iso_available(proxmox, iso_path)
            logger.info("ISO prepared for VM %s: %s", vm_id, iso_path)

            config_data = {"ide2": f"{iso_path},media=cdrom"}
            logger.debug("Updating VM %s config: %s", vm_id, config_data)
            task = vm_config.post(**config_data)

            logger.debug("Setting boot order for VM %s to ide2", vm_id)
            vm_config.post(boot="order=ide2")

            logger.info("InsertMedia completed successfully for VM %s, task: %s", vm_id, task)
            return {
                "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
                "@odata.type": "#Task.v1_0_0.Task",
                "Id": task,
                "Name": f"Insert Media for VM {vm_id}",
                "TaskState": "Running",
                "TaskStatus": "OK",
                "Messages": [{"Message": f"Mounted ISO {iso_path} to VM {vm_id}"}],
            }, 202

        elif action == "EjectMedia":
            logger.info("Processing EjectMedia for VM %s", vm_id)
            config_data = {"ide2": "none,media=cdrom"}
            logger.debug("Updating VM %s config: %s", vm_id, config_data)
            task = vm_config.post(**config_data)

            logger.info("EjectMedia completed successfully for VM %s, task: %s", vm_id, task)
            return {
                "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
                "@odata.type": "#Task.v1_0_0.Task",
                "Id": task,
                "Name": f"Eject Media from VM {vm_id}",
                "TaskState": "Running",
                "TaskStatus": "OK",
                "Messages": [{"Message": f"Ejected ISO from VM {vm_id}"}],
            }, 202
        else:
            logger.error("Unsupported VirtualMedia action: %s for VM %s", action, vm_id)
            return {"error": {"code": "Base.1.0.InvalidRequest", "message": f"Unsupported action: {action}"}}, 400

    except Exception as e:
        logger.error("VirtualMedia %s failed for VM %s: %s", action, vm_id, str(e), exc_info=True)
        return handle_proxmox_error(f"Virtual Media {action}", e, vm_id)
