"""Virtual media operations for the Proxmox Redfish daemon."""

from typing import Any, Dict, Optional, Tuple

from proxmoxer import ProxmoxAPI

from ..config.logging_config import logger
from ..proxmox.iso_manager import _ensure_iso_available
from ..proxmox.placement import node_for, vm
from ..utils.error_handling import handle_proxmox_error

EMPTY_DRIVE = "none"


def _attached_volid(config: Dict[str, Any]) -> Optional[str]:
    """The volid currently in the CD drive, or None when it is empty."""
    ide2 = config.get("ide2") if isinstance(config, dict) else None
    if not ide2:
        return None
    volid = str(ide2).split(",", 1)[0]
    # Proxmox writes an empty drive as the literal "none,media=cdrom".
    return None if volid == EMPTY_DRIVE else volid


def _task_response(task: Any, vm_id: int, name: str, message: str) -> Tuple[Dict[str, Any], int]:
    """A Task resource for work that has already finished.

    The daemon performs these operations before replying, so by the time this
    is written the media is attached. Reporting TaskState "Running" would tell
    a client to wait for something that is already done, and clients that act
    on that -- polling for completion, then proceeding regardless -- end up
    booting before they should.
    """
    body: Dict[str, Any] = {
        "Name": name,
        "TaskState": "Completed",
        "TaskStatus": "OK",
        "Messages": [{"Message": message}],
    }

    if task:
        body["@odata.id"] = f"/redfish/v1/TaskService/Tasks/{task}"
        body["@odata.type"] = "#Task.v1_0_0.Task"
        body["Id"] = str(task)
    else:
        # Nothing changed, so Proxmox ran no task. Handing back a task
        # reference that resolves to something else would be its own kind of
        # lie, so this is reported as an action response instead.
        body["@odata.type"] = "#ActionResponse.v1_0_0.ActionResponse"
        body["Id"] = name

    return body, 200


def manage_virtual_media(
    proxmox: ProxmoxAPI, vm_id: int, action: str, iso_path: Optional[str] = None
) -> Tuple[Dict[str, Any], int]:
    """
    Manage virtual media for a Proxmox VM, mapped to Redfish VirtualMedia actions.

    Args:
        proxmox: ProxmoxAPI instance
        vm_id: VM ID
        action: "InsertMedia" or "EjectMedia"
        iso_path: ISO URL or storage volid (for InsertMedia)

    Returns:
        Tuple of (response_dict, status_code)
    """
    logger.info("VirtualMedia operation: action=%s, vm_id=%s, iso_path=%s", action, vm_id, iso_path)

    try:
        vm_endpoint = vm(proxmox, vm_id)
        vm_config = vm_endpoint.config
        current = _attached_volid(vm_endpoint.config.get())

        if action == "InsertMedia":
            if not iso_path:
                logger.error("InsertMedia failed: No ISO path provided for VM %s", vm_id)
                return {
                    "error": {"code": "Base.1.0.InvalidRequest", "message": "ISO path is required for InsertMedia"}
                }, 400

            # A volid names an image directly, so whether it is already
            # attached can be answered without fetching anything. A client
            # that repeats the request -- which they do -- gets an immediate
            # answer instead of the image being fetched again.
            if ":iso/" in iso_path and current == iso_path:
                logger.info("InsertMedia: %s is already attached to VM %s", iso_path, vm_id)
                return _task_response(None, vm_id, f"Insert Media for VM {vm_id}", f"{iso_path} is already inserted")

            logger.info("Processing InsertMedia for VM %s with ISO: %s", vm_id, iso_path)
            # A URL has to be fetched and hashed before its volid is known:
            # the same URL can serve different images over time, and skipping
            # that check would attach whatever was there last.
            resolved = _ensure_iso_available(proxmox, iso_path, node_for(proxmox, vm_id))
            logger.info("ISO prepared for VM %s: %s", vm_id, resolved)

            if current == resolved:
                logger.info("InsertMedia: VM %s already has %s attached", vm_id, resolved)
                return _task_response(None, vm_id, f"Insert Media for VM {vm_id}", f"{resolved} is already inserted")

            config_data = {"ide2": f"{resolved},media=cdrom"}
            logger.debug("Updating VM %s config: %s", vm_id, config_data)
            task = vm_config.post(**config_data)

            logger.debug("Setting boot order for VM %s to ide2", vm_id)
            vm_config.post(boot="order=ide2")

            logger.info("InsertMedia completed successfully for VM %s, task: %s", vm_id, task)
            return _task_response(task, vm_id, f"Insert Media for VM {vm_id}", f"Mounted ISO {resolved} to VM {vm_id}")

        elif action == "EjectMedia":
            if current is None:
                logger.info("EjectMedia: VM %s has no media attached", vm_id)
                return _task_response(None, vm_id, f"Eject Media from VM {vm_id}", "No media was inserted")

            logger.info("Processing EjectMedia for VM %s", vm_id)
            config_data = {"ide2": f"{EMPTY_DRIVE},media=cdrom"}
            logger.debug("Updating VM %s config: %s", vm_id, config_data)
            task = vm_config.post(**config_data)

            logger.info("EjectMedia completed successfully for VM %s, task: %s", vm_id, task)
            return _task_response(task, vm_id, f"Eject Media from VM {vm_id}", f"Ejected ISO from VM {vm_id}")
        else:
            logger.error("Unsupported VirtualMedia action: %s for VM %s", action, vm_id)
            return {"error": {"code": "Base.1.0.InvalidRequest", "message": f"Unsupported action: {action}"}}, 400

    except Exception as e:
        logger.error("VirtualMedia %s failed for VM %s: %s", action, vm_id, str(e), exc_info=True)
        return handle_proxmox_error(f"Virtual Media {action}", e, vm_id)
