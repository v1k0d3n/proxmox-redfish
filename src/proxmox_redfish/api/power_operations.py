"""Power operations for the Proxmox Redfish daemon."""

from typing import Any, Dict, Tuple

from proxmoxer import ProxmoxAPI

from ..config.logging_config import logger
from ..config.settings import PROXMOX_NODE
from ..utils.error_handling import handle_proxmox_error


def power_on(proxmox: ProxmoxAPI, vm_id: int) -> Tuple[Dict[str, Any], int]:
    """Power on a VM."""
    logger.info("Power On request for VM %s", vm_id)
    try:
        task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.start.post()
        logger.info("Power On initiated for VM %s, task: %s", vm_id, task)
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Power On VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Power On request initiated for VM {vm_id}"}],
        }, 202
    except Exception as e:
        logger.error("Power On failed for VM %s: %s", vm_id, str(e), exc_info=True)
        return handle_proxmox_error("Power On", e, vm_id)


def power_off(proxmox: ProxmoxAPI, vm_id: int) -> Tuple[Dict[str, Any], int]:
    """Power off a VM gracefully."""
    try:
        task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.shutdown.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Power Off VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Power Off request initiated for VM {vm_id}"}],
        }, 202
    except Exception as e:
        return handle_proxmox_error("Power Off", e, vm_id)


def reboot(proxmox: ProxmoxAPI, vm_id: int) -> Tuple[Dict[str, Any], int]:
    """Reboot a VM gracefully."""
    try:
        task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.reboot.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Reboot VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Reboot request initiated for VM {vm_id}"}],
        }, 202
    except Exception as e:
        return handle_proxmox_error("Reboot", e, vm_id)


def reset_vm(proxmox: ProxmoxAPI, vm_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Perform a hard reset of the Proxmox VM, equivalent to a power cycle.

    Args:
        proxmox: ProxmoxAPI instance
        vm_id: VM ID

    Returns:
        Tuple of (response_dict, status_code) for Redfish response
    """
    try:
        task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.reset.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Hard Reset VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Hard reset request initiated for VM {vm_id}"}],
        }, 202
    except Exception as e:
        return handle_proxmox_error("Hard Reset", e, vm_id)


def suspend_vm(proxmox: ProxmoxAPI, vm_id: int) -> Tuple[Dict[str, Any], int]:
    """Suspend a VM."""
    try:
        task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.suspend.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Pause VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Pause request initiated for VM {vm_id}"}],
        }, 202
    except Exception as e:
        return handle_proxmox_error("Pause", e, vm_id)


def resume_vm(proxmox: ProxmoxAPI, vm_id: int) -> Tuple[Dict[str, Any], int]:
    """Resume a suspended VM."""
    try:
        task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.resume.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Resume VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Resume request initiated for VM {vm_id}"}],
        }, 202
    except Exception as e:
        return handle_proxmox_error("Resume", e, vm_id)


def stop_vm(proxmox: ProxmoxAPI, vm_id: int) -> Tuple[Dict[str, Any], int]:
    """Hard stop a VM."""
    try:
        task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.stop.post()
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": task,
            "Name": f"Hard stop VM {vm_id}",
            "TaskState": "Running",
            "TaskStatus": "OK",
            "Messages": [{"Message": f"Hard stop request initiated for VM {vm_id}"}],
        }, 202
    except Exception as e:
        return handle_proxmox_error("Hard stop", e, vm_id)
