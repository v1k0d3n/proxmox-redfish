"""Redfish TaskService, backed by Proxmox task status.

Every action this daemon performs hands back a task reference of the form
/redfish/v1/TaskService/Tasks/<upid>. A client that follows Redfish
convention will poll it to learn when the work finished, so the endpoint has
to exist and has to report the truth.

A Proxmox UPID names the node that ran the task, so a task can be looked up
without knowing which guest it belonged to:

    UPID:node:pid:pstart:starttime:type:id:user:comment
"""

from typing import Any, Dict, Tuple, Union

from proxmoxer import ProxmoxAPI

from ..config.logging_config import logger
from ..utils.error_handling import VMNotFound, handle_proxmox_error

# Proxmox reports a task as running, or stopped with an exit status. Redfish
# distinguishes finished-well from finished-badly, so the exit status decides.
TASK_STATES = {
    "running": ("Running", "OK"),
    "stopped": ("Completed", "OK"),
}


def node_from_upid(upid: str) -> str:
    """Return the node named in a UPID.

    Raises VMNotFound for anything that is not a UPID, so an unrecognised
    task id is reported as a missing resource rather than a server error.
    """
    parts = upid.split(":")
    if len(parts) < 3 or parts[0] != "UPID" or not parts[1]:
        raise VMNotFound(f"Not a task id: {upid}")
    return parts[1]


def redfish_task_state(status: Dict[str, Any]) -> Tuple[str, str]:
    """Map a Proxmox task status onto (TaskState, TaskStatus)."""
    running = str(status.get("status", "")).lower()
    state, task_status = TASK_STATES.get(running, ("Running", "OK"))

    if state == "Completed":
        exit_status = status.get("exitstatus")
        # Proxmox reports "OK" on success and a message otherwise.
        if exit_status not in (None, "OK"):
            return "Exception", "Critical"

    return state, task_status


def get_task(proxmox: ProxmoxAPI, upid: str) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """Return a Redfish Task resource for a Proxmox task."""
    try:
        node = node_from_upid(upid)
        status = proxmox.nodes(node).tasks(upid).status.get()
        if not isinstance(status, dict):
            raise VMNotFound(f"No such task: {upid}")

        state, task_status = redfish_task_state(status)
        messages = []
        exit_status = status.get("exitstatus")
        if exit_status:
            messages.append({"Message": str(exit_status)})

        logger.debug("Task %s on %s is %s", upid, node, state)
        return {
            "@odata.id": f"/redfish/v1/TaskService/Tasks/{upid}",
            "@odata.type": "#Task.v1_0_0.Task",
            "Id": upid,
            "Name": str(status.get("type", "Task")),
            "TaskState": state,
            "TaskStatus": task_status,
            "Messages": messages,
        }
    except Exception as e:
        return handle_proxmox_error("Task retrieval", e)


def get_task_service() -> Dict[str, Any]:
    """The TaskService resource itself."""
    return {
        "@odata.id": "/redfish/v1/TaskService",
        "@odata.type": "#TaskService.v1_0_0.TaskService",
        "Id": "TaskService",
        "Name": "Task Service",
        "ServiceEnabled": True,
        "Tasks": {"@odata.id": "/redfish/v1/TaskService/Tasks"},
    }


def get_task_collection(proxmox: ProxmoxAPI) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """Tasks the caller may see, newest first.

    Proxmox keeps a per-node task history. Only running tasks are listed:
    a Redfish client polls a task it was handed, and enumerating completed
    history serves no purpose here.
    """
    try:
        running = proxmox.cluster.tasks.get()
        if not isinstance(running, list):
            running = []

        members = [
            {"@odata.id": f"/redfish/v1/TaskService/Tasks/{t['upid']}"}
            for t in running
            if t.get("upid") and t.get("endtime") is None
        ]
        return {
            "@odata.id": "/redfish/v1/TaskService/Tasks",
            "@odata.type": "#TaskCollection.TaskCollection",
            "Name": "Task Collection",
            "Members": members,
            "Members@odata.count": len(members),
        }
    except Exception as e:
        return handle_proxmox_error("Task collection retrieval", e)
