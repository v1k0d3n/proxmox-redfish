"""HTTP request handler for the Proxmox Redfish daemon."""

import base64
import json
import secrets
import time
from http.server import BaseHTTPRequestHandler
from typing import Any, Dict, Tuple, Union

from proxmoxer import ProxmoxAPI

from ..api.power_operations import (
    power_off,
    power_on,
    reboot,
    reset_vm,
    resume_vm,
    stop_vm,
    suspend_vm,
)
from ..api.redfish_endpoints import (
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
    get_vm_status,
    get_volume_collection,
)
from ..api.virtual_media import manage_virtual_media
from ..auth.authentication import sessions, validate_token
from ..config.logging_config import logger
from ..config.settings import AUTH, PROXMOX_HOST, PROXMOX_NODE, VERIFY_SSL
from ..proxmox.client import get_proxmox_api
from ..proxmox.vm_operations import update_vm_config
from ..utils.boot_order import reorder_boot_order
from ..utils.error_handling import handle_proxmox_error
from ..utils.redaction import redact_headers, redact_payload, redact_response


class RedfishRequestHandler(BaseHTTPRequestHandler):
    """Custom request handler for Redfish API endpoints."""

    def do_GET(self) -> None:
        """Handle GET requests."""
        # Log request details
        headers_str = redact_headers(self.headers.items())
        logger.debug(f"GET Request: path={self.path}, headers=\n{headers_str}")

        path = self.path.rstrip("/")
        response: Union[Dict[str, Any], Tuple[Dict[str, Any], int]] = {}
        status_code = 200
        self.protocol_version = "HTTP/1.1"

        # Allow root endpoint without authentication for service discovery
        if path == "/redfish/v1":
            response = {
                "@odata.id": "/redfish/v1",
                "@odata.type": "#ServiceRoot.v1_0_0.ServiceRoot",
                "Id": "RootService",
                "Name": "Redfish Root Service",
                "RedfishVersion": "1.0.0",
                "Systems": {"@odata.id": "/redfish/v1/Systems"},
            }
        else:
            # Require authentication for all other endpoints
            valid, message = validate_token(self.headers)
            if not valid:
                status_code = 401
                response = {"error": {"code": "Base.1.0.GeneralError", "message": message}}
            else:
                proxmox = get_proxmox_api(self.headers)
                parts = path.split("/")
                if path == "/redfish/v1/Systems":
                    try:
                        vm_list = proxmox.nodes(PROXMOX_NODE).qemu.get()
                        members = [{"@odata.id": f"/redfish/v1/Systems/{vm['vmid']}"} for vm in vm_list]
                        response = {
                            "@odata.id": "/redfish/v1/Systems",
                            "@odata.type": "#SystemCollection.SystemCollection",
                            "Name": "Systems Collection",
                            "Members": members,
                            "Members@odata.count": len(members),
                        }
                    except Exception as e:
                        status_code = 500
                        response = {
                            "error": {
                                "code": "Base.1.0.GeneralError",
                                "message": f"Failed to retrieve VM list: {str(e)}",
                            }
                        }
                elif path.startswith("/redfish/v1/Systems/"):
                    if len(parts) == 5 and parts[4].isdigit():  # /redfish/v1/Systems/<vm_id>
                        vm_id = int(parts[4])
                        response = get_vm_status(proxmox, vm_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    # Handle /redfish/v1/Systems/<vm_id>/Bios
                    elif len(parts) == 6 and parts[5] == "Bios":  # /redfish/v1/Systems/<vm_id>/Bios
                        vm_id = int(parts[4])
                        response = get_bios(proxmox, vm_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    elif len(parts) == 6 and parts[5] == "Processors":  # /redfish/v1/Systems/<vm_id>/Processors
                        vm_id = int(parts[4])
                        response = get_processor_collection(proxmox, vm_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    elif (
                        len(parts) == 7 and parts[5] == "Processors"
                    ):  # /redfish/v1/Systems/<vm_id>/Processors/<processor_id>
                        vm_id = int(parts[4])
                        processor_id = parts[6]
                        response = get_processor_detail(proxmox, vm_id, processor_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    elif len(parts) == 6 and parts[5] == "Storage":  # /redfish/v1/Systems/<vm_id>/Storage
                        vm_id = int(parts[4])
                        response = get_storage_collection(proxmox, vm_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    elif (
                        len(parts) == 7 and parts[5] == "Storage" and parts[6].isdigit()
                    ):  # /redfish/v1/Systems/<vm_id>/Storage/<storage_id>
                        vm_id = int(parts[4])
                        storage_id = parts[6]
                        response = get_storage_detail(proxmox, vm_id, storage_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    elif (
                        len(parts) == 9 and parts[5] == "Storage" and parts[7] == "Drives"
                    ):  # /redfish/v1/Systems/<vm_id>/Storage/<storage_id>/Drives/<drive_id>
                        vm_id = int(parts[4])
                        storage_id = parts[6]
                        drive_id = parts[8]
                        response = get_drive_detail(proxmox, vm_id, storage_id, drive_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    elif (
                        len(parts) == 8 and parts[5] == "Storage" and parts[7] == "Volumes"
                    ):  # /redfish/v1/Systems/<vm_id>/Storage/<storage_id>/Volumes
                        vm_id = int(parts[4])
                        storage_id = parts[6]
                        response = get_volume_collection(proxmox, vm_id, storage_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    elif (
                        len(parts) == 8 and parts[5] == "Storage" and parts[7] == "Controllers"
                    ):  # /redfish/v1/Systems/<vm_id>/Storage/<storage_id>/Controllers
                        vm_id = int(parts[4])
                        storage_id = parts[6]
                        response = get_controller_collection(proxmox, vm_id, storage_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    elif (
                        len(parts) == 6 and parts[5] == "EthernetInterfaces"
                    ):  # /redfish/v1/Systems/<vm_id>/EthernetInterfaces
                        vm_id = int(parts[4])
                        response = get_ethernet_interface_collection(proxmox, vm_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    elif (
                        len(parts) == 7 and parts[5] == "EthernetInterfaces"
                    ):  # /redfish/v1/Systems/<vm_id>/EthernetInterfaces/<interface_id>
                        vm_id = int(parts[4])
                        interface_id = parts[6]
                        response = get_ethernet_interface_detail(proxmox, vm_id, interface_id)
                        if isinstance(response, tuple):
                            response, status_code = response
                    else:
                        status_code = 404
                        response = {
                            "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Resource not found: {path}"}
                        }
                # --- Managers endpoints (Metal3/Ironic path) -----------------
                elif path.startswith("/redfish/v1/Managers/") and len(parts) == 5 and parts[4].isdigit():
                    # /redfish/v1/Managers/<manager_id> - Manager detail
                    manager_id = parts[4]  # string
                    vm_id = int(manager_id)
                    response = get_manager(proxmox, vm_id)
                    if isinstance(response, tuple):
                        response, status_code = response
                elif path.startswith("/redfish/v1/Managers/") and len(parts) == 6 and parts[5] == "VirtualMedia":
                    # /redfish/v1/Managers/1/VirtualMedia - VirtualMedia collection
                    manager_id = parts[4]  # string
                    vm_id = int(manager_id)
                    response = {
                        "@odata.id": f"/redfish/v1/Managers/{manager_id}/VirtualMedia",
                        "@odata.type": "#VirtualMediaCollection.VirtualMediaCollection",
                        "Name": "Virtual Media Collection",
                        "Members": [{"@odata.id": f"/redfish/v1/Managers/{manager_id}/VirtualMedia/Cd"}],
                        "Members@odata.count": 1,
                    }
                elif (
                    path.startswith("/redfish/v1/Managers/")
                    and len(parts) == 7
                    and parts[5] == "VirtualMedia"
                    and parts[6] == "Cd"
                ):
                    manager_id = parts[4]  # string
                    vm_id = int(manager_id)
                    response = get_virtual_media(proxmox, vm_id)
                    if isinstance(response, tuple):
                        response, status_code = response
                else:
                    status_code = 404
                    response = {"error": {"code": "Base.1.0.GeneralError", "message": f"Resource not found: {path}"}}

        response_body = json.dumps(response).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response_body)
        logger.debug(
            f"GET Response: path={self.path}, status={status_code}, body={json.dumps(redact_response(self.path, response))}"
        )

    def do_POST(self) -> None:
        """Handle POST requests."""
        # Log request details
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            post_data_str = post_data.decode("utf-8")
            try:
                payload = json.loads(post_data_str)
            except json.JSONDecodeError:
                payload = post_data_str  # Log raw string if not JSON
        except UnicodeDecodeError:
            post_data_str = "<Non-UTF-8 data>"
            payload = post_data_str
        headers_str = redact_headers(self.headers.items())
        logger.debug(
            f"POST Request: path={self.path}\nHeaders:\n{headers_str}\nPayload:\n{json.dumps(redact_payload(payload), indent=2)}"
        )

        path = self.path
        response: Union[Dict[str, Any], Tuple[Dict[str, Any], int]] = {}
        token = None
        status_code = 200
        self.protocol_version = "HTTP/1.1"

        if path == "/redfish/v1/SessionService/Sessions" and AUTH == "Session":
            try:
                data = json.loads(post_data.decode("utf-8"))
                username = data.get("UserName")
                password = data.get("Password")
                if not username or not password:
                    status_code = 400
                    response = {"error": {"code": "Base.1.0.GeneralError", "message": "Missing credentials"}}
                else:
                    if "@" not in username:
                        username += "@pam"
                    proxmox = ProxmoxAPI(PROXMOX_HOST, user=username, password=password, verify_ssl=VERIFY_SSL)
                    token = secrets.token_hex(16)
                    sessions[token] = {"username": username, "created": time.time()}
                    status_code = 201
                    response = {
                        "@odata.id": f"/redfish/v1/SessionService/Sessions/{token}",
                        "Id": token,
                        "UserName": username,
                    }
            except Exception as e:
                status_code = 401
                response = {"error": {"code": "Base.1.0.GeneralError", "message": f"Authentication failed: {str(e)}"}}
        else:
            valid, message = validate_token(self.headers)
            if not valid:
                status_code = 401
                response = {"error": {"code": "Base.1.0.GeneralError", "message": message}}
            else:
                # Get the authenticated username
                auth_header = self.headers.get("Authorization")
                if auth_header and auth_header.startswith("Basic "):
                    credentials = base64.b64decode(auth_header.split(" ")[1]).decode("utf-8")
                    username, password = credentials.split(":", 1)
                    if "@" not in username:
                        username += "@pam"
                else:
                    # For session auth, get username from token
                    token = self.headers.get("X-Auth-Token")
                    if token in sessions:
                        username = sessions[token]["username"]
                    else:
                        username = "unknown"

                proxmox = get_proxmox_api(self.headers)

                # Handle payload parsing based on endpoint
                if post_data:
                    try:
                        data = json.loads(post_data.decode("utf-8"))
                    except json.JSONDecodeError:
                        status_code = 400
                        response = {"error": {"code": "Base.1.0.GeneralError", "message": "Invalid JSON payload"}}
                        response_body = json.dumps(response).encode("utf-8")
                        self.send_response(status_code)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(response_body)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(response_body)
                        # Log response
                        logger.debug(
                            f"POST Response: path={self.path}, status={status_code}, body={json.dumps(redact_response(self.path, response))}"
                        )
                        return

                    data = json.loads(post_data.decode("utf-8"))
                    if path.startswith("/redfish/v1/Systems/") and "/Actions/ComputerSystem.Reset" in path:
                        vm_id = int(path.split("/")[4])

                        # Authorization is Proxmox's to decide: the connection
                        # is opened as the caller, so a denied operation comes
                        # back as a 403 from the API itself.
                        reset_type = data.get("ResetType", "")
                        if reset_type == "On":
                            response, status_code = power_on(proxmox, vm_id)
                        elif reset_type == "GracefulShutdown":
                            response, status_code = power_off(proxmox, vm_id)
                        elif reset_type == "ForceOff":
                            response, status_code = stop_vm(proxmox, vm_id)
                        elif reset_type == "GracefulRestart":
                            response, status_code = reboot(proxmox, vm_id)
                        elif reset_type == "ForceRestart":
                            response, status_code = reset_vm(proxmox, vm_id)
                        elif reset_type == "Pause":
                            response, status_code = suspend_vm(proxmox, vm_id)
                        elif reset_type == "Resume":
                            response, status_code = resume_vm(proxmox, vm_id)
                        else:
                            status_code = 400
                            response = {
                                "error": {
                                    "code": "Base.1.0.InvalidRequest",
                                    "message": f"Unsupported ResetType: {reset_type}",
                                    "@Message.ExtendedInfo": [
                                        {
                                            "MessageId": "Base.1.0.PropertyValueNotInList",
                                            "Message": f"The value '{reset_type}' for ResetType is not in the supported list: On, GracefulShutdown, ForceOff, GracefulRestart, ForceRestart, Pause, Resume.",
                                            "MessageArgs": [reset_type],
                                            "Severity": "Warning",
                                            "Resolution": "Select a supported ResetType value.",
                                        }
                                    ],
                                }
                            }
                    elif (
                        path.startswith("/redfish/v1/Systems/")
                        and "/VirtualMedia/CDROM/Actions/VirtualMedia.InsertMedia" in path
                    ):
                        vm_id = int(path.split("/")[4])
                        iso_path = data.get("Image")
                        response, status_code = manage_virtual_media(proxmox, vm_id, "InsertMedia", iso_path)
                    elif (
                        path.startswith("/redfish/v1/Systems/")
                        and "/VirtualMedia/CDROM/Actions/VirtualMedia.EjectMedia" in path
                    ):
                        vm_id = int(path.split("/")[4])
                        response, status_code = manage_virtual_media(proxmox, vm_id, "EjectMedia")
                    # --- Managers/…/VirtualMedia (sushy default path) -----------------
                    elif (
                        path.startswith("/redfish/v1/Managers/")
                        and "/VirtualMedia/Cd/Actions/VirtualMedia.InsertMedia" in path
                    ):
                        manager_id = path.split("/")[4]  # usually "1"
                        iso_path = data.get("Image")
                        # map Manager-ID → VM-ID  (here we treat them as identical)
                        vm_id = int(manager_id)
                        response, status_code = manage_virtual_media(proxmox, vm_id, "InsertMedia", iso_path)

                    elif (
                        path.startswith("/redfish/v1/Managers/")
                        and "/VirtualMedia/Cd/Actions/VirtualMedia.EjectMedia" in path
                    ):
                        manager_id = path.split("/")[4]
                        vm_id = int(manager_id)
                        response, status_code = manage_virtual_media(proxmox, vm_id, "EjectMedia")
                    elif path.startswith("/redfish/v1/Systems/") and "/Actions/ComputerSystem.UpdateConfig" in path:
                        vm_id = int(path.split("/")[4])
                        config_data = data
                        response, status_code = update_vm_config(proxmox, vm_id, config_data)
                    else:
                        status_code = 404
                        response = {
                            "error": {"code": "Base.1.0.GeneralError", "message": f"Resource not found: {path}"}
                        }

        # Convert response to JSON and calculate its length
        response_body = json.dumps(response).encode("utf-8")
        content_length = len(response_body)

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(content_length))
        if token and path == "/redfish/v1/SessionService/Sessions":
            self.send_header("X-Auth-Token", token)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode("utf-8"))

        # Log response
        logger.debug(
            f"POST Response: path={self.path}, status={status_code}, body={json.dumps(redact_response(self.path, response))}"
        )

    def do_PATCH(self) -> None:
        """Handle PATCH requests."""
        # Log request details
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            post_data_str = post_data.decode("utf-8")
            try:
                payload = json.loads(post_data_str)
            except json.JSONDecodeError:
                payload = post_data_str  # Log raw string if not JSON
        except UnicodeDecodeError:
            post_data_str = "<Non-UTF-8 data>"
            payload = post_data_str
        headers_str = redact_headers(self.headers.items())
        logger.debug(
            f"PATCH Request: path={self.path}\nHeaders:\n{headers_str}\nPayload:\n{json.dumps(redact_payload(payload), indent=2)}"
        )

        path = self.path.rstrip("/")
        parts = path.split("/")
        response: Union[Dict[str, Any], Tuple[Dict[str, Any], int]] = {}
        status_code = 200
        self.protocol_version = "HTTP/1.1"

        logger.debug(f"Processing PATCH request for path: {path}")

        valid, message = validate_token(self.headers)
        if not valid:
            logger.error(f"Authentication failed: {message}")
            status_code = 401
            response = {"error": {"code": "Base.1.0.GeneralError", "message": message}}
        else:
            try:
                proxmox = get_proxmox_api(self.headers)
                logger.debug("Proxmox API connection established for VM operation")
            except Exception as e:
                logger.error(f"Failed to get Proxmox API: {str(e)}")
                status_code = 500
                response = {
                    "error": {"code": "Base.1.0.GeneralError", "message": f"Failed to connect to Proxmox API: {str(e)}"}
                }
                response_body = json.dumps(response).encode("utf-8")
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(response_body)
                logger.debug(
                    f"PATCH Response: path={self.path}, status={status_code}, body={json.dumps(redact_response(self.path, response))}"
                )
                return

            if len(parts) == 6 and parts[5] == "Bios":  # /redfish/v1/Systems/<vm_id>/Bios
                vm_id = parts[4]
                try:
                    data = json.loads(post_data.decode("utf-8"))
                    if "Attributes" in data:
                        attributes = data["Attributes"]
                        if "FirmwareMode" in attributes:
                            mode = attributes["FirmwareMode"]
                            if mode not in ["BIOS", "UEFI"]:
                                status_code = 400
                                response = {
                                    "error": {
                                        "code": "Base.1.0.PropertyValueNotInList",
                                        "message": f"Invalid FirmwareMode: {mode}",
                                    }
                                }
                            else:
                                bios_setting = "seabios" if mode == "BIOS" else "ovmf"
                                task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.set(bios=bios_setting)
                                response = {
                                    "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
                                    "@odata.type": "#Task.v1_0_0.Task",
                                    "Id": task,
                                    "Name": f"Set BIOS Mode for VM {vm_id}",
                                    "TaskState": "Running",
                                    "TaskStatus": "OK",
                                    "Messages": [{"Message": f"Set BIOS mode to {mode} for VM {vm_id}"}],
                                }
                                status_code = 202
                        else:
                            status_code = 400
                            response = {
                                "error": {
                                    "code": "Base.1.0.PropertyUnknown",
                                    "message": "No supported attributes provided",
                                }
                            }
                    else:
                        status_code = 400
                        response = {
                            "error": {
                                "code": "Base.1.0.InvalidRequest",
                                "message": "Attributes object required in PATCH request",
                            }
                        }
                except json.JSONDecodeError:
                    status_code = 400
                    response = {"error": {"code": "Base.1.0.GeneralError", "message": "Invalid JSON payload"}}
                except Exception as e:
                    response, status_code = handle_proxmox_error("BIOS update", e, vm_id)
            elif path.startswith("/redfish/v1/Systems/") and len(parts) == 5:
                vm_id = path.split("/")[4]
                logger.debug(f"Processing boot configuration for VM {vm_id}")
                try:
                    data = json.loads(post_data.decode("utf-8"))
                    logger.debug(f"Parsed payload: {json.dumps(data, indent=2)}")
                    # Handle sushy ironic drive's incorrect BootSourceOverrideMode request
                    if "Boot" in data and "BootSourceOverrideMode" in data["Boot"]:
                        logger.warning(
                            f"Received non-standard BootSourceOverrideMode request at /redfish/v1/Systems/{vm_id}; redirecting to BIOS handling"
                        )
                        mode = data["Boot"]["BootSourceOverrideMode"]
                        # Map BootSourceOverrideMode to FirmwareMode
                        mode_map = {"UEFI": "UEFI", "Legacy": "BIOS"}
                        if mode not in mode_map:
                            status_code = 400
                            response = {
                                "error": {
                                    "code": "Base.1.0.PropertyValueNotInList",
                                    "message": f"Invalid BootSourceOverrideMode: {mode}",
                                }
                            }
                        else:
                            firmware_mode = mode_map[mode]
                            bios_setting = "seabios" if firmware_mode == "BIOS" else "ovmf"
                            task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.set(bios=bios_setting)
                            response = {
                                "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
                                "@odata.type": "#Task.v1_0_0.Task",
                                "Id": task,
                                "Name": f"Set BIOS Mode for VM {vm_id}",
                                "TaskState": "Completed",  # Changed from "Running" to indicate immediate completion
                                "TaskStatus": "OK",
                                "Messages": [{"Message": f"Set BIOS mode to {firmware_mode} for VM {vm_id}"}],
                            }
                            status_code = 200  # Changed from 202 to 200 for sushi driver
                            response_body = json.dumps(response).encode("utf-8")
                            self.send_response(status_code)
                            self.send_header("Content-Type", "application/json")
                            self.send_header("Content-Length", str(len(response_body)))
                            self.send_header("Connection", "close")
                            self.end_headers()
                            self.wfile.write(response_body)
                            logger.debug(
                                f"PATCH Response: path={self.path}, status={status_code}, body={json.dumps(redact_response(self.path, response))}"
                            )
                            return
                    if "Boot" in data:
                        boot_data = data["Boot"]
                        if "BootSourceOverrideMode" in boot_data:
                            status_code = 400
                            response = {
                                "error": {
                                    "code": "Base.1.0.ActionNotSupported",
                                    "message": "Changing BootSourceOverrideMode is not supported through this resource. Use the Bios resource to change the boot mode.",
                                    "@Message.ExtendedInfo": [
                                        {
                                            "MessageId": "Base.1.0.ActionNotSupported",
                                            "Message": "The property BootSourceOverrideMode cannot be changed through the ComputerSystem resource. To change the boot mode, use a PATCH request to the Bios resource.",
                                            "Severity": "Warning",
                                            "Resolution": "Send a PATCH request to /redfish/v1/Systems/<vm_id>/Bios with the desired FirmwareMode in Attributes.",
                                        }
                                    ],
                                }
                            }
                        else:
                            target = boot_data.get("BootSourceOverrideTarget")
                            enabled = boot_data.get("BootSourceOverrideEnabled", "Once")
                            logger.debug(f"Boot parameters: target={target}, enabled={enabled}")

                            if target not in ["Pxe", "Cd", "Hdd"]:
                                logger.error(f"Invalid BootSourceOverrideTarget: {target}")
                                status_code = 400
                                response = {
                                    "error": {
                                        "code": "Base.1.0.InvalidRequest",
                                        "message": f"Unsupported BootSourceOverrideTarget: {target}",
                                        "@Message.ExtendedInfo": [
                                            {
                                                "MessageId": "Base.1.0.PropertyValueNotInList",
                                                "Message": f"The value '{target}' for BootSourceOverrideTarget is not in the supported list: Pxe, Cd, Hdd.",
                                                "MessageArgs": [target],
                                                "Severity": "Warning",
                                                "Resolution": "Select a supported boot device from BootSourceOverrideSupported.",
                                            }
                                        ],
                                    }
                                }
                            elif enabled not in ["Once", "Continuous", "Disabled"]:
                                logger.error(f"Invalid BootSourceOverrideEnabled: {enabled}")
                                status_code = 400
                                response = {
                                    "error": {
                                        "code": "Base.1.0.InvalidRequest",
                                        "message": f"Unsupported BootSourceOverrideEnabled: {enabled}",
                                        "@Message.ExtendedInfo": [
                                            {
                                                "MessageId": "Base.1.0.PropertyValueNotInList",
                                                "Message": f"The value '{enabled}' for BootSourceOverrideEnabled is not in the supported list: Once, Continuous, Disabled.",
                                                "MessageArgs": [enabled],
                                                "Severity": "Warning",
                                                "Resolution": "Select a supported value for BootSourceOverrideEnabled.",
                                            }
                                        ],
                                    }
                                }
                            # Check the VM's current power state
                            logger.debug(f"Checking power state for VM {vm_id}")
                            try:
                                status = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.current.get()
                                logger.debug(f"VM {vm_id} status: {status['status']}")
                            except Exception as e:
                                logger.error(f"Failed to get VM {vm_id} status: {str(e)}")
                                status_code = 500
                                response = {
                                    "error": {
                                        "code": "Base.1.0.GeneralError",
                                        "message": f"Failed to get VM status: {str(e)}",
                                    }
                                }

                            redfish_status = {
                                "running": "On",
                                "stopped": "Off",
                                "paused": "Paused",
                                "shutdown": "Off",
                            }.get(status["status"], "Unknown")
                            logger.debug(f"VM {vm_id} redfish_status: {redfish_status}")

                            # Proceed with boot order change
                            logger.debug(f"VM {vm_id}, proceeding with boot order change to {target}")
                            try:
                                config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
                                current_boot = config.get("boot", "")
                                logger.debug(f"Current boot order: {current_boot}")
                                new_boot_order = reorder_boot_order(proxmox, int(vm_id), current_boot, target)
                                logger.debug(f"New boot order: {new_boot_order}")
                                config_data = {"boot": f"order={new_boot_order}" if new_boot_order else ""}
                                task = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.post(**config_data)
                                logger.debug(f"Boot order update task initiated: {task}")
                                response = {
                                    "@odata.id": f"/redfish/v1/TaskService/Tasks/{task}",
                                    "@odata.type": "#Task.v1_0_0.Task",
                                    "Id": task,
                                    "Name": f"Set Boot Order for VM {vm_id}",
                                    "TaskState": "Running",
                                    "TaskStatus": "OK",
                                    "Messages": [
                                        {"Message": f"Boot order set to {target} ({new_boot_order}) for VM {vm_id}"}
                                    ],
                                }
                                status_code = 202
                            except ValueError as e:
                                logger.error(f"Failed to set boot order for VM {vm_id}: {str(e)}")
                                status_code = 400
                                response = {
                                    "error": {
                                        "code": "Base.1.0.ActionNotSupported",
                                        "message": f"Cannot set BootSourceOverrideTarget to {target}: {str(e)}",
                                        "@Message.ExtendedInfo": [
                                            {
                                                "MessageId": "Base.1.0.ActionNotSupported",
                                                "Message": f"The requested boot device '{target}' is not available. Available boot devices are: Pxe, Cd.",
                                                "MessageArgs": [target],
                                                "Severity": "Warning",
                                                "Resolution": "Select a supported boot device from BootSourceOverrideSupported or verify the VM configuration.",
                                            }
                                        ],
                                    }
                                }
                            except Exception as e:
                                logger.error(f"Failed to set boot order for VM {vm_id}: {str(e)}")
                                response, status_code = handle_proxmox_error("Boot configuration", e, vm_id)
                    else:
                        logger.error("Boot object required in PATCH request")
                        status_code = 400
                        response = {
                            "error": {
                                "code": "Base.1.0.InvalidRequest",
                                "message": "Boot object required in PATCH request",
                            }
                        }
                except json.JSONDecodeError:
                    logger.error("Invalid JSON payload")
                    status_code = 400
                    response = {"error": {"code": "Base.1.0.GeneralError", "message": "Invalid JSON payload"}}
            else:
                logger.error(f"Resource not found: {path}")
                status_code = 404
                response = {
                    "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Resource not found: {path}"}
                }

        response_body = json.dumps(response).encode("utf-8")
        content_length = len(response_body)
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(content_length))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response_body)

        logger.debug(
            f"PATCH Response: path={self.path}, status={status_code}, body={json.dumps(redact_response(self.path, response))}"
        )
