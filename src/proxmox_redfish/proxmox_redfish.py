#!/usr/bin/env python3
"""
Proxmox Redfish Daemon

A Redfish API daemon for managing Proxmox VMs, providing a standardized interface
for VM operations through the Redfish protocol.
"""

import argparse
import base64
import binascii
import fcntl
import hashlib
import json
import logging
import logging.handlers
import os
import secrets
import socketserver
import ssl
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler
from typing import Any, Dict, Optional, Tuple, Union

import requests
from proxmoxer import ProxmoxAPI
from proxmoxer.core import ResourceException

# Configure logging to send to system journal
# Logging configuration with configurable levels
logger = logging.getLogger("proxmox-redfish")

# Get logging level from environment variable
# Valid levels: CRITICAL, ERROR, WARNING, INFO, DEBUG
# Default to INFO for production use
log_level_str = os.getenv("REDFISH_LOG_LEVEL", "INFO").upper()
log_level_map = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}

# Validate and set logging level
if log_level_str in log_level_map:
    log_level = log_level_map[log_level_str]
else:
    print(f"Warning: Invalid REDFISH_LOG_LEVEL '{log_level_str}', using INFO")
    log_level = logging.INFO

# Check if logging is enabled at all
logging_enabled = os.getenv("REDFISH_LOGGING_ENABLED", "true").lower() == "true"

if logging_enabled:
    # Configure logging with the specified level
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s:%(lineno)d: %(message)s",
        handlers=[logging.handlers.SysLogHandler(address="/dev/log")],
    )
    logger.setLevel(log_level)
    logger.info("Proxmox-Redfish daemon started with log level: %s", log_level_str)
else:
    logger.handlers = [logging.NullHandler()]
    print("Logging disabled via REDFISH_LOGGING_ENABLED=false")

# Proxmox configuration from environment variables with fallbacks
PROXMOX_HOST = os.getenv("PROXMOX_HOST", "pve-node-hostname")
PROXMOX_USER = os.getenv("PROXMOX_USER", "username")
PROXMOX_PASSWORD = os.getenv("PROXMOX_PASSWORD", "password")
PROXMOX_NODE = os.getenv("PROXMOX_NODE", "pve=-node-name")
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() == "true"
# ISO storage configuration - specifies the storage pool for ISO downloads
PROXMOX_ISO_STORAGE = os.getenv("PROXMOX_ISO_STORAGE", "local")
# Legacy support for OCP_ZTP_AUTOLOAD (deprecated)
AUTOLOAD = os.getenv("OCP_ZTP_AUTOLOAD", "false").lower() == "true" or PROXMOX_ISO_STORAGE != "none"

# SSL certificate configuration
SSL_CERT_FILE = os.getenv("SSL_CERT_FILE", "/opt/redfish_daemon/config/ssl/server.crt")
SSL_KEY_FILE = os.getenv("SSL_KEY_FILE", "/opt/redfish_daemon/config/ssl/server.key")
SSL_CA_FILE = os.getenv("SSL_CA_FILE", "/opt/redfish_daemon/config/ssl/ca.crt")  # Optional CA bundle

# Options
# -A <Authn>, --Auth <Authn> -- Authentication type to use:  Authn={ None | Basic | Session (default) }
# -S <Secure>, --Secure=<Secure> -- <Secure>={ None | Always (default) }
AUTH = "Basic"
SECURE = "Always"

# In-memory session store
sessions: Dict[str, Dict[str, Any]] = {}

# Global lock for ISO operations to prevent race conditions
iso_operation_lock = threading.Lock()

# File locks for individual ISO files
iso_file_locks = {}
iso_file_locks_lock = threading.Lock()


def handle_proxmox_error(operation: str, exception: Exception, vm_id: Optional[Union[str, int]] = None) -> Tuple[Dict[str, Any], int]:
    """
    Handle Proxmox API exceptions and return a Redfish-compliant error response.

    Args:
        operation (str): The operation being performed (e.g., "Power On", "Reboot").
        exception (Exception): The exception raised by ProxmoxAPI (typically ResourceException).
        vm_id (int, optional): The VM ID, if applicable, for more specific error messages.

    Returns:
        tuple: (response_dict, status_code) for Redfish response.
    """
    if not isinstance(exception, ResourceException):
        # Handle unexpected non-Proxmox errors
        return {
            "error": {
                "code": "Base.1.0.GeneralError",
                "message": f"Unexpected error during {operation}: {str(exception)}",
                "@Message.ExtendedInfo": [
                    {"MessageId": "Base.1.0.GeneralError", "Message": "An unexpected error occurred on the server."}
                ],
            }
        }, 500

    # Extract Proxmox error details
    status_code = exception.status_code
    message = str(exception)
    vm_context = f" for VM {vm_id}" if vm_id is not None else ""

    # Map Proxmox status codes to Redfish error codes
    if status_code == 403:
        redfish_error_code = "Base.1.0.InsufficientPrivilege"
        extended_info = [
            {
                "MessageId": "Base.1.0.InsufficientPrivilege",
                "Message": (
                    f"The authenticated user lacks the required privileges to perform the {operation} "
                    f"operation{vm_context}."
                ),
            }
        ]
    elif status_code == 404:
        redfish_error_code = "Base.1.0.ResourceMissingAtURI"
        extended_info = [
            {"MessageId": "Base.1.0.ResourceMissingAtURI", "Message": f"The resource{vm_context} was not found."}
        ]
    elif status_code == 400:
        redfish_error_code = "Base.1.0.InvalidRequest"
        extended_info = [
            {"MessageId": "Base.1.0.InvalidRequest", "Message": f"The {operation} request was malformed or invalid."}
        ]
    else:
        # Fallback for other Proxmox errors (e.g., 500, 503)
        redfish_error_code = "Base.1.0.GeneralError"
        extended_info = [
            {"MessageId": "Base.1.0.GeneralError", "Message": f"An error occurred during {operation}{vm_context}."}
        ]

    return {
        "error": {
            "code": redfish_error_code,
            "message": f"{operation} failed: {message}",
            "@Message.ExtendedInfo": extended_info,
        }
    }, status_code


def get_proxmox_api(headers: Any) -> ProxmoxAPI:
    valid, message = validate_token(headers)
    if not valid:
        raise Exception(f"Authentication failed: {message}")

    # Always use the root session for Proxmox operations
    # The user authentication is handled in validate_token
    try:
        proxmox = ProxmoxAPI(
            PROXMOX_HOST,
            user=PROXMOX_USER,
            password=PROXMOX_PASSWORD,
            verify_ssl=VERIFY_SSL,
            timeout=1800,  # 30 minutes timeout for large uploads
        )
        return proxmox
    except Exception as e:
        raise Exception(f"Failed to connect to Proxmox API: {str(e)}")


def get_credentials(token: str) -> Tuple[str, str]:
    if token in sessions:
        session = sessions[token]
        return session["username"], session["password"]
    raise Exception("No credentials found for token")


def check_user_vm_permission(proxmox: ProxmoxAPI, username: str, vm_id: int) -> bool:
    """
    Check if a user has permission to access a specific VM.
    Uses the root session to check user permissions.

    Args:
        proxmox: ProxmoxAPI instance (root session)
        username: Username to check permissions for
        vm_id: VM ID to check access to

    Returns:
        bool: True if user has permission, False otherwise
    """
    try:
        # Get access control list to check user permissions
        acl = proxmox.access.get()
        logger.debug(f"Checking permissions for user {username} on VM {vm_id}")
        if acl is None:
            logger.warning("No ACL data returned from Proxmox API")
            return False
        logger.debug(f"Found {len(acl)} ACL entries")

        # Check if user has any permissions that would allow VM access
        for entry in acl:
            entry_ugid = entry.get("ugid", "")
            entry_path = entry.get("path", "")
            logger.debug(f"ACL entry: ugid={entry_ugid}, path={entry_path}")

            if entry_ugid == username:
                # Check if the user has permissions for this VM
                if entry_path == f"/vms/{vm_id}" or entry_path.startswith(f"/vms/{vm_id}/"):
                    # User has direct permissions for this VM
                    logger.info(f"User {username} has direct permissions for VM {vm_id}")
                    return True
                elif entry_path == "/vms" or entry_path == "/":
                    # User has permissions for all VMs
                    logger.info(f"User {username} has global VM permissions")
                    return True
                elif entry_path.startswith("/nodes/") and f"/qemu/{vm_id}" in entry_path:
                    # User has node-level permissions for this VM
                    logger.info(f"User {username} has node-level permissions for VM {vm_id}")
                    return True

        # Also check if user is in any groups that have permissions
        if acl is not None:
            for entry in acl:
                entry_ugid = entry.get("ugid", "")
                if entry_ugid.startswith("@") and entry_ugid != username:
                    # This is a group entry, check if user is in this group
                    group_name = entry_ugid[1:]  # Remove @ prefix
                    try:
                        # Check if user is in this group
                        group_members = proxmox.access.groups(group_name).get()
                        if group_members is not None:
                            for member in group_members:
                                if member.get("userid") == username.split("!")[0]:  # Remove token part
                                    # User is in this group, check if group has VM permissions
                                    path = entry.get("path", "")
                                    if path == f"/vms/{vm_id}" or path.startswith(f"/vms/{vm_id}/"):
                                        logger.info(f"User {username} has group permissions for VM {vm_id}")
                                        return True
                                    elif path == "/vms" or path == "/":
                                        logger.info(f"User {username} has global group permissions")
                                        return True
                    except Exception:
                        # Group doesn't exist or other error, continue
                        pass

        logger.warning(f"User {username} does not have permissions for VM {vm_id}")
        return False

    except Exception as e:
        logger.warning(f"Failed to check permissions for user {username} on VM {vm_id}: {str(e)}")
        # In case of error, deny access for security
        return False


def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticate a user by calling the Proxmox /access/ticket endpoint.
    This is the same logic used in the original redfish-proxmox.py script.

    Args:
        username: Username to authenticate (e.g., 'bmcadmin@pve')
        password: Password or token for the user

    Returns:
        bool: True if authentication successful, False otherwise
    """
    try:
        # Check if this looks like an API token (contains '!' and is a UUID-like string)
        if "!" in username and len(password) == 36 and password.count("-") == 4:
            # This is an API token - use Authorization header format
            token_header = f"PVEAPIToken={username}={password}"
            url = f"https://{PROXMOX_HOST}:8006/api2/json/version"

            # Test the token by making a simple API call
            response = requests.get(url, headers={"Authorization": token_header}, verify=VERIFY_SSL, timeout=10)

            if response.status_code == 200:
                logger.info(f"API token authentication successful for {username}")
                return True
            else:
                logger.warning(f"API token authentication failed for {username}: HTTP {response.status_code}")
                return False
        else:
            # This is a regular username/password - use the ticket endpoint
            payload = {"username": username, "password": password}
            url = f"https://{PROXMOX_HOST}:8006/api2/json/access/ticket"

            # Make the request to authenticate the user
            response = requests.post(url, data=payload, verify=VERIFY_SSL, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if "data" in data and "ticket" in data["data"]:
                    logger.info(f"User {username} authenticated successfully")
                    return True
                else:
                    logger.warning(f"User {username} authentication failed: no ticket in response")
                    return False
            else:
                logger.warning(f"User {username} authentication failed: HTTP {response.status_code}")
                return False

    except Exception as e:
        logger.warning(f"User {username} authentication failed with exception: {str(e)}")
        return False


def get_file_lock(filename: str) -> threading.Lock:
    """
    Get or create a lock for a specific ISO file.
    This ensures only one thread can modify a specific ISO file at a time.
    """
    with iso_file_locks_lock:
        if filename not in iso_file_locks:
            iso_file_locks[filename] = threading.Lock()
        return iso_file_locks[filename]


def atomic_file_write(temp_file_path: str, target_path: str, timeout: int = 300) -> None:
    """
    Atomically write a file to prevent corruption during concurrent access.
    Uses atomic rename operation to ensure file integrity.
    """
    # Create a temporary file in the same directory as target
    target_dir = os.path.dirname(target_path)
    temp_target = os.path.join(target_dir, f".tmp_{os.path.basename(target_path)}")

    try:
        # Copy the temp file to the target directory
        import shutil

        shutil.copy2(temp_file_path, temp_target)

        # Set proper permissions
        os.chmod(temp_target, 0o644)

        # Atomic rename - this is guaranteed to be atomic on POSIX systems
        os.rename(temp_target, target_path)
        logger.info("Atomic file write completed: %s", target_path)

    except Exception as e:
        # Clean up temp file if it exists
        if os.path.exists(temp_target):
            try:
                os.unlink(temp_target)
            except Exception:
                pass
        raise e


def safe_file_hash(file_path: str, timeout: int = 60) -> Optional[str]:
    """
    Safely calculate hash of a file with timeout and error handling.
    """
    try:
        hash_obj = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Use file locking to prevent reading while file is being written
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)  # Shared lock for reading
            try:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_obj.update(chunk)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)  # Release lock
        return hash_obj.hexdigest()
    except Exception as e:
        logger.warning("Failed to calculate hash for %s: %s", file_path, str(e))
        return None


# Power control functions (unchanged)
def power_on(proxmox: ProxmoxAPI, vm_id: int) -> Tuple[Dict[str, Any], int]:
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


# This section allows OpenShift ZTP to autoload a generated ISO
def _ensure_iso_available(proxmox: ProxmoxAPI, url_or_volid: str) -> str:
    """
    Return a storage:iso/… volid, downloading + uploading if needed.
    Supports HTTP/S URLs and local storage references.
    Implements hash-based conflict handling and thread-safe concurrent access.

    Args:
        proxmox: ProxmoxAPI instance
        url_or_volid: HTTP/S URL or storage:iso/... reference

    Returns:
        str: storage:iso/filename reference for Proxmox
    """
    # Already looks like "storage:iso/…" → nothing to do
    if ":iso/" in url_or_volid:
        return url_or_volid

    # Check if it's a URL (http/https)
    if url_or_volid.startswith(("http://", "https://")):
        if PROXMOX_ISO_STORAGE == "none":
            raise ValueError("ISO downloads are disabled (PROXMOX_ISO_STORAGE=none)")

        logger.info("Processing ISO from URL: %s", url_or_volid)

        # Extract filename from URL, handling query parameters
        fname = os.path.basename(url_or_volid.split("?", 1)[0])
        if not fname.endswith(".iso"):
            fname += ".iso"  # Ensure .iso extension

        # Determine storage path for hash checking
        if PROXMOX_ISO_STORAGE == "local":
            storage_path = "/var/lib/vz/template/iso"
        else:
            # Try to get storage path from Proxmox API
            try:
                storage_info = proxmox.nodes(PROXMOX_NODE).storage(PROXMOX_ISO_STORAGE).get()
                if isinstance(storage_info, dict):
                    storage_path = storage_info.get("path", "")
                else:
                    storage_path = ""
            except Exception:
                storage_path = ""

        if not storage_path:
            raise Exception(f"Could not determine storage path for {PROXMOX_ISO_STORAGE}")

        # Get file-specific lock to prevent concurrent access to the same ISO
        file_lock = get_file_lock(fname)

        with file_lock:
            logger.info("Acquired lock for ISO file: %s", fname)

            # Check if file already exists and compare hashes
            iso_path = os.path.join(storage_path, fname)
            if os.path.exists(iso_path):
                logger.info("ISO file already exists: %s", iso_path)

                # Download to temp file to calculate hash
                logger.info("Downloading ISO to calculate hash for comparison")
                resp = requests.get(url_or_volid, stream=True, timeout=600, verify=VERIFY_SSL)
                resp.raise_for_status()

                with tempfile.NamedTemporaryFile() as tmp:
                    for chunk in resp.iter_content(16 << 20):  # 16 MiB chunks
                        tmp.write(chunk)
                    tmp.flush()

                    # Calculate hash of downloaded file
                    tmp.seek(0)
                    downloaded_hash = hashlib.sha256()
                    for chunk in iter(lambda: tmp.read(8192), b""):
                        downloaded_hash.update(chunk)
                    downloaded_hash_hex = downloaded_hash.hexdigest()

                    # Safely calculate hash of existing file
                    existing_hash_hex = safe_file_hash(iso_path)

                    if existing_hash_hex:
                        logger.info(
                            "Hash comparison - Downloaded: %s, Existing: %s",
                            downloaded_hash_hex[:16],
                            existing_hash_hex[:16],
                        )

                        if downloaded_hash_hex == existing_hash_hex:
                            logger.info("ISO files are identical, skipping upload")
                            volid = f"{PROXMOX_ISO_STORAGE}:iso/{fname}"
                            logger.info("ISO available as: %s", volid)
                            return volid
                        else:
                            logger.info("ISO files differ, will upload with hash suffix")
                            # Create filename with hash suffix to avoid conflicts
                            name_without_ext = os.path.splitext(fname)[0]
                            ext = os.path.splitext(fname)[1]
                            fname = f"{name_without_ext}_{downloaded_hash_hex[:8]}{ext}"
                            iso_path = os.path.join(storage_path, fname)
                            logger.info("Using unique filename: %s", fname)
                    else:
                        logger.warning("Could not calculate hash of existing file, proceeding with upload")
            else:
                logger.info("ISO file does not exist, downloading: %s", fname)
                # Download the ISO
                resp = requests.get(url_or_volid, stream=True, timeout=600, verify=VERIFY_SSL)
                resp.raise_for_status()

                with tempfile.NamedTemporaryFile() as tmp:
                    for chunk in resp.iter_content(16 << 20):  # 16 MiB chunks
                        tmp.write(chunk)
                    tmp.flush()

                    # Try API upload first, fallback to direct file copy if it fails
                    try:
                        logger.info("Attempting API upload to storage %s", PROXMOX_ISO_STORAGE)
                        upload = proxmox.nodes(PROXMOX_NODE).storage(PROXMOX_ISO_STORAGE).upload
                        task = upload.post(content="iso", filename=fname, file=open(tmp.name, "rb"))

                        # Wait for the upload task to finish
                        logger.info("API upload task started: %s", task)
                        while True:
                            status = proxmox.nodes(PROXMOX_NODE).tasks(task).status.get()
                            if status is None:
                                raise Exception("Failed to get task status")
                            if status.get("status") == "stopped":
                                if status.get("exitstatus") == "OK":
                                    logger.info("API upload completed successfully")
                                    break
                                else:
                                    raise Exception(f"API upload failed: {status}")
                            time.sleep(2)

                    except Exception as api_error:
                        logger.warning("API upload failed: %s, trying direct file copy", str(api_error))

                        # Fallback: Direct file copy to storage directory with atomic write
                        try:
                            logger.info("Copying ISO to: %s", iso_path)

                            # Ensure directory exists
                            os.makedirs(os.path.dirname(iso_path), exist_ok=True)

                            # Use atomic file write to prevent corruption
                            atomic_file_write(tmp.name, iso_path)

                            logger.info("Direct file copy completed successfully")

                        except Exception as copy_error:
                            raise Exception(
                                f"Both API upload and direct copy failed. "
                                f"API error: {api_error}, Copy error: {copy_error}"
                            )

            volid = f"{PROXMOX_ISO_STORAGE}:iso/{fname}"
            logger.info("ISO available as: %s", volid)
            return volid

    # Not a URL and not a storage reference - return as-is (Proxmox will handle validation)
    logger.warning("Unknown ISO format: %s", url_or_volid)
    return url_or_volid


# Add this new function to manage VirtualMedia state (replaces manage_virtual_cd)
def manage_virtual_media(proxmox: ProxmoxAPI, vm_id: int, action: str, iso_path: Optional[str] = None) -> Tuple[Dict[str, Any], int]:
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


# Update VM config (unchanged)
def update_vm_config(proxmox: ProxmoxAPI, vm_id: int, config_data: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
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


def reorder_boot_order(proxmox: ProxmoxAPI, vm_id: int, current_order: str, target: str) -> str:
    """
    Reorder Proxmox boot devices based on Redfish target, preserving all devices including multiple hard drives.
    Returns the new boot order string for Proxmox config.
    """
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            raise ValueError("Failed to retrieve VM configuration")

        # Parse current boot order
        devices = current_order.split(";") if current_order else []
        # Initialize device lists
        disk_devs = []
        cd_dev = None
        net_dev = None

        # Check for hard drives and CD-ROMs (SCSI, SATA, IDE)
        for dev_type in ["scsi", "sata", "ide"]:
            for i in range(4):  # ide0-3, scsi0-3, sata0-3 (simplified range)
                dev_key = f"{dev_type}{i}"
                if dev_key in config:
                    dev_value = config[dev_key]
                    if "media=cdrom" in dev_value:
                        cd_dev = dev_key  # CD-ROM found
                    elif dev_type in ["scsi", "sata"] or (dev_type == "ide" and "media=cdrom" not in dev_value):
                        disk_devs.append(dev_key)  # Hard drive found

        # Check for network devices
        for i in range(4):  # net0-3 (simplified range)
            net_key = f"net{i}"
            if net_key in config:
                net_dev = net_key
                break

        # Build the full list of available devices, preserving all from config and current order
        available_devs = [d for d in devices if d in config] if devices else []
        for dev in disk_devs + ([cd_dev] if cd_dev else []) + ([net_dev] if net_dev else []):
            if dev and dev not in available_devs:
                available_devs.append(dev)

        # Validate the target device availability
        if target == "Pxe" and not net_dev:
            raise ValueError("No network device available for Pxe boot")
        elif target == "Cd" and not cd_dev:
            raise ValueError("No CD-ROM device available for Cd boot")
        elif target == "Hdd" and not disk_devs:
            raise ValueError("No hard disk device available for Hdd boot")

        # Reorder based on target, keeping all devices
        new_order = []
        if target == "Pxe" and net_dev:
            new_order = [net_dev] + [d for d in available_devs if d != net_dev]
        elif target == "Cd" and cd_dev:
            new_order = [cd_dev] + [d for d in available_devs if d != cd_dev]
        elif target == "Hdd" and disk_devs:
            primary_disk = disk_devs[0]
            new_order = [primary_disk] + [d for d in available_devs if d != primary_disk]
        else:
            # This should not be reached due to earlier validation
            new_order = available_devs

        # Remove duplicates and ensure valid devices only
        unique_devices = list(dict.fromkeys(new_order))
        result = ";".join(unique_devices) if unique_devices else ""
        logger.debug(f"Computed new boot order for VM {vm_id}: {result}")
        return result
    except Exception as e:
        logger.error(f"Failed to reorder boot order for VM {vm_id}: {str(e)}")
        raise


def get_bios(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error("BIOS retrieval", Exception("Failed to retrieve VM configuration"), vm_id)
        firmware_type = config.get("bios", "seabios")
        firmware_mode = "BIOS" if firmware_type == "seabios" else "UEFI"

        # Minimal BIOS info with link to SMBIOS details
        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Bios",
            "@odata.type": "#Bios.v1_0_0.Bios",
            "Id": "Bios",
            "Name": "BIOS Settings",
            "FirmwareMode": firmware_mode,  # From previous enhancement
            "Attributes": {"BootOrder": config.get("boot", "order=scsi0;ide2;net0")},
            "Links": {"SMBIOS": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Bios/SMBIOS"}},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("BIOS retrieval", e, vm_id)


def get_smbios_type1(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """
    Retrieve SMBIOS Type 1 (System Information) data from Proxmox VM config,
    including firmware type (BIOS or UEFI).
    """
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error("SMBIOS retrieval", Exception("Failed to retrieve VM configuration"), vm_id)
        smbios1 = config.get("smbios1", "")
        firmware_type = config.get("bios", "seabios")  # Default to seabios if not specified

        # Map Proxmox bios setting to Redfish-friendly terms
        firmware_mode = "BIOS" if firmware_type == "seabios" else "UEFI"

        # Default SMBIOS values
        smbios_data = {
            "UUID": None,
            "Manufacturer": "Proxmox",
            "ProductName": "QEMU Virtual Machine",
            "Version": None,
            "SerialNumber": None,
            "SKUNumber": None,
            "Family": None,
        }

        # Parse smbios1 string if it exists
        if smbios1:
            smbios_entries = smbios1.split(",")
            for entry in smbios_entries:
                if "=" in entry:
                    key, value = entry.split("=", 1)

                    # Attempt to decode Base64 if it looks encoded
                    try:
                        decoded_value = base64.b64decode(value).decode("utf-8")
                        # Only use decoded value if it's valid UTF-8 and not a UUID
                        if key != "uuid" and decoded_value.isprintable():
                            value = decoded_value
                    except (binascii.Error, UnicodeDecodeError):
                        pass  # Keep original value if decoding fails

                    if key == "uuid":
                        smbios_data["UUID"] = value
                    elif key == "manufacturer":
                        smbios_data["Manufacturer"] = value
                    elif key == "product":
                        smbios_data["ProductName"] = value
                    elif key == "version":
                        smbios_data["Version"] = value
                    elif key == "serial":
                        smbios_data["SerialNumber"] = value
                    elif key == "sku":
                        smbios_data["SKUNumber"] = value
                    elif key == "family":
                        smbios_data["Family"] = value

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Bios/SMBIOS",
            "@odata.type": "#Bios.v1_0_0.Bios",
            "Id": "SMBIOS",
            "Name": "SMBIOS System Information",
            "FirmwareMode": firmware_mode,  # New field to indicate BIOS or UEFI
            "Attributes": {"SMBIOSType1": smbios_data},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("SMBIOS retrieval", e, vm_id)


def get_vm_config(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """
    Optional helper function for config details (not a standard Redfish endpoint).
    Returns a subset of data for custom use, but prefer get_vm_status for Redfish compliance.
    """
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error("Configuration retrieval", Exception("Failed to retrieve VM configuration"), vm_id)
        return {
            "Name": config.get("name", f"VM-{vm_id}"),
            "MemoryMB": config.get("memory", 0),
            "CPUCores": config.get("cores", 0),
            "Sockets": config.get("sockets", 1),
            "CDROM": config.get("ide2", "none"),
        }
    except Exception as e:
        return handle_proxmox_error("Configuration retrieval", e, vm_id)


def validate_token(headers: Any) -> Tuple[bool, str]:
    if AUTH is None:
        return True, "No auth required"
    elif AUTH == "Basic":
        auth_header = headers.get("Authorization")
        if auth_header and auth_header.startswith("Basic "):
            try:
                credentials = base64.b64decode(auth_header.split(" ")[1]).decode("utf-8")
                username, password = credentials.split(":", 1)
                if "@" not in username:
                    username += "@pam"
                if authenticate_user(username, password):
                    token = f"{username}-{password}"
                    sessions[token] = {"created": time.time(), "username": username, "password": password}
                    return True, username
                else:
                    return False, f"Invalid Basic Authentication credentials for user {username}"
            except Exception as e:
                return False, f"Invalid Basic Authentication format: {str(e)}"
        else:
            return False, "Basic Authentication required but no valid Authorization header provided"
    elif AUTH == "Session":
        token = headers.get("X-Auth-Token")
        if token in sessions:
            session = sessions[token]
            if time.time() - session["created"] < 3600:
                return True, session["username"]
            else:
                del sessions[token]
                return False, "Token expired"
        else:
            return False, "Invalid or no token provided"
    else:
        return False, "Invalid authentication method"


def get_processor_collection(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error("Processor collection retrieval", Exception("Failed to retrieve VM configuration"), vm_id)
        # Removed unused variables 'cores' and 'sockets'
        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Processors",
            "@odata.type": "#ProcessorCollection.ProcessorCollection",
            "Name": "Processor Collection",
            "Members": [{"@odata.id": f"/redfish/v1/Systems/{vm_id}/Processors/CPU1"}],
            "Members@odata.count": 1,
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Processor collection retrieval", e, vm_id)


def get_processor_detail(proxmox: ProxmoxAPI, vm_id: int, processor_id: str) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error("Processor detail retrieval", Exception("Failed to retrieve VM configuration"), vm_id)
        cores = config.get("cores", 1)
        sockets = config.get("sockets", 1)
        total_cores = cores * sockets

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Processors/{processor_id}",
            "@odata.type": "#Processor.v1_0_0.Processor",
            "Id": processor_id,
            "Name": f"Processor {processor_id}",
            "TotalCores": total_cores,
            "TotalThreads": total_cores,  # Assuming 1 thread per core
            "Status": {"State": "Enabled", "Health": "OK"},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Processor detail retrieval", e, vm_id)


def get_storage_collection(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage",
            "@odata.type": "#StorageCollection.StorageCollection",
            "Name": "Storage Collection",
            "Members": [{"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/1"}],
            "Members@odata.count": 1,
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Storage collection retrieval", e, vm_id)


def parse_disk_size(drive_info: Dict[str, Any]) -> str:
    """
    Parse disk size from Proxmox config string (e.g., 'size=16G') and convert to bytes.
    Returns size as a string representation in bytes.
    """
    try:
        size_str = drive_info.get("size", "0")
        if not size_str or size_str == "0":
            return "0"
        # Handle size strings like "16G", "500M", etc.
        if isinstance(size_str, str):
            size_str = size_str.upper()
            if size_str.endswith("G"):
                size_gb = float(size_str[:-1])
                size_bytes = int(size_gb * 1024 * 1024 * 1024)
                return str(size_bytes)
            elif size_str.endswith("M"):
                size_mb = float(size_str[:-1])
                size_bytes = int(size_mb * 1024 * 1024)
                return str(size_bytes)
            elif size_str.endswith("K"):
                size_kb = float(size_str[:-1])
                size_bytes = int(size_kb * 1024)
                return str(size_bytes)
            else:
                # Assume it's already in bytes
                return str(int(float(size_str)))
        else:
            return str(int(float(size_str)))
    except (ValueError, TypeError):
        return "0"


def get_storage_detail(proxmox: ProxmoxAPI, vm_id: int, storage_id: str) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        if storage_id != "1":
            return {
                "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Storage {storage_id} not found"}
            }, 404

        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error("Storage detail retrieval", Exception("Failed to retrieve VM configuration"), vm_id)

        # Get disk drives from config
        drives = []
        for dev_type in ["scsi", "sata", "ide"]:
            for i in range(4):
                dev_key = f"{dev_type}{i}"
                if dev_key in config:
                    drives.append({"Id": dev_key, "Name": f"Drive {dev_key}"})

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}",
            "@odata.type": "#Storage.v1_0_0.Storage",
            "Id": storage_id,
            "Name": f"Storage {storage_id}",
            "Drives": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Drives"},
            "Volumes": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Volumes"},
            "Controllers": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Controllers"},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Storage detail retrieval", e, vm_id)


def get_drive_detail(proxmox: ProxmoxAPI, vm_id: int, storage_id: str, drive_id: str) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        if storage_id != "1":
            return {
                "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Storage {storage_id} not found"}
            }, 404

        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error("Drive detail retrieval", Exception("Failed to retrieve VM configuration"), vm_id)

        if drive_id not in config:
            return {
                "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Drive {drive_id} not found"}
            }, 404

        drive_config = config[drive_id]
        size = parse_disk_size({"size": drive_config})

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Drives/{drive_id}",
            "@odata.type": "#Drive.v1_0_0.Drive",
            "Id": drive_id,
            "Name": f"Drive {drive_id}",
            "CapacityBytes": size,
            "Status": {"State": "Enabled", "Health": "OK"},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Drive detail retrieval", e, vm_id)


def get_volume_collection(proxmox: ProxmoxAPI, vm_id: int, storage_id: str) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        if storage_id != "1":
            return {
                "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Storage {storage_id} not found"}
            }, 404

        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error("Volume collection retrieval", Exception("Failed to retrieve VM configuration"), vm_id)

        # Get volumes from config
        volumes = []
        for dev_type in ["scsi", "sata", "ide"]:
            for i in range(4):
                dev_key = f"{dev_type}{i}"
                if dev_key in config:
                    volumes.append({"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Volumes/{dev_key}"})

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Volumes",
            "@odata.type": "#VolumeCollection.VolumeCollection",
            "Name": "Volume Collection",
            "Members": volumes,
            "Members@odata.count": len(volumes),
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Volume collection retrieval", e, vm_id)


def get_controller_collection(proxmox: ProxmoxAPI, vm_id: int, storage_id: str) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        if storage_id != "1":
            return {
                "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Storage {storage_id} not found"}
            }, 404

        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error("Controller collection retrieval", Exception("Failed to retrieve VM configuration"), vm_id)

        # Get controllers from config
        controllers = []
        for dev_type in ["scsi", "sata", "ide"]:
            for i in range(4):
                dev_key = f"{dev_type}{i}"
                if dev_key in config:
                    controllers.append({"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Controllers/{dev_type}"})

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Controllers",
            "@odata.type": "#ControllerCollection.ControllerCollection",
            "Name": "Controller Collection",
            "Members": controllers,
            "Members@odata.count": len(controllers),
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Controller collection retrieval", e, vm_id)


def get_ethernet_interface_collection(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error("Ethernet interface collection retrieval", Exception("Failed to retrieve VM configuration"), vm_id)

        # Get network interfaces from config
        interfaces = []
        for i in range(4):
            net_key = f"net{i}"
            if net_key in config:
                interfaces.append({"@odata.id": f"/redfish/v1/Systems/{vm_id}/EthernetInterfaces/{net_key}"})

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/EthernetInterfaces",
            "@odata.type": "#EthernetInterfaceCollection.EthernetInterfaceCollection",
            "Name": "Ethernet Interface Collection",
            "Members": interfaces,
            "Members@odata.count": len(interfaces),
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Ethernet interface collection retrieval", e, vm_id)


def get_ethernet_interface_detail(proxmox: ProxmoxAPI, vm_id: int, interface_id: str) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error("Ethernet interface detail retrieval", Exception("Failed to retrieve VM configuration"), vm_id)

        if interface_id not in config:
            return {
                "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Interface {interface_id} not found"}
            }, 404

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/EthernetInterfaces/{interface_id}",
            "@odata.type": "#EthernetInterface.v1_0_0.EthernetInterface",
            "Id": interface_id,
            "Name": f"Interface {interface_id}",
            "Status": {"State": "Enabled", "Health": "OK"},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Ethernet interface detail retrieval", e, vm_id)


def get_virtual_media(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """
    Get virtual media information for a Proxmox VM.
    """
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error("Virtual media retrieval", Exception("Failed to retrieve VM configuration"), vm_id)

        # Check if CD-ROM is configured
        cd_configured = "ide2" in config and "media=cdrom" in config["ide2"]

        response = {
            "@odata.id": f"/redfish/v1/Managers/{vm_id}/VirtualMedia/Cd",
            "@odata.type": "#VirtualMedia.v1_0_0.VirtualMedia",
            "Id": "Cd",
            "Name": "Virtual CD",
            "MediaTypes": ["CD", "DVD"],
            "ConnectedVia": "Applet",
            "Inserted": cd_configured,
            "WriteProtected": True,
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Virtual media retrieval", e, vm_id)


def get_vm_status(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    try:
        status = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.current.get()
        if status is None:
            return handle_proxmox_error("VM status retrieval", Exception("Failed to retrieve VM status"), vm_id)

        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error("VM status retrieval", Exception("Failed to retrieve VM configuration"), vm_id)

        # Map Proxmox status to Redfish power state
        proxmox_status = status.get("status", "unknown")
        if proxmox_status == "running":
            power_state = "On"
            health = "OK"
        elif proxmox_status == "stopped":
            power_state = "Off"
            health = "OK"
        elif proxmox_status == "paused":
            power_state = "Paused"
            health = "Warning"
        else:
            power_state = "Unknown"
            health = "Critical"

        # Add Memory field as expected by tests
        memory_mb = config.get("memory", 0)
        try:
            memory_mb = float(memory_mb)
        except (ValueError, TypeError):
            memory_mb = 0
        memory_gib = memory_mb / 1024.0
        memory_field = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Memory",
            "TotalSystemMemoryGiB": round(memory_gib, 2),
        }

        # Add Boot field as expected by tests
        boot_order = config.get("boot", "")
        boot_field = {
            "BootSourceOverrideEnabled": "Once",  # or "Continuous"/"Disabled" as appropriate
            "BootSourceOverrideTarget": "None",   # Could be "Pxe", "Cd", "Hdd", etc.
            "BootSourceOverrideMode": "UEFI" if config.get("bios") == "ovmf" else "Legacy",
            "BootSourceOverrideTarget@Redfish.AllowableValues": ["Pxe", "Cd", "Hdd"],
            "BootSourceOverrideMode@Redfish.AllowableValues": ["UEFI", "Legacy"],
            "BootOrder": boot_order,
        }

        # Add Actions field as expected by tests
        actions_field = {
            "#ComputerSystem.Reset": {
                "target": f"/redfish/v1/Systems/{vm_id}/Actions/ComputerSystem.Reset",
                "ResetType@Redfish.AllowableValues": [
                    "On", "ForceOff", "GracefulShutdown", "GracefulRestart", "ForceRestart", "Nmi", "PowerCycle"
                ],
            }
        }

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}",
            "@odata.type": "#ComputerSystem.v1_0_0.ComputerSystem",
            "Id": str(vm_id),
            "Name": config.get("name", f"VM-{vm_id}"),
            "SystemType": "Physical",
            "Status": {"State": power_state, "Health": health},
            "PowerState": power_state,
            "Bios": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Bios"},
            "Processors": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Processors"},
            "Memory": memory_field,
            "Storage": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage"},
            "EthernetInterfaces": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/EthernetInterfaces"},
            "Boot": boot_field,
            "Actions": actions_field,
        }
        return response
    except Exception as e:
        return handle_proxmox_error("VM status retrieval", e, vm_id)


# Custom request handler
class RedfishRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        # Log request details
        headers_str = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        logger.debug(f"GET Request: path={self.path}, headers=\n{headers_str}")

        path = self.path.rstrip("/")
        response: Union[Dict[str, Any], Tuple[Dict[str, Any], int]] = {}
        status_code = 200
        self.protocol_version = "HTTP/1.1"

        valid, message = validate_token(self.headers)
        if not valid:
            status_code = 401
            response = {"error": {"code": "Base.1.0.GeneralError", "message": message}}
        else:
            proxmox = get_proxmox_api(self.headers)
            parts = path.split("/")
            if path == "/redfish/v1":
                response = {
                    "@odata.id": "/redfish/v1",
                    "@odata.type": "#ServiceRoot.v1_0_0.ServiceRoot",
                    "Id": "RootService",
                    "Name": "Redfish Root Service",
                    "RedfishVersion": "1.0.0",
                    "Systems": {"@odata.id": "/redfish/v1/Systems"},
                }
            elif path == "/redfish/v1/Systems":
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
                        "error": {"code": "Base.1.0.GeneralError", "message": f"Failed to retrieve VM list: {str(e)}"}
                    }
            elif path.startswith("/redfish/v1/Systems/"):
                if len(parts) == 5 and parts[4].isdigit():  # /redfish/v1/Systems/<vm_id>
                    vm_id = int(parts[4])
                    response = get_vm_status(proxmox, vm_id)
                    if isinstance(response, tuple):
                        response, status_code = response
                # START NEW CODE: Handle /redfish/v1/Systems/<vm_id>/Bios
                elif len(parts) == 6 and parts[5] == "Bios":  # /redfish/v1/Systems/<vm_id>/Bios
                    vm_id = int(parts[4])
                    response = get_bios(proxmox, vm_id)
                    if isinstance(response, tuple):
                        response, status_code = response
                # END NEW CODE
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
            # --- New: Managers/…/VirtualMedia (Metal3/Ironic path) -----------------
            elif path.startswith("/redfish/v1/Managers/") and len(parts) == 6 and parts[5] == "VirtualMedia":
                # /redfish/v1/Managers/1/VirtualMedia - VirtualMedia collection
                manager_id = parts[4]  # usually "1"
                vm_id = int(manager_id)  # map Manager-ID → VM-ID
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
                # /redfish/v1/Managers/1/VirtualMedia/Cd - VirtualMedia detail
                manager_id = parts[4]  # usually "1"
                vm_id = int(manager_id)  # map Manager-ID → VM-ID
                response = get_virtual_media(proxmox, int(vm_id))
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
        logger.debug(f"GET Response: path={self.path}, status={status_code}, body={json.dumps(response)}")

    def do_POST(self) -> None:
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
        headers_str = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        logger.debug(
            f"POST Request: path={self.path}\nHeaders:\n{headers_str}\nPayload:\n{json.dumps(payload, indent=2)}"
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
                    sessions[token] = {"username": username, "password": password, "created": time.time()}
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
                            f"POST Response: path={self.path}, status={status_code}, body={json.dumps(response)}"
                        )
                        return

                    data = json.loads(post_data.decode("utf-8"))
                    if path.startswith("/redfish/v1/Systems/") and "/Actions/ComputerSystem.Reset" in path:
                        vm_id = path.split("/")[4]

                        # Check user permissions for this VM
                        logger.info(f"Temporarily bypassing permission check for user {username} on VM {vm_id}")
                        # if not check_user_vm_permission(proxmox, username, vm_id):
                        #     status_code = 403
                        #     response = {
                        #         "error": {
                        #             "code": "Base.1.0.InsufficientPrivilege",
                        #             "message": f"User {username} does not have permission to access VM {vm_id}"
                        #         }
                        #     }
                        # else:
                        reset_type = data.get("ResetType", "")
                        if reset_type == "On":
                            response, status_code = power_on(proxmox, int(vm_id))
                        elif reset_type == "GracefulShutdown":
                            response, status_code = power_off(proxmox, int(vm_id))
                        elif reset_type == "ForceOff":
                            response, status_code = stop_vm(proxmox, int(vm_id))
                        elif reset_type == "GracefulRestart":
                            response, status_code = reboot(proxmox, int(vm_id))
                        elif reset_type == "ForceRestart":
                            response, status_code = reset_vm(proxmox, int(vm_id))
                        elif reset_type == "Pause":
                            response, status_code = suspend_vm(proxmox, int(vm_id))
                        elif reset_type == "Resume":
                            response, status_code = resume_vm(proxmox, int(vm_id))
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
                        vm_id = path.split("/")[4]
                        iso_path = data.get("Image")
                        response, status_code = manage_virtual_media(proxmox, int(vm_id), "InsertMedia", iso_path)
                    elif (
                        path.startswith("/redfish/v1/Systems/")
                        and "/VirtualMedia/CDROM/Actions/VirtualMedia.EjectMedia" in path
                    ):
                        vm_id = path.split("/")[4]
                        response, status_code = manage_virtual_media(proxmox, int(vm_id), "EjectMedia")
                    # --- New: Managers/…/VirtualMedia (sushy default path) -----------------
                    elif (
                        path.startswith("/redfish/v1/Managers/")
                        and "/VirtualMedia/Cd/Actions/VirtualMedia.InsertMedia" in path
                    ):
                        manager_id = path.split("/")[4]  # usually "1"
                        iso_path = data.get("Image")
                        # map Manager-ID → VM-ID  (here we treat them as identical)
                        vm_id = manager_id
                        response, status_code = manage_virtual_media(proxmox, int(vm_id), "InsertMedia", iso_path)

                    elif (
                        path.startswith("/redfish/v1/Managers/")
                        and "/VirtualMedia/Cd/Actions/VirtualMedia.EjectMedia" in path
                    ):
                        manager_id = path.split("/")[4]
                        vm_id = manager_id
                        response, status_code = manage_virtual_media(proxmox, int(vm_id), "EjectMedia")
                    elif path.startswith("/redfish/v1/Systems/") and "/Actions/ComputerSystem.UpdateConfig" in path:
                        vm_id = path.split("/")[4]
                        config_data = data
                        response, status_code = update_vm_config(proxmox, int(vm_id), config_data)
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
        logger.debug(f"POST Response: path={self.path}, status={status_code}, body={json.dumps(response)}")

    def do_PATCH(self) -> None:
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
        headers_str = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        logger.debug(
            f"PATCH Request: path={self.path}\nHeaders:\n{headers_str}\nPayload:\n{json.dumps(payload, indent=2)}"
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
                logger.debug(f"PATCH Response: path={self.path}, status={status_code}, body={json.dumps(response)}")
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
                    # START NEW CODE: Handle sushy ironic drive's incorrect BootSourceOverrideMode request
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
                                f"PATCH Response: path={self.path}, status={status_code}, body={json.dumps(response)}"
                            )
                            return
                    # END NEW CODE
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

        logger.debug(f"PATCH Response: path={self.path}, status={status_code}, body={json.dumps(response)}")


# Server function (unchanged)
def run_server(port: int = 8000) -> None:
    server_address = ("", port)
    httpd = socketserver.TCPServer(server_address, RedfishRequestHandler)

    print(f"Redfish server running on port {port}...")
    httpd.serve_forever()


# Server function with configurable SSL certificates
def run_server_ssl(port: int = 443) -> None:
    server_address = ("", port)
    httpd = socketserver.TCPServer(server_address, RedfishRequestHandler)

    # Wrap the socket with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Check if certificate files exist
    if not os.path.exists(SSL_CERT_FILE):
        raise FileNotFoundError(f"SSL certificate file not found: {SSL_CERT_FILE}")
    if not os.path.exists(SSL_KEY_FILE):
        raise FileNotFoundError(f"SSL key file not found: {SSL_KEY_FILE}")

    # Load certificate chain
    if os.path.exists(SSL_CA_FILE):
        # Load certificate with CA bundle
        context.load_cert_chain(certfile=SSL_CERT_FILE, keyfile=SSL_KEY_FILE)
        context.load_verify_locations(cafile=SSL_CA_FILE)
        logger.info(f"SSL context loaded with certificate: {SSL_CERT_FILE}, key: {SSL_KEY_FILE}, CA: {SSL_CA_FILE}")
    else:
        # Load certificate without CA bundle
        context.load_cert_chain(certfile=SSL_CERT_FILE, keyfile=SSL_KEY_FILE)
        logger.info(f"SSL context loaded with certificate: {SSL_CERT_FILE}, key: {SSL_KEY_FILE}")

    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"Redfish server running on port {port} with SSL...")
    logger.info(f"Redfish server started on port {port} with SSL certificates")
    httpd.serve_forever()


def main() -> None:
    """Main entry point for the proxmox-redfish daemon."""
    parser = argparse.ArgumentParser(description="Proxmox Redfish Daemon - Redfish API for Proxmox VMs")
    parser.add_argument("--config", help="Path to configuration file (JSON format)")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )
    parser.add_argument("--port", type=int, help="Port to run the server on (overrides config)")
    parser.add_argument("--host", help="Host to bind to (default: 0.0.0.0)")

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=getattr(logging, args.log_level), format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    logger = logging.getLogger(__name__)

    # Load configuration
    config = {}

    # Load from config file if specified
    if args.config:
        try:
            with open(args.config, "r") as f:
                config = json.load(f)
            logger.info(f"Loaded configuration from {args.config}")
        except Exception as e:
            logger.error(f"Failed to load config file {args.config}: {e}")
            sys.exit(1)

    # Override with environment variables
    if os.getenv("PROXMOX_HOST"):
        config.setdefault("proxmox", {})["host"] = os.getenv("PROXMOX_HOST")
    if os.getenv("PROXMOX_USER"):
        config.setdefault("proxmox", {})["user"] = os.getenv("PROXMOX_USER")
    if os.getenv("PROXMOX_PASSWORD"):
        config.setdefault("proxmox", {})["password"] = os.getenv("PROXMOX_PASSWORD")
    if os.getenv("REDFISH_PORT"):
        port_value = os.getenv("REDFISH_PORT")
        if port_value:
            config.setdefault("redfish", {})["port"] = int(port_value)
    if os.getenv("SSL_CERT_FILE"):
        config.setdefault("redfish", {})["ssl_cert"] = os.getenv("SSL_CERT_FILE")
    if os.getenv("SSL_KEY_FILE"):
        config.setdefault("redfish", {})["ssl_key"] = os.getenv("SSL_KEY_FILE")
    if os.getenv("LOG_LEVEL"):
        config.setdefault("logging", {})["level"] = os.getenv("LOG_LEVEL")

    # Override with command line arguments
    if args.port:
        config.setdefault("redfish", {})["port"] = args.port
    if args.host:
        config.setdefault("redfish", {})["host"] = args.host

    # Set defaults
    config.setdefault("redfish", {}).setdefault("port", 8443)
    config.setdefault("redfish", {}).setdefault("host", "0.0.0.0")
    config.setdefault("logging", {}).setdefault("level", "INFO")

    # Validate required configuration
    proxmox_config = config.get("proxmox", {})
    if not all(key in proxmox_config for key in ["host", "user", "password"]):
        logger.error("Missing required Proxmox configuration: host, user, password")
        logger.error("Set via environment variables or config file")
        sys.exit(1)

    # Start the daemon
    try:
        logger.info("Starting Proxmox Redfish Daemon...")
        logger.info(f"Proxmox Host: {proxmox_config['host']}")
        logger.info(f"Redfish Port: {config['redfish']['port']}")

        # Check if SSL certificates are configured
        ssl_cert = config.get("redfish", {}).get("ssl_cert")
        ssl_key = config.get("redfish", {}).get("ssl_key")

        if ssl_cert and ssl_key:
            # Start SSL server
            logger.info("Starting Redfish server with SSL...")
            run_server_ssl(config["redfish"]["port"])
        else:
            # Start regular HTTP server
            logger.info("Starting Redfish server without SSL...")
            run_server(config["redfish"]["port"])

    except KeyboardInterrupt:
        logger.info("Shutting down Proxmox Redfish Daemon...")

    except Exception as e:
        logger.error(f"Failed to start daemon: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

__all__ = [
    "RedfishRequestHandler",
    "power_on",
    "power_off",
    "reboot",
    "reset_vm",
    "manage_virtual_media",
    "get_vm_status",
    "get_bios",
    "validate_token",
    "get_proxmox_api",
    "handle_proxmox_error",
    "reorder_boot_order",
    "_ensure_iso_available",
    "ProxmoxAPI",
    "sessions",
    "AUTH",
    "SECURE",
    "PROXMOX_HOST",
    "PROXMOX_USER",
    "PROXMOX_PASSWORD",
    "PROXMOX_NODE",
    "VERIFY_SSL",
]
