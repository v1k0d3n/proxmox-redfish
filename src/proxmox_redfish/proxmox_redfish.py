#!/usr/bin/env python3
"""Backwards-compatible facade over the proxmox_redfish package.

This module used to hold the whole daemon. Its contents now live in
api/, auth/, config/, proxmox/, server/ and utils/, and this file
re-exports them so existing imports keep working:

    from proxmox_redfish.proxmox_redfish import power_on, validate_token

New code should import from the module that owns the name instead, and
so should anything that patches one:

    from proxmox_redfish.api.power_operations import power_on

Note for test authors: patching a name here rebinds it only on this
facade. The modules that call these functions resolve them in their own
namespace, so `patch("proxmox_redfish.proxmox_redfish.validate_token")`
no longer affects the request handler. Patch it where it is used --
`patch("proxmox_redfish.server.request_handler.validate_token")`.
"""

import os
import sys

# The deployed systemd unit still executes this file as a script:
#
#   python /opt/proxmox-redfish/src/proxmox_redfish/proxmox_redfish.py --port 8000
#
# Run that way there is no parent package, so the relative imports below
# would raise "attempted relative import with no known parent package"
# and the daemon would not come back after a restart. Put the source root
# on sys.path and adopt the package identity first, so that invocation
# keeps working for deployments that predate the packaged entry point.
if __package__ in (None, ""):  # pragma: no cover - only hit as a script
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import proxmox_redfish  # noqa: F401

    __package__ = "proxmox_redfish"

from proxmoxer import ProxmoxAPI

from .api.power_operations import (
    power_off,
    power_on,
    reboot,
    reset_vm,
    resume_vm,
    stop_vm,
    suspend_vm,
)
from .api.redfish_endpoints import (
    get_bios,
    get_controller_collection,
    get_drive_detail,
    get_ethernet_interface_collection,
    get_ethernet_interface_detail,
    get_manager,
    get_processor_collection,
    get_processor_detail,
    get_smbios_type1,
    get_storage_collection,
    get_storage_detail,
    get_virtual_media,
    get_vm_config,
    get_vm_status,
    get_volume_collection,
    parse_disk_size,
)
from .api.virtual_media import manage_virtual_media
from .auth.authentication import (
    authenticate_user,
    extract_credentials,
    qualify_username,
    sessions,
    validate_token,
)
from .config.logging_config import logger, setup_logging
from .config.settings import (
    AUTH,
    PROXMOX_API_PORT,
    PROXMOX_HOST,
    PROXMOX_ISO_STORAGE,
    PROXMOX_NODE,
    PROXMOX_PASSWORD,
    PROXMOX_USER,
    SSL_CA_FILE,
    SSL_CERT_FILE,
    SSL_KEY_FILE,
    VERIFY_SSL,
)
from .main import main
from .proxmox.client import build_proxmox_api, get_proxmox_api
from .proxmox.iso_manager import _ensure_iso_available
from .proxmox.vm_operations import update_vm_config
from .server.http_server import run_server
from .server.request_handler import RedfishRequestHandler
from .server.ssl_server import run_server_ssl
from .utils.boot_order import reorder_boot_order
from .utils.error_handling import handle_proxmox_error
from .utils.file_operations import (
    atomic_file_write,
    get_file_lock,
    iso_file_locks,
    iso_file_locks_lock,
    iso_operation_lock,
    safe_file_hash,
)

__all__ = [
    "AUTH",
    "PROXMOX_API_PORT",
    "PROXMOX_HOST",
    "PROXMOX_ISO_STORAGE",
    "PROXMOX_NODE",
    "PROXMOX_PASSWORD",
    "PROXMOX_USER",
    "ProxmoxAPI",
    "RedfishRequestHandler",
    "SSL_CA_FILE",
    "SSL_CERT_FILE",
    "SSL_KEY_FILE",
    "VERIFY_SSL",
    "_ensure_iso_available",
    "atomic_file_write",
    "authenticate_user",
    "build_proxmox_api",
    "extract_credentials",
    "get_bios",
    "get_controller_collection",
    "get_drive_detail",
    "get_ethernet_interface_collection",
    "get_ethernet_interface_detail",
    "get_file_lock",
    "get_manager",
    "get_processor_collection",
    "get_processor_detail",
    "get_proxmox_api",
    "get_smbios_type1",
    "get_storage_collection",
    "get_storage_detail",
    "get_virtual_media",
    "get_vm_config",
    "get_vm_status",
    "get_volume_collection",
    "handle_proxmox_error",
    "iso_file_locks",
    "iso_file_locks_lock",
    "iso_operation_lock",
    "logger",
    "main",
    "manage_virtual_media",
    "parse_disk_size",
    "qualify_username",
    "power_off",
    "power_on",
    "reboot",
    "reorder_boot_order",
    "reset_vm",
    "resume_vm",
    "run_server",
    "run_server_ssl",
    "safe_file_hash",
    "sessions",
    "setup_logging",
    "stop_vm",
    "suspend_vm",
    "update_vm_config",
    "validate_token",
]


if __name__ == "__main__":
    main()
