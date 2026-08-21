"""Error handling utilities for the Proxmox Redfish daemon."""

import re
from typing import Any, Dict, Optional, Tuple, Union

from proxmoxer.core import ResourceException


# Proxmox answers 500 when a guest's configuration file is absent, which is
# what asking about a VM id that does not exist looks like. In Redfish terms
# the resource is simply missing, and the distinction matters to clients:
# a 5xx says the server failed and the request may be worth retrying, so an
# unknown id can stall a caller such as Ironic instead of failing outright.
#
# The match is deliberately narrow. Proxmox also answers 500 for a node it
# cannot resolve and for a storage that is not configured, and neither of
# those is a missing Redfish resource -- they are faults, and must stay 5xx.
class VMNotFound(LookupError):
    """No qemu guest with this id is visible to the caller.

    The cluster listing is filtered by the caller's permissions, so a guest
    that does not exist and a guest they may not see are indistinguishable
    from here. Both are reported as missing, which also avoids confirming
    that an id exists to someone with no rights to it.
    """


MISSING_GUEST_CONFIG = re.compile(r"Configuration file '[^']*/qemu-server/\d+\.conf' does not exist")


def handle_proxmox_error(
    operation: str, exception: Exception, vm_id: Optional[Union[str, int]] = None
) -> Tuple[Dict[str, Any], int]:
    """
    Handle Proxmox API exceptions and return a Redfish-compliant error response.

    Args:
        operation (str): The operation being performed (e.g., "Power On", "Reboot").
        exception (Exception): The exception raised by ProxmoxAPI (typically ResourceException).
        vm_id (int, optional): The VM ID, if applicable, for more specific error messages.

    Returns:
        tuple: (response_dict, status_code) for Redfish response.
    """
    if isinstance(exception, VMNotFound):
        return {
            "error": {
                "code": "Base.1.0.ResourceMissingAtURI",
                "message": f"{operation} failed: {exception}",
                "@Message.ExtendedInfo": [
                    {
                        "MessageId": "Base.1.0.ResourceMissingAtURI",
                        "Message": f"The resource{' for VM ' + str(vm_id) if vm_id is not None else ''} was not found.",
                    }
                ],
            }
        }, 404

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

    if status_code == 500 and MISSING_GUEST_CONFIG.search(message):
        status_code = 404
        # Proxmox names the configuration file it looked for, which exposes
        # the node's hostname and the layout of /etc/pve to any caller. The
        # useful part is simply that the system is not there.
        message = f"No such system{vm_context.replace(' for VM', ':')}" if vm_id is not None else "No such system"

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
