"""Error handling utilities for the Proxmox Redfish daemon."""

from typing import Any, Dict, Optional, Tuple, Union

from proxmoxer.core import ResourceException


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
