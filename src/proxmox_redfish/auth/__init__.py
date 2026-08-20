"""Authentication for the Proxmox Redfish daemon.

Authorization is not handled here. Connections are opened as the calling
user, so Proxmox evaluates its own ACLs and refuses what the caller may
not do. See proxmox.client.get_proxmox_api.
"""

from .authentication import (
    authenticate_user,
    validate_token,
)

__all__ = [
    "validate_token",
    "authenticate_user",
    "extract_credentials",
    "qualify_username",
]
