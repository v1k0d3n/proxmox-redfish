"""Proxmox API client for the Proxmox Redfish daemon."""

from typing import Any

from proxmoxer import ProxmoxAPI

from ..auth.authentication import validate_token
from ..config.settings import (
    PROXMOX_HOST,
    PROXMOX_PASSWORD,
    PROXMOX_USER,
    VERIFY_SSL,
)


def get_proxmox_api(headers: Any) -> ProxmoxAPI:
    """Get a Proxmox API client instance."""
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
