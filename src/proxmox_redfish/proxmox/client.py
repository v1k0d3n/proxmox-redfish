"""Proxmox API client for the Proxmox Redfish daemon."""

from typing import Any

from proxmoxer import ProxmoxAPI

from ..auth.authentication import extract_credentials, validate_token
from ..config.settings import (
    PROXMOX_API_PORT,
    PROXMOX_HOST,
    VERIFY_SSL,
)

# Long enough to cover an ISO upload of a full installer image.
API_TIMEOUT = 1800


def build_proxmox_api(username: str, secret: str) -> ProxmoxAPI:
    """Open a Proxmox connection as the given identity.

    `username` is either `user@realm` with a password, or `user@realm!tokenid`
    with an API token value. proxmoxer authenticates each form differently:
    a password is exchanged for a ticket, while an API token is sent on every
    request and needs no ticket round trip.
    """
    port = int(PROXMOX_API_PORT)

    if "!" in username:
        user, token_name = username.split("!", 1)
        return ProxmoxAPI(
            PROXMOX_HOST,
            user=user,
            token_name=token_name,
            token_value=secret,
            verify_ssl=VERIFY_SSL,
            timeout=API_TIMEOUT,
            port=port,
        )

    return ProxmoxAPI(
        PROXMOX_HOST,
        user=username,
        password=secret,
        verify_ssl=VERIFY_SSL,
        timeout=API_TIMEOUT,
        port=port,
    )


def get_proxmox_api(headers: Any) -> ProxmoxAPI:
    """Open a Proxmox connection as the caller of the current request.

    Every Proxmox call made through this client carries the caller's own
    identity, so Proxmox applies its own ACLs and returns 403 for anything
    the caller may not touch. That is deliberate: this daemon does not
    evaluate permissions itself, because doing so means reimplementing
    Proxmox's permission model and getting it wrong.

    Connecting as a single privileged account instead would make every
    caller effectively that account.
    """
    valid, message = validate_token(headers)
    if not valid:
        raise Exception(f"Authentication failed: {message}")

    username, secret = extract_credentials(headers)

    try:
        return build_proxmox_api(username, secret)
    except Exception as e:
        raise Exception(f"Failed to connect to Proxmox API: {str(e)}")
