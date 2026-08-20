"""Authentication functions for the Proxmox Redfish daemon."""

import base64
import time
from typing import Any, Tuple

import requests

from ..config.logging_config import logger
from ..config.settings import (
    AUTH,
    PROXMOX_API_PORT,
    PROXMOX_HOST,
    VERIFY_SSL,
)

# In-memory session store
sessions: dict[str, dict[str, Any]] = {}


def get_credentials(token: str) -> Tuple[str, str]:
    """Get credentials for a given token."""
    if token in sessions:
        session = sessions[token]
        return session["username"], session["password"]
    raise Exception("No credentials found for token")


def qualify_username(username: str) -> str:
    """Append the default realm when the caller omitted one.

    An API token identity is `user@realm!tokenid`, so the realm test has to
    look at the part before the "!" -- otherwise "alice!mytoken" would be
    rewritten to "alice!mytoken@pam", which is not a valid identity.
    """
    user, sep, token_name = username.partition("!")
    if "@" not in user:
        user += "@pam"
    return f"{user}{sep}{token_name}"


def extract_credentials(headers: Any) -> Tuple[str, str]:
    """Return the caller's (username, secret) from the Authorization header.

    The secret is either a password or an API token value, depending on
    whether the username carries a "!" token id. Callers use this to open a
    Proxmox connection *as the caller*, so that Proxmox applies its own
    permissions rather than this daemon reimplementing them.
    """
    auth_header = headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Basic "):
        raise ValueError("Basic Authentication required but no valid Authorization header provided")
    try:
        decoded = base64.b64decode(auth_header.split(" ")[1]).decode("utf-8")
        username, secret = decoded.split(":", 1)
    except Exception as exc:
        raise ValueError(f"Invalid Basic Authentication format: {exc}")
    return qualify_username(username), secret


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
            url = f"https://{PROXMOX_HOST}:{PROXMOX_API_PORT}/api2/json/version"

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
            url = f"https://{PROXMOX_HOST}:{PROXMOX_API_PORT}/api2/json/access/ticket"

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


def validate_token(headers: Any) -> Tuple[bool, str]:
    """Validate authentication token from request headers."""
    if AUTH is None:
        return True, "No auth required"
    elif AUTH == "Basic":
        auth_header = headers.get("Authorization")
        if auth_header and auth_header.startswith("Basic "):
            try:
                credentials = base64.b64decode(auth_header.split(" ")[1]).decode("utf-8")
                username, password = credentials.split(":", 1)
                username = qualify_username(username)
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
