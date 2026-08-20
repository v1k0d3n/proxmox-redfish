"""Configuration management for the Proxmox Redfish daemon."""

from .settings import (
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

__all__ = [
    "PROXMOX_HOST",
    "PROXMOX_USER",
    "PROXMOX_PASSWORD",
    "PROXMOX_NODE",
    "PROXMOX_API_PORT",
    "VERIFY_SSL",
    "PROXMOX_ISO_STORAGE",
    "SSL_CERT_FILE",
    "SSL_KEY_FILE",
    "SSL_CA_FILE",
    "AUTH",
]
