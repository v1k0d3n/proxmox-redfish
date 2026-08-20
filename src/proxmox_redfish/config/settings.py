"""Configuration settings for the Proxmox Redfish daemon."""

import os

# Proxmox configuration from environment variables with fallbacks
PROXMOX_HOST = os.getenv("PROXMOX_HOST", "pve-node-hostname")
PROXMOX_USER = os.getenv("PROXMOX_USER", "username")
PROXMOX_PASSWORD = os.getenv("PROXMOX_PASSWORD", "password")
PROXMOX_NODE = os.getenv("PROXMOX_NODE", "pve=-node-name")
PROXMOX_API_PORT = os.getenv("PROXMOX_API_PORT", "8006")
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