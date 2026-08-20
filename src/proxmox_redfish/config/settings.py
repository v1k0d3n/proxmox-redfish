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

# SSL certificate configuration
SSL_CERT_FILE = os.getenv("SSL_CERT_FILE", "/opt/redfish_daemon/config/ssl/server.crt")
SSL_KEY_FILE = os.getenv("SSL_KEY_FILE", "/opt/redfish_daemon/config/ssl/server.key")
SSL_CA_FILE = os.getenv("SSL_CA_FILE", "/opt/redfish_daemon/config/ssl/ca.crt")  # Optional CA bundle

# Authentication mode. Only "Basic" is implemented; see the X-Auth-Token issue.
AUTH = "Basic"
