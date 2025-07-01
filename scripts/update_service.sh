#!/bin/bash

# Proxmox-Redfish Daemon Service Update Script

set -e

echo "Proxmox-Redfish Daemon Service Update"
echo "====================================="
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Backup existing service file
if [ -f "/etc/systemd/system/proxmox-redfish.service" ]; then
    echo "Backing up existing service file..."
    cp /etc/systemd/system/proxmox-redfish.service /etc/systemd/system/proxmox-redfish.service.backup
    echo "✓ Backup created: /etc/systemd/system/proxmox-redfish.service.backup"
fi

# Copy new service file
echo "Installing updated service file..."
cp config/proxmox-redfish.service /etc/systemd/system/

# Reload systemd
echo "Reloading systemd daemon..."
systemctl daemon-reload

# Check if service file is valid
echo "Validating service file..."
if systemctl cat proxmox-redfish.service > /dev/null 2>&1; then
    echo "✓ Service file is valid"
else
    echo "✗ Service file validation failed"
    exit 1
fi

# Show service status
echo
echo "Current service status:"
systemctl status proxmox-redfish.service --no-pager -l

echo
echo "Service update completed!"
echo
echo "To restart the service:"
echo "  sudo systemctl restart proxmox-redfish"
echo
echo "To check service logs:"
echo "  sudo journalctl -u proxmox-redfish -f"
echo
echo "To enable service on boot:"
echo "  sudo systemctl enable proxmox-redfish" 