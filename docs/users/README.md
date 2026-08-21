# User Guide - Redfish API Usage

This guide shows you how to use the Proxmox Redfish Daemon to manage your VMs through the Redfish API. The daemon provides a standardized Redfish interface that's compatible with tools like Metal3/Ironic and OpenShift ZTP.

## Getting Started

### Prerequisites

- Proxmox Redfish Daemon installed and running
- Access to the daemon's HTTPS endpoint (default: `https://your-proxmox-host:8443`)
- Valid Proxmox user credentials or API token
- `curl` command-line tool (or any HTTP client)

### Setup Environment Variables

To make the examples easier to use, set up these environment variables with your actual values:

```bash
# Set these variables with your actual values
export REDFISH_USER="your-user@pam"
export REDFISH_PASS="your-password-or-api-token"
export REDFISH_BASEURL="https://your-proxmox-host:8443"
export REDFISH_VMID="100"
export REDFISH_ISOURL="https://download.fedoraproject.org/pub/fedora/linux/releases/38/Workstation/x86_64/iso/Fedora-Workstation-Live-38-1.6.x86_64.iso"
```

**Note:** Replace the values above with your actual Proxmox credentials, host, VM ID, and ISO URL. All examples below use these variables for consistency and ease of use.

### Authentication

Every request is authenticated with HTTP Basic authentication, using a
Proxmox account or an API token belonging to one. The daemon then talks to
Proxmox as that account, so a caller can reach exactly the VMs their Proxmox
permissions allow. See "Proxmox Permissions" in the administrator guide for
the privileges an account needs.

## Authentication Examples

### Username and password

```bash
curl -k -u "${REDFISH_USER}:${REDFISH_PASS}" \
  "${REDFISH_BASEURL}/redfish/v1/Systems"
```

### API token

An API token is supplied through the same Basic authentication header. The
username carries the token id, and the password is the token's secret:

```bash
curl -k -u 'bmcadmin@pve!redfish:<token-secret>' \
  "${REDFISH_BASEURL}/redfish/v1/Systems"
```

Tokens are the better choice for automation. They are sent with each
request, so no ticket is exchanged first, and they can be revoked in Proxmox
without touching the account's password.

By default a token is limited to a subset of its owner's rights, so either
clear "Privilege Separation" on the token or grant it its own permissions.

### `X-Auth-Token` is not supported

Redfish defines `X-Auth-Token` as a session token issued by `SessionService`,
which this daemon does not implement. A request carrying that header is
rejected:

```
{"error": {"code": "Base.1.0.GeneralError",
           "message": "Basic Authentication required but no valid Authorization header provided"}}
```

A Proxmox API token is not an `X-Auth-Token` and cannot be used as one. Send
it through Basic authentication as shown above.

Session authentication is tracked in
[#4](https://github.com/v1k0d3n/proxmox-redfish/issues/4).

## System Discovery

### Get Redfish Service Root

```bash
curl -k -u "${REDFISH_USER}:${REDFISH_PASS}" \
  "${REDFISH_BASEURL}/redfish/v1/" | jq
```

**Response:**
```json
{
  "@odata.context": "/redfish/v1/$metadata#ServiceRoot.ServiceRoot",
  "@odata.id": "/redfish/v1/",
  "@odata.type": "#ServiceRoot.v1_0_0.ServiceRoot",
  "Id": "RootService",
  "Name": "Root Service",
  "Systems": {
    "@odata.id": "/redfish/v1/Systems"
  },
  "Managers": {
    "@odata.id": "/redfish/v1/Managers"
  }
}
```

### List All VMs (Systems)

```bash
curl -k -u "${REDFISH_USER}:${REDFISH_PASS}" \
  "${REDFISH_BASEURL}/redfish/v1/Systems" | jq
```

**Response:**
```json
{
  "@odata.context": "/redfish/v1/$metadata#ComputerSystemCollection.ComputerSystemCollection",
  "@odata.id": "/redfish/v1/Systems",
  "@odata.type": "#ComputerSystemCollection.ComputerSystemCollection",
  "Name": "Computer System Collection",
  "Members": [
    {
      "@odata.id": "/redfish/v1/Systems/100"
    },
    {
      "@odata.id": "/redfish/v1/Systems/101"
    }
  ],
  "Members@odata.count": 2
}
```

## Power Management

### Get VM Status

```bash
curl -k -u "${REDFISH_USER}:${REDFISH_PASS}" \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}" | jq
```

**Response:**
```json
{
  "@odata.context": "/redfish/v1/$metadata#ComputerSystem.ComputerSystem",
  "@odata.id": "/redfish/v1/Systems/100",
  "@odata.type": "#ComputerSystem.v1_0_0.ComputerSystem",
  "Id": "100",
  "Name": "test-vm-1",
  "SystemType": "Physical",
  "Status": {
    "State": "On",
    "Health": "OK"
  },
  "PowerState": "On",
  "Memory": {
    "@odata.id": "/redfish/v1/Systems/100/Memory",
    "TotalSystemMemoryGiB": 2.0
  },
  "Boot": {
    "BootSourceOverrideEnabled": "Once",
    "BootSourceOverrideTarget": "None",
    "BootSourceOverrideMode": "Legacy"
  }
}
```

### Power On VM

```bash
curl -k -X POST -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"ResetType": "On"}' \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/Actions/ComputerSystem.Reset" | jq
```

### Power Off VM (Graceful Shutdown)

```bash
curl -k -X POST -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"ResetType": "GracefulShutdown"}' \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/Actions/ComputerSystem.Reset" | jq
```

### Force Power Off VM

```bash
curl -k -X POST -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"ResetType": "ForceOff"}' \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/Actions/ComputerSystem.Reset" | jq
```

### Reboot VM (Graceful Restart)

```bash
curl -k -X POST -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"ResetType": "GracefulRestart"}' \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/Actions/ComputerSystem.Reset" | jq
```

### Hard Reset VM (Force Restart)

```bash
curl -k -X POST -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"ResetType": "ForceRestart"}' \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/Actions/ComputerSystem.Reset" | jq
```

### Pause VM

```bash
curl -k -X POST -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"ResetType": "Pause"}' \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/Actions/ComputerSystem.Reset" | jq
```

### Resume VM

```bash
curl -k -X POST -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"ResetType": "Resume"}' \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/Actions/ComputerSystem.Reset" | jq
```

## Virtual Media Operations

### Get Virtual Media Status

```bash
# Method 1: Systems endpoint (Metal3/Ironic style)
curl -k -u "${REDFISH_USER}:${REDFISH_PASS}" \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/VirtualMedia/Cd" | jq

# Method 2: Managers endpoint (Sushy default style)
curl -k -u "${REDFISH_USER}:${REDFISH_PASS}" \
  "${REDFISH_BASEURL}/redfish/v1/Managers/${REDFISH_VMID}/VirtualMedia/Cd" | jq
```

**Response:**
```json
{
  "@odata.context": "/redfish/v1/$metadata#VirtualMedia.VirtualMedia",
  "@odata.id": "/redfish/v1/Managers/100/VirtualMedia/Cd",
  "@odata.type": "#VirtualMedia.v1_0_0.VirtualMedia",
  "Id": "Cd",
  "Name": "Virtual CD",
  "MediaTypes": ["CD", "DVD"],
  "ConnectedVia": "Applet",
  "Inserted": false,
  "WriteProtected": true
}
```

### Insert ISO Image

```bash
# Method 1: Systems endpoint
curl -k -X POST -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d "{\"Image\": \"${REDFISH_ISOURL}\"}" \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/VirtualMedia/CDROM/Actions/VirtualMedia.InsertMedia" | jq

# Method 2: Managers endpoint
curl -k -X POST -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d "{\"Image\": \"${REDFISH_ISOURL}\"}" \
  "${REDFISH_BASEURL}/redfish/v1/Managers/${REDFISH_VMID}/VirtualMedia/Cd/Actions/VirtualMedia.InsertMedia" | jq
```

**Response:**
```json
{
  "@odata.context": "/redfish/v1/$metadata#Task.Task",
  "@odata.id": "/redfish/v1/TaskService/Tasks/UPID:pve:00001234:1234:5678:9012:test:qemu:100:user@pam:",
  "@odata.type": "#Task.v1_0_0.Task",
  "Id": "UPID:pve:00001234:1234:5678:9012:test:qemu:100:user@pam:",
  "Name": "Insert Media for VM 100",
  "TaskState": "Running",
  "TaskStatus": "OK",
  "Messages": [
    {
      "Message": "Mounted ISO local:iso/Fedora-Workstation-Live-38-1.6.x86_64.iso to VM 100"
    }
  ]
}
```

### Eject ISO Image

```bash
# Method 1: Systems endpoint
curl -k -X POST -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d '{}' \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/VirtualMedia/CDROM/Actions/VirtualMedia.EjectMedia" | jq

# Method 2: Managers endpoint
curl -k -X POST -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d '{}' \
  "${REDFISH_BASEURL}/redfish/v1/Managers/${REDFISH_VMID}/VirtualMedia/Cd/Actions/VirtualMedia.EjectMedia" | jq
```

## 🔧 Boot Configuration

### Get BIOS Information

```bash
curl -k -u "${REDFISH_USER}:${REDFISH_PASS}" \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/Bios" | jq
```

**Response:**
```json
{
  "@odata.context": "/redfish/v1/$metadata#Bios.Bios",
  "@odata.id": "/redfish/v1/Systems/100/Bios",
  "@odata.type": "#Bios.v1_0_0.Bios",
  "Id": "Bios",
  "Name": "BIOS Configuration",
  "FirmwareMode": "BIOS",
  "Attributes": {
    "BootMode": "Legacy",
    "BootOrder": "order=scsi0;ide2;net0"
  }
}
```

### Set Boot Mode (BIOS/UEFI)

```bash
# Set to UEFI mode
curl -k -X PATCH -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"FirmwareMode": "UEFI"}' \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/Bios" | jq

# Set to BIOS mode
curl -k -X PATCH -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"FirmwareMode": "BIOS"}' \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/Bios" | jq
```

### Configure Boot Order

```bash
# Set boot order to CD first
curl -k -X PATCH -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"Boot": {"BootSourceOverrideEnabled": "Once", "BootSourceOverrideTarget": "Cd"}}' \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}" | jq

# Set boot order to PXE first
curl -k -X PATCH -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"Boot": {"BootSourceOverrideEnabled": "Once", "BootSourceOverrideTarget": "Pxe"}}' \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}" | jq

# Set boot order to HDD first
curl -k -X PATCH -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"Boot": {"BootSourceOverrideEnabled": "Once", "BootSourceOverrideTarget": "Hdd"}}' \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}" | jq
```

## System Information

### Get Memory Information

```bash
curl -k -u "${REDFISH_USER}:${REDFISH_PASS}" \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/Memory" | jq
```

### Get Storage Information

```bash
curl -k -u "${REDFISH_USER}:${REDFISH_PASS}" \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/Storage" | jq
```

### Get Network Interface Information

```bash
curl -k -u "${REDFISH_USER}:${REDFISH_PASS}" \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/EthernetInterfaces" | jq
```

## Complete Workflow Examples

### Example 1: Deploy a VM with ISO Boot

```bash
#!/bin/bash

# Configuration (using environment variables)
echo "Starting VM deployment workflow..."

# 1. Check VM status
echo "Checking VM status..."
curl -k -s -u "${REDFISH_USER}:${REDFISH_PASS}" \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}" | jq '.PowerState'

# 2. Power off if running
echo "Powering off VM if running..."
curl -k -X POST -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"ResetType": "ForceOff"}' \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/Actions/ComputerSystem.Reset"

# 3. Wait for power off
sleep 10

# 4. Insert ISO
echo "Inserting ISO..."
curl -k -X POST -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d "{\"Image\": \"${REDFISH_ISOURL}\"}" \
  "${REDFISH_BASEURL}/redfish/v1/Managers/${REDFISH_VMID}/VirtualMedia/Cd/Actions/VirtualMedia.InsertMedia"

# 5. Set boot order to CD
echo "Setting boot order to CD..."
curl -k -X PATCH -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"Boot": {"BootSourceOverrideEnabled": "Once", "BootSourceOverrideTarget": "Cd"}}' \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}"

# 6. Power on VM
echo "Powering on VM..."
curl -k -X POST -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"ResetType": "On"}' \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/Actions/ComputerSystem.Reset"

echo "Deployment workflow completed!"
```

### Example 2: Metal3/Ironic Integration

```bash
#!/bin/bash

# Metal3/Ironic style API calls (using environment variables)

# Get system information (Metal3 style)
curl -k -u "${REDFISH_USER}:${REDFISH_PASS}" \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}"

# Get virtual media (Metal3 style)
curl -k -u "${REDFISH_USER}:${REDFISH_PASS}" \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/VirtualMedia/Cd"

# Insert media (Metal3 style)
curl -k -X POST -u "${REDFISH_USER}:${REDFISH_PASS}" \
  -H "Content-Type: application/json" \
  -d "{\"Image\": \"${REDFISH_ISOURL}\"}" \
  "${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}/VirtualMedia/CDROM/Actions/VirtualMedia.InsertMedia"
```

## Error Handling

### Common HTTP Status Codes

- **200 OK**: Request successful
- **202 Accepted**: Operation accepted (async task)
- **400 Bad Request**: Invalid request parameters
- **401 Unauthorized**: Authentication required
- **404 Not Found**: Resource not found
- **500 Internal Server Error**: Server error

### Error Response Format

```json
{
  "error": {
    "code": "Base.1.0.GeneralError",
    "message": "Detailed error message",
    "@Message.ExtendedInfo": [
      {
        "MessageId": "Base.1.0.PropertyValueNotInList",
        "Message": "Extended error information",
        "Severity": "Warning",
        "Resolution": "How to fix the issue"
      }
    ]
  }
}
```

## Integration Examples

### OpenShift ZTP Integration

The daemon is compatible with OpenShift Zero Touch Provisioning (ZTP). Configure your ZTP hub to use the Redfish endpoints:

```yaml
# Example ZTP configuration
apiVersion: ran.openshift.io/v1
kind: ZTPPolicy
metadata:
  name: example-policy
spec:
  targets:
    - name: vm-${REDFISH_VMID}
      redfish:
        endpoint: ${REDFISH_BASEURL}/redfish/v1/Systems/${REDFISH_VMID}
        username: ${REDFISH_USER}
        password: ${REDFISH_PASS}
```

### Metal3/Ironic Integration

For Metal3/Ironic integration, use the Managers endpoint style:

```yaml
# Example Ironic configuration
ironic:
  redfish:
    endpoint: ${REDFISH_BASEURL}/redfish/v1/Managers/${REDFISH_VMID}
    username: ${REDFISH_USER}
    password: ${REDFISH_PASS}
```

## Best Practices

1. **Use API Tokens**: For automation, use API tokens instead of passwords
2. **Check Status**: Always verify VM status before operations
3. **Handle Async Operations**: Some operations return 202 status with task IDs
4. **Error Handling**: Implement proper error handling for all API calls
5. **SSL Verification**: In production, use proper SSL certificates
6. **Rate Limiting**: Don't overwhelm the API with rapid requests

## Additional Resources

- [Redfish Specification](https://www.dmtf.org/standards/redfish)
- [Metal3 Documentation](https://metal3.io/documentation/)
- [OpenShift ZTP Guide](https://docs.openshift.com/container-platform/4.12/installing/installing_bare_metal/installing-bare-metal.html)
- [Proxmox VE API Documentation](https://pve.proxmox.com/pve-docs/api-viewer/) 