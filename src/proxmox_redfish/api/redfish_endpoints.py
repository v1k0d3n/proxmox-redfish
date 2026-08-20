"""Redfish API endpoints for the Proxmox Redfish daemon."""

import base64
import binascii
from typing import Any, Dict, Tuple, Union

from proxmoxer import ProxmoxAPI

from ..config.settings import PROXMOX_NODE
from ..utils.error_handling import handle_proxmox_error


def get_vm_status(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """Get VM status information."""
    try:
        status = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).status.current.get()
        if status is None:
            return handle_proxmox_error("VM status retrieval", Exception("Failed to retrieve VM status"), vm_id)

        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error("VM status retrieval", Exception("Failed to retrieve VM configuration"), vm_id)

        # Map Proxmox status to Redfish power state
        proxmox_status = status.get("status", "unknown")
        if proxmox_status == "running":
            power_state = "On"
            health = "OK"
        elif proxmox_status == "stopped":
            power_state = "Off"
            health = "OK"
        elif proxmox_status == "paused":
            power_state = "Paused"
            health = "Warning"
        else:
            power_state = "Unknown"
            health = "Critical"

        # Add Memory field as expected by tests
        memory_mb = config.get("memory", 0)
        try:
            memory_mb = float(memory_mb)
        except (ValueError, TypeError):
            memory_mb = 0
        memory_gib = memory_mb / 1024.0
        memory_field = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Memory",
            "TotalSystemMemoryGiB": round(memory_gib, 2),
        }

        # Add Boot field as expected by tests
        boot_order = config.get("boot", "")
        boot_field = {
            "BootSourceOverrideEnabled": "Once",  # or "Continuous"/"Disabled" as appropriate
            "BootSourceOverrideTarget": "None",  # Could be "Pxe", "Cd", "Hdd", etc.
            "BootSourceOverrideMode": "UEFI" if config.get("bios") == "ovmf" else "Legacy",
            "BootSourceOverrideTarget@Redfish.AllowableValues": ["Pxe", "Cd", "Hdd"],
            "BootSourceOverrideMode@Redfish.AllowableValues": ["UEFI", "Legacy"],
            "BootOrder": boot_order,
        }

        # Add Actions field as expected by tests
        actions_field = {
            "#ComputerSystem.Reset": {
                "target": f"/redfish/v1/Systems/{vm_id}/Actions/ComputerSystem.Reset",
                "ResetType@Redfish.AllowableValues": [
                    "On",
                    "ForceOff",
                    "GracefulShutdown",
                    "GracefulRestart",
                    "ForceRestart",
                    "Nmi",
                    "PowerCycle",
                ],
            }
        }

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}",
            "@odata.type": "#ComputerSystem.v1_0_0.ComputerSystem",
            "Id": str(vm_id),
            "Name": config.get("name", f"VM-{vm_id}"),
            "SystemType": "Physical",
            "Status": {"State": power_state, "Health": health},
            "PowerState": power_state,
            "Bios": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Bios"},
            "Processors": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Processors"},
            "Memory": memory_field,
            "Storage": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage"},
            "EthernetInterfaces": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/EthernetInterfaces"},
            "Boot": boot_field,
            "Actions": actions_field,
            "Links": {"ManagedBy": [{"@odata.id": f"/redfish/v1/Managers/{vm_id}"}]},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("VM status retrieval", e, vm_id)


def get_bios(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """Get BIOS information for a VM."""
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error("BIOS retrieval", Exception("Failed to retrieve VM configuration"), vm_id)
        firmware_type = config.get("bios", "seabios")
        firmware_mode = "BIOS" if firmware_type == "seabios" else "UEFI"

        # Minimal BIOS info with link to SMBIOS details
        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Bios",
            "@odata.type": "#Bios.v1_0_0.Bios",
            "Id": "Bios",
            "Name": "BIOS Settings",
            "FirmwareMode": firmware_mode,  # From previous enhancement
            "Attributes": {"BootOrder": config.get("boot", "order=scsi0;ide2;net0")},
            "Links": {"SMBIOS": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Bios/SMBIOS"}},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("BIOS retrieval", e, vm_id)


def get_smbios_type1(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """
    Retrieve SMBIOS Type 1 (System Information) data from Proxmox VM config,
    including firmware type (BIOS or UEFI).
    """
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error("SMBIOS retrieval", Exception("Failed to retrieve VM configuration"), vm_id)
        smbios1 = config.get("smbios1", "")
        firmware_type = config.get("bios", "seabios")  # Default to seabios if not specified

        # Map Proxmox bios setting to Redfish-friendly terms
        firmware_mode = "BIOS" if firmware_type == "seabios" else "UEFI"

        # Default SMBIOS values
        smbios_data = {
            "UUID": None,
            "Manufacturer": "Proxmox",
            "ProductName": "QEMU Virtual Machine",
            "Version": None,
            "SerialNumber": None,
            "SKUNumber": None,
            "Family": None,
        }

        # Parse smbios1 string if it exists
        if smbios1:
            smbios_entries = smbios1.split(",")
            for entry in smbios_entries:
                if "=" in entry:
                    key, value = entry.split("=", 1)

                    # Attempt to decode Base64 if it looks encoded
                    try:
                        decoded_value = base64.b64decode(value).decode("utf-8")
                        # Only use decoded value if it's valid UTF-8 and not a UUID
                        if key != "uuid" and decoded_value.isprintable():
                            value = decoded_value
                    except (binascii.Error, UnicodeDecodeError):
                        pass  # Keep original value if decoding fails

                    if key == "uuid":
                        smbios_data["UUID"] = value
                    elif key == "manufacturer":
                        smbios_data["Manufacturer"] = value
                    elif key == "product":
                        smbios_data["ProductName"] = value
                    elif key == "version":
                        smbios_data["Version"] = value
                    elif key == "serial":
                        smbios_data["SerialNumber"] = value
                    elif key == "sku":
                        smbios_data["SKUNumber"] = value
                    elif key == "family":
                        smbios_data["Family"] = value

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Bios/SMBIOS",
            "@odata.type": "#Bios.v1_0_0.Bios",
            "Id": "SMBIOS",
            "Name": "SMBIOS System Information",
            "FirmwareMode": firmware_mode,  # New field to indicate BIOS or UEFI
            "Attributes": {"SMBIOSType1": smbios_data},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("SMBIOS retrieval", e, vm_id)


def get_vm_config(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """
    Optional helper function for config details (not a standard Redfish endpoint).
    Returns a subset of data for custom use, but prefer get_vm_status for Redfish compliance.
    """
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Configuration retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )
        return {
            "Name": config.get("name", f"VM-{vm_id}"),
            "MemoryMB": config.get("memory", 0),
            "CPUCores": config.get("cores", 0),
            "Sockets": config.get("sockets", 1),
            "CDROM": config.get("ide2", "none"),
        }
    except Exception as e:
        return handle_proxmox_error("Configuration retrieval", e, vm_id)


def get_processor_collection(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """Get processor collection for a VM."""
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Processor collection retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )
        # Removed unused variables 'cores' and 'sockets'
        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Processors",
            "@odata.type": "#ProcessorCollection.ProcessorCollection",
            "Name": "Processor Collection",
            "Members": [{"@odata.id": f"/redfish/v1/Systems/{vm_id}/Processors/CPU1"}],
            "Members@odata.count": 1,
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Processor collection retrieval", e, vm_id)


def get_processor_detail(
    proxmox: ProxmoxAPI, vm_id: int, processor_id: str
) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """Get processor detail for a VM."""
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Processor detail retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )
        cores = config.get("cores", 1)
        sockets = config.get("sockets", 1)
        total_cores = cores * sockets

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Processors/{processor_id}",
            "@odata.type": "#Processor.v1_0_0.Processor",
            "Id": processor_id,
            "Name": f"Processor {processor_id}",
            "TotalCores": total_cores,
            "TotalThreads": total_cores,  # Assuming 1 thread per core
            "Status": {"State": "Enabled", "Health": "OK"},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Processor detail retrieval", e, vm_id)


def get_storage_collection(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """Get storage collection for a VM."""
    try:
        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage",
            "@odata.type": "#StorageCollection.StorageCollection",
            "Name": "Storage Collection",
            "Members": [{"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/1"}],
            "Members@odata.count": 1,
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Storage collection retrieval", e, vm_id)


def parse_disk_size(drive_info: Dict[str, Any]) -> str:
    """
    Parse disk size from Proxmox config string (e.g., 'size=16G') and convert to bytes.
    Returns size as a string representation in bytes.
    """
    try:
        size_str = drive_info.get("size", "0")
        if not size_str or size_str == "0":
            return "0"
        # Handle size strings like "16G", "500M", etc.
        if isinstance(size_str, str):
            size_str = size_str.upper()
            if size_str.endswith("G"):
                size_gb = float(size_str[:-1])
                size_bytes = int(size_gb * 1024 * 1024 * 1024)
                return str(size_bytes)
            elif size_str.endswith("M"):
                size_mb = float(size_str[:-1])
                size_bytes = int(size_mb * 1024 * 1024)
                return str(size_bytes)
            elif size_str.endswith("K"):
                size_kb = float(size_str[:-1])
                size_bytes = int(size_kb * 1024)
                return str(size_bytes)
            else:
                # Assume it's already in bytes
                return str(int(float(size_str)))
        else:
            return str(int(float(size_str)))
    except (ValueError, TypeError):
        return "0"


def get_storage_detail(
    proxmox: ProxmoxAPI, vm_id: int, storage_id: str
) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """Get storage detail for a VM."""
    try:
        if storage_id != "1":
            return {
                "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Storage {storage_id} not found"}
            }, 404

        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Storage detail retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )

        # Get disk drives from config
        drives = []
        for dev_type in ["scsi", "sata", "ide"]:
            for i in range(4):
                dev_key = f"{dev_type}{i}"
                if dev_key in config:
                    drives.append({"Id": dev_key, "Name": f"Drive {dev_key}"})

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}",
            "@odata.type": "#Storage.v1_0_0.Storage",
            "Id": storage_id,
            "Name": f"Storage {storage_id}",
            "Drives": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Drives"},
            "Volumes": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Volumes"},
            "Controllers": {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Controllers"},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Storage detail retrieval", e, vm_id)


def get_drive_detail(
    proxmox: ProxmoxAPI, vm_id: int, storage_id: str, drive_id: str
) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """Get drive detail for a VM."""
    try:
        if storage_id != "1":
            return {
                "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Storage {storage_id} not found"}
            }, 404

        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Drive detail retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )

        if drive_id not in config:
            return {"error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Drive {drive_id} not found"}}, 404

        drive_config = config[drive_id]
        size = parse_disk_size({"size": drive_config})

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Drives/{drive_id}",
            "@odata.type": "#Drive.v1_0_0.Drive",
            "Id": drive_id,
            "Name": f"Drive {drive_id}",
            "CapacityBytes": size,
            "Status": {"State": "Enabled", "Health": "OK"},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Drive detail retrieval", e, vm_id)


def get_volume_collection(
    proxmox: ProxmoxAPI, vm_id: int, storage_id: str
) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """Get volume collection for a VM."""
    try:
        if storage_id != "1":
            return {
                "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Storage {storage_id} not found"}
            }, 404

        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Volume collection retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )

        # Get volumes from config
        volumes = []
        for dev_type in ["scsi", "sata", "ide"]:
            for i in range(4):
                dev_key = f"{dev_type}{i}"
                if dev_key in config:
                    volumes.append({"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Volumes/{dev_key}"})

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Volumes",
            "@odata.type": "#VolumeCollection.VolumeCollection",
            "Name": "Volume Collection",
            "Members": volumes,
            "Members@odata.count": len(volumes),
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Volume collection retrieval", e, vm_id)


def get_controller_collection(
    proxmox: ProxmoxAPI, vm_id: int, storage_id: str
) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """Get controller collection for a VM."""
    try:
        if storage_id != "1":
            return {
                "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Storage {storage_id} not found"}
            }, 404

        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Controller collection retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )

        # Get controllers from config
        controllers = []
        for dev_type in ["scsi", "sata", "ide"]:
            for i in range(4):
                dev_key = f"{dev_type}{i}"
                if dev_key in config:
                    controllers.append(
                        {"@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Controllers/{dev_type}"}
                    )

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/Storage/{storage_id}/Controllers",
            "@odata.type": "#ControllerCollection.ControllerCollection",
            "Name": "Controller Collection",
            "Members": controllers,
            "Members@odata.count": len(controllers),
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Controller collection retrieval", e, vm_id)


def get_ethernet_interface_collection(
    proxmox: ProxmoxAPI, vm_id: int
) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """Get ethernet interface collection for a VM."""
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Ethernet interface collection retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )

        # Get network interfaces from config
        interfaces = []
        for i in range(4):
            net_key = f"net{i}"
            if net_key in config:
                interfaces.append({"@odata.id": f"/redfish/v1/Systems/{vm_id}/EthernetInterfaces/{net_key}"})

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/EthernetInterfaces",
            "@odata.type": "#EthernetInterfaceCollection.EthernetInterfaceCollection",
            "Name": "Ethernet Interface Collection",
            "Members": interfaces,
            "Members@odata.count": len(interfaces),
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Ethernet interface collection retrieval", e, vm_id)


def get_ethernet_interface_detail(
    proxmox: ProxmoxAPI, vm_id: int, interface_id: str
) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """Get ethernet interface detail for a VM."""
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Ethernet interface detail retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )

        if interface_id not in config:
            return {
                "error": {"code": "Base.1.0.ResourceMissingAtURI", "message": f"Interface {interface_id} not found"}
            }, 404

        response = {
            "@odata.id": f"/redfish/v1/Systems/{vm_id}/EthernetInterfaces/{interface_id}",
            "@odata.type": "#EthernetInterface.v1_0_0.EthernetInterface",
            "Id": interface_id,
            "Name": f"Interface {interface_id}",
            "Status": {"State": "Enabled", "Health": "OK"},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Ethernet interface detail retrieval", e, vm_id)


def get_virtual_media(proxmox: ProxmoxAPI, vm_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """Get virtual media information for a Proxmox VM."""
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error(
                "Virtual media retrieval", Exception("Failed to retrieve VM configuration"), vm_id
            )

        # Inserted is True only if ide2 is present, is a cdrom, and not 'none,media=cdrom'
        cd_configured = "ide2" in config and "media=cdrom" in config["ide2"] and not config["ide2"].startswith("none,")

        response = {
            "@odata.id": f"/redfish/v1/Managers/{vm_id}/VirtualMedia/Cd",
            "@odata.type": "#VirtualMedia.v1_0_0.VirtualMedia",
            "Id": "Cd",
            "Name": "Virtual CD",
            "MediaTypes": ["CD", "DVD"],
            "ConnectedVia": "Applet",
            "Inserted": cd_configured,
            "WriteProtected": True,
            "Actions": {
                "#VirtualMedia.InsertMedia": {
                    "target": f"/redfish/v1/Managers/{vm_id}/VirtualMedia/Cd/Actions/VirtualMedia.InsertMedia"
                },
                "#VirtualMedia.EjectMedia": {
                    "target": f"/redfish/v1/Managers/{vm_id}/VirtualMedia/Cd/Actions/VirtualMedia.EjectMedia"
                },
            },
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Virtual media retrieval", e, vm_id)


def get_manager(proxmox: ProxmoxAPI, manager_id: int) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int]]:
    """Get manager information for a Proxmox VM."""
    try:
        # Map manager_id to vm_id (they are the same in our implementation)
        vm_id = manager_id

        # Get VM config to verify it exists
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            return handle_proxmox_error("Manager retrieval", Exception("Failed to retrieve VM configuration"), vm_id)

        response = {
            "@odata.id": f"/redfish/v1/Managers/{manager_id}",
            "@odata.type": "#Manager.v1_0_0.Manager",
            "Id": str(manager_id),
            "Name": f"Manager for VM {vm_id}",
            "ManagerType": "BMC",
            "Status": {"State": "Enabled", "Health": "OK"},
            "VirtualMedia": {"@odata.id": f"/redfish/v1/Managers/{manager_id}/VirtualMedia"},
        }
        return response
    except Exception as e:
        return handle_proxmox_error("Manager retrieval", e, manager_id)
