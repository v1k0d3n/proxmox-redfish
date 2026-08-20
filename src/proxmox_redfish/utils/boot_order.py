"""Boot order management utilities for the Proxmox Redfish daemon."""

from proxmoxer import ProxmoxAPI

from ..config.logging_config import logger
from ..config.settings import PROXMOX_NODE


def reorder_boot_order(proxmox: ProxmoxAPI, vm_id: int, current_order: str, target: str) -> str:
    """
    Reorder Proxmox boot devices based on Redfish target, preserving all devices including multiple hard drives.
    Returns the new boot order string for Proxmox config.
    """
    try:
        config = proxmox.nodes(PROXMOX_NODE).qemu(vm_id).config.get()
        if config is None:
            raise ValueError("Failed to retrieve VM configuration")

        # Parse current boot order
        devices = current_order.split(";") if current_order else []
        # Initialize device lists
        disk_devs = []
        cd_dev = None
        net_dev = None

        # Check for hard drives and CD-ROMs (SCSI, SATA, IDE)
        for dev_type in ["scsi", "sata", "ide"]:
            for i in range(4):  # ide0-3, scsi0-3, sata0-3 (simplified range)
                dev_key = f"{dev_type}{i}"
                if dev_key in config:
                    dev_value = config[dev_key]
                    if "media=cdrom" in dev_value:
                        cd_dev = dev_key  # CD-ROM found
                    elif dev_type in ["scsi", "sata"] or (dev_type == "ide" and "media=cdrom" not in dev_value):
                        disk_devs.append(dev_key)  # Hard drive found

        # Check for network devices
        for i in range(4):  # net0-3 (simplified range)
            net_key = f"net{i}"
            if net_key in config:
                net_dev = net_key
                break

        # Build the full list of available devices, preserving all from config and current order
        available_devs = [d for d in devices if d in config] if devices else []
        for dev in disk_devs + ([cd_dev] if cd_dev else []) + ([net_dev] if net_dev else []):
            if dev and dev not in available_devs:
                available_devs.append(dev)

        # Validate the target device availability
        if target == "Pxe" and not net_dev:
            raise ValueError("No network device available for Pxe boot")
        elif target == "Cd" and not cd_dev:
            raise ValueError("No CD-ROM device available for Cd boot")
        elif target == "Hdd" and not disk_devs:
            raise ValueError("No hard disk device available for Hdd boot")

        # Reorder based on target, keeping all devices
        new_order = []
        if target == "Pxe" and net_dev:
            new_order = [net_dev] + [d for d in available_devs if d != net_dev]
        elif target == "Cd" and cd_dev:
            new_order = [cd_dev] + [d for d in available_devs if d != cd_dev]
        elif target == "Hdd" and disk_devs:
            primary_disk = disk_devs[0]
            new_order = [primary_disk] + [d for d in available_devs if d != primary_disk]
        else:
            # This should not be reached due to earlier validation
            new_order = available_devs

        # Remove duplicates and ensure valid devices only
        unique_devices = list(dict.fromkeys(new_order))
        result = ";".join(unique_devices) if unique_devices else ""
        logger.debug(f"Computed new boot order for VM {vm_id}: {result}")
        return result
    except Exception as e:
        logger.error(f"Failed to reorder boot order for VM {vm_id}: {str(e)}")
        raise
