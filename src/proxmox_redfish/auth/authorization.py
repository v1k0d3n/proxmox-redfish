"""Authorization functions for the Proxmox Redfish daemon."""

from proxmoxer import ProxmoxAPI

from ..config.logging_config import logger


def check_user_vm_permission(proxmox: ProxmoxAPI, username: str, vm_id: int) -> bool:
    """
    Check if a user has permission to access a specific VM.
    Uses the root session to check user permissions.

    Args:
        proxmox: ProxmoxAPI instance (root session)
        username: Username to check permissions for
        vm_id: VM ID to check access to

    Returns:
        bool: True if user has permission, False otherwise
    """
    try:
        # Get access control list to check user permissions
        acl = proxmox.access.get()
        logger.debug(f"Checking permissions for user {username} on VM {vm_id}")
        if acl is None:
            logger.warning("No ACL data returned from Proxmox API")
            return False
        logger.debug(f"Found {len(acl)} ACL entries")

        # Check if user has any permissions that would allow VM access
        for entry in acl:
            entry_ugid = entry.get("ugid", "")
            entry_path = entry.get("path", "")
            logger.debug(f"ACL entry: ugid={entry_ugid}, path={entry_path}")

            if entry_ugid == username:
                # Check if the user has permissions for this VM
                if entry_path == f"/vms/{vm_id}" or entry_path.startswith(f"/vms/{vm_id}/"):
                    # User has direct permissions for this VM
                    logger.info(f"User {username} has direct permissions for VM {vm_id}")
                    return True
                elif entry_path == "/vms" or entry_path == "/":
                    # User has permissions for all VMs
                    logger.info(f"User {username} has global VM permissions")
                    return True
                elif entry_path.startswith("/nodes/") and f"/qemu/{vm_id}" in entry_path:
                    # User has node-level permissions for this VM
                    logger.info(f"User {username} has node-level permissions for VM {vm_id}")
                    return True

        # Also check if user is in any groups that have permissions
        if acl is not None:
            for entry in acl:
                entry_ugid = entry.get("ugid", "")
                if entry_ugid.startswith("@") and entry_ugid != username:
                    # This is a group entry, check if user is in this group
                    group_name = entry_ugid[1:]  # Remove @ prefix
                    try:
                        # Check if user is in this group
                        group_members = proxmox.access.groups(group_name).get()
                        if group_members is not None:
                            for member in group_members:
                                if member.get("userid") == username.split("!")[0]:  # Remove token part
                                    # User is in this group, check if group has VM permissions
                                    path = entry.get("path", "")
                                    if path == f"/vms/{vm_id}" or path.startswith(f"/vms/{vm_id}/"):
                                        logger.info(f"User {username} has group permissions for VM {vm_id}")
                                        return True
                                    elif path == "/vms" or path == "/":
                                        logger.info(f"User {username} has global group permissions")
                                        return True
                    except Exception:
                        # Group doesn't exist or other error, continue
                        pass

        logger.warning(f"User {username} does not have permissions for VM {vm_id}")
        return False

    except Exception as e:
        logger.warning(f"Failed to check permissions for user {username} on VM {vm_id}: {str(e)}")
        # In case of error, deny access for security
        return False
