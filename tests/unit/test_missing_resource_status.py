"""An unknown VM id is a missing resource, not a server failure.

Proxmox answers 500 when a guest's configuration file is absent, which is
what asking about a VM id that does not exist looks like. Passing that
through unchanged tells the client the server broke and the request may be
worth retrying; Redfish clients such as Ironic can retry on 5xx, so an
unknown id stalls instead of failing outright.

Proxmox also answers 500 for genuine faults. Those must stay 5xx.
"""

import unittest

from proxmoxer.core import ResourceException

from proxmox_redfish.utils.error_handling import handle_proxmox_error


def proxmox_error(status_code, content):
    return ResourceException(status_code, "Internal Server Error", content)


class MissingGuestBecomesNotFoundTest(unittest.TestCase):
    def test_unknown_vm_id_is_404(self):
        exc = proxmox_error(500, "Configuration file 'nodes/n1/qemu-server/99999999.conf' does not exist")
        response, status = handle_proxmox_error("VM status retrieval", exc, 99999999)
        self.assertEqual(status, 404)
        self.assertEqual(response["error"]["code"], "Base.1.0.ResourceMissingAtURI")

    def test_a_container_id_is_also_404(self):
        """An LXC id is simply an id that is not a qemu guest."""
        exc = proxmox_error(500, "Configuration file 'nodes/n1/qemu-server/106.conf' does not exist")
        _, status = handle_proxmox_error("VM status retrieval", exc, 106)
        self.assertEqual(status, 404)

    def test_the_message_names_the_vm(self):
        exc = proxmox_error(500, "Configuration file 'nodes/n1/qemu-server/42.conf' does not exist")
        response, _ = handle_proxmox_error("VM status retrieval", exc, 42)
        self.assertIn("42", response["error"]["@Message.ExtendedInfo"][0]["Message"])

    def test_the_response_does_not_echo_proxmox_internals(self):
        """Proxmox names the file it looked for, exposing the node and /etc/pve layout."""
        exc = proxmox_error(500, "Configuration file 'nodes/secret-node-name/qemu-server/42.conf' does not exist")
        response, _ = handle_proxmox_error("VM status retrieval", exc, 42)
        rendered = str(response)
        self.assertNotIn("secret-node-name", rendered)
        self.assertNotIn("qemu-server", rendered)
        self.assertNotIn(".conf", rendered)


class GenuineFaultsStayServerErrorsTest(unittest.TestCase):
    """The mapping must not swallow real failures."""

    def test_unresolvable_node_stays_500(self):
        exc = proxmox_error(500, "hostname lookup 'nosuchnode' failed - failed to get address info")
        _, status = handle_proxmox_error("VM status retrieval", exc, 101)
        self.assertEqual(status, 500)

    def test_missing_storage_stays_500(self):
        """Also a 'does not exist', but a misconfiguration rather than a missing system."""
        exc = proxmox_error(500, "storage 'nosuchstore' does not exist")
        _, status = handle_proxmox_error("Virtual Media InsertMedia", exc, 101)
        self.assertEqual(status, 500)

    def test_qmp_failure_stays_500(self):
        exc = proxmox_error(500, "VM 101 qmp command 'query-status' failed - unable to connect")
        _, status = handle_proxmox_error("VM status retrieval", exc, 101)
        self.assertEqual(status, 500)

    def test_a_config_path_that_is_not_a_guest_stays_500(self):
        exc = proxmox_error(500, "Configuration file '/etc/pve/storage.cfg' does not exist")
        _, status = handle_proxmox_error("VM status retrieval", exc, 101)
        self.assertEqual(status, 500)


class OtherStatusesAreUntouchedTest(unittest.TestCase):
    def test_permission_denied_stays_403(self):
        exc = proxmox_error(403, "Permission check failed (/vms/101, VM.Audit)")
        response, status = handle_proxmox_error("VM status retrieval", exc, 101)
        self.assertEqual(status, 403)
        self.assertEqual(response["error"]["code"], "Base.1.0.InsufficientPrivilege")

    def test_proxmox_404_still_maps_to_404(self):
        exc = proxmox_error(404, "not found")
        _, status = handle_proxmox_error("VM status retrieval", exc, 101)
        self.assertEqual(status, 404)

    def test_non_proxmox_exception_is_still_500(self):
        _, status = handle_proxmox_error("VM status retrieval", ValueError("boom"), 101)
        self.assertEqual(status, 500)


if __name__ == "__main__":
    unittest.main()
