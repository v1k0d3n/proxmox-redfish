"""Finding the node a guest runs on.

Every Proxmox call used to be aimed at a single configured node, so the
daemon could only manage guests on that node: anything elsewhere in a
cluster failed, and a guest that migrated stopped responding until the
setting was edited to match.
"""

import unittest
from unittest.mock import MagicMock, patch

from proxmox_redfish.proxmox import placement
from proxmox_redfish.proxmox.placement import VMNotFound, list_vm_ids, node_for, vm

CLUSTER = [
    {"vmid": 100, "node": "alpha", "type": "qemu", "name": "one"},
    {"vmid": 101, "node": "beta", "type": "qemu", "name": "two"},
    {"vmid": 102, "node": "gamma", "type": "qemu", "name": "three"},
    {"vmid": 200, "node": "alpha", "type": "lxc", "name": "a-container"},
]


def proxmox_with(resources=CLUSTER):
    proxmox = MagicMock()
    proxmox.cluster.resources.get.return_value = resources
    return proxmox


class ResolutionTest(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(placement, "PROXMOX_NODE", "")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_guest_is_found_on_its_own_node(self):
        proxmox = proxmox_with()
        self.assertEqual(node_for(proxmox, 100), "alpha")
        self.assertEqual(node_for(proxmox, 101), "beta")
        self.assertEqual(node_for(proxmox, 102), "gamma")

    def test_a_string_id_resolves(self):
        self.assertEqual(node_for(proxmox_with(), "101"), "beta")

    def test_an_unknown_id_is_reported_as_missing(self):
        with self.assertRaises(VMNotFound):
            node_for(proxmox_with(), 999)

    def test_a_non_numeric_id_is_reported_as_missing(self):
        with self.assertRaises(VMNotFound):
            node_for(proxmox_with(), "not-an-id")

    def test_the_endpoint_is_built_on_the_right_node(self):
        proxmox = proxmox_with()
        vm(proxmox, 101)
        proxmox.nodes.assert_called_once_with("beta")
        proxmox.nodes.return_value.qemu.assert_called_once_with(101)


class ContainersAreNotSystemsTest(unittest.TestCase):
    """/cluster/resources?type=vm returns containers as well as machines.

    They share the id namespace but are not reachable through the qemu
    endpoints this daemon uses, so publishing them would produce ids that
    fail on every subsequent call.
    """

    def setUp(self):
        patcher = patch.object(placement, "PROXMOX_NODE", "")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_containers_are_not_listed(self):
        self.assertEqual(list_vm_ids(proxmox_with()), [100, 101, 102])

    def test_a_container_id_does_not_resolve(self):
        with self.assertRaises(VMNotFound):
            node_for(proxmox_with(), 200)


class SingleNodeRestrictionTest(unittest.TestCase):
    """PROXMOX_NODE, when set, keeps the daemon to one node."""

    def test_only_that_node_is_listed(self):
        with patch.object(placement, "PROXMOX_NODE", "alpha"):
            self.assertEqual(list_vm_ids(proxmox_with()), [100])

    def test_a_guest_elsewhere_is_not_visible(self):
        with patch.object(placement, "PROXMOX_NODE", "alpha"):
            with self.assertRaises(VMNotFound):
                node_for(proxmox_with(), 101)

    def test_unset_covers_the_whole_cluster(self):
        with patch.object(placement, "PROXMOX_NODE", ""):
            self.assertEqual(list_vm_ids(proxmox_with()), [100, 101, 102])


class LookupCachingTest(unittest.TestCase):
    """A connection serves one request, so caching on it is request-scoped."""

    def setUp(self):
        patcher = patch.object(placement, "PROXMOX_NODE", "")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_repeated_lookups_query_once(self):
        proxmox = proxmox_with()
        for _ in range(5):
            node_for(proxmox, 100)
            node_for(proxmox, 101)
        proxmox.cluster.resources.get.assert_called_once_with(type="vm")

    def test_a_new_connection_looks_up_again(self):
        first, second = proxmox_with(), proxmox_with()
        node_for(first, 100)
        node_for(second, 100)
        first.cluster.resources.get.assert_called_once()
        second.cluster.resources.get.assert_called_once()

    def test_a_migrated_guest_is_found_on_the_next_request(self):
        moved = [dict(r, node="delta") if r["vmid"] == 100 else r for r in CLUSTER]
        self.assertEqual(node_for(proxmox_with(), 100), "alpha")
        self.assertEqual(node_for(proxmox_with(moved), 100), "delta")


class MalformedResponseTest(unittest.TestCase):
    def test_a_non_list_response_is_rejected(self):
        proxmox = MagicMock()
        proxmox.cluster.resources.get.return_value = {"unexpected": True}
        with self.assertRaises(TypeError):
            list_vm_ids(proxmox)

    def test_entries_without_a_node_are_skipped(self):
        with patch.object(placement, "PROXMOX_NODE", ""):
            proxmox = proxmox_with([{"vmid": 100, "type": "qemu"}])
            with self.assertRaises(VMNotFound):
                node_for(proxmox, 100)


if __name__ == "__main__":
    unittest.main()


class UnresolvableIdBecomesNotFoundTest(unittest.TestCase):
    """A guest that cannot be placed is a missing resource, not a fault.

    Resolution happens before any call reaches Proxmox, so these never
    produce a ResourceException and would otherwise be reported as 500.
    """

    def setUp(self):
        patcher = patch.object(placement, "PROXMOX_NODE", "")
        patcher.start()
        self.addCleanup(patcher.stop)

    def _status_for(self, vm_id):
        from proxmox_redfish.api.redfish_endpoints import get_vm_status

        result = get_vm_status(proxmox_with(), vm_id)
        self.assertIsInstance(result, tuple, "expected an error response")
        return result[1]

    def test_unknown_id_is_404(self):
        self.assertEqual(self._status_for(999), 404)

    def test_container_id_is_404(self):
        self.assertEqual(self._status_for(200), 404)

    def test_a_guest_the_caller_cannot_see_is_404(self):
        """The listing is permission-filtered, so absent and forbidden look alike."""
        with patch.object(placement, "PROXMOX_NODE", "alpha"):
            self.assertEqual(self._status_for(101), 404)

    def test_the_error_body_is_a_redfish_missing_resource(self):
        from proxmox_redfish.api.redfish_endpoints import get_vm_status

        response, _ = get_vm_status(proxmox_with(), 999)
        self.assertEqual(response["error"]["code"], "Base.1.0.ResourceMissingAtURI")
