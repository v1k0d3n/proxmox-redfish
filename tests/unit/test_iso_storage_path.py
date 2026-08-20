"""ISO storage directory resolution.

The daemon used to hardcode a path for the storage named "local" and, for
anything else, read /nodes/{node}/storage/{name} expecting a mapping. That
endpoint returns a directory index of sub-endpoints, so the lookup produced
nothing and every storage other than "local" was unusable.

Nothing here should depend on a storage being called anything in
particular. Names below are arbitrary, and the cases are chosen to cover
the storage *types* an operator might actually configure.
"""

import unittest
from unittest.mock import MagicMock

from proxmox_redfish.proxmox.iso_manager import iso_directory


def proxmox_listing(entries):
    proxmox = MagicMock()
    proxmox.storage.get.return_value = entries
    return proxmox


class FileBackedStorageTest(unittest.TestCase):
    """Any storage Proxmox gives a filesystem path can hold ISOs.

    Proxmox mounts these under /mnt/pve/<name> (except `dir`, which has an
    operator-chosen path) and lays ISOs out at <path>/template/iso.
    """

    def test_directory_storage(self):
        proxmox = proxmox_listing([{"storage": "anyname", "type": "dir", "path": "/srv/vz"}])
        self.assertEqual(iso_directory(proxmox, "anyname"), "/srv/vz/template/iso")

    def test_nfs_storage(self):
        proxmox = proxmox_listing([{"storage": "anyname", "type": "nfs", "path": "/mnt/pve/anyname", "shared": 1}])
        self.assertEqual(iso_directory(proxmox, "anyname"), "/mnt/pve/anyname/template/iso")

    def test_cifs_storage(self):
        proxmox = proxmox_listing([{"storage": "anyname", "type": "cifs", "path": "/mnt/pve/anyname", "shared": 1}])
        self.assertEqual(iso_directory(proxmox, "anyname"), "/mnt/pve/anyname/template/iso")

    def test_cephfs_storage(self):
        proxmox = proxmox_listing([{"storage": "anyname", "type": "cephfs", "path": "/mnt/pve/anyname", "shared": 1}])
        self.assertEqual(iso_directory(proxmox, "anyname"), "/mnt/pve/anyname/template/iso")

    def test_glusterfs_storage(self):
        proxmox = proxmox_listing([{"storage": "anyname", "type": "glusterfs", "path": "/mnt/pve/anyname"}])
        self.assertEqual(iso_directory(proxmox, "anyname"), "/mnt/pve/anyname/template/iso")

    def test_the_storage_name_is_never_special_cased(self):
        """ "local" is only a default for PROXMOX_ISO_STORAGE, not a branch."""
        for name in ("local", "anyname", "iso-store", "a.b_c-1"):
            proxmox = proxmox_listing([{"storage": name, "type": "dir", "path": "/some/path"}])
            self.assertEqual(iso_directory(proxmox, name), "/some/path/template/iso")


class BlockStorageTest(unittest.TestCase):
    """Block storages have no filesystem path and cannot hold an ISO file.

    Proxmox reports path: null for these. The error should name the type so
    an operator can tell why their configured storage was rejected.
    """

    def _assert_rejected(self, storage_type):
        proxmox = proxmox_listing([{"storage": "anyname", "type": storage_type, "path": None}])
        with self.assertRaises(ValueError) as caught:
            iso_directory(proxmox, "anyname")
        self.assertIn(storage_type, str(caught.exception))

    def test_zfs_pool(self):
        self._assert_rejected("zfspool")

    def test_lvm_thin(self):
        self._assert_rejected("lvmthin")

    def test_ceph_rbd(self):
        self._assert_rejected("rbd")

    def test_missing_path_key_entirely(self):
        proxmox = proxmox_listing([{"storage": "anyname", "type": "iscsi"}])
        with self.assertRaises(ValueError):
            iso_directory(proxmox, "anyname")


class LookupTest(unittest.TestCase):
    def test_reads_the_storage_collection_not_the_item(self):
        """The item endpoint requires Datastore.Allocate; the collection does not."""
        proxmox = proxmox_listing([{"storage": "anyname", "type": "dir", "path": "/srv/iso"}])
        iso_directory(proxmox, "anyname")
        proxmox.storage.get.assert_called_once_with()
        proxmox.nodes.assert_not_called()

    def test_picks_the_requested_storage_out_of_several(self):
        proxmox = proxmox_listing(
            [
                {"storage": "first", "type": "dir", "path": "/one"},
                {"storage": "second", "type": "nfs", "path": "/two"},
                {"storage": "third", "type": "dir", "path": "/three"},
            ]
        )
        self.assertEqual(iso_directory(proxmox, "second"), "/two/template/iso")

    def test_storage_the_caller_cannot_see_is_reported_clearly(self):
        # The collection is ACL-filtered, so an invisible storage is simply absent.
        proxmox = proxmox_listing([{"storage": "visible", "type": "dir", "path": "/one"}])
        with self.assertRaises(ValueError) as caught:
            iso_directory(proxmox, "invisible")
        self.assertIn("invisible", str(caught.exception))

    def test_subdir_index_response_is_rejected(self):
        """The exact shape the old code accepted as 'no path'."""
        proxmox = MagicMock()
        proxmox.storage.get.return_value = {"subdir": "content"}
        with self.assertRaises(ValueError):
            iso_directory(proxmox, "anyname")


if __name__ == "__main__":
    unittest.main()
