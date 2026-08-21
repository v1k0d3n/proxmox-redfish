"""A refused upload is never worked around.

When the upload API fails, the image is written into the storage directory
instead. That is load bearing rather than a nicety: the upload API rejects
the request outright on at least some installations, so without it virtual
media does not work there at all.

The write runs as the daemon's own OS user and does not consult Proxmox, so
it must never happen after a refusal. The upload is where Proxmox decides
whether the caller may write to this storage; falling back past a 401 or 403
would carry out precisely the operation that was denied.
"""

import unittest
from unittest.mock import MagicMock, patch

from proxmoxer.core import ResourceException

from proxmox_redfish.proxmox.iso_manager import _ensure_iso_available

# Patched where it is used: iso_manager binds the name at import, so patching
# it in utils.file_operations would not reach this call.

URL = "http://example.invalid/test.iso"


def resource_exception(status_code, message="failed"):
    return ResourceException(status_code, "Error", message)


class RefusalsAreNeverWorkedAroundTest(unittest.TestCase):
    def setUp(self):
        self.response = MagicMock()
        self.response.iter_content.return_value = [b"iso-bytes"]
        self.response.raise_for_status.return_value = None

    def _run(self, upload_error):
        """Drive the fetch to the upload step and report what happened."""
        proxmox = MagicMock()
        proxmox.storage.get.return_value = [{"storage": "local", "type": "dir", "path": "/var/lib/vz"}]
        proxmox.nodes.return_value.storage.return_value.upload.post.side_effect = upload_error

        with (
            patch("proxmox_redfish.proxmox.iso_manager.requests.get", return_value=self.response),
            patch("proxmox_redfish.proxmox.iso_manager.os.path.exists", return_value=False),
            patch("proxmox_redfish.proxmox.iso_manager.atomic_file_write") as copy,
            patch("proxmox_redfish.proxmox.iso_manager.os.makedirs"),
        ):
            raised = None
            try:
                _ensure_iso_available(proxmox, URL, "node1")
            except Exception as exc:  # noqa: BLE001 - the test inspects it
                raised = exc
            return copy, raised

    def test_a_refusal_is_reported(self):
        copy, raised = self._run(resource_exception(403, "Permission check failed"))
        copy.assert_not_called()
        self.assertIsInstance(raised, ResourceException)
        self.assertEqual(raised.status_code, 403)

    def test_an_unauthorized_upload_is_reported(self):
        copy, raised = self._run(resource_exception(401))
        copy.assert_not_called()
        self.assertIsInstance(raised, ResourceException)

    def test_nothing_is_written_after_a_refusal(self):
        for refusal in (resource_exception(401), resource_exception(403)):
            copy, _ = self._run(refusal)
            copy.assert_not_called()


class OtherFailuresFallBackTest(unittest.TestCase):
    """The upload API is rejected outright on some installations.

    A 1 KiB file comes back "400 Bad Request" with an empty error body there,
    on both proxmoxer 2.2 and 2.3, so the direct write is what makes virtual
    media work at all. It is reached only by a caller Proxmox did not refuse.
    """

    setUp = RefusalsAreNeverWorkedAroundTest.setUp
    _run = RefusalsAreNeverWorkedAroundTest._run

    def test_a_bad_request_falls_back(self):
        copy, raised = self._run(resource_exception(400, "Bad Request"))
        copy.assert_called_once()
        self.assertIsNone(raised)

    def test_a_broken_connection_falls_back(self):
        copy, raised = self._run(BrokenPipeError(32, "Broken pipe"))
        copy.assert_called_once()
        self.assertIsNone(raised)

    def test_a_server_error_falls_back(self):
        copy, raised = self._run(resource_exception(500, "Internal Server Error"))
        copy.assert_called_once()
        self.assertIsNone(raised)


if __name__ == "__main__":
    unittest.main()
