"""A refused ISO upload must not be completed by other means.

_ensure_iso_available falls back to writing the ISO straight into the
storage directory when the upload API call fails. That write happens as the
daemon's own OS user and does not consult Proxmox at all, so treating an
authorization refusal as a retryable fault would carry out exactly the
operation Proxmox just denied.
"""

import unittest
from unittest.mock import MagicMock, patch

from proxmoxer.core import ResourceException

from proxmox_redfish.proxmox.iso_manager import _ensure_iso_available

URL = "http://example.invalid/test.iso"


def resource_exception(status_code):
    return ResourceException(status_code, "Forbidden", "Permission check failed")


class IsoUploadRefusalTest(unittest.TestCase):
    def setUp(self):
        # A small, well-formed download so the function reaches the upload.
        self.response = MagicMock()
        self.response.iter_content.return_value = [b"iso-bytes"]
        self.response.raise_for_status.return_value = None

    def _run(self, upload_error):
        """Drive the function to the upload step and report what happened."""
        proxmox = MagicMock()
        proxmox.nodes.return_value.storage.return_value.upload.post.side_effect = upload_error

        with (
            patch("proxmox_redfish.proxmox.iso_manager.requests.get", return_value=self.response),
            patch("proxmox_redfish.proxmox.iso_manager.os.path.exists", return_value=False),
            patch("proxmox_redfish.proxmox.iso_manager.atomic_file_write") as copy,
            patch("proxmox_redfish.proxmox.iso_manager.os.makedirs"),
        ):
            raised = None
            try:
                _ensure_iso_available(proxmox, URL)
            except Exception as exc:  # noqa: BLE001 - the test inspects it
                raised = exc
            return copy, raised

    def test_403_does_not_fall_back_to_a_direct_write(self):
        copy, raised = self._run(resource_exception(403))
        copy.assert_not_called()
        self.assertIsInstance(raised, ResourceException)
        self.assertEqual(raised.status_code, 403)

    def test_401_does_not_fall_back_to_a_direct_write(self):
        copy, raised = self._run(resource_exception(401))
        copy.assert_not_called()
        self.assertIsInstance(raised, ResourceException)

    def test_transient_api_failure_still_falls_back(self):
        """The fallback exists for real faults; keep it working for those."""
        copy, raised = self._run(ResourceException(500, "Internal Server Error", "boom"))
        copy.assert_called_once()
        self.assertIsNone(raised)


if __name__ == "__main__":
    unittest.main()
