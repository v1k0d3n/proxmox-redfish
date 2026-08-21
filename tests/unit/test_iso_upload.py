"""The image goes up as the caller, and is never written around them.

The upload is the only route into the ISO storage, and it runs over the
caller's own API connection, so Proxmox is what decides whether that caller
may write there. An upload that fails has nowhere else to go.

Proxmox wants the image in the multipart field named ``filename``. Handing
it over as ``file`` beside a separate ``filename`` string is refused with an
empty "400 Bad Request", and the stored image takes its name from the file
on disk, so both of those are pinned here.
"""

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from proxmoxer.core import ResourceException

from proxmox_redfish.proxmox.iso_manager import _ensure_iso_available

URL = "http://example.invalid/test.iso"
CONTENTS = b"iso-bytes"


def resource_exception(status_code, message="failed"):
    return ResourceException(status_code, "Error", message)


class UploadTestCase(unittest.TestCase):
    def setUp(self):
        self.response = MagicMock()
        self.response.iter_content.return_value = [CONTENTS]
        self.response.raise_for_status.return_value = None

        self.proxmox = MagicMock()
        self.proxmox.nodes.return_value.tasks.return_value.status.get.return_value = {
            "status": "stopped",
            "exitstatus": "OK",
        }
        self.upload = self.proxmox.nodes.return_value.storage.return_value.upload

        # An empty directory stands in for the storage, so the image really
        # is absent and the fetch goes on to upload it.
        self.storage = tempfile.TemporaryDirectory()
        self.addCleanup(self.storage.cleanup)

    def _run(self, upload_error=None):
        """Drive the fetch to the upload step and report what happened."""
        if upload_error is not None:
            self.upload.post.side_effect = upload_error

        with (
            patch("proxmox_redfish.proxmox.iso_manager.requests.get", return_value=self.response),
            patch(
                "proxmox_redfish.proxmox.iso_manager.iso_directory",
                return_value=self.storage.name,
            ),
        ):
            try:
                return _ensure_iso_available(self.proxmox, URL, "node1"), None
            except Exception as exc:  # noqa: BLE001 - the test inspects it
                return None, exc


class TheImageGoesUpThroughTheAPITest(UploadTestCase):
    def test_the_image_is_uploaded(self):
        volid, raised = self._run()
        self.assertIsNone(raised)
        self.assertEqual(volid, "local:iso/test.iso")
        self.upload.post.assert_called_once()

    def test_the_image_is_sent_as_the_filename_field(self):
        """Proxmox reads the image out of ``filename``.

        Sending it as ``file`` is what produced the empty 400.
        """
        self._run()
        kwargs = self.upload.post.call_args.kwargs
        self.assertEqual(kwargs["content"], "iso")
        self.assertNotIn("file", kwargs)
        self.assertTrue(hasattr(kwargs["filename"], "read"))

    def test_the_stored_image_keeps_the_name_from_the_url(self):
        """Proxmox names the image after the file it is handed."""
        self._run()
        handed_over = self.upload.post.call_args.kwargs["filename"]
        self.assertEqual(os.path.basename(handed_over.name), "test.iso")

    def test_the_uploaded_bytes_are_the_downloaded_ones(self):
        recorded = {}

        def record(content, filename):
            filename.seek(0)
            recorded["body"] = filename.read()
            return "UPID:node1:0:0:0:imgcopy::user@pam:"

        self.upload.post.side_effect = record
        self._run()
        self.assertEqual(recorded["body"], CONTENTS)


class AFailedUploadHasNowhereElseToGoTest(UploadTestCase):
    """There is no second route into the storage.

    Every one of these used to end in a write performed by the daemon's own
    OS user, putting the image into a storage Proxmox may just have refused
    the caller. Each is reported now instead.
    """

    def test_a_refusal_is_reported(self):
        _, raised = self._run(resource_exception(403, "Permission check failed"))
        self.assertIsInstance(raised, ResourceException)
        self.assertEqual(raised.status_code, 403)

    def test_an_unauthorized_upload_is_reported(self):
        _, raised = self._run(resource_exception(401))
        self.assertIsInstance(raised, ResourceException)

    def test_a_bad_request_is_reported(self):
        _, raised = self._run(resource_exception(400, "Bad Request"))
        self.assertIsInstance(raised, ResourceException)

    def test_a_server_error_is_reported(self):
        _, raised = self._run(resource_exception(500, "Internal Server Error"))
        self.assertIsInstance(raised, ResourceException)

    def test_a_broken_connection_is_reported(self):
        _, raised = self._run(BrokenPipeError(32, "Broken pipe"))
        self.assertIsInstance(raised, BrokenPipeError)

    def test_nothing_is_left_in_the_storage_directory(self):
        for failure in (
            resource_exception(401),
            resource_exception(403),
            resource_exception(400),
        ):
            self._run(failure)
            self.assertEqual(os.listdir(self.storage.name), [])


class AnUploadTaskThatFailsIsReportedTest(UploadTestCase):
    def test_a_task_that_ends_badly_is_reported(self):
        self.proxmox.nodes.return_value.tasks.return_value.status.get.return_value = {
            "status": "stopped",
            "exitstatus": "copy failed",
        }
        _, raised = self._run()
        self.assertIsNotNone(raised)
        self.assertIn("copy failed", str(raised))


if __name__ == "__main__":
    unittest.main()
