"""Drive the real request handler and assert nothing secret reaches the log.

test_redaction.py covers the helpers in isolation. This covers the wiring:
that the handler actually calls them on every path that logs a request or
a response. A helper that is correct but not called protects nothing.
"""

import base64
import logging
import unittest
from io import BytesIO
from unittest.mock import patch

from proxmox_redfish.server.request_handler import RedfishRequestHandler

PASSWORD = "hunter2-do-not-log-me"
USERNAME = "bmcadmin@pve"
BASIC_BLOB = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()


class CapturingHandler(logging.Handler):
    """Collects every formatted record so tests can search the whole log."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())

    @property
    def text(self):
        return "\n".join(self.messages)


class RedactionWiringTest(unittest.TestCase):
    """Exercises do_GET/do_POST/do_PATCH with credentials in the request."""

    def setUp(self):
        self.captured = CapturingHandler()
        self.logger = logging.getLogger("proxmox-redfish")
        self._old_level = self.logger.level
        self._old_propagate = self.logger.propagate
        self.logger.addHandler(self.captured)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

    def tearDown(self):
        self.logger.removeHandler(self.captured)
        self.logger.setLevel(self._old_level)
        self.logger.propagate = self._old_propagate

    def _drive(self, method, path, body=""):
        """Run one request through the handler without touching a socket."""
        handler = RedfishRequestHandler.__new__(RedfishRequestHandler)
        handler.path = path
        handler.rfile = BytesIO(body.encode("utf-8"))
        handler.wfile = BytesIO()
        handler.headers = {
            "Authorization": f"Basic {BASIC_BLOB}",
            "X-Auth-Token": "session-token-abc123",
            "Content-Length": str(len(body.encode("utf-8"))),
            "Content-Type": "application/json",
        }
        handler.send_response = lambda *a, **k: None
        handler.send_header = lambda *a, **k: None
        handler.end_headers = lambda *a, **k: None

        getattr(handler, f"do_{method}")()
        return self.captured.text

    def _assert_clean(self, log):
        self.assertNotIn(PASSWORD, log, "cleartext password reached the log")
        self.assertNotIn(BASIC_BLOB, log, "base64 Basic blob reached the log; it decodes to the password")
        self.assertNotIn("session-token-abc123", log, "session token reached the log")

    def test_get_does_not_log_credentials(self):
        # Unauthenticated service root still logs the request headers.
        self._assert_clean(self._drive("GET", "/redfish/v1"))

    def test_post_session_creation_does_not_log_password(self):
        body = '{"UserName": "%s", "Password": "%s"}' % (USERNAME, PASSWORD)
        log = self._drive("POST", "/redfish/v1/SessionService/Sessions", body)
        self._assert_clean(log)

    def test_patch_does_not_log_credentials(self):
        body = '{"Boot": {"BootSourceOverrideTarget": "Cd"}}'
        with patch("proxmox_redfish.server.request_handler.validate_token", return_value=(False, "denied")):
            log = self._drive("PATCH", "/redfish/v1/Systems/1001", body)
        self._assert_clean(log)

    def test_the_log_is_still_worth_reading(self):
        """Redaction must not reduce the logs to noise."""
        log = self._drive("GET", "/redfish/v1")
        self.assertIn("/redfish/v1", log, "request path should survive redaction")
        self.assertIn("Authorization", log, "header names should survive, only values are masked")
        self.assertIn("Basic <redacted>", log, "auth scheme should survive for diagnosis")


if __name__ == "__main__":
    unittest.main()
