"""An unreachable Proxmox is not a credential problem.

authenticate_user caught every exception and returned False, so a DNS
failure, a refused connection or a timeout all surfaced as "Invalid Basic
Authentication credentials". Operators then went looking for a password
problem that did not exist -- which is what happened when a configuration
example wrote an unexpanded $(...) into PROXMOX_HOST and the daemon tried
to resolve that string as a hostname.
"""

import base64
import unittest
from unittest.mock import patch

import requests

from proxmox_redfish.auth import authentication
from proxmox_redfish.auth.authentication import ProxmoxUnreachable, authenticate_user, validate_token

USER = "redfish@pam"
PASSWORD = "secret"


def basic_header():
    blob = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
    return {"Authorization": f"Basic {blob}"}


class TransportFailuresAreNotCredentialFailuresTest(unittest.TestCase):
    def _raise(self, error):
        return patch.object(authentication.requests, "post", side_effect=error)

    def test_name_resolution_failure_is_reported_as_unreachable(self):
        failure = requests.exceptions.ConnectionError("Failed to resolve 'nosuchhost'")
        with self._raise(failure):
            with self.assertRaises(ProxmoxUnreachable):
                authenticate_user(USER, PASSWORD)

    def test_timeout_is_reported_as_unreachable(self):
        with self._raise(requests.exceptions.ConnectTimeout("timed out")):
            with self.assertRaises(ProxmoxUnreachable):
                authenticate_user(USER, PASSWORD)

    def test_the_message_names_the_setting_to_check(self):
        with self._raise(requests.exceptions.ConnectionError("boom")):
            with self.assertRaises(ProxmoxUnreachable) as caught:
                authenticate_user(USER, PASSWORD)
        self.assertIn("PROXMOX_HOST", str(caught.exception))

    def test_validate_token_surfaces_it_rather_than_blaming_credentials(self):
        with self._raise(requests.exceptions.ConnectionError("Failed to resolve")):
            valid, message = validate_token(basic_header())
        self.assertFalse(valid)
        self.assertIn("Could not reach the Proxmox API", message)
        self.assertNotIn("Invalid Basic Authentication credentials", message)

    def test_the_supplied_password_is_not_echoed(self):
        with self._raise(requests.exceptions.ConnectionError("boom")):
            _, message = validate_token(basic_header())
        self.assertNotIn(PASSWORD, message)


class RejectedCredentialsStillReportAsSuchTest(unittest.TestCase):
    """The distinction only helps if a real rejection still reads as one."""

    def test_a_refused_credential_is_still_a_credential_error(self):
        class Response:
            status_code = 401

            def json(self):
                return {}

        with patch.object(authentication.requests, "post", return_value=Response()):
            valid, message = validate_token(basic_header())
        self.assertFalse(valid)
        self.assertIn("Invalid Basic Authentication credentials", message)


if __name__ == "__main__":
    unittest.main()
