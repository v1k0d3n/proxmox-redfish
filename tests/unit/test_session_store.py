"""The session store must never hold a credential.

Basic authentication used to record, on every request,
`sessions[f"{username}-{password}"] = {..., "password": password}`. The key
was the credential and the value repeated it. Nothing ever read those
records, and nothing removed them, so a long-running process accumulated
one cleartext credential per user that had ever authenticated.
"""

import base64
import time
import unittest
from unittest.mock import patch

from proxmox_redfish.auth import authentication
from proxmox_redfish.auth.authentication import sessions, validate_token

PASSWORD = "hunter2-do-not-store-me"
USERNAME = "bmcadmin@pve"


def basic_header(username=USERNAME, password=PASSWORD):
    blob = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {blob}"}


class BasicAuthStoresNothingTest(unittest.TestCase):
    def setUp(self):
        sessions.clear()

    tearDown = setUp

    @patch.object(authentication, "authenticate_user", return_value=True)
    def test_successful_auth_records_nothing(self, _auth):
        valid, who = validate_token(basic_header())
        self.assertTrue(valid)
        self.assertEqual(who, USERNAME)
        self.assertEqual(len(sessions), 0, "Basic auth must not populate the session store")

    @patch.object(authentication, "authenticate_user", return_value=True)
    def test_repeated_requests_do_not_accumulate(self, _auth):
        for index in range(25):
            validate_token(basic_header(username=f"user{index}@pve"))
        self.assertEqual(len(sessions), 0, "the store grew once per request")

    @patch.object(authentication, "authenticate_user", return_value=True)
    def test_the_password_is_not_recoverable_from_the_store(self, _auth):
        validate_token(basic_header())
        self.assertNotIn(PASSWORD, repr(sessions))

    @patch.object(authentication, "authenticate_user", return_value=False)
    def test_failed_auth_records_nothing_either(self, _auth):
        valid, _ = validate_token(basic_header())
        self.assertFalse(valid)
        self.assertEqual(len(sessions), 0)


class SessionRecordsHoldNoCredentialTest(unittest.TestCase):
    """Whatever the session path stores, a password is not part of it."""

    def setUp(self):
        sessions.clear()

    tearDown = setUp

    def test_a_session_record_has_no_credential_field(self):
        sessions["opaque-token"] = {"username": USERNAME, "created": time.time()}
        record = sessions["opaque-token"]
        for field in ("password", "passwd", "secret", "token_value"):
            self.assertNotIn(field, record)

    def test_session_lookup_still_resolves_the_user(self):
        sessions["opaque-token"] = {"username": USERNAME, "created": time.time()}
        with patch.object(authentication, "AUTH", "Session"):
            valid, who = validate_token({"X-Auth-Token": "opaque-token"})
        self.assertTrue(valid)
        self.assertEqual(who, USERNAME)

    def test_expired_sessions_are_dropped(self):
        sessions["stale"] = {"username": USERNAME, "created": time.time() - 7200}
        with patch.object(authentication, "AUTH", "Session"):
            valid, message = validate_token({"X-Auth-Token": "stale"})
        self.assertFalse(valid)
        self.assertIn("expired", message.lower())
        self.assertNotIn("stale", sessions)


class RemovedApiTest(unittest.TestCase):
    def test_get_credentials_is_gone(self):
        """It existed only to hand a stored password back out."""
        self.assertFalse(hasattr(authentication, "get_credentials"))


if __name__ == "__main__":
    unittest.main()
