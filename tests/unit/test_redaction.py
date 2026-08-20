"""Tests for debug-log redaction.

These assert on the thing that matters: that a real credential cannot be
recovered from what gets logged.
"""

import base64
import json
import unittest

from proxmox_redfish.utils.redaction import (
    REDACTED,
    redact_header_value,
    redact_headers,
    redact_payload,
    redact_response,
)

PASSWORD = "hunter2-do-not-log-me"
USERNAME = "bmcadmin@pve"
BASIC = "Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()


class TestHeaderRedaction(unittest.TestCase):
    def test_basic_auth_credentials_are_not_recoverable(self):
        rendered = redact_headers([("Authorization", BASIC)])
        self.assertNotIn(PASSWORD, rendered)
        # The base64 blob decodes to the password, so it must be gone too.
        self.assertNotIn(BASIC.split(" ", 1)[1], rendered)

    def test_auth_scheme_survives_for_diagnosis(self):
        self.assertEqual(redact_header_value("Authorization", BASIC), f"Basic {REDACTED}")

    def test_session_token_header_is_masked(self):
        self.assertEqual(redact_header_value("X-Auth-Token", "abc123"), REDACTED)

    def test_cookies_are_masked(self):
        self.assertEqual(redact_header_value("Cookie", "PVEAuthCookie=xyz"), REDACTED)

    def test_header_matching_is_case_insensitive(self):
        self.assertEqual(redact_header_value("AUTHORIZATION", BASIC), f"Basic {REDACTED}")

    def test_ordinary_headers_are_untouched(self):
        self.assertEqual(redact_header_value("Content-Type", "application/json"), "application/json")
        rendered = redact_headers([("Content-Length", "42"), ("Authorization", BASIC)])
        self.assertIn("Content-Length: 42", rendered)


class TestPayloadRedaction(unittest.TestCase):
    def test_session_creation_password_is_masked(self):
        body = {"UserName": USERNAME, "Password": PASSWORD}
        result = redact_payload(body)
        self.assertEqual(result["Password"], REDACTED)
        self.assertNotIn(PASSWORD, json.dumps(result))

    def test_username_is_kept(self):
        # The username is what makes the log useful; it is not the secret.
        self.assertEqual(redact_payload({"UserName": USERNAME})["UserName"], USERNAME)

    def test_nested_secrets_are_masked(self):
        body = {"Oem": {"Proxmox": {"token": "t0ps3cret"}}}
        self.assertNotIn("t0ps3cret", json.dumps(redact_payload(body)))

    def test_secrets_inside_lists_are_masked(self):
        body = {"Accounts": [{"Password": PASSWORD}, {"Password": "other"}]}
        self.assertNotIn(PASSWORD, json.dumps(redact_payload(body)))

    def test_key_matching_is_case_insensitive(self):
        for key in ("password", "PASSWORD", "PassWord"):
            self.assertEqual(redact_payload({key: PASSWORD})[key], REDACTED)

    def test_structure_is_preserved(self):
        body = {"Image": "http://example/x.iso", "Inserted": True, "Password": PASSWORD}
        result = redact_payload(body)
        self.assertEqual(result["Image"], "http://example/x.iso")
        self.assertIs(result["Inserted"], True)
        self.assertEqual(set(result), set(body))

    def test_original_payload_is_not_mutated(self):
        body = {"Password": PASSWORD}
        redact_payload(body)
        self.assertEqual(body["Password"], PASSWORD)

    def test_non_dict_payloads_pass_through(self):
        self.assertEqual(redact_payload("raw string"), "raw string")
        self.assertEqual(redact_payload(None), None)


class TestResponseRedaction(unittest.TestCase):
    SESSION_PATH = "/redfish/v1/SessionService/Sessions"

    def test_new_session_token_is_masked(self):
        token = "a3f1c2d4e5b6a7c8"
        response = {
            "@odata.id": f"{self.SESSION_PATH}/{token}",
            "Id": token,
            "UserName": USERNAME,
        }
        result = redact_response(self.SESSION_PATH, response)
        self.assertNotIn(token, json.dumps(result))
        self.assertEqual(result["UserName"], USERNAME)

    def test_vm_ids_on_other_paths_are_kept(self):
        # Redacting "Id" everywhere would gut the usefulness of these logs.
        response = {"Id": "1001", "Name": "redfish-test"}
        self.assertEqual(redact_response("/redfish/v1/Systems/1001", response)["Id"], "1001")

    def test_non_dict_response_passes_through(self):
        self.assertEqual(redact_response(self.SESSION_PATH, "text"), "text")


if __name__ == "__main__":
    unittest.main()
