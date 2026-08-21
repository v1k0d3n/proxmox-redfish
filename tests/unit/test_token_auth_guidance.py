"""A caller sending X-Auth-Token should be told what to do instead.

The user guide documented `X-Auth-Token: <proxmox api token>` as the
recommended way to authenticate. It never worked: the header is only
consulted in a branch that AUTH never selects, and Redfish defines
X-Auth-Token as a session token from SessionService rather than a Proxmox
API token. Callers following that advice got told their Authorization
header was missing, which does not describe the problem.
"""

import base64
import unittest

from proxmox_redfish.auth.authentication import validate_token


class XAuthTokenGuidanceTest(unittest.TestCase):
    def test_a_caller_sending_x_auth_token_is_told_it_is_unsupported(self):
        valid, message = validate_token({"X-Auth-Token": "0d6a51c9-d58c-479b-a4bc-6241c8af9fa9"})
        self.assertFalse(valid)
        self.assertIn("X-Auth-Token is not supported", message)

    def test_the_message_points_at_basic_authentication(self):
        _, message = validate_token({"X-Auth-Token": "irrelevant"})
        self.assertIn("Basic", message)
        self.assertIn("user@realm!tokenid", message)

    def test_the_supplied_token_is_not_echoed_back(self):
        secret = "0d6a51c9-d58c-479b-a4bc-6241c8af9fa9"
        _, message = validate_token({"X-Auth-Token": secret})
        self.assertNotIn(secret, message)

    def test_a_request_with_no_credentials_keeps_the_plain_message(self):
        valid, message = validate_token({})
        self.assertFalse(valid)
        self.assertIn("Basic Authentication required", message)
        self.assertNotIn("X-Auth-Token", message)

    def test_an_api_token_via_basic_is_not_diverted_by_the_new_branch(self):
        """The supported path must still reach real authentication."""
        blob = base64.b64encode(b"bmcadmin@pve!redfish:secret").decode()
        headers = {"Authorization": f"Basic {blob}", "X-Auth-Token": "also-sent"}
        valid, message = validate_token(headers)
        # Authentication fails here because Proxmox is not reachable in a unit
        # test, but it must fail on the credentials, not on the header check.
        self.assertNotIn("X-Auth-Token is not supported", message)


if __name__ == "__main__":
    unittest.main()
