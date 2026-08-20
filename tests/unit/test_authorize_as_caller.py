"""The daemon must act as the caller, never as a privileged stand-in.

The bug these cover: callers were authenticated and then every Proxmox
operation was performed over a connection opened as PROXMOX_USER. Any
account that could authenticate could therefore drive any VM, because
nothing downstream carried the caller's identity.
"""

import base64
import unittest
from unittest.mock import patch

from proxmox_redfish.auth.authentication import extract_credentials, qualify_username
from proxmox_redfish.proxmox.client import build_proxmox_api, get_proxmox_api


def basic_header(username, secret):
    blob = base64.b64encode(f"{username}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {blob}"}


class TestQualifyUsername(unittest.TestCase):
    def test_bare_username_gets_default_realm(self):
        self.assertEqual(qualify_username("alice"), "alice@pam")

    def test_explicit_realm_is_left_alone(self):
        self.assertEqual(qualify_username("alice@pve"), "alice@pve")

    def test_realm_is_applied_to_the_user_not_the_token_id(self):
        # "alice!tok" must not become "alice!tok@pam", which is not an identity.
        self.assertEqual(qualify_username("alice!tok"), "alice@pam!tok")

    def test_token_identity_with_realm_is_unchanged(self):
        self.assertEqual(qualify_username("root@pam!redfish"), "root@pam!redfish")


class TestExtractCredentials(unittest.TestCase):
    def test_reads_username_and_secret(self):
        user, secret = extract_credentials(basic_header("alice@pve", "s3cret"))
        self.assertEqual((user, secret), ("alice@pve", "s3cret"))

    def test_secret_containing_a_colon_is_preserved(self):
        _, secret = extract_credentials(basic_header("alice@pve", "a:b:c"))
        self.assertEqual(secret, "a:b:c")

    def test_missing_header_is_rejected(self):
        with self.assertRaises(ValueError):
            extract_credentials({})

    def test_malformed_header_is_rejected(self):
        with self.assertRaises(ValueError):
            extract_credentials({"Authorization": "Basic !!!not-base64!!!"})


class TestBuildProxmoxApi(unittest.TestCase):
    """The identity handed to proxmoxer must be the caller's."""

    @patch("proxmox_redfish.proxmox.client.ProxmoxAPI")
    def test_password_identity_is_passed_through(self, mock_api):
        build_proxmox_api("alice@pve", "s3cret")
        kwargs = mock_api.call_args.kwargs
        self.assertEqual(kwargs["user"], "alice@pve")
        self.assertEqual(kwargs["password"], "s3cret")
        self.assertNotIn("token_name", kwargs)

    @patch("proxmox_redfish.proxmox.client.ProxmoxAPI")
    def test_api_token_identity_is_split_correctly(self, mock_api):
        build_proxmox_api("root@pam!redfish", "0d6a51c9-d58c-479b-a4bc-6241c8af9fa9")
        kwargs = mock_api.call_args.kwargs
        self.assertEqual(kwargs["user"], "root@pam")
        self.assertEqual(kwargs["token_name"], "redfish")
        self.assertEqual(kwargs["token_value"], "0d6a51c9-d58c-479b-a4bc-6241c8af9fa9")
        # A token is sent per request; there is no password exchange.
        self.assertNotIn("password", kwargs)


class TestGetProxmoxApiUsesCallerIdentity(unittest.TestCase):
    """Regression guard for the escalation itself."""

    @patch("proxmox_redfish.proxmox.client.ProxmoxAPI")
    @patch("proxmox_redfish.proxmox.client.validate_token", return_value=(True, "alice@pve"))
    def test_connection_is_opened_as_the_caller(self, _validate, mock_api):
        get_proxmox_api(basic_header("alice@pve", "s3cret"))
        self.assertEqual(mock_api.call_args.kwargs["user"], "alice@pve")

    @patch("proxmox_redfish.proxmox.client.ProxmoxAPI")
    @patch("proxmox_redfish.proxmox.client.validate_token", return_value=(True, "alice@pve"))
    def test_the_configured_service_account_is_never_substituted(self, _validate, mock_api):
        """This is the bug. Never connect as PROXMOX_USER on a caller's behalf."""
        from proxmox_redfish.config import settings

        get_proxmox_api(basic_header("alice@pve", "s3cret"))
        kwargs = mock_api.call_args.kwargs
        self.assertNotEqual(kwargs["user"], settings.PROXMOX_USER)
        self.assertNotEqual(kwargs.get("password"), settings.PROXMOX_PASSWORD)

    @patch("proxmox_redfish.proxmox.client.ProxmoxAPI")
    @patch("proxmox_redfish.proxmox.client.validate_token", return_value=(False, "bad credentials"))
    def test_no_connection_is_opened_when_authentication_fails(self, _validate, mock_api):
        with self.assertRaises(Exception):
            get_proxmox_api(basic_header("alice@pve", "wrong"))
        mock_api.assert_not_called()


if __name__ == "__main__":
    unittest.main()


class TestStartupRequiresNoServiceAccount(unittest.TestCase):
    """The daemon holds no Proxmox account, so it must not demand one.

    Requiring PROXMOX_USER/PROXMOX_PASSWORD to start would mean keeping a
    privileged credential on disk that nothing reads.
    """

    def _run_main(self, env):
        import proxmox_redfish.main as main_module

        with (
            patch.dict("os.environ", env, clear=True),
            patch.object(main_module.sys, "argv", ["proxmox-redfish"]),
            patch.object(main_module, "setup_logging"),
            patch.object(main_module, "run_server") as serve,
        ):
            try:
                main_module.main()
            except SystemExit as exc:
                return exc.code, serve
            return 0, serve

    def test_starts_with_only_a_host_configured(self):
        code, serve = self._run_main({"PROXMOX_HOST": "proxmox.example"})
        self.assertEqual(code, 0)
        serve.assert_called_once()

    def test_exits_when_the_host_is_missing(self):
        code, serve = self._run_main({})
        self.assertEqual(code, 1)
        serve.assert_not_called()
