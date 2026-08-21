"""Command line options must actually do something.

Three of the four did not. `--host` was recorded and never read, so the
daemon always bound every interface. `--log-level` was applied with a second
logging.basicConfig() call, which does nothing once handlers exist, so the
level always came from the environment. `--config` was parsed into a mapping
that almost nothing read: a file could set proxmox.host, pass validation and
be logged, while connections still used the environment's host.
"""

import unittest
from unittest.mock import patch

import proxmox_redfish.main as main_module
from proxmox_redfish.config.logging_config import setup_logging


def run_main(argv, env):
    """Run main() with a given command line and environment."""
    with (
        patch.dict("os.environ", env, clear=True),
        patch.object(main_module.sys, "argv", ["proxmox-redfish", *argv]),
        patch.object(main_module, "setup_logging") as logging_setup,
        patch.object(main_module, "run_server") as plain,
        patch.object(main_module, "run_server_ssl") as tls,
    ):
        code = 0
        try:
            main_module.main()
        except SystemExit as exc:
            code = exc.code
        return code, plain, tls, logging_setup


HOST_ONLY = {"PROXMOX_HOST": "proxmox.example"}


class BindAddressTest(unittest.TestCase):
    def test_host_reaches_the_server(self):
        _, plain, _, _ = run_main(["--host", "127.0.0.1"], HOST_ONLY)
        self.assertEqual(plain.call_args.args[1], "127.0.0.1")

    def test_default_binds_every_interface(self):
        _, plain, _, _ = run_main([], HOST_ONLY)
        self.assertEqual(plain.call_args.args[1], "")

    def test_environment_can_set_the_bind_address(self):
        _, plain, _, _ = run_main([], {**HOST_ONLY, "REDFISH_HOST": "10.0.0.5"})
        self.assertEqual(plain.call_args.args[1], "10.0.0.5")

    def test_the_flag_beats_the_environment(self):
        _, plain, _, _ = run_main(["--host", "127.0.0.1"], {**HOST_ONLY, "REDFISH_HOST": "10.0.0.5"})
        self.assertEqual(plain.call_args.args[1], "127.0.0.1")


class PortTest(unittest.TestCase):
    def test_flag_is_used(self):
        _, plain, _, _ = run_main(["--port", "9000"], HOST_ONLY)
        self.assertEqual(plain.call_args.args[0], 9000)

    def test_environment_is_used(self):
        _, plain, _, _ = run_main([], {**HOST_ONLY, "REDFISH_PORT": "9001"})
        self.assertEqual(plain.call_args.args[0], 9001)

    def test_the_flag_beats_the_environment(self):
        _, plain, _, _ = run_main(["--port", "9000"], {**HOST_ONLY, "REDFISH_PORT": "9001"})
        self.assertEqual(plain.call_args.args[0], 9000)

    def test_default_is_unchanged(self):
        _, plain, _, _ = run_main([], HOST_ONLY)
        self.assertEqual(plain.call_args.args[0], main_module.DEFAULT_PORT)


class LogLevelTest(unittest.TestCase):
    def test_the_flag_reaches_logging_setup(self):
        _, _, _, logging_setup = run_main(["--log-level", "DEBUG"], HOST_ONLY)
        logging_setup.assert_called_once_with("DEBUG")

    def test_no_flag_leaves_the_environment_in_charge(self):
        _, _, _, logging_setup = run_main([], HOST_ONLY)
        logging_setup.assert_called_once_with(None)

    def test_setup_logging_honours_an_explicit_level(self):
        import logging

        with (
            patch.dict("os.environ", {"REDFISH_LOG_LEVEL": "INFO"}, clear=True),
            patch("logging.basicConfig") as basic_config,
        ):
            setup_logging("DEBUG")
        self.assertEqual(basic_config.call_args.kwargs["level"], logging.DEBUG)

    def test_setup_logging_falls_back_to_the_environment(self):
        import logging

        with (
            patch.dict("os.environ", {"REDFISH_LOG_LEVEL": "WARNING"}, clear=True),
            patch("logging.basicConfig") as basic_config,
        ):
            setup_logging(None)
        self.assertEqual(basic_config.call_args.kwargs["level"], logging.WARNING)


class TlsSelectionTest(unittest.TestCase):
    def test_tls_used_when_both_cert_and_key_are_set(self):
        env = {**HOST_ONLY, "SSL_CERT_FILE": "/c.pem", "SSL_KEY_FILE": "/k.pem"}
        _, plain, tls, _ = run_main([], env)
        tls.assert_called_once()
        plain.assert_not_called()

    def test_a_cert_without_a_key_does_not_enable_tls(self):
        _, plain, tls, _ = run_main([], {**HOST_ONLY, "SSL_CERT_FILE": "/c.pem"})
        plain.assert_called_once()
        tls.assert_not_called()


class RemovedConfigFlagTest(unittest.TestCase):
    def test_config_flag_is_gone(self):
        code, plain, _, _ = run_main(["--config", "/tmp/x.json"], HOST_ONLY)
        self.assertEqual(code, 2, "argparse should reject an unknown option")
        plain.assert_not_called()

    def test_missing_proxmox_host_still_exits(self):
        code, plain, _, _ = run_main([], {})
        self.assertEqual(code, 1)
        plain.assert_not_called()


if __name__ == "__main__":
    unittest.main()
