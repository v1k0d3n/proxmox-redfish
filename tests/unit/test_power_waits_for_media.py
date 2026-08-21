"""A guest is not started while its media is still being changed.

Inserting media fetches the image, uploads it and attaches it. A power
action arriving in the middle would start the guest against whatever was
attached before, which is usually nothing.

Requests were once handled one at a time, which prevented this by
accident. These tests describe the ordering now that they are not.
"""

import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from proxmox_redfish.api.power_operations import power_off, power_on, reset_vm
from proxmox_redfish.api.virtual_media import manage_virtual_media

URL = "http://example.invalid/boot.iso"


class PowerWaitsForMediaTest(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.lock = threading.Lock()
        self.transfer_running = threading.Event()
        self.release_transfer = threading.Event()

        self.proxmox = MagicMock()
        self.proxmox.nodes.return_value.qemu.return_value.config.get.return_value = {"ide2": "none,media=cdrom"}

    def _record(self, what):
        with self.lock:
            self.events.append(what)

    def _slow_fetch(self, *args, **kwargs):
        """Stand in for the transfer: long, and observable while it runs."""
        self._record("transfer-start")
        self.transfer_running.set()
        self.release_transfer.wait(timeout=5)
        self._record("transfer-end")
        return "store:iso/boot.iso"

    def _insert(self):
        with (
            patch("proxmox_redfish.api.virtual_media._ensure_iso_available", side_effect=self._slow_fetch),
            patch("proxmox_redfish.api.virtual_media.node_for", return_value="node1"),
            patch("proxmox_redfish.api.virtual_media.vm", return_value=self.proxmox),
        ):
            manage_virtual_media(self.proxmox, 900, "InsertMedia", URL)

    def _power(self, fn, label):
        def start(*args, **kwargs):
            self._record(label)
            return "UPID:node1:0:0:0:qmstart:900:user@pam:"

        target = MagicMock()
        target.status.start.post.side_effect = start
        target.status.reset.post.side_effect = start
        target.status.shutdown.post.side_effect = start
        with patch("proxmox_redfish.api.power_operations.vm", return_value=target):
            fn(self.proxmox, 900)

    def _run_race(self, power_fn, label):
        inserter = threading.Thread(target=self._insert)
        inserter.start()
        self.assertTrue(self.transfer_running.wait(timeout=5), "transfer never started")

        powerer = threading.Thread(target=self._power, args=(power_fn, label))
        powerer.start()
        time.sleep(0.2)  # give the power action every chance to go first

        self.release_transfer.set()
        inserter.join(timeout=5)
        powerer.join(timeout=5)
        return self.events

    def test_power_on_waits_for_the_transfer(self):
        events = self._run_race(power_on, "power-on")
        self.assertLess(events.index("transfer-end"), events.index("power-on"), f"guest started mid-transfer: {events}")

    def test_reset_waits_for_the_transfer(self):
        events = self._run_race(reset_vm, "reset")
        self.assertLess(events.index("transfer-end"), events.index("reset"), f"guest reset mid-transfer: {events}")

    def test_a_guest_can_still_be_stopped_during_a_transfer(self):
        """A transfer never makes powering a guest off wrong."""
        events = self._run_race(power_off, "power-off")
        self.assertLess(events.index("power-off"), events.index("transfer-end"), f"stop was blocked: {events}")


if __name__ == "__main__":
    unittest.main()
