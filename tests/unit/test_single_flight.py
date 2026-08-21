"""One transfer serves every caller waiting on the same image.

Provisioning a cluster points several machines at the same image at the same
moment. Each request would otherwise fetch it in full: the image already
being on storage does not help, because it is downloaded again to hash it.
Six machines meant six transfers of the same file, and on a server that
handled one request at a time, six transfers one after another.
"""

import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from proxmox_redfish.proxmox import iso_manager
from proxmox_redfish.proxmox.iso_manager import _ensure_iso_available

URL = "http://example.invalid/discovery.iso"
OTHER = "http://example.invalid/other.iso"


class SingleFlightTest(unittest.TestCase):
    def setUp(self):
        iso_manager._inflight.clear()
        self.fetches = []
        self.gate = threading.Event()

    def _slow_fetch(self, proxmox, url, node):
        """Stand in for the real transfer, slow enough for others to arrive."""
        self.fetches.append(url)
        self.gate.wait(timeout=5)
        return f"local:iso/{url.rsplit('/', 1)[-1]}"

    def _run_concurrently(self, urls):
        results = {}
        errors = []

        def worker(index, url):
            try:
                results[index] = _ensure_iso_available(MagicMock(), url, "node1")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        with patch.object(iso_manager, "_fetch_iso", self._slow_fetch):
            threads = [threading.Thread(target=worker, args=(i, u)) for i, u in enumerate(urls)]
            for t in threads:
                t.start()
            time.sleep(0.15)  # let them all reach the coalescing point
            self.gate.set()
            for t in threads:
                t.join(timeout=5)
        return results, errors

    def test_ten_callers_cause_one_transfer(self):
        results, errors = self._run_concurrently([URL] * 10)
        self.assertEqual(errors, [])
        self.assertEqual(len(self.fetches), 1, f"expected one transfer, got {len(self.fetches)}")
        self.assertEqual(len(results), 10)

    def test_every_caller_gets_the_same_image(self):
        results, _ = self._run_concurrently([URL] * 10)
        self.assertEqual(len(set(results.values())), 1)

    def test_different_images_are_not_conflated(self):
        """Two URLs may serve different content, so they must not share a result."""
        results, errors = self._run_concurrently([URL, OTHER, URL, OTHER])
        self.assertEqual(errors, [])
        self.assertEqual(sorted(self.fetches), sorted([URL, OTHER]))
        self.assertNotEqual(results[0], results[1])

    def test_a_failure_reaches_every_waiter(self):
        failure = RuntimeError("transfer failed")

        def failing(proxmox, url, node):
            self.fetches.append(url)
            self.gate.wait(timeout=5)
            raise failure

        errors = []

        def worker():
            try:
                _ensure_iso_available(MagicMock(), URL, "node1")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        with patch.object(iso_manager, "_fetch_iso", failing):
            threads = [threading.Thread(target=worker) for _ in range(5)]
            for t in threads:
                t.start()
            time.sleep(0.15)
            self.gate.set()
            for t in threads:
                t.join(timeout=5)

        self.assertEqual(len(errors), 5, "every caller should learn the transfer failed")
        self.assertEqual(len(self.fetches), 1)

    def test_a_later_request_starts_a_fresh_transfer(self):
        """Nothing is cached: the same URL may serve a different image later."""
        with patch.object(iso_manager, "_fetch_iso", lambda p, u, n: "local:iso/x.iso"):
            _ensure_iso_available(MagicMock(), URL, "node1")
            _ensure_iso_available(MagicMock(), URL, "node1")
        self.assertEqual(iso_manager._inflight, {})

    def test_a_volid_is_not_coalesced(self):
        """A volid names an image already on storage; there is nothing to fetch."""
        seen = []
        with patch.object(iso_manager, "_fetch_iso", lambda p, u, n: seen.append(u) or u):
            _ensure_iso_available(MagicMock(), "local:iso/already.iso", "node1")
        self.assertEqual(seen, ["local:iso/already.iso"])
        self.assertEqual(iso_manager._inflight, {})


if __name__ == "__main__":
    unittest.main()
