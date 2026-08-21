"""Everything the service root names can be reached from it.

The service root is where a client starts. A resource it advertises has to
answer, and a resource the daemon serves has to be reachable by following
links from here -- otherwise a client that walks the tree, rather than
guessing URIs, never finds it.
"""

import json
import unittest
from unittest.mock import MagicMock, patch

from proxmox_redfish.server.request_handler import RedfishRequestHandler


class HandlerTestCase(unittest.TestCase):
    """Drive do_GET without a socket and hand back the parsed body."""

    def _get(self, path, vm_ids=(101, 102)):
        handler = RedfishRequestHandler.__new__(RedfishRequestHandler)
        handler.path = path
        handler.headers = {"Authorization": "Basic dTpw"}
        handler.protocol_version = "HTTP/1.1"

        captured = {}
        handler.send_response = lambda code, *a: captured.setdefault("code", code)
        handler.send_header = lambda *a, **k: None
        handler.end_headers = lambda: None
        handler.wfile = MagicMock()
        handler.wfile.write = lambda b: captured.setdefault("body", b)

        with (
            patch("proxmox_redfish.server.request_handler.validate_token", return_value=(True, "ok")),
            patch("proxmox_redfish.server.request_handler.get_proxmox_api", return_value=MagicMock()),
            patch("proxmox_redfish.server.request_handler.list_vm_ids", return_value=list(vm_ids)),
        ):
            handler.do_GET()

        return captured.get("code"), json.loads(captured["body"].decode())


class TheServiceRootIsCompleteTest(HandlerTestCase):
    def test_it_carries_the_required_properties(self):
        """The declared schema requires Id, Name and Links."""
        code, root = self._get("/redfish/v1")
        self.assertEqual(code, 200)
        for required in ("Id", "Name", "Links"):
            self.assertIn(required, root, f"service root omits required property {required}")

    def test_links_names_the_session_collection(self):
        _, root = self._get("/redfish/v1")
        self.assertIn("Sessions", root["Links"])
        self.assertEqual(root["Links"]["Sessions"]["@odata.id"], "/redfish/v1/SessionService/Sessions")

    def test_it_advertises_the_managers_collection(self):
        _, root = self._get("/redfish/v1")
        self.assertEqual(root["Managers"]["@odata.id"], "/redfish/v1/Managers")

    def test_everything_it_advertises_answers(self):
        """A link that 404s is worse than no link at all."""
        _, root = self._get("/redfish/v1")
        advertised = [
            v["@odata.id"] for k, v in root.items() if isinstance(v, dict) and "@odata.id" in v and k != "Links"
        ]
        advertised.append(root["Links"]["Sessions"]["@odata.id"])
        self.assertTrue(advertised)
        for uri in advertised:
            code, _ = self._get(uri)
            self.assertEqual(code, 200, f"service root advertises {uri}, which answered {code}")


class ManagersAreReachableTest(HandlerTestCase):
    def test_the_collection_lists_a_manager_per_guest(self):
        code, body = self._get("/redfish/v1/Managers", vm_ids=(101, 102, 103))
        self.assertEqual(code, 200)
        self.assertEqual(body["Members@odata.count"], 3)
        self.assertEqual(body["Members"][0]["@odata.id"], "/redfish/v1/Managers/101")

    def test_it_is_a_manager_collection(self):
        _, body = self._get("/redfish/v1/Managers")
        self.assertEqual(body["@odata.type"], "#ManagerCollection.ManagerCollection")


class TheSessionCollectionAnswersTest(HandlerTestCase):
    def test_the_collection_answers_even_with_no_sessions(self):
        """Basic authentication issues none, but the collection still exists."""
        code, body = self._get("/redfish/v1/SessionService/Sessions")
        self.assertEqual(code, 200)
        self.assertEqual(body["@odata.type"], "#SessionCollection.SessionCollection")
        self.assertIn("Members@odata.count", body)

    def test_the_session_service_points_at_its_collection(self):
        code, body = self._get("/redfish/v1/SessionService")
        self.assertEqual(code, 200)
        self.assertEqual(body["Sessions"]["@odata.id"], "/redfish/v1/SessionService/Sessions")


if __name__ == "__main__":
    unittest.main()
