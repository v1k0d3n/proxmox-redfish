"""Actions must report what actually happened, and repeat calls must be cheap.

Every action handed back a task reference pointing at /TaskService/Tasks/,
which nothing served, and reported TaskState "Running" for work that had
already finished before the response was written. A client following Redfish
convention polls that reference to learn when it may proceed; getting a 404
and a state of "Running" tells it nothing, and clients that give up and act
anyway end up booting before the media is attached.
"""

import unittest
from unittest.mock import MagicMock

from proxmox_redfish.api.task_service import (
    get_task,
    get_task_service,
    node_from_upid,
    redfish_task_state,
)
from proxmox_redfish.api.virtual_media import manage_virtual_media
from proxmox_redfish.utils.error_handling import VMNotFound

UPID = "UPID:node1:0010A2A7:042F3100:6A872524:qmconfig:1001:root@pam:"


def proxmox_with(config, task_status=None):
    proxmox = MagicMock()
    proxmox.cluster.resources.get.return_value = [{"vmid": 1001, "node": "node1", "type": "qemu"}]
    qemu = proxmox.nodes.return_value.qemu.return_value
    qemu.config.get.return_value = config
    qemu.config.post.return_value = UPID
    if task_status is not None:
        proxmox.nodes.return_value.tasks.return_value.status.get.return_value = task_status
    return proxmox


class UpidParsingTest(unittest.TestCase):
    def test_the_node_is_read_from_the_upid(self):
        self.assertEqual(node_from_upid(UPID), "node1")

    def test_a_non_upid_is_a_missing_resource(self):
        for bad in ("", "not-a-upid", "UPID:", "12345"):
            with self.assertRaises(VMNotFound):
                node_from_upid(bad)


class TaskStateMappingTest(unittest.TestCase):
    def test_running(self):
        self.assertEqual(redfish_task_state({"status": "running"}), ("Running", "OK"))

    def test_finished_well(self):
        self.assertEqual(redfish_task_state({"status": "stopped", "exitstatus": "OK"}), ("Completed", "OK"))

    def test_finished_badly_is_an_exception(self):
        state, status = redfish_task_state({"status": "stopped", "exitstatus": "command failed"})
        self.assertEqual(state, "Exception")
        self.assertEqual(status, "Critical")


class TaskEndpointTest(unittest.TestCase):
    def test_a_task_can_be_read_back(self):
        proxmox = proxmox_with({}, task_status={"status": "stopped", "exitstatus": "OK", "type": "qmconfig"})
        task = get_task(proxmox, UPID)
        self.assertEqual(task["TaskState"], "Completed")
        self.assertEqual(task["@odata.id"], f"/redfish/v1/TaskService/Tasks/{UPID}")

    def test_it_is_looked_up_on_the_node_named_in_the_upid(self):
        proxmox = proxmox_with({}, task_status={"status": "running"})
        get_task(proxmox, UPID)
        proxmox.nodes.assert_called_with("node1")

    def test_an_unknown_task_is_reported_missing(self):
        proxmox = proxmox_with({})
        response, status = get_task(proxmox, "not-a-upid")
        self.assertEqual(status, 404)

    def test_the_service_points_at_its_collection(self):
        self.assertEqual(get_task_service()["Tasks"]["@odata.id"], "/redfish/v1/TaskService/Tasks")


class ActionsReportCompletion(unittest.TestCase):
    """The work is done before the response is written."""

    def test_insert_reports_completed(self):
        proxmox = proxmox_with({"ide2": "none,media=cdrom"})
        response, status = manage_virtual_media(proxmox, 1001, "InsertMedia", "local:iso/new.iso")
        self.assertEqual(status, 200)
        self.assertEqual(response["TaskState"], "Completed")

    def test_the_task_reference_is_the_real_upid(self):
        proxmox = proxmox_with({"ide2": "none,media=cdrom"})
        response, _ = manage_virtual_media(proxmox, 1001, "InsertMedia", "local:iso/new.iso")
        self.assertEqual(response["@odata.id"], f"/redfish/v1/TaskService/Tasks/{UPID}")

    def test_eject_reports_completed(self):
        proxmox = proxmox_with({"ide2": "local:iso/old.iso,media=cdrom"})
        response, status = manage_virtual_media(proxmox, 1001, "EjectMedia")
        self.assertEqual(status, 200)
        self.assertEqual(response["TaskState"], "Completed")


class RepeatRequestsAreCheap(unittest.TestCase):
    """A client that repeats a request should not have the work redone."""

    def test_inserting_the_attached_image_changes_nothing(self):
        proxmox = proxmox_with({"ide2": "local:iso/same.iso,media=cdrom"})
        response, status = manage_virtual_media(proxmox, 1001, "InsertMedia", "local:iso/same.iso")
        self.assertEqual(status, 200)
        self.assertEqual(response["TaskState"], "Completed")
        self.assertIn("already inserted", response["Messages"][0]["Message"])
        proxmox.nodes.return_value.qemu.return_value.config.post.assert_not_called()

    def test_ejecting_an_empty_drive_changes_nothing(self):
        proxmox = proxmox_with({"ide2": "none,media=cdrom"})
        response, status = manage_virtual_media(proxmox, 1001, "EjectMedia")
        self.assertEqual(status, 200)
        self.assertIn("No media", response["Messages"][0]["Message"])
        proxmox.nodes.return_value.qemu.return_value.config.post.assert_not_called()

    def test_a_drive_with_no_ide2_at_all_is_treated_as_empty(self):
        proxmox = proxmox_with({"name": "vm"})
        _, status = manage_virtual_media(proxmox, 1001, "EjectMedia")
        self.assertEqual(status, 200)
        proxmox.nodes.return_value.qemu.return_value.config.post.assert_not_called()

    def test_a_different_image_is_still_swapped(self):
        """Replacing media is how a redeploy attaches a new image."""
        proxmox = proxmox_with({"ide2": "local:iso/old.iso,media=cdrom"})
        _, status = manage_virtual_media(proxmox, 1001, "InsertMedia", "local:iso/new.iso")
        self.assertEqual(status, 200)
        proxmox.nodes.return_value.qemu.return_value.config.post.assert_called()


if __name__ == "__main__":
    unittest.main()


class NoOpResponsesDoNotInventATask(unittest.TestCase):
    """When nothing changed, Proxmox ran no task, so there is none to point at."""

    def test_no_task_reference_when_the_image_was_already_attached(self):
        proxmox = proxmox_with({"ide2": "local:iso/same.iso,media=cdrom"})
        response, _ = manage_virtual_media(proxmox, 1001, "InsertMedia", "local:iso/same.iso")
        self.assertNotIn("@odata.id", response)
        self.assertEqual(response["@odata.type"], "#ActionResponse.v1_0_0.ActionResponse")

    def test_no_task_reference_when_the_drive_was_already_empty(self):
        proxmox = proxmox_with({"ide2": "none,media=cdrom"})
        response, _ = manage_virtual_media(proxmox, 1001, "EjectMedia")
        self.assertNotIn("@odata.id", response)

    def test_real_work_still_carries_a_task_reference(self):
        proxmox = proxmox_with({"ide2": "none,media=cdrom"})
        response, _ = manage_virtual_media(proxmox, 1001, "InsertMedia", "local:iso/new.iso")
        self.assertTrue(response["@odata.id"].startswith("/redfish/v1/TaskService/Tasks/"))
        self.assertEqual(response["@odata.type"], "#Task.v1_0_0.Task")
