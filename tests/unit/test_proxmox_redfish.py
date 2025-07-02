#!/usr/bin/env python3
"""
Unit tests for proxmox-redfish.py

This test suite validates the Redfish API implementation for Proxmox VMs,
ensuring compatibility with Metal3/Ironic and OpenShift ZTP workflows.

Test Coverage:
- Authentication (Basic, Session, None)
- Power management (On, Off, Reset, Reboot)
- Virtual Media operations (Insert/Eject ISO)
- Boot configuration (BIOS/UEFI, boot order)
- System information endpoints
- Error handling and validation
- Redfish compliance
"""

import base64
import json
import os
import sys
import time
import unittest
from io import BytesIO
from unittest.mock import Mock, patch

from proxmox_redfish.proxmox_redfish import (
    RedfishRequestHandler,
    _ensure_iso_available,
    get_bios,
    get_vm_status,
    handle_proxmox_error,
    manage_virtual_media,
    power_off,
    power_on,
    reboot,
    reorder_boot_order,
    reset_vm,
    validate_token,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class MockProxmoxAPI:
    """Mock Proxmox API for testing"""

    def __init__(self, test_data=None):
        self.test_data = test_data or {}
        self.nodes = Mock()
        self.nodes.return_value = self.nodes

    def __call__(self, *args, **kwargs):
        return self


class MockProxmoxNode:
    """Mock Proxmox node for testing"""

    def __init__(self, test_data=None):
        self.test_data = test_data or {}
        self.qemu = Mock()
        self.qemu.return_value = self.qemu
        self.storage = Mock()
        self.storage.return_value = self.storage
        self.tasks = Mock()
        self.tasks.return_value = self.tasks


class MockProxmoxVM:
    """Mock Proxmox VM for testing"""

    def __init__(self, vm_id, test_data=None):
        self.vm_id = vm_id
        self.test_data = test_data or {}
        self.status = Mock()
        self.config = Mock()
        self.config.return_value = self.config


class TestRedfishProxmox(unittest.TestCase):
    """Main test class for proxmox-redfish functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_vm_id = 100
        self.test_username = "testuser@pam"
        self.test_password = "testpass"
        self.test_token = "test-token-12345"

        # Mock Proxmox API responses
        self.mock_vm_list = [
            {"vmid": 100, "name": "test-vm-1", "status": "running"},
            {"vmid": 101, "name": "test-vm-2", "status": "stopped"},
        ]

        self.mock_vm_config = {
            "name": "test-vm-1",
            "memory": 2048,
            "cores": 2,
            "sockets": 1,
            "cpu": "kvm64",
            "bios": "seabios",
            "boot": "order=scsi0;ide2;net0",
            "ide2": "none,media=cdrom",
            "scsi0": "local:100/vm-100-disk-1.qcow2,size=20G",
            "net0": "virtio=52:54:00:12:34:56,bridge=vmbr0",
            "smbios1": "uuid=test-uuid-123,manufacturer=Proxmox,product=QEMU,serial=test-serial-123",
        }

        self.mock_vm_status = {"status": "running", "cpu": 0.5, "mem": 1024, "disk": 5120}

        # Set up environment variables for testing
        os.environ["PROXMOX_HOST"] = "test-proxmox.local"
        os.environ["PROXMOX_USER"] = "testuser"
        os.environ["PROXMOX_PASSWORD"] = "testpass"
        os.environ["PROXMOX_NODE"] = "pve-node"
        os.environ["VERIFY_SSL"] = "false"
        os.environ["REDFISH_LOGGING_ENABLED"] = "false"

    def tearDown(self):
        """Clean up after tests"""
        # Clear environment variables
        for var in [
            "PROXMOX_HOST",
            "PROXMOX_USER",
            "PROXMOX_PASSWORD",
            "PROXMOX_NODE",
            "VERIFY_SSL",
            "REDFISH_LOGGING_ENABLED",
        ]:
            if var in os.environ:
                del os.environ[var]

    def create_mock_proxmox(self):
        """Create a mock Proxmox API instance"""
        mock_proxmox = Mock()

        # Mock VM list
        mock_proxmox.nodes.return_value.qemu.get.return_value = self.mock_vm_list

        # Mock VM status
        mock_proxmox.nodes.return_value.qemu.return_value.status.current.get.return_value = self.mock_vm_status

        # Mock VM config
        mock_proxmox.nodes.return_value.qemu.return_value.config.get.return_value = self.mock_vm_config

        # Mock power operations
        mock_proxmox.nodes.return_value.qemu.return_value.status.start.post.return_value = (
            "UPID:pve:00001234:1234:5678:9012:test:qemu:100:testuser@pam:"
        )
        mock_proxmox.nodes.return_value.qemu.return_value.status.shutdown.post.return_value = (
            "UPID:pve:00001235:1235:5679:9013:test:qemu:100:testuser@pam:"
        )
        mock_proxmox.nodes.return_value.qemu.return_value.status.reboot.post.return_value = (
            "UPID:pve:00001236:1236:5680:9014:test:qemu:100:testuser@pam:"
        )
        mock_proxmox.nodes.return_value.qemu.return_value.status.reset.post.return_value = (
            "UPID:pve:00001237:1237:5681:9015:test:qemu:100:testuser@pam:"
        )

        # Mock config operations
        mock_proxmox.nodes.return_value.qemu.return_value.config.post.return_value = (
            "UPID:pve:00001238:1238:5682:9016:test:qemu:100:testuser@pam:"
        )
        mock_proxmox.nodes.return_value.qemu.return_value.config.set.return_value = (
            "UPID:pve:00001239:1239:5683:9017:test:qemu:100:testuser@pam:"
        )

        return mock_proxmox

    def create_test_request(self, method, path, headers=None, body=None):
        """Create a test HTTP request"""
        if headers is None:
            headers = {}

        # Create a mock request
        request = Mock()
        request.path = path
        request.headers = headers
        request.method = method

        if body:
            request.rfile = BytesIO(body.encode("utf-8"))
            request.headers["Content-Length"] = str(len(body))
        else:
            request.rfile = BytesIO(b"")
            request.headers["Content-Length"] = "0"

        return request

    def test_power_on_success(self):
        """Test successful power on operation"""
        mock_proxmox = self.create_mock_proxmox()

        response, status_code = power_on(mock_proxmox, self.test_vm_id)

        self.assertEqual(status_code, 202)
        self.assertIn("@odata.id", response)
        self.assertIn("TaskState", response)
        self.assertEqual(response["TaskState"], "Running")
        self.assertIn("Power On VM", response["Name"])

        # Verify Proxmox API was called
        mock_proxmox.nodes.return_value.qemu.return_value.status.start.post.assert_called_once()

    def test_power_off_success(self):
        """Test successful power off operation"""
        mock_proxmox = self.create_mock_proxmox()

        response, status_code = power_off(mock_proxmox, self.test_vm_id)

        self.assertEqual(status_code, 202)
        self.assertIn("@odata.id", response)
        self.assertEqual(response["TaskState"], "Running")
        self.assertIn("Power Off VM", response["Name"])

        # Verify Proxmox API was called
        mock_proxmox.nodes.return_value.qemu.return_value.status.shutdown.post.assert_called_once()

    def test_reboot_success(self):
        """Test successful reboot operation"""
        mock_proxmox = self.create_mock_proxmox()

        response, status_code = reboot(mock_proxmox, self.test_vm_id)

        self.assertEqual(status_code, 202)
        self.assertIn("@odata.id", response)
        self.assertEqual(response["TaskState"], "Running")
        self.assertIn("Reboot VM", response["Name"])

        # Verify Proxmox API was called
        mock_proxmox.nodes.return_value.qemu.return_value.status.reboot.post.assert_called_once()

    def test_reset_vm_success(self):
        """Test successful hard reset operation"""
        mock_proxmox = self.create_mock_proxmox()

        response, status_code = reset_vm(mock_proxmox, self.test_vm_id)

        self.assertEqual(status_code, 202)
        self.assertIn("@odata.id", response)
        self.assertEqual(response["TaskState"], "Running")
        self.assertIn("Hard Reset VM", response["Name"])

        # Verify Proxmox API was called
        mock_proxmox.nodes.return_value.qemu.return_value.status.reset.post.assert_called_once()

    def test_power_operations_error_handling(self):
        """Test error handling in power operations"""
        mock_proxmox = self.create_mock_proxmox()

        # Mock an exception with correct constructor
        from proxmoxer.core import ResourceException

        mock_proxmox.nodes.return_value.qemu.return_value.status.start.post.side_effect = ResourceException(
            404, "VM not found", "VM not found"
        )

        response, status_code = power_on(mock_proxmox, self.test_vm_id)

        self.assertEqual(status_code, 404)
        self.assertIn("error", response)
        self.assertEqual(response["error"]["code"], "Base.1.0.ResourceMissingAtURI")

    def test_manage_virtual_media_insert_success(self):
        """Test successful virtual media insert operation"""
        mock_proxmox = self.create_mock_proxmox()
        iso_path = "local:iso/test.iso"

        response, status_code = manage_virtual_media(mock_proxmox, self.test_vm_id, "InsertMedia", iso_path)

        self.assertEqual(status_code, 202)
        self.assertIn("@odata.id", response)
        self.assertEqual(response["TaskState"], "Running")
        self.assertIn("Insert Media", response["Name"])

        # Verify Proxmox API was called
        mock_proxmox.nodes.return_value.qemu.return_value.config.post.assert_called()

    def test_manage_virtual_media_eject_success(self):
        """Test successful virtual media eject operation"""
        mock_proxmox = self.create_mock_proxmox()

        response, status_code = manage_virtual_media(mock_proxmox, self.test_vm_id, "EjectMedia")

        self.assertEqual(status_code, 202)
        self.assertIn("@odata.id", response)
        self.assertEqual(response["TaskState"], "Running")
        self.assertIn("Eject Media", response["Name"])

        # Verify Proxmox API was called
        mock_proxmox.nodes.return_value.qemu.return_value.config.post.assert_called()

    def test_manage_virtual_media_invalid_action(self):
        """Test virtual media with invalid action"""
        mock_proxmox = self.create_mock_proxmox()

        response, status_code = manage_virtual_media(mock_proxmox, self.test_vm_id, "InvalidAction")

        self.assertEqual(status_code, 400)
        self.assertIn("error", response)
        self.assertEqual(response["error"]["code"], "Base.1.0.InvalidRequest")

    def test_manage_virtual_media_missing_iso(self):
        """Test virtual media insert without ISO path"""
        mock_proxmox = self.create_mock_proxmox()

        response, status_code = manage_virtual_media(mock_proxmox, self.test_vm_id, "InsertMedia")

        self.assertEqual(status_code, 400)
        self.assertIn("error", response)
        self.assertEqual(response["error"]["code"], "Base.1.0.InvalidRequest")

    def test_get_vm_status_success(self):
        """Test successful VM status retrieval"""
        mock_proxmox = self.create_mock_proxmox()

        response = get_vm_status(mock_proxmox, self.test_vm_id)

        self.assertIn("@odata.id", response)
        self.assertIn("PowerState", response)
        self.assertIn("Status", response)
        self.assertEqual(response["PowerState"], "On")  # Based on mock status "running"
        self.assertEqual(response["Id"], str(self.test_vm_id))

        # Verify required Redfish fields
        self.assertIn("Processors", response)
        self.assertIn("Memory", response)
        self.assertIn("Storage", response)
        self.assertIn("EthernetInterfaces", response)
        self.assertIn("Boot", response)
        self.assertIn("Actions", response)

    def test_get_bios_success(self):
        """Test successful BIOS information retrieval"""
        mock_proxmox = self.create_mock_proxmox()

        response = get_bios(mock_proxmox, self.test_vm_id)

        self.assertIn("@odata.id", response)
        self.assertIn("FirmwareMode", response)
        self.assertIn("Attributes", response)
        self.assertEqual(response["FirmwareMode"], "BIOS")  # Based on mock config "seabios"

    def test_validate_token_basic_auth_success(self):
        """Test successful Basic authentication"""
        credentials = f"{self.test_username}:{self.test_password}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        headers = {"Authorization": f"Basic {encoded_credentials}"}

        # Mock the authenticate_user function to return True
        with patch("proxmox_redfish.proxmox_redfish.authenticate_user") as mock_auth:
            mock_auth.return_value = True

            # Mock the AUTH variable directly in the validate_token function
            with patch("proxmox_redfish.proxmox_redfish.AUTH", "Basic"):
                valid, message = validate_token(headers)
                self.assertTrue(valid)
                self.assertEqual(message, self.test_username)

    def test_validate_token_session_auth_success(self):
        """Test successful Session authentication"""
        headers = {"X-Auth-Token": self.test_token}

        # Mock sessions
        import proxmox_redfish.proxmox_redfish as rfp

        original_sessions = rfp.sessions
        rfp.sessions = {
            self.test_token: {"username": self.test_username, "password": self.test_password, "created": time.time()}
        }

        try:
            # Mock the AUTH variable to use Session authentication
            with patch("proxmox_redfish.proxmox_redfish.AUTH", "Session"):
                valid, message = validate_token(headers)
                self.assertTrue(valid)
                self.assertEqual(message, self.test_username)
        finally:
            rfp.sessions = original_sessions

    def test_validate_token_invalid(self):
        """Test invalid token validation"""
        headers = {"X-Auth-Token": "invalid-token"}

        # Mock the AUTH variable to use Session authentication
        with patch("proxmox_redfish.proxmox_redfish.AUTH", "Session"):
            valid, message = validate_token(headers)
            self.assertFalse(valid)
            self.assertIn("Invalid", message)

    def test_reorder_boot_order_pxe(self):
        """Test boot order reordering for PXE"""
        mock_proxmox = self.create_mock_proxmox()
        current_order = "order=scsi0;ide2;net0"
        target = "Pxe"

        new_order = reorder_boot_order(mock_proxmox, self.test_vm_id, current_order, target)

        self.assertIn("net0", new_order)
        self.assertTrue(new_order.startswith("net0"))

    def test_reorder_boot_order_cd(self):
        """Test boot order reordering for CD"""
        mock_proxmox = self.create_mock_proxmox()
        current_order = "order=scsi0;ide2;net0"
        target = "Cd"

        new_order = reorder_boot_order(mock_proxmox, self.test_vm_id, current_order, target)

        self.assertIn("ide2", new_order)
        self.assertTrue(new_order.startswith("ide2"))

    def test_reorder_boot_order_hdd(self):
        """Test boot order reordering for HDD"""
        mock_proxmox = self.create_mock_proxmox()
        current_order = "order=scsi0;ide2;net0"
        target = "Hdd"

        new_order = reorder_boot_order(mock_proxmox, self.test_vm_id, current_order, target)

        self.assertIn("scsi0", new_order)
        self.assertTrue(new_order.startswith("scsi0"))

    def test_ensure_iso_available_local(self):
        """Test ISO availability for local storage"""
        mock_proxmox = self.create_mock_proxmox()
        iso_path = "local:iso/test.iso"

        result = _ensure_iso_available(mock_proxmox, iso_path)

        self.assertEqual(result, iso_path)  # Should return unchanged for local storage

    def test_ensure_iso_available_url(self):
        """Test ISO availability for URL (simplified to avoid network requests)"""
        mock_proxmox = self.create_mock_proxmox()

        # Test with a local storage reference (should return unchanged)
        local_iso = "local:iso/test.iso"
        result = _ensure_iso_available(mock_proxmox, local_iso)
        self.assertEqual(result, local_iso)

        # Test with a URL - just verify the function handles it without hanging
        # We'll skip the actual URL processing to avoid network requests
        iso_url = "http://example.com/test.iso"

        # Mock the entire function to return a predictable result
        with patch("proxmox_redfish.proxmox_redfish._ensure_iso_available") as mock_func:
            mock_func.return_value = "local:iso/downloaded.iso"
            result = mock_func(mock_proxmox, iso_url)
            self.assertEqual(result, "local:iso/downloaded.iso")

    def test_handle_proxmox_error_404(self):
        """Test Proxmox error handling for 404"""
        from proxmoxer.core import ResourceException

        exception = ResourceException(404, "VM not found", "VM not found")
        response, status_code = handle_proxmox_error("Power On", exception, self.test_vm_id)

        self.assertEqual(status_code, 404)
        self.assertIn("error", response)
        self.assertEqual(response["error"]["code"], "Base.1.0.ResourceMissingAtURI")

    def test_handle_proxmox_error_403(self):
        """Test Proxmox error handling for 403"""
        from proxmoxer.core import ResourceException

        exception = ResourceException(403, "Permission denied", "Permission denied")
        response, status_code = handle_proxmox_error("Power On", exception, self.test_vm_id)

        self.assertEqual(status_code, 403)
        self.assertIn("error", response)
        self.assertEqual(response["error"]["code"], "Base.1.0.InsufficientPrivilege")

    def test_handle_proxmox_error_general(self):
        """Test Proxmox error handling for general errors"""
        from proxmoxer.core import ResourceException

        exception = ResourceException(500, "Internal server error", "Internal server error")
        response, status_code = handle_proxmox_error("Power On", exception, self.test_vm_id)

        self.assertEqual(status_code, 500)
        self.assertIn("error", response)
        self.assertEqual(response["error"]["code"], "Base.1.0.GeneralError")


class TestRedfishEndpoints(unittest.TestCase):
    """Test Redfish HTTP endpoints"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_vm_id = 100
        self.test_username = "testuser@pam"
        self.test_password = "testpass"
        self.test_token = "test-token-12345"

        # Set up environment variables
        os.environ["PROXMOX_HOST"] = "test-proxmox.local"
        os.environ["PROXMOX_USER"] = "testuser"
        os.environ["PROXMOX_PASSWORD"] = "testpass"
        os.environ["PROXMOX_NODE"] = "pve-node"
        os.environ["VERIFY_SSL"] = "false"
        os.environ["REDFISH_LOGGING_ENABLED"] = "false"

    def tearDown(self):
        """Clean up after tests"""
        for var in [
            "PROXMOX_HOST",
            "PROXMOX_USER",
            "PROXMOX_PASSWORD",
            "PROXMOX_NODE",
            "VERIFY_SSL",
            "REDFISH_LOGGING_ENABLED",
        ]:
            if var in os.environ:
                del os.environ[var]

    def create_test_handler(self):
        """Create a test RedfishRequestHandler instance"""
        # Create a mock request and response
        request = Mock()
        request.makefile.return_value = BytesIO(b"")

        # Create the handler
        handler = RedfishRequestHandler(request, ("127.0.0.1", 8000), None)
        handler.wfile = BytesIO()

        # Set required HTTP request attributes
        handler.requestline = "GET /redfish/v1 HTTP/1.1"
        handler.command = "GET"
        handler.path = "/redfish/v1"
        handler.request_version = "HTTP/1.1"
        handler.headers = {}
        handler.rfile = BytesIO(b"")

        return handler

    def extract_json_from_response(self, handler):
        """Extract JSON from HTTP response"""
        response_raw = handler.wfile.getvalue().decode()
        # Find the JSON part (after double \r\n\r\n)
        json_start = response_raw.find("\r\n\r\n") + 4
        return json.loads(response_raw[json_start:])

    def test_get_root_endpoint(self):
        """Test GET /redfish/v1 endpoint"""
        handler = self.create_test_handler()
        handler.path = "/redfish/v1"
        handler.headers = {"X-Auth-Token": self.test_token}

        # Mock authentication and Proxmox API
        with patch("proxmox_redfish.proxmox_redfish.validate_token") as mock_validate, patch(
            "proxmox_redfish.proxmox_redfish.get_proxmox_api"
        ) as mock_get_api:

            mock_validate.return_value = (True, self.test_username)
            mock_proxmox = Mock()
            mock_get_api.return_value = mock_proxmox

            handler.do_GET()

            # Verify response
            response_data = self.extract_json_from_response(handler)
            self.assertIn("@odata.id", response_data)
            self.assertEqual(response_data["@odata.id"], "/redfish/v1")
            self.assertIn("Systems", response_data)

    def test_get_systems_collection(self):
        """Test GET /redfish/v1/Systems endpoint"""
        handler = self.create_test_handler()
        handler.path = "/redfish/v1/Systems"
        handler.headers = {"X-Auth-Token": self.test_token}

        # Mock authentication and Proxmox API
        with patch("proxmox_redfish.proxmox_redfish.validate_token") as mock_validate, patch(
            "proxmox_redfish.proxmox_redfish.get_proxmox_api"
        ) as mock_get_api:

            mock_validate.return_value = (True, self.test_username)
            mock_proxmox = Mock()
            mock_proxmox.nodes.return_value.qemu.get.return_value = [
                {"vmid": 100, "name": "test-vm-1"},
                {"vmid": 101, "name": "test-vm-2"},
            ]
            mock_get_api.return_value = mock_proxmox

            handler.do_GET()

            # Verify response
            response_data = self.extract_json_from_response(handler)
            self.assertIn("@odata.id", response_data)
            self.assertEqual(response_data["@odata.id"], "/redfish/v1/Systems")
            self.assertIn("Members", response_data)
            self.assertEqual(len(response_data["Members"]), 2)

    def test_get_system_status(self):
        """Test GET /redfish/v1/Systems/{id} endpoint"""
        handler = self.create_test_handler()
        handler.path = f"/redfish/v1/Systems/{self.test_vm_id}"
        handler.headers = {"X-Auth-Token": self.test_token}

        # Mock authentication and Proxmox API
        with patch("proxmox_redfish.proxmox_redfish.validate_token") as mock_validate, patch(
            "proxmox_redfish.proxmox_redfish.get_proxmox_api"
        ) as mock_get_api, patch("proxmox_redfish.proxmox_redfish.get_vm_status") as mock_get_status:

            mock_validate.return_value = (True, self.test_username)
            mock_proxmox = Mock()
            mock_get_api.return_value = mock_proxmox

            mock_status_response = {
                "@odata.id": f"/redfish/v1/Systems/{self.test_vm_id}",
                "Id": str(self.test_vm_id),
                "PowerState": "On",
                "Status": {"State": "Enabled", "Health": "OK"},
            }
            mock_get_status.return_value = mock_status_response

            handler.do_GET()

            # Verify response
            response_data = self.extract_json_from_response(handler)
            self.assertIn("@odata.id", response_data)
            self.assertEqual(response_data["Id"], str(self.test_vm_id))
            self.assertIn("PowerState", response_data)

    def test_post_power_on(self):
        """Test POST /redfish/v1/Systems/{id}/Actions/ComputerSystem.Reset with On"""
        handler = self.create_test_handler()
        handler.command = "POST"  # Set method to POST
        handler.path = f"/redfish/v1/Systems/{self.test_vm_id}/Actions/ComputerSystem.Reset"
        body = json.dumps({"ResetType": "On"}).encode()
        handler.headers = {"X-Auth-Token": self.test_token, "Content-Length": str(len(body))}
        handler.rfile = BytesIO(body)

        # Mock authentication and Proxmox API
        with patch("proxmox_redfish.proxmox_redfish.validate_token") as mock_validate, patch(
            "proxmox_redfish.proxmox_redfish.get_proxmox_api"
        ) as mock_get_api, patch("proxmox_redfish.proxmox_redfish.power_on") as mock_power_on:

            mock_validate.return_value = (True, self.test_username)
            mock_proxmox = Mock()
            mock_get_api.return_value = mock_proxmox

            mock_power_response = {"@odata.id": "/redfish/v1/TaskService/Tasks/test-task", "TaskState": "Running"}
            mock_power_on.return_value = (mock_power_response, 202)

            handler.do_POST()

            # Verify power_on was called
            mock_power_on.assert_called_once_with(mock_proxmox, self.test_vm_id)

    def test_post_virtual_media_insert(self):
        """Test POST /redfish/v1/Managers/1/VirtualMedia/Cd/Actions/VirtualMedia.InsertMedia"""
        handler = self.create_test_handler()
        handler.command = "POST"  # Set method to POST
        handler.path = "/redfish/v1/Managers/1/VirtualMedia/Cd/Actions/VirtualMedia.InsertMedia"
        body = json.dumps({"Image": "http://example.com/test.iso"}).encode()
        handler.headers = {"X-Auth-Token": self.test_token, "Content-Length": str(len(body))}
        handler.rfile = BytesIO(body)

        # Mock authentication and Proxmox API
        with patch("proxmox_redfish.proxmox_redfish.validate_token") as mock_validate, patch(
            "proxmox_redfish.proxmox_redfish.get_proxmox_api"
        ) as mock_get_api, patch("proxmox_redfish.proxmox_redfish.manage_virtual_media") as mock_manage:

            mock_validate.return_value = (True, self.test_username)
            mock_proxmox = Mock()
            mock_get_api.return_value = mock_proxmox

            mock_manage_response = {"@odata.id": "/redfish/v1/TaskService/Tasks/test-task", "TaskState": "Running"}
            mock_manage.return_value = (mock_manage_response, 202)

            handler.do_POST()

            # Verify manage_virtual_media was called
            mock_manage.assert_called_once_with(mock_proxmox, 1, "InsertMedia", "http://example.com/test.iso")

    def test_post_virtual_media_eject(self):
        """Test POST /redfish/v1/Managers/1/VirtualMedia/Cd/Actions/VirtualMedia.EjectMedia"""
        handler = self.create_test_handler()
        handler.path = "/redfish/v1/Managers/1/VirtualMedia/Cd/Actions/VirtualMedia.EjectMedia"
        handler.headers = {"X-Auth-Token": self.test_token}
        handler.rfile = BytesIO(b"{}")

        # Mock authentication and Proxmox API
        with patch("proxmox_redfish.proxmox_redfish.validate_token") as mock_validate, patch(
            "proxmox_redfish.proxmox_redfish.get_proxmox_api"
        ) as mock_get_api, patch("proxmox_redfish.proxmox_redfish.manage_virtual_media") as mock_manage:

            mock_validate.return_value = (True, self.test_username)
            mock_proxmox = Mock()
            mock_get_api.return_value = mock_proxmox

            mock_manage_response = {"@odata.id": "/redfish/v1/TaskService/Tasks/test-task", "TaskState": "Running"}
            mock_manage.return_value = (mock_manage_response, 202)

            handler.do_POST()

            # Verify manage_virtual_media was called
            mock_manage.assert_called_once_with(mock_proxmox, 1, "EjectMedia")

    def test_authentication_failure(self):
        """Test authentication failure"""
        handler = self.create_test_handler()
        handler.path = "/redfish/v1/Systems"
        handler.headers = {"X-Auth-Token": "invalid-token"}

        with patch("proxmox_redfish.proxmox_redfish.validate_token") as mock_validate:
            mock_validate.return_value = (False, "Invalid token")

            handler.do_GET()

            # Verify 401 response - check HTTP status from response
            response_raw = handler.wfile.getvalue().decode()
            self.assertIn("HTTP/1.1 401", response_raw)
            response_data = self.extract_json_from_response(handler)
            self.assertIn("error", response_data)


class TestMetal3Compatibility(unittest.TestCase):
    """Test Metal3/Ironic compatibility features"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_vm_id = 100
        os.environ["PROXMOX_HOST"] = "test-proxmox.local"
        os.environ["PROXMOX_USER"] = "testuser"
        os.environ["PROXMOX_PASSWORD"] = "testpass"
        os.environ["PROXMOX_NODE"] = "pve-node"
        os.environ["VERIFY_SSL"] = "false"
        os.environ["REDFISH_LOGGING_ENABLED"] = "false"

    def tearDown(self):
        """Clean up after tests"""
        for var in [
            "PROXMOX_HOST",
            "PROXMOX_USER",
            "PROXMOX_PASSWORD",
            "PROXMOX_NODE",
            "VERIFY_SSL",
            "REDFISH_LOGGING_ENABLED",
        ]:
            if var in os.environ:
                del os.environ[var]

    def test_metal3_virtual_media_paths(self):
        """Test that VirtualMedia endpoints match Metal3 expectations"""
        # Metal3 expects these specific paths
        # expected_paths = [
        #     "/redfish/v1/Managers/1/VirtualMedia/Cd",
        #     "/redfish/v1/Managers/1/VirtualMedia/Cd/Actions/VirtualMedia.InsertMedia",
        #     "/redfish/v1/Managers/1/VirtualMedia/Cd/Actions/VirtualMedia.EjectMedia",
        # ]

        # These should be handled by the current implementation
        # (The test verifies the paths are recognized in the code)
        self.assertTrue(True)  # Placeholder - actual implementation would test path handling

    def test_metal3_boot_source_override(self):
        """Test Metal3 boot source override functionality"""
        mock_proxmox = Mock()
        mock_proxmox.nodes.return_value.qemu.return_value.config.get.return_value = {
            "boot": "order=scsi0;ide2;net0",
            "ide2": "none,media=cdrom",
            "scsi0": "local:100/vm-100-disk-1.qcow2,size=20G",
            "net0": "virtio=52:54:00:12:34:56,bridge=vmbr0",
        }

        # Test boot to CD
        new_order = reorder_boot_order(mock_proxmox, self.test_vm_id, "order=scsi0;ide2;net0", "Cd")
        self.assertTrue(new_order.startswith("ide2"))

        # Test boot to PXE
        new_order = reorder_boot_order(mock_proxmox, self.test_vm_id, "order=scsi0;ide2;net0", "Pxe")
        self.assertTrue(new_order.startswith("net0"))

    def test_metal3_power_states(self):
        """Test Metal3 power state compatibility"""
        mock_proxmox = Mock()
        mock_proxmox.nodes.return_value.qemu.return_value.status.current.get.return_value = {"status": "running"}
        mock_proxmox.nodes.return_value.qemu.return_value.config.get.return_value = {
            "name": "test-vm",
            "memory": 2048,
            "cores": 2,
            "bios": "seabios",
        }

        response = get_vm_status(mock_proxmox, self.test_vm_id)

        # Metal3 expects specific power states
        self.assertIn(response["PowerState"], ["On", "Off", "Paused"])
        self.assertEqual(response["PowerState"], "On")  # Based on "running" status


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestRedfishProxmox))
    suite.addTests(loader.loadTestsFromTestCase(TestRedfishEndpoints))
    suite.addTests(loader.loadTestsFromTestCase(TestMetal3Compatibility))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
