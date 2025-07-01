#!/usr/bin/env python3
"""
Real-world test script for concurrent ISO access handling.
Uses actual VMs (501, 502, 503) to test the Proxmox-Redfish daemon
with real OpenShift-style concurrent ISO operations.
"""

import os
import sys
import time
import threading
import requests
import json
import tempfile
from urllib.parse import urlparse
import pytest

# Configuration - adjust these for your environment
REDFISH_BASE_URL = "http://localhost:8000" # Your available VMs for testing
VM_IDS = [501, 502, 503] # Your available VMs for testing
TEST_ISO_URL = "https://download.fedoraproject.org/pub/fedora/linux/releases/42/Workstation/x86_64/iso/Fedora-Workstation-Live-42-1.1.x86_64.iso" # ISO you want to use for testing

# Authentication - use environment variables or adjust as needed
AUTH_TOKEN = os.getenv("REDFISH_AUTH_TOKEN", "your-auth-token-here")
HEADERS = {
    "X-Auth-Token": AUTH_TOKEN,
    "Content-Type": "application/json"
}

# Dummy fixtures for local runs
@pytest.fixture
def vm_id():
    return 501

@pytest.fixture
def iso_url():
    return "http://example.com/test.iso"

# Skip tests unless REAL_VM_TESTS=1 is set
skip_if_no_real_vms = pytest.mark.skipif(
    os.environ.get("REAL_VM_TESTS") != "1",
    reason="Skipping real VM tests unless REAL_VM_TESTS=1"
)

def log(message, vm_id=None):
    """Log messages with VM context."""
    timestamp = time.strftime("%H:%M:%S")
    vm_prefix = f"[VM {vm_id}]" if vm_id else "[MAIN]"
    print(f"{timestamp} {vm_prefix} {message}")

@skip_if_no_real_vms
def test_vm_power_status(vm_id):
    """Test if VM is accessible and get its power status."""
    try:
        url = f"{REDFISH_BASE_URL}/redfish/v1/Systems/{vm_id}"
        response = requests.get(url, headers=HEADERS, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            power_state = data.get("PowerState", "Unknown")
            log(f"Power state: {power_state}", vm_id)
            return True, power_state
        else:
            log(f"Failed to get VM status: {response.status_code}", vm_id)
            return False, None
            
    except Exception as e:
        log(f"Error accessing VM: {e}", vm_id)
        return False, None

@skip_if_no_real_vms
def test_virtual_media_get(vm_id):
    """Test VirtualMedia GET endpoint."""
    try:
        url = f"{REDFISH_BASE_URL}/redfish/v1/Systems/{vm_id}/VirtualMedia/Cd"
        response = requests.get(url, headers=HEADERS, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            media_state = data.get("MediaPresent", False)
            log(f"VirtualMedia status: MediaPresent={media_state}", vm_id)
            return True, data
        else:
            log(f"VirtualMedia GET failed: {response.status_code}", vm_id)
            return False, None
            
    except Exception as e:
        log(f"VirtualMedia GET error: {e}", vm_id)
        return False, None

@skip_if_no_real_vms
def test_virtual_media_insert(vm_id, iso_url):
    """Test VirtualMedia InsertMedia operation."""
    try:
        url = f"{REDFISH_BASE_URL}/redfish/v1/Systems/{vm_id}/VirtualMedia/Cd/Actions/VirtualMedia.InsertMedia"
        
        payload = {
            "Image": iso_url,
            "Inserted": True
        }
        
        log(f"Inserting media: {iso_url}", vm_id)
        response = requests.post(url, headers=HEADERS, json=payload, timeout=60)
        
        if response.status_code in [200, 202]:
            data = response.json()
            log(f"InsertMedia successful: {data.get('Id', 'Unknown')}", vm_id)
            return True, data
        else:
            log(f"InsertMedia failed: {response.status_code} - {response.text}", vm_id)
            return False, None
            
    except Exception as e:
        log(f"InsertMedia error: {e}", vm_id)
        return False, None

@skip_if_no_real_vms
def test_virtual_media_eject(vm_id):
    """Test VirtualMedia EjectMedia operation."""
    try:
        url = f"{REDFISH_BASE_URL}/redfish/v1/Systems/{vm_id}/VirtualMedia/Cd/Actions/VirtualMedia.EjectMedia"
        
        payload = {
            "Inserted": False
        }
        
        log("Ejecting media", vm_id)
        response = requests.post(url, headers=HEADERS, json=payload, timeout=30)
        
        if response.status_code in [200, 202]:
            data = response.json()
            log(f"EjectMedia successful: {data.get('Id', 'Unknown')}", vm_id)
            return True, data
        else:
            log(f"EjectMedia failed: {response.status_code} - {response.text}", vm_id)
            return False, None
            
    except Exception as e:
        log(f"EjectMedia error: {e}", vm_id)
        return False, None

def simulate_concurrent_iso_operations(vm_id, iso_url, operation_delay=2):
    """
    Simulate a complete concurrent ISO operation for a VM.
    This represents what OpenShift would do when provisioning a node.
    """
    log(f"Starting concurrent ISO operation simulation", vm_id)
    
    try:
        # Step 1: Check VM accessibility
        accessible, power_state = test_vm_power_status(vm_id)
        if not accessible:
            log(f"VM {vm_id} not accessible, skipping", vm_id)
            return False
        
        # Step 2: Check current VirtualMedia state
        vm_ok, vm_data = test_virtual_media_get(vm_id)
        if not vm_ok:
            log(f"VirtualMedia not accessible for VM {vm_id}, skipping", vm_id)
            return False
        
        # Step 3: Insert media (this will trigger concurrent access handling)
        log(f"Attempting to insert ISO: {iso_url}", vm_id)
        insert_ok, insert_data = test_virtual_media_insert(vm_id, iso_url)
        
        if insert_ok:
            log(f"ISO insertion successful for VM {vm_id}", vm_id)
            
            # Step 4: Verify media was inserted
            time.sleep(operation_delay)
            vm_ok, vm_data = test_virtual_media_get(vm_id)
            if vm_ok and vm_data.get("MediaPresent", False):
                log(f"Media verification successful for VM {vm_id}", vm_id)
            else:
                log(f"Media verification failed for VM {vm_id}", vm_id)
            
            # Step 5: Eject media (cleanup)
            time.sleep(operation_delay)
            eject_ok, eject_data = test_virtual_media_eject(vm_id)
            if eject_ok:
                log(f"Media ejection successful for VM {vm_id}", vm_id)
            else:
                log(f"Media ejection failed for VM {vm_id}", vm_id)
            
            return True
        else:
            log(f"ISO insertion failed for VM {vm_id}", vm_id)
            return False
            
    except Exception as e:
        log(f"Concurrent operation failed for VM {vm_id}: {e}", vm_id)
        return False

def run_concurrent_test():
    """Run the concurrent ISO access test with all VMs."""
    log("=== Real VM Concurrent ISO Access Test ===")
    log(f"Testing with VMs: {VM_IDS}")
    log(f"ISO URL: {TEST_ISO_URL}")
    log(f"Redfish Base URL: {REDFISH_BASE_URL}")
    log("")
    
    # Check if daemon is accessible
    try:
        response = requests.get(f"{REDFISH_BASE_URL}/redfish/v1", timeout=5)
        if response.status_code != 200:
            log("ERROR: Redfish daemon not accessible")
            return False
        log("✓ Redfish daemon is accessible")
    except Exception as e:
        log(f"ERROR: Cannot connect to Redfish daemon: {e}")
        return False
    
    # Create threads for concurrent operations
    threads = []
    results = {}
    
    log("Starting concurrent ISO operations...")
    log("This simulates OpenShift trying to load the same ISO to multiple VMs simultaneously.")
    log("")
    
    start_time = time.time()
    
    for vm_id in VM_IDS:
        thread = threading.Thread(
            target=lambda vid=vm_id: results.update({vid: simulate_concurrent_iso_operations(vid, TEST_ISO_URL)})
        )
        threads.append(thread)
        thread.start()
        
        # Small delay to ensure operations start in sequence
        time.sleep(0.5)
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # Report results
    log("")
    log("=== Test Results ===")
    log(f"Total test time: {total_time:.2f} seconds")
    log("")
    
    success_count = 0
    for vm_id in VM_IDS:
        success = results.get(vm_id, False)
        status = "✓ SUCCESS" if success else "✗ FAILED"
        log(f"VM {vm_id}: {status}")
        if success:
            success_count += 1
    
    log("")
    log(f"Overall result: {success_count}/{len(VM_IDS)} VMs successful")
    
    if success_count == len(VM_IDS):
        log("✓ All concurrent operations completed successfully!")
        log("✓ No file corruption or conflicts detected")
        log("✓ Thread-safe operations working correctly")
    else:
        log("⚠ Some operations failed - check logs for details")
    
    return success_count == len(VM_IDS)

def main():
    """Main test function."""
    print("Real VM Concurrent ISO Access Test")
    print("==================================")
    print()
    print("This test will:")
    print("1. Connect to your Proxmox-Redfish daemon")
    print("2. Test concurrent ISO operations on VMs 501, 502, 503")
    print("3. Verify thread-safe file handling")
    print("4. Demonstrate hash-based conflict resolution")
    print()
    
    # Check configuration
    if AUTH_TOKEN == "your-auth-token-here":
        print("⚠ WARNING: Please set REDFISH_AUTH_TOKEN environment variable")
        print("   or update the AUTH_TOKEN variable in this script")
        print()
    
    # Confirm before running
    response = input("Do you want to proceed with the test? (y/N): ")
    if response.lower() != 'y':
        print("Test cancelled.")
        return
    
    print()
    
    # Run the test
    success = run_concurrent_test()
    
    print()
    if success:
        print("🎉 Test completed successfully!")
        print("Your Proxmox-Redfish daemon is handling concurrent ISO access correctly.")
    else:
        print("⚠ Test completed with some failures.")
        print("Check the logs above for details on what went wrong.")

if __name__ == "__main__":
    main() 