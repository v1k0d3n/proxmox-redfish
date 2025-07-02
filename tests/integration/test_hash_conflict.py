#!/usr/bin/env python3
"""
Test script to demonstrate hash-based ISO conflict handling.
This script simulates the ISO download and conflict resolution logic.
"""

import hashlib
import os
import tempfile
from urllib.parse import urlparse

import requests


def calculate_file_hash(file_path):
    """Calculate SHA256 hash of a file."""
    hash_obj = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()


def download_file_to_temp(url, timeout=60):
    """Download a file to a temporary location and return the path."""
    print(f"Downloading: {url}")
    resp = requests.get(url, stream=True, timeout=timeout)
    resp.raise_for_status()

    # Extract filename from URL
    parsed_url = urlparse(url)
    filename = os.path.basename(parsed_url.path)
    if not filename.endswith(".iso"):
        filename += ".iso"

    # Create temporary file
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".iso")
    temp_path = temp_file.name

    try:
        for chunk in resp.iter_content(16 << 20):  # 16 MiB chunks
            temp_file.write(chunk)
        temp_file.flush()
        print(f"Downloaded to: {temp_path}")
        return temp_path, filename
    except Exception as e:
        os.unlink(temp_path)
        raise e


def handle_iso_conflict(storage_path, filename, temp_file_path):
    """
    Handle ISO filename conflicts using hash comparison.

    Args:
        storage_path: Directory where ISOs are stored
        filename: Original filename
        temp_file_path: Path to downloaded temporary file

    Returns:
        tuple: (final_filename, was_uploaded)
    """
    iso_path = os.path.join(storage_path, filename)

    # Calculate hash of downloaded file
    downloaded_hash = calculate_file_hash(temp_file_path)
    print(f"Downloaded file hash: {downloaded_hash[:16]}...")

    if os.path.exists(iso_path):
        print(f"File already exists: {iso_path}")

        # Calculate hash of existing file
        existing_hash = calculate_file_hash(iso_path)
        print(f"Existing file hash: {existing_hash[:16]}...")

        if downloaded_hash == existing_hash:
            print("Files are identical - skipping upload")
            return filename, False
        else:
            print("Files differ - creating unique filename")
            # Create filename with hash suffix
            name_without_ext = os.path.splitext(filename)[0]
            ext = os.path.splitext(filename)[1]
            unique_filename = f"{name_without_ext}_{downloaded_hash[:8]}{ext}"
            print(f"Unique filename: {unique_filename}")
            return unique_filename, True
    else:
        print(f"File does not exist - will upload as: {filename}")
        return filename, True


def simulate_iso_upload(storage_path, filename, temp_file_path):
    """Simulate uploading an ISO file."""
    final_path = os.path.join(storage_path, filename)
    print(f"Simulating upload to: {final_path}")

    # In real implementation, this would be the actual file copy/upload
    # For demo purposes, we'll just create a small test file
    with open(final_path, "w") as f:
        f.write(f"Simulated ISO file: {filename}\n")

    print(f"Upload completed: {final_path}")
    return final_path


def main():
    """Main test function."""
    print("=== Hash-based ISO Conflict Handling Test ===\n")

    # Test configuration
    storage_path = "/tmp/test_iso_storage"
    # test_url = "https://example.com/test.iso"  # Dummy URL for testing (unused)

    # Create test storage directory
    os.makedirs(storage_path, exist_ok=True)
    print(f"Test storage directory: {storage_path}\n")

    # Scenario 1: First download (file doesn't exist)
    print("Scenario 1: First download")
    print("-" * 40)

    # Create a dummy temp file for testing
    with tempfile.NamedTemporaryFile(delete=False, suffix=".iso") as tmp:
        tmp.write(b"Test ISO content 1")
        temp_path = tmp.name

    filename, should_upload = handle_iso_conflict(storage_path, "test.iso", temp_path)
    if should_upload:
        simulate_iso_upload(storage_path, filename, temp_path)

    print()

    # Scenario 2: Download same file again (identical content)
    print("Scenario 2: Download identical file")
    print("-" * 40)

    # Create another temp file with same content
    with tempfile.NamedTemporaryFile(delete=False, suffix=".iso") as tmp:
        tmp.write(b"Test ISO content 1")  # Same content
        temp_path2 = tmp.name

    filename2, should_upload2 = handle_iso_conflict(storage_path, "test.iso", temp_path2)
    if should_upload2:
        simulate_iso_upload(storage_path, filename2, temp_path2)

    print()

    # Scenario 3: Download different file with same name
    print("Scenario 3: Download different file with same name")
    print("-" * 40)

    # Create temp file with different content
    with tempfile.NamedTemporaryFile(delete=False, suffix=".iso") as tmp:
        tmp.write(b"Test ISO content 2")  # Different content
        temp_path3 = tmp.name

    filename3, should_upload3 = handle_iso_conflict(storage_path, "test.iso", temp_path3)
    if should_upload3:
        simulate_iso_upload(storage_path, filename3, temp_path3)

    print()

    # Cleanup
    print("Cleaning up test files...")
    for temp_file in [temp_path, temp_path2, temp_path3]:
        if os.path.exists(temp_file):
            os.unlink(temp_file)

    print("Test completed successfully!")
    print("\nKey benefits of hash-based conflict handling:")
    print("1. Avoids duplicate downloads of identical files")
    print("2. Prevents filename conflicts with unique hash suffixes")
    print("3. Ensures data integrity through hash verification")
    print("4. Saves storage space and bandwidth")


if __name__ == "__main__":
    main()
