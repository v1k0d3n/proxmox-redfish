"""ISO management for the Proxmox Redfish daemon."""

import hashlib
import os
import tempfile
import time
from typing import Dict, Any

import requests
from proxmoxer import ProxmoxAPI

from ..config.logging_config import logger
from ..config.settings import (
    PROXMOX_ISO_STORAGE,
    PROXMOX_NODE,
    VERIFY_SSL,
)
from ..utils.file_operations import (
    get_file_lock,
    atomic_file_write,
    safe_file_hash,
)


def _ensure_iso_available(proxmox: ProxmoxAPI, url_or_volid: str) -> str:
    """
    Return a storage:iso/… volid, downloading + uploading if needed.
    Supports HTTP/S URLs and local storage references.
    Implements hash-based conflict handling and thread-safe concurrent access.

    Args:
        proxmox: ProxmoxAPI instance
        url_or_volid: HTTP/S URL or storage:iso/... reference

    Returns:
        str: storage:iso/filename reference for Proxmox
    """
    # Already looks like "storage:iso/…" → nothing to do
    if ":iso/" in url_or_volid:
        return url_or_volid

    # Check if it's a URL (http/https)
    if url_or_volid.startswith(("http://", "https://")):
        if PROXMOX_ISO_STORAGE == "none":
            raise ValueError("ISO downloads are disabled (PROXMOX_ISO_STORAGE=none)")

        logger.info("Processing ISO from URL: %s", url_or_volid)

        # Extract filename from URL, handling query parameters
        fname = os.path.basename(url_or_volid.split("?", 1)[0])
        if not fname.endswith(".iso"):
            fname += ".iso"  # Ensure .iso extension

        # Determine storage path for hash checking
        if PROXMOX_ISO_STORAGE == "local":
            storage_path = "/var/lib/vz/template/iso"
        else:
            # Try to get storage path from Proxmox API
            try:
                storage_info = proxmox.nodes(PROXMOX_NODE).storage(PROXMOX_ISO_STORAGE).get()
                if isinstance(storage_info, dict):
                    storage_path = storage_info.get("path", "")
                else:
                    storage_path = ""
            except Exception:
                storage_path = ""

        if not storage_path:
            raise Exception(f"Could not determine storage path for {PROXMOX_ISO_STORAGE}")

        # Get file-specific lock to prevent concurrent access to the same ISO
        file_lock = get_file_lock(fname)

        with file_lock:
            logger.info("Acquired lock for ISO file: %s", fname)
            needs_upload = False

            # Check if file already exists and compare hashes
            iso_path = os.path.join(storage_path, fname)
            if os.path.exists(iso_path):
                logger.info("ISO file already exists: %s", iso_path)

                # Download to temp file to calculate hash
                logger.info("Downloading ISO to calculate hash for comparison")
                resp = requests.get(url_or_volid, stream=True, timeout=(30, 1800), verify=VERIFY_SSL)
                resp.raise_for_status()

                with tempfile.NamedTemporaryFile() as tmp:
                    for chunk in resp.iter_content(16 << 20):  # 16 MiB chunks
                        tmp.write(chunk)
                    tmp.flush()

                    # Calculate hash of downloaded file
                    tmp.seek(0)
                    downloaded_hash = hashlib.sha256()
                    for chunk in iter(lambda: tmp.read(8192), b""):
                        downloaded_hash.update(chunk)
                    downloaded_hash_hex = downloaded_hash.hexdigest()

                    # Safely calculate hash of existing file
                    existing_hash_hex = safe_file_hash(iso_path)

                    if existing_hash_hex:
                        logger.info(
                            "Hash comparison - Downloaded: %s, Existing: %s",
                            downloaded_hash_hex[:16],
                            existing_hash_hex[:16],
                        )

                        if downloaded_hash_hex == existing_hash_hex:
                            logger.info("ISO files are identical, skipping upload")
                            volid = f"{PROXMOX_ISO_STORAGE}:iso/{fname}"
                            logger.info("ISO available as: %s", volid)
                            return volid
                        else:
                            logger.info("ISO files differ, will upload with hash suffix")
                            # Create filename with hash suffix to avoid conflicts
                            name_without_ext = os.path.splitext(fname)[0]
                            ext = os.path.splitext(fname)[1]
                            fname = f"{name_without_ext}_{downloaded_hash_hex[:8]}{ext}"
                            iso_path = os.path.join(storage_path, fname)
                            logger.info("Using unique filename: %s", fname)
                            # Need to upload the new file with hash suffix
                            needs_upload = True
                    else:
                        logger.warning("Could not calculate hash of existing file, proceeding with upload")
                        needs_upload = True
            else:
                logger.info("ISO file does not exist, will download: %s", fname)
                needs_upload = True

            # Upload the ISO if needed (either new file or hash-suffixed file)
            if needs_upload:
                logger.info("ISO file needs to be uploaded: %s", fname)
                # Download the ISO
                resp = requests.get(url_or_volid, stream=True, timeout=(30, 1800), verify=VERIFY_SSL)
                resp.raise_for_status()

                with tempfile.NamedTemporaryFile() as tmp:
                    for chunk in resp.iter_content(16 << 20):  # 16 MiB chunks
                        tmp.write(chunk)
                    tmp.flush()

                    # Try API upload first, fallback to direct file copy if it fails
                    try:
                        logger.info("Attempting API upload to storage %s", PROXMOX_ISO_STORAGE)
                        upload = proxmox.nodes(PROXMOX_NODE).storage(PROXMOX_ISO_STORAGE).upload
                        task = upload.post(content="iso", filename=fname, file=open(tmp.name, "rb"))

                        # Wait for the upload task to finish
                        logger.info("API upload task started: %s", task)
                        while True:
                            status = proxmox.nodes(PROXMOX_NODE).tasks(task).status.get()
                            if status is None:
                                raise Exception("Failed to get task status")
                            if status.get("status") == "stopped":
                                if status.get("exitstatus") == "OK":
                                    logger.info("API upload completed successfully")
                                    break
                                else:
                                    raise Exception(f"API upload failed: {status}")
                            time.sleep(2)

                    except Exception as api_error:
                        logger.warning("API upload failed: %s, trying direct file copy", str(api_error))

                        # Fallback: Direct file copy to storage directory with atomic write
                        try:
                            logger.info("Copying ISO to: %s", iso_path)

                            # Ensure directory exists
                            os.makedirs(os.path.dirname(iso_path), exist_ok=True)

                            # Use atomic file write to prevent corruption
                            atomic_file_write(tmp.name, iso_path)

                            logger.info("Direct file copy completed successfully")

                        except Exception as copy_error:
                            raise Exception(
                                f"Both API upload and direct copy failed. "
                                f"API error: {api_error}, Copy error: {copy_error}"
                            )

            volid = f"{PROXMOX_ISO_STORAGE}:iso/{fname}"
            logger.info("ISO available as: %s", volid)
            return volid

    # Not a URL and not a storage reference - return as-is (Proxmox will handle validation)
    logger.warning("Unknown ISO format: %s", url_or_volid)
    return url_or_volid 