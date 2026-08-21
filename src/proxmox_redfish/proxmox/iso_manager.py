"""ISO management for the Proxmox Redfish daemon."""

import hashlib
import os
import tempfile
import threading
import time
from typing import Dict, Optional

import requests
from proxmoxer import ProxmoxAPI
from proxmoxer.core import ResourceException

from ..config.logging_config import logger
from ..config.settings import (
    PROXMOX_ISO_STORAGE,
    VERIFY_SSL,
)
from ..utils.file_operations import (
    atomic_file_write,
    get_file_lock,
    safe_file_hash,
)


def iso_directory(proxmox: ProxmoxAPI, storage_name: str) -> str:
    """Return the filesystem directory holding ISOs for a storage.

    The path is read from the /storage collection rather than the
    /storage/{name} item. Both report it, but the item requires
    Datastore.Allocate -- an administrative privilege over the storage
    itself -- while the collection is readable by anyone with audit rights
    and is filtered to the storages the caller may see. Requiring
    Datastore.Allocate just to locate a directory would mean handing every
    Redfish caller storage administration.

    Not /nodes/{node}/storage/{name}: that returns a directory index of
    sub-endpoints ({'subdir': 'content'} and friends), not configuration.
    Its /status sub-resource is readable but reports no path.

    Proxmox lays ISOs out under <path>/template/iso for every file-backed
    storage type.
    """
    entries = proxmox.storage.get()
    if not isinstance(entries, list):
        raise ValueError("Unexpected response listing storages")

    for entry in entries:
        if entry.get("storage") != storage_name:
            continue

        path = entry.get("path")
        if not path:
            raise ValueError(
                f"Storage {storage_name} has no filesystem path; "
                f"it is type {entry.get('type', 'unknown')} and cannot hold ISOs"
            )
        return os.path.join(path, "template", "iso")

    raise ValueError(f"Storage {storage_name} was not found, or the caller may not see it")


class _Fetch:
    """A transfer one caller is performing on behalf of any others waiting."""

    def __init__(self) -> None:
        self.done = threading.Event()
        self.volid: Optional[str] = None
        self.error: Optional[BaseException] = None


_inflight: Dict[str, _Fetch] = {}
_inflight_lock = threading.Lock()


def _ensure_iso_available(proxmox: ProxmoxAPI, url_or_volid: str, node: str) -> str:
    """Return a storage volid for an image, fetching it once however many ask.

    Provisioning a cluster points several machines at the same image at the
    same time. Each request would otherwise download it in full -- the image
    already being present does not help, since it is downloaded again to hash
    it -- so a six node cluster means six transfers of the same file.

    Callers arriving while a transfer is running wait for it and use its
    result. Nothing is cached beyond that: a later request starts a fresh
    transfer, because the same URL can serve a different image over time.
    """
    # A volid already names an image on storage; there is nothing to fetch.
    if ":iso/" in url_or_volid:
        return _fetch_iso(proxmox, url_or_volid, node)

    with _inflight_lock:
        fetch = _inflight.get(url_or_volid)
        leading = fetch is None
        if fetch is None:
            fetch = _Fetch()
            _inflight[url_or_volid] = fetch

    if not leading:
        logger.info("Waiting for an in-progress transfer of %s", url_or_volid)
        fetch.done.wait()
        if fetch.error is not None:
            raise fetch.error
        # A leader that somehow finished without either is treated as a miss.
        if fetch.volid is not None:
            return fetch.volid
        return _ensure_iso_available(proxmox, url_or_volid, node)

    try:
        fetch.volid = _fetch_iso(proxmox, url_or_volid, node)
        return fetch.volid
    except BaseException as exc:
        fetch.error = exc
        raise
    finally:
        with _inflight_lock:
            _inflight.pop(url_or_volid, None)
        fetch.done.set()


def _fetch_iso(proxmox: ProxmoxAPI, url_or_volid: str, node: str) -> str:
    """
    Return a storage:iso/… volid, downloading + uploading if needed.
    Supports HTTP/S URLs and local storage references.
    Implements hash-based conflict handling and thread-safe concurrent access.

    Args:
        proxmox: ProxmoxAPI instance
        url_or_volid: HTTP/S URL or storage:iso/... reference
        node: node that will attach the ISO; the upload has to land there,
            since a node-local storage cannot serve a guest elsewhere

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
        try:
            storage_path = iso_directory(proxmox, PROXMOX_ISO_STORAGE)
        except Exception as exc:
            raise Exception(f"Could not determine storage path for {PROXMOX_ISO_STORAGE}: {exc}")

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
                        upload = proxmox.nodes(node).storage(PROXMOX_ISO_STORAGE).upload
                        task = upload.post(content="iso", filename=fname, file=open(tmp.name, "rb"))

                        # Wait for the upload task to finish
                        logger.info("API upload task started: %s", task)
                        while True:
                            status = proxmox.nodes(node).tasks(task).status.get()
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
                        # Refusals are never worked around. The upload is where
                        # Proxmox checks whether the caller may write to this
                        # storage, so falling back past a 401 or 403 would carry
                        # out exactly the operation that was just denied.
                        if isinstance(api_error, ResourceException) and api_error.status_code in (401, 403):
                            logger.warning(
                                "Upload of %s refused (HTTP %s); not writing it directly",
                                fname,
                                api_error.status_code,
                            )
                            raise

                        # Anything else falls back to writing the file into the
                        # storage directory. That is not a nicety: the upload API
                        # rejects this request outright on at least some Proxmox
                        # installations -- a one kilobyte file comes back "400 Bad
                        # Request" with an empty error body, on both proxmoxer
                        # 2.2 and 2.3 -- so without this, virtual media does not
                        # work there at all.
                        #
                        # The write runs as the daemon's OS user, so it is
                        # deliberately placed after the permission check above: a
                        # caller Proxmox refuses is refused here too, and only a
                        # caller it accepted reaches this path.
                        logger.warning(
                            "Upload of %s failed (%s); writing it to the storage directory instead",
                            fname,
                            api_error,
                        )

                        try:
                            logger.info("Copying ISO to: %s", iso_path)
                            os.makedirs(os.path.dirname(iso_path), exist_ok=True)
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
