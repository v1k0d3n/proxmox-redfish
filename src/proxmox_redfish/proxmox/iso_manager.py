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


def _may_upload(proxmox: ProxmoxAPI, storage_name: str) -> Optional[bool]:
    """Whether the caller holds Datastore.AllocateTemplate on a storage.

    Returns ``None`` when the answer could not be obtained, which is left
    for the upload itself to settle rather than guessed at.

    Callers may read their own privileges without holding any, so this
    costs nothing and reveals nothing they could not already see.
    """
    path = f"/storage/{storage_name}"
    try:
        granted = proxmox.access.permissions.get(path=path)
    except Exception as exc:  # noqa: BLE001 - an unreadable answer is not an answer
        logger.debug("Could not read privileges on %s: %s", path, exc)
        return None

    if not isinstance(granted, dict):
        return None
    return bool(granted.get(path, {}).get("Datastore.AllocateTemplate"))


def _upload_iso(proxmox: ProxmoxAPI, node: str, path: str) -> None:
    """Upload a local file into the ISO storage as the calling user.

    The image goes up over the caller's own API connection, so Proxmox is
    the one deciding whether this caller may write to this storage. A
    refusal propagates: there is no second route to the storage, so a
    caller Proxmox turns away is turned away.

    Proxmox wants the image itself in the field named ``filename``.
    Sending it as ``file`` beside a separate ``filename`` string comes
    back as an empty "400 Bad Request", which is why the stored image is
    named after the file on disk rather than by a field of its own.
    """
    # Proxmox is the one that decides this, and it is asked again below by
    # the upload itself. The question is put first only so that a refusal
    # arrives as a refusal: Proxmox answers 403 and closes the connection
    # at once, which a client still streaming a real ISO sees as a dropped
    # socket rather than as the 403 it is.
    if _may_upload(proxmox, PROXMOX_ISO_STORAGE) is False:
        raise ResourceException(
            403,
            "Forbidden",
            f"Permission check failed (/storage/{PROXMOX_ISO_STORAGE}, Datastore.AllocateTemplate)",
        )

    fname = os.path.basename(path)
    logger.info("Uploading %s to storage %s", fname, PROXMOX_ISO_STORAGE)

    with open(path, "rb") as image:
        task = proxmox.nodes(node).storage(PROXMOX_ISO_STORAGE).upload.post(content="iso", filename=image)

    logger.info("Upload task started: %s", task)
    while True:
        status = proxmox.nodes(node).tasks(task).status.get()
        if status is None:
            raise Exception("Failed to get task status")
        if status.get("status") == "stopped":
            if status.get("exitstatus") == "OK":
                logger.info("Upload of %s completed", fname)
                return
            raise Exception(f"Upload of {fname} failed: {status}")
        time.sleep(2)


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

                # Proxmox names the stored image after the file it is handed,
                # so the download lands in a scratch directory under the name
                # it should keep rather than under a random temporary one.
                with tempfile.TemporaryDirectory() as tmpdir:
                    tmp_path = os.path.join(tmpdir, fname)
                    with open(tmp_path, "wb") as tmp:
                        for chunk in resp.iter_content(16 << 20):  # 16 MiB chunks
                            tmp.write(chunk)

                    _upload_iso(proxmox, node, tmp_path)

            volid = f"{PROXMOX_ISO_STORAGE}:iso/{fname}"
            logger.info("ISO available as: %s", volid)
            return volid

    # Not a URL and not a storage reference - return as-is (Proxmox will handle validation)
    logger.warning("Unknown ISO format: %s", url_or_volid)
    return url_or_volid
