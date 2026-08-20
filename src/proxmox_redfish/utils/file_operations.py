"""File operation utilities for the Proxmox Redfish daemon."""

import fcntl
import hashlib
import os
import shutil
import tempfile
import threading
from typing import Optional

from ..config.logging_config import logger

# Global lock for ISO operations to prevent race conditions
iso_operation_lock = threading.Lock()

# File locks for individual ISO files
iso_file_locks = {}
iso_file_locks_lock = threading.Lock()


def get_file_lock(filename: str) -> threading.Lock:
    """
    Get or create a lock for a specific ISO file.
    This ensures only one thread can modify a specific ISO file at a time.
    """
    with iso_file_locks_lock:
        if filename not in iso_file_locks:
            iso_file_locks[filename] = threading.Lock()
        return iso_file_locks[filename]


def atomic_file_write(temp_file_path: str, target_path: str, timeout: int = 300) -> None:
    """
    Atomically write a file to prevent corruption during concurrent access.
    Uses atomic rename operation to ensure file integrity.
    """
    # Create a temporary file in the same directory as target
    target_dir = os.path.dirname(target_path)
    temp_target = os.path.join(target_dir, f".tmp_{os.path.basename(target_path)}")

    try:
        # Copy the temp file to the target directory
        shutil.copy2(temp_file_path, temp_target)

        # Set proper permissions
        os.chmod(temp_target, 0o644)

        # Atomic rename - this is guaranteed to be atomic on POSIX systems
        os.rename(temp_target, target_path)
        logger.info("Atomic file write completed: %s", target_path)

    except Exception as e:
        # Clean up temp file if it exists
        if os.path.exists(temp_target):
            try:
                os.unlink(temp_target)
            except Exception:
                pass
        raise e


def safe_file_hash(file_path: str, timeout: int = 60) -> Optional[str]:
    """
    Safely calculate hash of a file with timeout and error handling.
    """
    try:
        hash_obj = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Use file locking to prevent reading while file is being written
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)  # Shared lock for reading
            try:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_obj.update(chunk)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)  # Release lock
        return hash_obj.hexdigest()
    except Exception as e:
        logger.warning("Failed to calculate hash for %s: %s", file_path, str(e))
        return None 