"""Keeping a media change and a power action on one guest from overlapping.

Inserting media fetches the image, uploads it and attaches it, and the
guest is only ready to boot once all of that has happened. A power action
arriving in the middle would start the guest against whatever was attached
before -- often nothing at all.

Requests used to be handled one at a time, which prevented this by
accident: a power action simply queued behind the transfer. Now that they
are handled concurrently the same ordering has to be asked for.

Nothing here decides whether an operation is allowed; it decides only when
it runs.
"""

import threading
from contextlib import contextmanager
from typing import Dict, Iterator

from ..config.logging_config import logger

# One lock per guest, created on first use. Guests come and go, but a lock
# is a few bytes and dropping one while a thread is waiting on it would be
# the bug this module exists to prevent.
_vm_locks: Dict[int, threading.Lock] = {}
_vm_locks_lock = threading.Lock()


def _lock_for(vm_id: int) -> threading.Lock:
    with _vm_locks_lock:
        lock = _vm_locks.get(vm_id)
        if lock is None:
            lock = threading.Lock()
            _vm_locks[vm_id] = lock
        return lock


@contextmanager
def media_change(vm_id: int) -> Iterator[None]:
    """Hold a guest while its media is being changed."""
    lock = _lock_for(vm_id)
    lock.acquire()
    try:
        yield
    finally:
        lock.release()


@contextmanager
def settled_media(vm_id: int, operation: str) -> Iterator[None]:
    """Wait for any media change on a guest to finish, then proceed.

    The wait is bounded by the transfer itself, which carries its own
    timeouts, so this cannot hold a request open indefinitely.
    """
    lock = _lock_for(vm_id)
    if not lock.acquire(blocking=False):
        logger.info("%s for VM %s is waiting for a media change to finish", operation, vm_id)
        lock.acquire()
        logger.info("%s for VM %s proceeding; media change finished", operation, vm_id)
    try:
        yield
    finally:
        lock.release()
