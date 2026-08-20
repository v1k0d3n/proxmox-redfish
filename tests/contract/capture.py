#!/usr/bin/env python3
"""Capture a normalized snapshot of a running Redfish daemon.

The snapshot is the safety net for refactoring: capture once from the
known-good daemon, once from the candidate, then diff the two trees.

Volatile fields (uptime, cpu load, task ids, session tokens) are detected
rather than hard-coded -- every endpoint is requested several times and
any leaf whose value moves between passes is masked. That keeps the
snapshot stable without someone having to guess the volatile set up front.

Credentials come from REDFISH_USER / REDFISH_PASS in the environment and
are never written into the snapshot.
"""

import argparse
import json
import os
import pathlib
import sys
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3

from catalog import Endpoint, mutating, read_only, unauthenticated

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VOLATILE = "<volatile>"


def _merge(a: Any, b: Any) -> Any:
    """Combine two observations, masking anything that changed."""
    if a == b:
        return a
    if isinstance(a, dict) and isinstance(b, dict):
        if set(a) != set(b):
            return VOLATILE
        return {k: _merge(a[k], b[k]) for k in a}
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return VOLATILE
        return [_merge(x, y) for x, y in zip(a, b)]
    return VOLATILE


def _request(
    session: requests.Session,
    base_url: str,
    ep: Endpoint,
    auth: Optional[Tuple[str, str]],
    timeout: int,
) -> Dict[str, Any]:
    url = base_url.rstrip("/") + ep.path
    try:
        resp = session.request(
            ep.method,
            url,
            json=ep.body if ep.body is not None else None,
            auth=auth,
            verify=False,
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001 - transport failure is itself a result
        return {"transport_error": type(exc).__name__}

    try:
        body: Any = resp.json()
    except ValueError:
        body = resp.text

    return {"status": resp.status_code, "body": body}


def capture(
    base_url: str,
    endpoints: List[Endpoint],
    auth: Optional[Tuple[str, str]],
    passes: int,
    timeout: int,
) -> Dict[str, Any]:
    session = requests.Session()
    snapshot: Dict[str, Any] = {}

    for ep in endpoints:
        observed = _request(session, base_url, ep, auth, timeout)
        for _ in range(passes - 1):
            observed = _merge(observed, _request(session, base_url, ep, auth, timeout))
        snapshot[ep.name] = {"method": ep.method, "path": ep.path, "response": observed}
        status = observed.get("status", observed.get("transport_error"))
        print(f"  {ep.method:6} {ep.path:-<62} {status}", file=sys.stderr)

    return snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="e.g. https://127.0.0.1:8000")
    parser.add_argument("--vm-id", type=int, required=True)
    parser.add_argument("--out", required=True, help="Snapshot file to write")
    parser.add_argument("--passes", type=int, default=3, help="Requests per endpoint (volatility detection)")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--storage-id", default="0")
    parser.add_argument("--nic-id", default="0")
    parser.add_argument(
        "--include-mutating",
        action="store_true",
        help="Also exercise power/media actions. DISPOSABLE VMs ONLY.",
    )
    parser.add_argument("--iso-url", default="", help="ISO URL used by the mutating catalog")
    args = parser.parse_args()

    user = os.getenv("REDFISH_USER")
    password = os.getenv("REDFISH_PASS")
    if not user or not password:
        print("REDFISH_USER and REDFISH_PASS must be set in the environment", file=sys.stderr)
        return 2
    auth = (user, password)

    if args.include_mutating and not args.iso_url:
        print("--include-mutating requires --iso-url", file=sys.stderr)
        return 2

    snapshot: Dict[str, Any] = {"vm_id": args.vm_id}

    print("Unauthenticated contract:", file=sys.stderr)
    snapshot["unauthenticated"] = capture(args.base_url, unauthenticated(), None, args.passes, args.timeout)

    print("Read-only contract:", file=sys.stderr)
    snapshot["read_only"] = capture(
        args.base_url,
        read_only(args.vm_id, args.storage_id, args.nic_id),
        auth,
        args.passes,
        args.timeout,
    )

    if args.include_mutating:
        print("Mutating contract (single pass, ordered):", file=sys.stderr)
        # Mutating calls change state, so they are inherently single-pass.
        snapshot["mutating"] = capture(
            args.base_url,
            mutating(args.vm_id, args.iso_url),
            auth,
            1,
            args.timeout,
        )

    # snapshots/ is gitignored, so it may not exist on a fresh checkout.
    parent = pathlib.Path(args.out).parent
    if parent and not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)

    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, indent=2, sort_keys=True)
    print(f"\nWrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
