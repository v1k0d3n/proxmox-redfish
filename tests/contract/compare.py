#!/usr/bin/env python3
"""Diff two snapshots produced by capture.py.

Exit status is 0 only when the candidate matches the baseline on every
endpoint, which is the gate a refactor has to pass.
"""

import argparse
import json
import sys
from typing import Any, List

VOLATILE = "<volatile>"


def diff(baseline: Any, candidate: Any, path: str = "") -> List[str]:
    """Report every leaf where candidate departs from baseline."""
    if baseline == VOLATILE or candidate == VOLATILE:
        return []
    if type(baseline) is not type(candidate):
        return [f"{path}: type {type(baseline).__name__} -> {type(candidate).__name__}"]
    if isinstance(baseline, dict):
        problems = []
        for key in sorted(set(baseline) | set(candidate)):
            where = f"{path}.{key}" if path else key
            if key not in baseline:
                problems.append(f"{where}: added ({candidate[key]!r})")
            elif key not in candidate:
                problems.append(f"{where}: removed (was {baseline[key]!r})")
            else:
                problems.extend(diff(baseline[key], candidate[key], where))
        return problems
    if isinstance(baseline, list):
        if len(baseline) != len(candidate):
            return [f"{path}: length {len(baseline)} -> {len(candidate)}"]
        problems = []
        for index, (left, right) in enumerate(zip(baseline, candidate)):
            problems.extend(diff(left, right, f"{path}[{index}]"))
        return problems
    if baseline != candidate:
        return [f"{path}: {baseline!r} -> {candidate!r}"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline")
    parser.add_argument("candidate")
    args = parser.parse_args()

    with open(args.baseline, encoding="utf-8") as handle:
        baseline = json.load(handle)
    with open(args.candidate, encoding="utf-8") as handle:
        candidate = json.load(handle)

    problems = diff(baseline, candidate)
    if not problems:
        print(f"MATCH: {args.candidate} is identical to {args.baseline}")
        return 0

    print(f"{len(problems)} difference(s) between baseline and candidate:\n")
    for problem in problems:
        print(f"  {problem}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
