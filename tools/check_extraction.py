#!/usr/bin/env python3
"""Prove the modular tree is a faithful extraction of the monolith.

Every top-level function and class in proxmox_redfish.py is matched
against its counterpart in the package modules and compared as an AST,
so formatting, comments and import placement are ignored while real
changes in behaviour are not.

Run it after each refactor step; anything reported as DIFFERS is either
a deliberate change that needs justifying or an accident.
"""

import argparse
import ast
import pathlib
import sys
from typing import Dict, List, Tuple

Node = ast.AST


def _definitions(tree: ast.Module) -> Dict[str, Node]:
    """Top-level defs and classes, keyed by name."""
    found = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found[node.name] = node
    return found


def _parse(path: pathlib.Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _strip_docstrings(node: Node) -> None:
    """Remove docstrings from a node and everything nested inside it.

    Prose is documentation, not behaviour, so re-wrapping a docstring or
    adding one to an extracted method must not read as a difference.
    """
    for child in ast.walk(node):
        if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            continue
        body = getattr(child, "body", None)
        if not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
            if isinstance(first.value.value, str):
                child.body = body[1:] or [ast.Pass()]


def _normalize(node: Node) -> str:
    """AST dump with positions and docstrings stripped."""
    clone = ast.parse(ast.unparse(node)).body[0]
    _strip_docstrings(clone)
    return ast.dump(clone, include_attributes=False)


def compare(monolith: pathlib.Path, package: pathlib.Path) -> Tuple[List[str], List[str], List[str]]:
    baseline = _definitions(_parse(monolith))

    modular: Dict[str, Tuple[str, Node]] = {}
    for path in sorted(package.rglob("*.py")):
        if path == monolith or path.name == "__init__.py":
            continue
        for name, node in _definitions(_parse(path)).items():
            modular[name] = (str(path.relative_to(package)), node)

    same, differs, missing = [], [], []
    for name, node in sorted(baseline.items()):
        if name not in modular:
            missing.append(name)
            continue
        where, other = modular[name]
        if _normalize(node) == _normalize(other):
            same.append(f"{name} ({where})")
        else:
            differs.append(f"{name} ({where})")
    return same, differs, missing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--monolith", default="src/proxmox_redfish/proxmox_redfish.py")
    parser.add_argument("--package", default="src/proxmox_redfish")
    parser.add_argument("--quiet", action="store_true", help="Only list problems")
    parser.add_argument(
        "--allow",
        default="tools/extraction_allowlist.txt",
        help="File of 'name: justification' lines for accepted differences",
    )
    args = parser.parse_args()

    allowed = {}
    allow_path = pathlib.Path(args.allow)
    if allow_path.exists():
        for line in allow_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, _, why = line.partition(":")
            allowed[name.strip()] = why.strip()

    same, differs, missing = compare(pathlib.Path(args.monolith), pathlib.Path(args.package))

    if not args.quiet:
        for entry in same:
            print(f"  IDENTICAL  {entry}")
    unexpected = []
    for entry in differs:
        name = entry.split(" (")[0]
        if name in allowed:
            if not args.quiet:
                print(f"  ALLOWED    {entry} -- {allowed[name]}")
        else:
            unexpected.append(entry)
            print(f"  DIFFERS    {entry}")
    for entry in missing:
        print(f"  MISSING    {entry}")

    accepted = len(differs) - len(unexpected)
    print(
        f"\n{len(same)} identical, {accepted} allowed, "
        f"{len(unexpected)} unexpected, {len(missing)} not extracted"
    )
    return 1 if (unexpected or missing) else 0


if __name__ == "__main__":
    sys.exit(main())
