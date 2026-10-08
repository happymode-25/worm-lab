"""Fail if any Python file here imports something outside the standard library.

The whole appeal of worm-lab is that it is one file you can copy to an
air-gapped box and run with the Python that is already installed. That promise
dies the moment somebody adds `requests` or `scipy`, so it is checked in CI
rather than assumed.

Usage:  python ci/import_gate.py            # checks every .py in the repo
        python ci/import_gate.py --quiet
"""
from __future__ import annotations

import argparse
import ast
import importlib.machinery
import pathlib
import sys
import sysconfig

# Names that are legitimately not third-party. worm-lab imports nothing but
# stdlib and its own module, but keeping the table around means a future
# legitimate local helper does not silently rot the gate.
EXEMPT = {"worm_lab"}

# Directory names that mean "third-party code lives here". Matched against path
# components, not substrings, so a project directory called `site-packages-docs`
# is not mistaken for one.
SITE_DIRS = frozenset({"site-packages", "dist-packages"})


def _stdlib_dirs() -> list[str]:
    """Every directory the interpreter uses for the standard library, and none
    for third-party code.

    Taken from `sys.path` with the site directories removed, rather than from a
    guess at what the stdlib looks like on each platform. On Windows
    `site-packages` sits *inside* Lib, so any check that reasons about where a
    module loaded from is wrong there; sys.path already has it right.
    """
    roots: set[str] = set()

    stdlib = sysconfig.get_paths().get("stdlib")
    if stdlib:
        roots.add(str(pathlib.Path(stdlib).resolve()))

    for entry in list(sys.path):
        if not entry:
            continue
        try:
            path = pathlib.Path(entry).resolve()
        except OSError:
            continue
        if SITE_DIRS.intersection(path.parts):
            continue
        roots.add(str(path))

    return sorted(p for p in roots if pathlib.Path(p).is_dir())


def _is_stdlib(name: str, dirs: list[str]) -> bool:
    """True if `name` is part of the interpreter's own standard library.

    Asked as "can the stdlib dirs satisfy this import", never as "where did it
    load from". `sys.stdlib_module_names` answers it from 3.10; this tool
    supports 3.9, so the older path asks PathFinder to search the stdlib
    directories and nothing else.
    """
    table = getattr(sys, "stdlib_module_names", None)
    if table is not None and name in table:
        return True
    if name in sys.builtin_module_names:
        return True
    if not dirs:
        return False
    try:
        return importlib.machinery.PathFinder.find_spec(name, dirs) is not None
    except (ImportError, ValueError, AttributeError):
        return False


def imported_names(tree: ast.AST) -> list[tuple[int, str]]:
    """Every top-level module name the file imports, with its line number."""
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((node.lineno, alias.name.split(".")[0]))
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                continue  # relative import: local by definition
            found.append((node.lineno, (node.module or "").split(".")[0]))
    return [(line, name) for line, name in found if name]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quiet", action="store_true", help="only report problems")
    args = parser.parse_args()

    dirs = _stdlib_dirs()

    bad: list[str] = []
    checked = 0
    for path in sorted(pathlib.Path(".").rglob("*.py")):
        if "__pycache__" in path.parts or ".git" in path.parts:
            continue
        checked += 1
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError) as exc:
            bad.append(f"{path}: could not be parsed: {exc}")
            continue
        for lineno, name in imported_names(tree):
            if name in EXEMPT or _is_stdlib(name, dirs):
                continue
            bad.append(f"{path}:{lineno}: {name}")

    if bad:
        print("imports that are neither stdlib nor local:")
        print("\n".join(bad))
        print("\nworm-lab ships as one file with no dependencies. If a name above")
        print("is genuinely required, it has to be reasoned about, not pip-installed.")
        return 1

    if not args.quiet:
        print(f"stdlib only: {checked} file(s) checked on {sys.version.split()[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())