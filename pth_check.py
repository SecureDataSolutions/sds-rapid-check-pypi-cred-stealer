#!/usr/bin/env python3
# Eddie Espino, Secure Data Solutions. MIT License. No warranty; run only on systems you own or are authorized to check.
"""Look for Python startup hooks (.pth files that run code) and the bad agent-framework releases.

Background: on Nov 17, 2026, agent-framework 1.26.1 and 1.26.2 on PyPI carried a credential
stealer. Python normally runs executable .pth lines at startup, even if nobody imports
the package. 1.26.0 and earlier were unaffected by this incident.

Usage:
  python3 -I -B -S pth_check.py                 # this trusted Python's site-packages
  python3 -I -B -S pth_check.py ~/projects /opt # also walk these folders

Read-only. Changes nothing. Sends nothing. Python 3 standard library only.
Use a trusted Python binary. Keep -I -B -S to isolate startup, disable bytecode writes,
and prevent .pth execution. Pass the roots of virtualenvs or CI directories to inspect.

What it flags (!!):  the two bad versions, the published file names and file fingerprints,
                     a suspiciously named wheel, or a bad version pin in a supported lock or
                     requirements file. Renamed wheels and some lock layouts may be missed.
What it also lists:  .pth files with executable lines in the scanned site-packages folders.
                     Most are normal (setuptools, virtualenv, editable installs).

Indicators: GitHub advisory GHSA-764m-3ppc-5m73, Wiz and JFrog write-ups.
"""
import sys

if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site):
    sys.exit("Use a trusted Python with -I -B -S. Startup hooks may already have run in this invocation.")

import hashlib, json, os, re, site
from itertools import islice

LAST_CHECKED = "2026-11-23"  # date the indicators below were last compared with the sources
BAD_VERSIONS = {"1.26.1", "1.26.2"}
# Path relative to site-packages -> published SHA-256.
KNOWN_BAD_FILES = {
    "agent_framework_meta.pth": "21f28e8517a10ffe431f8d68f5875c85eca4001ae6d118322b0a41873998eb5e",  # 1.26.1
    "agent_framework_meta/_telemetry.py": "39fa329f2a93f734b0bb8f5adb203ea3331d1ae479832a5015a54cb17aabd663",
    "agent_framework_meta/__init__.py": "c275ccbe520ef3c0f02dc6a35389e427f9f1b4e0b12e140cd7bf7179ce143f02",
    "af_runtime_diag.pth": "325e7e9f0ec94e41ad1a1b7a3f18a6b8b5bffece2e2b97b8d3369eb967452f93",       # 1.26.2
    "af_runtime_diag.py": "54d885b7d7161c9ed96489c66364c4bfbf635929166843bba10d97d46b5a2e1f",        # 1.26.2
}
BAD_WHEELS = {
    "d27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110": "1.26.1",
    "3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9": "1.26.2",
}
COMMON_NAMES = ("distutils-precedence.pth", "_virtualenv.pth", "easy-install.pth")
META = re.compile(r"^agent[-_]framework-(\d[^-]*)\.(dist-info|egg-info)$", re.I)
WHEEL = re.compile(r"^agent[-_]framework-(1\.26\.[12])-.*\.whl$", re.I)
LOCK_NAMES = re.compile(r"^(requirements[^/\\]*\.(txt|in)|constraints[^/\\]*\.txt|uv\.lock|poetry\.lock|Pipfile\.lock|pdm\.lock)$", re.I)
NAME = r"agent[-_.]+framework"
PIN = re.compile(r"=={1,2}[ \t]*(1\.26\.[12])")
REQUIREMENT = re.compile(
    rf"^[ \t]*{NAME}(?:\[[^\n\]]*\])?[ \t]*=={{1,2}}[ \t]*(1\.26\.[12])(?=[ \t;#]|$)", re.I | re.M
)
LOCK_ENTRY = re.compile(
    rf"^[ \t]*name[ \t]*=[ \t]*['\"]{NAME}['\"][ \t]*\n"
    r"[ \t]*version[ \t]*=[ \t]*['\"](1\.26\.[12])['\"]", re.I | re.M
)
SKIP_DIRS = {".git", "node_modules"}
SITE_NAMES = ("site-packages", "dist-packages")


def sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
    except OSError:
        return None
    return h.hexdigest()


def lock_version(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        content = f.read(20 * 1024 * 1024 + 1)
    if len(content) > 20 * 1024 * 1024:
        raise ValueError("file exceeds scan limit")
    name = os.path.basename(path).lower()
    if name == "pipfile.lock":
        sections = json.loads(content)
        if not isinstance(sections, dict):
            raise ValueError("expected a Pipfile.lock object")
        for packages in sections.values():
            if not isinstance(packages, dict):
                continue
            for package, entry in packages.items():
                if re.fullmatch(NAME, package, re.I) and isinstance(entry, dict):
                    version = entry.get("version")
                    if isinstance(version, str):
                        match = PIN.fullmatch(version)
                        if match:
                            return match.group(1)
        return None
    match = (LOCK_ENTRY if name.endswith(".lock") else REQUIREMENT).search(content)
    return match.group(1) if match else None


def collect(extra, report_error):
    """Return (site-packages folders, wheel files, lock files)."""
    dirs = set(getattr(site, "getsitepackages", lambda: [])())
    try:
        dirs.add(site.getusersitepackages())
    except Exception:
        pass
    dirs.update(p for p in sys.path if p.endswith(SITE_NAMES))
    wheels, locks = [], []
    for root in extra:
        folder = os.path.expanduser(root)
        if not os.path.isdir(folder):
            report_error(f"{root!r} is missing, inaccessible, or not a directory")
            continue
        for d, subdirs, files in os.walk(folder, onerror=report_error):
            if os.path.basename(d) in SITE_NAMES:
                dirs.add(os.path.abspath(d))
                subdirs[:] = []
            subdirs[:] = [s for s in subdirs if s not in SKIP_DIRS]
            for name in files:
                path = os.path.join(d, name)
                if WHEEL.match(name) and os.path.isfile(path):
                    wheels.append(path)
                elif LOCK_NAMES.match(name) and os.path.isfile(path):
                    locks.append(path)
    return sorted(d for d in dirs if os.path.isdir(d)), wheels, locks


def main():
    flagged = hooks = pth_files = 0
    errors = 0

    def report_error(error):
        nonlocal errors
        errors += 1
        print(f"could not read: {error}")

    dirs, wheels, locks = collect(sys.argv[1:], report_error)

    for d in dirs:
        try:
            names = sorted(os.listdir(d))
        except OSError as e:
            report_error(e)
            continue
        for name, digest in KNOWN_BAD_FILES.items():
            path = os.path.join(d, *name.split("/"))
            if not os.path.isfile(path):
                continue
            same = sha256(path) == digest
            if not same and name.endswith("/__init__.py"):
                continue  # The clean package ships a file at this path too.
            why = "fingerprint matches" if same else "indicator file name matches"
            print(f"!! SUSPICIOUS FILE ({why}): {path}")
            flagged += 1
        for name in names:
            path = os.path.join(d, name)
            m = META.match(name)
            if m:
                bad = m.group(1) in BAD_VERSIONS
                print(f"{'!! BAD VERSION' if bad else 'info'}: agent-framework {m.group(1)} in {d}")
                flagged += bad
            if name.endswith(".pth") and not name.startswith(".") and os.path.isfile(path):
                pth_files += 1
                try:
                    with open(path, encoding="utf-8-sig", errors="replace") as f:
                        lines = (line for line in f if line.startswith(("import ", "import\t")))
                        code = [line.rstrip("\n") for line in islice(lines, 3)]
                except OSError as e:
                    report_error(e)
                    continue
                if code:
                    hooks += 1
                    common = " (common name; content not verified)" if name in COMMON_NAMES else ""
                    print(f"hook: {path}{common}")
                    for line in code:
                        print(f"      {line[:120]}")

    for path in wheels:
        ver = BAD_WHEELS.get(sha256(path) or "")
        why = f"fingerprint matches the bad {ver} wheel" if ver else "bad version number in the file name"
        print(f"!! BAD DOWNLOAD ({why}): {path}")
        flagged += 1

    for path in locks:
        try:
            version = lock_version(path)
        except (OSError, ValueError, RecursionError) as e:
            report_error(f"{path} ({e})")
            continue
        if version:
            print(f"!! LOCK OR REQUIREMENTS PIN TO A BAD VERSION ({version}): {path}")
            flagged += 1

    print(f"\nChecked {len(dirs)} site-packages folder(s), {pth_files} .pth file(s), "
          f"{len(locks)} lock/requirements file(s).")
    print(f".pth files with executable lines: {hooks} (up to three lines per file shown above).")
    print(f"Flagged (!!): {flagged}")
    if errors:
        print(f"Scan incomplete: {errors} read or parse error(s).")
    if flagged:
        print("\nIf a bad version, file or download shows up: treat the machine as exposed.\n"
              "Pin agent-framework to 1.26.0, change every cloud, CI, registry and git secret\n"
              "the machine could reach, review sign-in logs, and rebuild the environment.\n"
              "Revoke active sessions and previously issued credentials after rotation.")
    print("\nNo finding is not proof of no compromise. This checks the Python environments and\n"
          "folders it was pointed at, for the published indicators only. An attacker can delete\n"
          "the files after use, and a new bad release will have new names.")
    print(f"Indicators last checked: {LAST_CHECKED} (GHSA-764m-3ppc-5m73, Wiz, JFrog).")
    return 1 if flagged else 2 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
