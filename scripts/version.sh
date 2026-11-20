#!/usr/bin/env bash
# scripts/version.sh — the single version source for Sealbox (gate G26, docs/RELEASE.md).
#
#   VERSION                 X.Y.Z[-pre]              the source of truth (semver)
#   app/pubspec.yaml        version: X.Y.Z+BUILD      BUILD = Android versionCode / iOS CFBundleVersion
#   Cargo.toml              [workspace.package] version = "X.Y.Z"   (every crate inherits it)
#   docs/PRIVACY_POLICY.md  "**Applies to:** Sealbox X.Y.Z"
#
# Usage:
#   scripts/version.sh                 print "X.Y.Z+BUILD"
#   scripts/version.sh check           exit 1 unless every derived file agrees with VERSION
#   scripts/version.sh sync            rewrite the derived files from VERSION (keeps BUILD)
#   scripts/version.sh set X.Y.Z [B]   write a new VERSION (+ BUILD, default previous+1), then sync
#   scripts/version.sh bump major|minor|patch
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 - "$ROOT" "$@" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
argv = sys.argv[2:]
cmd = argv[0] if argv else "show"

SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?$")
F_VERSION = root / "VERSION"
F_PUBSPEC = root / "app/pubspec.yaml"
F_CARGO = root / "Cargo.toml"
F_PRIVACY = root / "docs/PRIVACY_POLICY.md"
F_CHANGELOG = root / "CHANGELOG.md"

PUB_RE = re.compile(r"^(version:[ \t]*)([^\s+]+)(?:\+(\d+))?[ \t]*$", re.M)
CARGO_RE = re.compile(r'(\[workspace\.package\][^\[]*?^version[ \t]*=[ \t]*")([^"]+)(")', re.M | re.S)
PRIV_RE = re.compile(r"(\*\*Applies to:\*\*[ \t]*Sealbox[ \t]+)(\S+)")


def die(msg):
    print(f"version.sh: {msg}", file=sys.stderr)
    sys.exit(1)


def read_version():
    if not F_VERSION.exists():
        die("VERSION file missing")
    v = F_VERSION.read_text().strip()
    if not SEMVER.match(v):
        die(f"VERSION {v!r} is not semver X.Y.Z[-pre]")
    return v


def pubspec():
    t = F_PUBSPEC.read_text()
    m = PUB_RE.search(t)
    if not m:
        die("app/pubspec.yaml has no 'version:' line")
    return t, m


def cargo():
    t = F_CARGO.read_text()
    m = CARGO_RE.search(t)
    if not m:
        die("Cargo.toml has no [workspace.package] version")
    return t, m


def privacy():
    if not F_PRIVACY.exists():
        return None, None
    t = F_PRIVACY.read_text()
    return t, PRIV_RE.search(t)


def rows():
    _, pm = pubspec()
    _, cm = cargo()
    _, prm = privacy()
    out = [("app/pubspec.yaml", pm.group(2)), ("Cargo.toml", cm.group(2))]
    if prm is not None:
        out.append(("docs/PRIVACY_POLICY.md", prm.group(2)))
    elif F_PRIVACY.exists():
        out.append(("docs/PRIVACY_POLICY.md", '(no "**Applies to:** Sealbox X.Y.Z" line)'))
    return out, (pm.group(3) or "0")


def do_show():
    v = read_version()
    _, b = rows()
    print(f"{v}+{b}")


def do_check():
    v = read_version()
    rs, b = rows()
    bad = False
    for name, got in rs:
        ok = got == v
        bad |= not ok
        print(f"  {'OK      ' if ok else 'MISMATCH'} {name}: {got}")
    if F_CHANGELOG.exists() and f"## [{v}]" not in F_CHANGELOG.read_text():
        print(f"  WARN     CHANGELOG.md has no '## [{v}]' section (scripts/gate_release.sh requires one)")
    print(f"VERSION {v} build {b}")
    if bad:
        die("derived files disagree with VERSION — run scripts/version.sh sync")


def do_sync(build=None):
    v = read_version()
    t, m = pubspec()
    b = build or m.group(3) or "1"
    new = t[: m.start()] + f"{m.group(1)}{v}+{b}" + t[m.end():]
    if new != t:
        F_PUBSPEC.write_text(new)
        print(f"  app/pubspec.yaml      version: {v}+{b}")
    t, m = cargo()
    new = t[: m.start(2)] + v + t[m.end(2):]
    if new != t:
        F_CARGO.write_text(new)
        print(f"  Cargo.toml            [workspace.package] version = \"{v}\"")
    t, m = privacy()
    if t is not None and m is not None:
        new = t[: m.start(2)] + v + t[m.end(2):]
        if new != t:
            F_PRIVACY.write_text(new)
            print(f"  docs/PRIVACY_POLICY.md  Applies to: Sealbox {v}")
    print(f"VERSION {v} build {b}: in sync")


def do_set(v, build=None):
    if not SEMVER.match(v):
        die(f"{v!r} is not semver X.Y.Z[-pre]")
    _, m = pubspec()
    prev = int(m.group(3) or "0")
    if build is None:
        build = str(prev + 1)
    elif not build.isdigit() or int(build) < 1:
        die("BUILD must be a positive integer")
    F_VERSION.write_text(v + "\n")
    print(f"  VERSION               {v}")
    do_sync(build)
    if F_CHANGELOG.exists() and f"## [{v}]" not in F_CHANGELOG.read_text():
        print(f"  next: add a '## [{v}] - YYYY-MM-DD' section to CHANGELOG.md")


def do_bump(part):
    v = read_version()
    mm = SEMVER.match(v)
    major, minor, patch = (int(mm.group(i)) for i in (1, 2, 3))
    if part == "major":
        major, minor, patch = major + 1, 0, 0
    elif part == "minor":
        minor, patch = minor + 1, 0
    elif part == "patch":
        patch += 1
    else:
        die("bump takes major|minor|patch")
    do_set(f"{major}.{minor}.{patch}")


if cmd == "show":
    do_show()
elif cmd == "check":
    do_check()
elif cmd == "sync":
    do_sync()
elif cmd == "set":
    if len(argv) < 2:
        die("set needs X.Y.Z [BUILD]")
    do_set(argv[1], argv[2] if len(argv) > 2 else None)
elif cmd == "bump":
    if len(argv) < 2:
        die("bump needs major|minor|patch")
    do_bump(argv[1])
else:
    die(f"unknown command {cmd!r} (show|check|sync|set|bump)")
PY
