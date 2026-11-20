#!/usr/bin/env bash
# scripts/gate_release.sh — gate G26 (docs/GATES.md): release engineering. Procedure: docs/RELEASE.md.
#
#   PASS ⇔ every step below exits 0:
#     version      VERSION ⇔ app/pubspec.yaml ⇔ Cargo.toml ⇔ docs/PRIVACY_POLICY.md   (scripts/version.sh check)
#     docs         CHANGELOG.md has "## [X.Y.Z]"; docs/PRIVACY_POLICY.md exists and says "Applies to: Sealbox X.Y.Z"
#     ci           every .github/workflows/*.yml parses (PyYAML) and passes actionlint when it is installed
#     redaction    no logging/printing statement in Rust or Dart sources formats a secret-bearing value
#                  (passwords, tokens, secrets, passphrases, private keys, bodies/plaintext) unless
#                  allow-listed in scripts/redaction_allowlist.txt; #[instrument] must skip such params
#     linux        release bundle → dist/  (scripts/package_linux.sh when present, else flutter build linux --release + tar)
#     android      flutter build apk --release + appbundle --release, signed (TEST keystore unless
#                  $SEALBOX_KEY_PROPERTIES points elsewhere) → dist/; apksigner verify + jarsigner -verify
#                  + keytool -printcert must show the expected certificate and NOT the Android debug key
#     sums         dist/SHA256SUMS
#
#   Artifacts: dist/sealbox-X.Y.Z+B-{linux-x64.tar.gz,android.apk,android.aab}, dist/SHA256SUMS.
#   Logs: target/gate_release/<step>.log.  ONLY_AUDIT=1 runs just the non-build checks and can never PASS.
set -u -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
. scripts/env.sh
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"
export PATH="$JAVA_HOME/bin:$ROOT/target/tools:$PATH"
export CI=true
LOGDIR="$ROOT/target/gate_release"; DIST="$ROOT/dist"
mkdir -p "$LOGDIR" "$DIST"
ONLY_AUDIT="${ONLY_AUDIT:-0}"

RESULTS=(); FAILED=0
say()  { printf '\n=== %s\n' "$*"; }
step() {
  local name="$1"; shift
  local log="$LOGDIR/${name//[^A-Za-z0-9_.-]/_}.log" t0 rc
  say "[$name]"
  t0=$(date +%s)
  if "$@" >"$log" 2>&1; then rc=0; else rc=$?; fi
  if [ $rc -eq 0 ]; then
    echo "    PASS ($(( $(date +%s) - t0 ))s)"; RESULTS+=("PASS  $name")
    grep -E '^(  |>>)' "$log" | head -n 25 | sed 's/^/    /'
  else
    echo "    FAIL (exit $rc, $(( $(date +%s) - t0 ))s) — log: $log"; RESULTS+=("FAIL  $name"); FAILED=1
    grep -v 'Too many open files' "$log" | tail -n 40 | sed 's/^/    | /'
  fi
  return $rc
}

VERSION_FULL="$(scripts/version.sh 2>/dev/null)" || VERSION_FULL="unknown"
VER="${VERSION_FULL%%+*}"; BUILD="${VERSION_FULL##*+}"
say "Sealbox gate G26 — release engineering · version $VERSION_FULL ($(date -u +%FT%TZ))"

check_docs() {
  local ok=0
  [ -f CHANGELOG.md ] || { echo "CHANGELOG.md missing"; ok=1; }
  grep -qE "^## \[$VER\]" CHANGELOG.md 2>/dev/null && echo "  CHANGELOG.md: section [$VER] present" || { echo "CHANGELOG.md has no '## [$VER]' section"; ok=1; }
  [ -f docs/PRIVACY_POLICY.md ] || { echo "docs/PRIVACY_POLICY.md missing"; ok=1; }
  grep -qE "\*\*Applies to:\*\* *Sealbox $VER\b" docs/PRIVACY_POLICY.md 2>/dev/null && echo "  docs/PRIVACY_POLICY.md: applies to $VER" || { echo "docs/PRIVACY_POLICY.md does not say 'Applies to: Sealbox $VER'"; ok=1; }
  [ -f docs/RELEASE.md ] && echo "  docs/RELEASE.md: present" || { echo "docs/RELEASE.md missing"; ok=1; }
  return $ok
}

check_ci() {
  local f n=0
  for f in .github/workflows/*.yml .github/workflows/*.yaml; do
    [ -f "$f" ] || continue
    n=$((n + 1))
    python3 -I - "$f" <<'PY' || return 1
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
assert isinstance(d, dict) and "jobs" in d and d["jobs"], "no jobs"
on = d.get("on", d.get(True))
assert on, "no triggers"
print(f"  {sys.argv[1]}: {len(d['jobs'])} jobs ({', '.join(d['jobs'])})")
PY
  done
  [ $n -gt 0 ] || { echo "no workflows under .github/workflows/"; return 1; }
  if command -v actionlint >/dev/null 2>&1; then
    actionlint -no-color .github/workflows/*.yml && echo "  actionlint $(actionlint --version | head -n 1): clean"
  else
    echo "  actionlint not installed (target/tools/actionlint or PATH) — YAML parse only"
  fi
}

redaction_audit() {
  python3 -I - "$ROOT" <<'PY'
import os, re, sys
ROOT = sys.argv[1]
SCAN_DIRS = ["crates", "app/rust/src", "app/lib"]
EXCLUDE_PARTS = ("/tests/", "/test/", "/integration_test/", "/test_driver/", "/benches/", "/examples/", "/target/", "/build/", "/.dart_tool/")
EXCLUDE_NAMES = ("frb_generated",)
PARTS = {"password", "passwd", "passphrase", "pw", "pwd", "secret", "secrets", "token", "tokens", "privkey",
         "plaintext", "cleartext", "credential", "credentials", "authorization", "bearer", "body", "bodies",
         "mnemonic", "otp", "apppassword"}
PAIRS = {("private", "key"), ("secret", "key"), ("access", "token"), ("refresh", "token"), ("id", "token"),
         ("client", "secret"), ("app", "password"), ("session", "key"), ("signing", "key"), ("auth", "header")}
SAFE_PARTS = {"len", "length", "count", "size", "n", "num", "hash", "digest", "fingerprint", "fpr", "id", "ids",
              "kind", "type", "present", "exists", "is", "has", "empty", "ok", "name", "label", "path", "file",
              "dir", "hint", "policy", "mode", "required", "needed", "set", "changed", "expired", "expiry", "expires", "redacted", "masked",
              "url", "uri", "endpoint", "host", "port", "scope", "scopes", "method", "source", "status", "error", "err"}
SAFE_ACCESS = re.compile(r"^\s*\??\.\s*(len|length|is_empty|isEmpty|isNotEmpty|is_some|is_none|count|size|fingerprint|key_id|keyId|id|name|kind|hash|digest|hashCode|runtimeType|expires_at|expiresAt|expiry|as_ref\(\)\.map\(\|\w+\|\s*\w+\.len)")
SAFE_WRAP = re.compile(r"(redact|mask|masked|redacted|hash|digest|fingerprint|len_of|summar)\w*\s*\(\s*$")
RUST_START = re.compile(r"(?<![A-Za-z0-9_:])(?:(?:tracing|log|std)::)?(println|eprintln|print|eprint|dbg|trace|debug|info|warn|error|event|panic)!\s*\(")
DART_START = re.compile(r"(?<![A-Za-z0-9_.$])(?:(print|debugPrint|debugPrintStack|log|developer\.log)|(?:stdout|stderr)\.(write|writeln)|(?:_?log(?:ger)?|_logger|logger)\.(d|i|w|e|v|t|f|fine|finer|finest|info|warning|severe|shout|config|debug|error|trace|wtf))\s*\(")
INSTRUMENT = re.compile(r"#\[(?:tracing::)?instrument(?:\(([^)]*)\))?\]\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+\w+\s*(?:<[^>]*>)?\s*\(([^)]*)\)", re.S)
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
KEYWORDS = {"let", "mut", "as", "if", "else", "match", "for", "in", "true", "false", "self", "Self", "None", "Some", "Ok", "Err",
            "const", "final", "var", "new", "this", "null", "await", "return", "String", "str", "format"}

def parts_of(ident):
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", ident).lower()
    return [p for p in s.split("_") if p]

def sensitive(ident):
    ps = parts_of(ident)
    if any(p in SAFE_PARTS for p in ps):
        return False
    if any(p in PARTS for p in ps):
        return True
    return any((a, b) in PAIRS for a, b in zip(ps, ps[1:]))

def balanced(text, start, dart=False):
    """text[start] == '(' → index after the matching ')' (skipping string/char literals) or None."""
    depth, i, n = 0, start, len(text)
    while i < n and i - start < 6000:
        c = text[i]
        if c in "\"'":
            j = skip_string(text, i, dart)
            if j is None: return None
            i = j; continue
        if c == "(": depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0: return i + 1
        i += 1
    return None

def skip_string(text, i, dart=False):
    q = text[i]
    # Rust: 'x' is a char literal (or a lifetime); Dart: '...' is an ordinary string
    if q == "'" and not dart:
        m = re.match(r"'(\\.|[^'\\])'", text[i:])
        return i + m.end() if m else i + 1          # lifetime or stray quote
    if text[i:i + 3] in ('"""', "'''"):
        j = text.find(text[i:i + 3], i + 3); return None if j < 0 else j + 3
    j = i + 1
    while j < len(text):
        if text[j] == "\\": j += 2; continue
        if text[j] == q: return j + 1
        j += 1
    return None

def segments(stmt, dart):
    """Split a statement into ('code'|'str', text, raw) segments."""
    out, i, n, buf = [], 0, len(stmt), []
    while i < n:
        c = stmt[i]
        raw = False
        if c in "\"'":
            if c == "'" and not dart:
                m = re.match(r"'(\\.|[^'\\])'", stmt[i:])
                if not m: buf.append(c); i += 1; continue
                i += m.end(); continue
            if buf: out.append(("code", "".join(buf), False)); buf = []
            if i > 0 and stmt[i - 1] == "r" and (i < 2 or not (stmt[i - 2].isalnum() or stmt[i - 2] == "_")): raw = True
            j = skip_string(stmt, i, dart)
            if j is None: j = n
            lit = stmt[i:j]
            inner = lit[3:-3] if lit[:3] in ('"""', "'''") else lit[1:-1]
            out.append(("str", inner, raw)); i = j; continue
        if not dart and c == "#" and stmt[i - 1:i] == "r":  # r#"..."# raw string
            m = re.match(r'#+"', stmt[i:])
            if m:
                hashes = m.group(0)[:-1]; end = stmt.find('"' + hashes, i + len(m.group(0)))
                if buf: out.append(("code", "".join(buf), False)); buf = []
                out.append(("str", stmt[i + len(m.group(0)):end if end >= 0 else n], True)); i = (end + 1 + len(hashes)) if end >= 0 else n; continue
        buf.append(c); i += 1
    if buf: out.append(("code", "".join(buf), False))
    return out

def flagged_idents(stmt, dart, skip_first_ident=None):
    hits = []
    for kind, text, raw in segments(stmt, dart):
        if kind == "code":
            for m in IDENT.finditer(text):
                name = m.group(0)
                if name in KEYWORDS or name == skip_first_ident: continue
                before = text[max(0, m.start() - 40):m.start()]
                if before.endswith(".") and not before.endswith(".."):   # field access: judge the field name itself
                    pass
                after = text[m.end():]
                if sensitive(name) and not SAFE_ACCESS.match(after) and not SAFE_WRAP.search(before):
                    hits.append(name)
        elif not raw:
            if dart:
                for m in re.finditer(r"\$([A-Za-z_][A-Za-z0-9_]*)", text):
                    if sensitive(m.group(1)): hits.append("$" + m.group(1))
                for m in re.finditer(r"\$\{([^}]*)\}", text):
                    hits += ["${%s}" % h for h in flagged_idents(m.group(1), dart)]
            else:
                for m in re.finditer(r"\{([A-Za-z_][A-Za-z0-9_]*)(?::[^}]*)?\}", text):
                    if sensitive(m.group(1)): hits.append("{%s}" % m.group(1))
    return hits

allow = []
al = os.path.join(ROOT, "scripts/redaction_allowlist.txt")
if os.path.exists(al):
    for ln in open(al):
        ln = ln.strip()
        if not ln or ln.startswith("#") or "::" not in ln: continue
        p, rx = ln.split("::", 1); allow.append((p.strip(), re.compile(rx.strip())))

files, stmts, hits, allowed = 0, 0, [], 0
for d in SCAN_DIRS:
    for dp, dns, fns in os.walk(os.path.join(ROOT, d)):
        for fn in fns:
            path = os.path.join(dp, fn); rel = os.path.relpath(path, ROOT)
            if not (fn.endswith(".rs") or fn.endswith(".dart")): continue
            if any(x in "/" + rel + "/" for x in EXCLUDE_PARTS) or any(x in fn for x in EXCLUDE_NAMES) or fn.endswith(".g.dart"): continue
            dart = fn.endswith(".dart")
            try: text = open(path, encoding="utf-8", errors="replace").read()
            except OSError: continue
            if not dart:
                cut = text.find("#[cfg(test)]")
                if cut >= 0: text = text[:cut]
            files += 1
            starts = DART_START if dart else RUST_START
            for m in starts.finditer(text):
                open_idx = m.end() - 1
                end = balanced(text, open_idx, dart)
                if end is None: continue
                stmt = text[m.start():end]; stmts += 1
                found = flagged_idents(text[open_idx:end], dart)
                if not found: continue
                line = text.count("\n", 0, m.start()) + 1
                norm = " ".join(stmt.split())
                if any(rel.startswith(p) and (rx.search(stmt) or rx.search(norm)) for p, rx in allow):
                    allowed += 1; continue
                hits.append((rel, line, sorted(set(found)), norm[:160]))
            if not dart:
                for m in INSTRUMENT.finditer(text):
                    args = m.group(1) or ""; params = m.group(2) or ""
                    if "skip_all" in args: continue
                    skipped = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", re.search(r"skip\(([^)]*)\)", args).group(1))) if "skip(" in args else set()
                    names = [p.split(":")[0].strip().lstrip("&").replace("mut ", "").strip() for p in params.split(",") if ":" in p]
                    bad = [n for n in names if sensitive(n) and n not in skipped]
                    if bad:
                        line = text.count("\n", 0, m.start()) + 1
                        stmt = " ".join(m.group(0).split())[:160]
                        if any(rel.startswith(p) and rx.search(stmt) for p, rx in allow): allowed += 1; continue
                        hits.append((rel, line, ["#[instrument] logs " + ",".join(bad)], stmt))
print(f"  scanned {files} files, {stmts} logging/printing statements; hits {len(hits)}, allow-listed {allowed}")
for rel, line, names, stmt in hits:
    print(f"  HIT {rel}:{line}: {', '.join(names)}\n      {stmt}")
if hits:
    print("  fix the log line, or add '<path>::<regex>' with a justification to scripts/redaction_allowlist.txt")
    sys.exit(1)
PY
}

fl() { (cd "$ROOT/app" && flutter "$@"); }

build_linux() {
  local before after
  fl pub get || return 1
  if [ -x scripts/package_linux.sh ]; then
    echo "  using scripts/package_linux.sh (gate G18's packager)"
    local marker="$LOGDIR/.linux_t0"; touch "$marker"; sleep 1
    scripts/package_linux.sh || return 1
    # anything it (re)wrote since the marker counts — it reuses the same file names on every run
    local fresh; fresh="$(find "$DIST" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.AppImage' \) -newer "$marker" | sort)"
    if [ -n "$fresh" ]; then
      for f in $fresh; do echo "  packaged: $f ($(stat -c %s "$f") bytes)"; done
      return 0
    fi
    echo "  package_linux.sh produced nothing new in dist/ — falling back to a plain tarball"
  fi
  # No --no-pub on release builds: with --no-pub flutter skips regenerating the plugin registrants,
  # which leaves the debug registrant (integration_test, a dev dependency) in a release build that
  # excludes that module → 'package dev.flutter.plugins.integration_test does not exist'.
  fl build linux --release || return 1
  [ -x app/build/linux/x64/release/bundle/sealbox_app ] || { echo "bundle binary missing"; return 1; }
  local out="$DIST/sealbox-${VERSION_FULL}-linux-x64.tar.gz"
  tar -C app/build/linux/x64/release -czf "$out" --transform "s,^bundle,sealbox-${VER},S" bundle || return 1
  echo "  packaged: $out ($(stat -c %s "$out") bytes)"
}

KEYPROPS=""
build_android() {
  if [ -n "${SEALBOX_KEY_PROPERTIES:-}" ]; then
    KEYPROPS="$SEALBOX_KEY_PROPERTIES"; echo "  signing with \$SEALBOX_KEY_PROPERTIES=$KEYPROPS"
  else
    KEYPROPS="$LOGDIR/key.properties"
    printf 'storeFile=%s\nstorePassword=sealbox-test\nkeyAlias=sealbox-test\nkeyPassword=sealbox-test\n' "$ROOT/testing/keys/sealbox-test.jks" >"$KEYPROPS"
    echo "  signing with the TEST keystore testing/keys/sealbox-test.jks (NOT FOR PRODUCTION)"
  fi
  [ -f "$(grep '^storeFile=' "$KEYPROPS" | cut -d= -f2-)" ] || { echo "keystore named in $KEYPROPS missing"; return 1; }
  export SEALBOX_KEY_PROPERTIES="$KEYPROPS"
  fl pub get || return 1
  fl build apk --release || return 1        # not --no-pub: see build_linux (registrant regeneration)
  fl build appbundle --release || return 1
  cp app/build/app/outputs/flutter-apk/app-release.apk "$DIST/sealbox-${VERSION_FULL}-android.apk" || return 1
  cp app/build/app/outputs/bundle/release/app-release.aab "$DIST/sealbox-${VERSION_FULL}-android.aab" || return 1
  echo "  apk: $DIST/sealbox-${VERSION_FULL}-android.apk ($(stat -c %s "$DIST/sealbox-${VERSION_FULL}-android.apk") bytes)"
  echo "  aab: $DIST/sealbox-${VERSION_FULL}-android.aab ($(stat -c %s "$DIST/sealbox-${VERSION_FULL}-android.aab") bytes)"
  unzip -l "$DIST/sealbox-${VERSION_FULL}-android.apk" | grep -E 'lib/[^/]+/librust_lib_sealbox_app\.so' | awk '{print "  "$4" ("$1" bytes)"}'
}

verify_android() {
  local apk="$DIST/sealbox-${VERSION_FULL}-android.apk" aab="$DIST/sealbox-${VERSION_FULL}-android.aab"
  local store pass alias expected apksigner got
  store="$(grep '^storeFile=' "$KEYPROPS" | cut -d= -f2-)"; pass="$(grep '^storePassword=' "$KEYPROPS" | cut -d= -f2-)"; alias="$(grep '^keyAlias=' "$KEYPROPS" | cut -d= -f2-)"
  expected="$(keytool -list -v -keystore "$store" -storepass "$pass" -alias "$alias" 2>/dev/null | grep -m1 'SHA256:' | awk '{print $2}' | tr -d ':' | tr 'A-F' 'a-f')"
  [ -n "$expected" ] || { echo "could not read the keystore certificate"; return 1; }
  echo "  expected signer SHA-256: $expected"
  apksigner="$(find "${ANDROID_HOME:?}/build-tools" -maxdepth 2 -name apksigner | sort -V | tail -n 1)"
  [ -x "$apksigner" ] || { echo "apksigner not found under $ANDROID_HOME/build-tools"; return 1; }
  "$apksigner" verify --print-certs "$apk" >"$LOGDIR/apksigner.txt" 2>&1 || { cat "$LOGDIR/apksigner.txt"; echo "apksigner verify FAILED"; return 1; }
  got="$(grep -m1 'certificate SHA-256 digest' "$LOGDIR/apksigner.txt" | awk '{print $NF}')"
  [ "$got" = "$expected" ] || { cat "$LOGDIR/apksigner.txt"; echo "APK signer $got ≠ keystore $expected"; return 1; }
  grep -qi 'CN=Android Debug' "$LOGDIR/apksigner.txt" && { echo "APK is signed with the Android debug key"; return 1; }
  echo "  apk: apksigner verify OK — $(grep -m1 'certificate DN' "$LOGDIR/apksigner.txt" | sed 's/^Signer #1 //')"
  "$apksigner" verify --verbose "$apk" 2>/dev/null | grep -E '^Verified using' | sed 's/^/  apk: /'
  jarsigner -verify "$aab" >"$LOGDIR/jarsigner.txt" 2>&1 && grep -q 'jar verified' "$LOGDIR/jarsigner.txt" || { cat "$LOGDIR/jarsigner.txt"; echo "jarsigner -verify FAILED for the AAB"; return 1; }
  got="$(keytool -printcert -jarfile "$aab" 2>/dev/null | grep -m1 'SHA256:' | awk '{print $2}' | tr -d ':' | tr 'A-F' 'a-f')"
  [ "$got" = "$expected" ] || { echo "AAB signer $got ≠ keystore $expected"; return 1; }
  echo "  aab: jarsigner verified, signer $(keytool -printcert -jarfile "$aab" 2>/dev/null | grep -m1 'Owner:' | sed 's/^Owner: //')"
}

write_sums() {
  # every release file in dist/ (ours: sealbox-<ver>-*, gate G18's packager: sealbox-linux-x64-<ver>.tar.gz, *.AppImage)
  (cd "$DIST" && find . -maxdepth 1 -type f -iname 'sealbox-*' ! -name '*.sha256' -printf '%f\n' | sort | xargs -r sha256sum >SHA256SUMS) || return 1
  [ -s "$DIST/SHA256SUMS" ] || { echo "no artifacts in dist/"; return 1; }
  grep -q "sealbox-${VERSION_FULL}-android.apk" "$DIST/SHA256SUMS" || { echo "release APK for $VERSION_FULL missing from dist/"; return 1; }
  sed 's/^/  /' "$DIST/SHA256SUMS"
  (cd "$DIST" && ls -l [Ss]ealbox-* | awk '{print "  "$5" bytes  "$9}')
}

step "version consistency (scripts/version.sh check)"   scripts/version.sh check
step "changelog + privacy policy name $VER"              check_docs
step "ci workflows parse (+ actionlint)"                 check_ci
step "log-redaction audit (Rust + Dart)"                 redaction_audit
if [ "$ONLY_AUDIT" = 1 ]; then
  RESULTS+=("SKIP  linux release bundle (ONLY_AUDIT=1)" "SKIP  android release apk + aab (ONLY_AUDIT=1)")
else
  step "linux release bundle → dist/"                    build_linux
  step "android release apk + aab (signed) → dist/"      build_android \
    && step "verify android signatures"                  verify_android
  step "dist/SHA256SUMS"                                 write_sums
fi

say "Summary"
printf '  %s\n' "${RESULTS[@]}"
if [ "$ONLY_AUDIT" = 1 ]; then echo "GATE G26: INCOMPLETE (ONLY_AUDIT=1 — builds skipped; $( [ $FAILED -eq 0 ] && echo audits clean || echo audits FAILED))"; exit 2; fi
if [ $FAILED -eq 0 ]; then echo "GATE G26: PASS — artifacts in dist/ (version $VERSION_FULL)"; exit 0; fi
echo "GATE G26: FAIL"; exit 1
