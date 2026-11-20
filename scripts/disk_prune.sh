#!/usr/bin/env bash
# scripts/disk_prune.sh — free regenerable build output inside this repo when / runs low.
#
# The project lives on / on purpose (CLAUDE.md) and the daily driver refuses to start below
# SEALBOX_MIN_FREE_GB (12). Everything deleted here is rebuilt by the next gate that needs it:
#   - cargo incremental caches (target/*/incremental, target/app-rust/*/incremental)
#   - Android Gradle intermediates (app/build/app/intermediates; G10/G19 rebuild them)
#   - the Android review loop's APK scratch (target/review_android)
#   - gate G17 run directories older than a day (target/gate_g17/run-*)
#   - the perf builder's throw-away profiles (target/perf*) unless perf_sync.sh is running
#   - a stray app/rust/target and the non-x86_64 Android DEBUG trees of cargokit (G10 rebuilds them)
#   - then `cargo sweep --maxsize <budget>` over target/ (oldest artifacts first) if cargo-sweep
#     is installed (`cargo install cargo-sweep --locked`).
# Never touches anything outside the repo, never touches sources, and refuses to run while a
# cargo / rustc / flutter build is in progress (deleting artifacts under a running build breaks it).
#
# Usage: scripts/disk_prune.sh [--force] [--budget-gb N]   (default budget 14 GB for target/)
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
BUDGET="${SEALBOX_TARGET_BUDGET_GB:-14}"; FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --force) FORCE=1 ;;
    --budget-gb) BUDGET="$2"; shift ;;
    *) echo "usage: $0 [--force] [--budget-gb N]" >&2; exit 2 ;;
  esac
  shift
done
free_gb() { df --output=avail -BG / | tail -1 | tr -dc 0-9; }
before=$(free_gb)
busy=$(ps -eo comm= | grep -cE '^(cargo|rustc|flutter|dart|ninja|gradle|java)$')
if [ "$busy" -gt 0 ] && [ "$FORCE" = 0 ]; then
  echo "disk_prune: $busy build process(es) running (cargo/rustc/flutter/dart/ninja/gradle/java); not pruning (use --force)"; exit 3
fi
rm -rf target/debug/incremental target/release/incremental target/app-rust/debug/incremental target/app-rust/release/incremental
rm -rf app/build/app/intermediates target/review_android
# A stray cargo target inside app/rust (every script sets CARGO_TARGET_DIR=target/app-rust; a builder
# that runs cargo there by hand creates a second 4–5 GB copy of the same artifacts).
rm -rf app/rust/target
# cargokit's Android DEBUG trees for the ABIs the emulator never runs (G19 uses x86_64 only; G10 rebuilds
# them in ~10 min). The release trees stay: G26 builds the signed APK/AAB from them.
for abi in aarch64-linux-android i686-linux-android armv7-linux-androideabi; do
  rm -rf "app/build/rust_lib_sealbox_app/build/$abi/debug"
done
find target/gate_g17 -maxdepth 1 -type d -name 'run-*' -mtime +1 -exec rm -rf {} + 2>/dev/null
if ! ps -eo args= | grep -v grep | grep -q 'perf_sync.sh'; then rm -rf target/perf target/perf-release; fi
if command -v cargo-sweep >/dev/null 2>&1; then
  cargo sweep --maxsize "${BUDGET}GB" . 2>&1 | grep -E 'Cleaned|nothing' || true
else
  echo "disk_prune: cargo-sweep not installed (cargo install cargo-sweep --locked); skipped the target/ sweep"
fi
after=$(free_gb)
echo "disk_prune: / free ${before} GB → ${after} GB (target/ $(du -sh target 2>/dev/null | cut -f1), app/build $(du -sh app/build 2>/dev/null | cut -f1))"
