#!/usr/bin/env bash
# G10: the Flutter app builds a debug APK (arm64) with the Rust bridge compiled through the NDK.
set -euo pipefail
cd "$(dirname "$0")/.." && . scripts/env.sh
[ -f app/pubspec.yaml ] || { echo "app/pubspec.yaml missing — Flutter app not scaffolded yet"; exit 1; }
[ -d "${ANDROID_HOME:-/nonexistent}" ] || { echo "ANDROID_HOME missing"; exit 1; }
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"
flutter config --no-analytics >/dev/null 2>&1 || true
yes | flutter doctor --android-licenses >/dev/null 2>&1 || true
cd app
flutter pub get
flutter build apk --debug --target-platform android-arm64
apk="build/app/outputs/flutter-apk/app-debug.apk"
[ -s "$apk" ] || { echo "APK not produced"; exit 1; }
size=$(stat -c %s "$apk"); echo "APK: $apk ($size bytes)"
[ "$size" -gt 1000000 ] || { echo "APK suspiciously small"; exit 1; }
# the Rust bridge must be inside the APK (capture first: grep -q + pipefail would turn unzip's SIGPIPE into a failure)
listing="$(unzip -l "$apk")"
rust_lib="$(printf '%s\n' "$listing" | grep -E 'lib/arm64-v8a/librust_lib_sealbox_app\.so' || true)"
if [ -n "$rust_lib" ]; then
  echo "native libs present:"; printf '%s\n' "$listing" | grep -E 'lib/arm64-v8a/.*\.so' | awk '{print "  "$4" ("$1" bytes)"}'
else
  echo "arm64 Rust bridge library missing from APK"; exit 1
fi
