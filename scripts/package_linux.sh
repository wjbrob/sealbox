#!/usr/bin/env bash
# scripts/package_linux.sh — stage the Linux release bundle with packaging/linux/* into
#   dist/sealbox-linux-x64-<version>.tar.gz   (always)
#   dist/Sealbox-<version>-x86_64.AppImage    (when appimagetool is installed or can be fetched)
#   dist/SHA256SUMS
# Usage: scripts/package_linux.sh [--build] [--no-appimage]
#   --build        run `flutter build linux --release` first (otherwise the bundle must exist)
#   --no-appimage  skip the AppImage even if the tool is around
# The version is the pubspec `version:` without the build number (0.1.0+1 → 0.1.0).
set -u -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
. scripts/env.sh
export CI=true
BUILD=0; APPIMAGE=1
while [ $# -gt 0 ]; do case "$1" in --build) BUILD=1;; --no-appimage) APPIMAGE=0;; *) echo "unknown arg $1" >&2; exit 2;; esac; shift; done

VERSION="$(sed -n 's/^version:[[:space:]]*\([^+[:space:]]*\).*/\1/p' app/pubspec.yaml | head -n1)"
[ -n "$VERSION" ] || { echo "cannot read version from app/pubspec.yaml" >&2; exit 1; }
BUNDLE="app/build/linux/x64/release/bundle"
NAME="sealbox-linux-x64-$VERSION"
DIST="$ROOT/dist"
STAGE="$DIST/stage/$NAME"

if [ $BUILD -eq 1 ] || [ ! -x "$BUNDLE/sealbox_app" ]; then
  echo "== flutter build linux --release"
  (cd app && flutter build linux --release --no-pub) || exit 1
fi
[ -x "$BUNDLE/sealbox_app" ] || { echo "release bundle missing: $BUNDLE" >&2; exit 1; }
[ -f "$BUNDLE/lib/librust_lib_sealbox_app.so" ] || { echo "Rust engine library missing from the bundle" >&2; exit 1; }

echo "== staging $NAME"
rm -rf "$STAGE"; mkdir -p "$STAGE/bundle" "$DIST"
cp -a "$BUNDLE/." "$STAGE/bundle/"
install -m 0755 packaging/linux/sealbox "$STAGE/sealbox"
install -m 0644 packaging/linux/sealbox.desktop packaging/linux/sealbox.svg packaging/linux/sealbox.png packaging/linux/sealbox-128.png "$STAGE/"
install -m 0644 packaging/linux/README.md "$STAGE/README.md"
[ -f LICENSE ] && install -m 0644 LICENSE "$STAGE/LICENSE"
cat > "$STAGE/VERSION" <<V
sealbox $VERSION
built $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(uname -srm)
commit $(git rev-parse --short HEAD 2>/dev/null || echo unknown)
flutter $(flutter --version 2>/dev/null | head -n1 | awk '{print $2}')
V
tar -C "$DIST/stage" -czf "$DIST/$NAME.tar.gz" "$NAME" || exit 1
echo "tar.gz: $DIST/$NAME.tar.gz ($(du -h "$DIST/$NAME.tar.gz" | cut -f1))"

appimage_ok=0
if [ $APPIMAGE -eq 1 ]; then
  TOOL="$(command -v appimagetool || true)"
  if [ -z "$TOOL" ]; then
    mkdir -p "$ROOT/target/tools"
    TOOL="$ROOT/target/tools/appimagetool-x86_64.AppImage"
    if [ ! -x "$TOOL" ]; then
      echo "== fetching appimagetool (optional)"
      curl -fsSL --max-time 120 -o "$TOOL" \
        "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" \
        && chmod +x "$TOOL" || { echo "appimagetool not available; skipping AppImage"; TOOL=""; }
    fi
  fi
  if [ -n "$TOOL" ]; then
    echo "== AppImage"
    APPDIR="$DIST/stage/Sealbox.AppDir"
    rm -rf "$APPDIR"; mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/256x256/apps"
    cp -a "$STAGE/bundle" "$APPDIR/usr/bin/bundle"
    install -m 0755 packaging/linux/sealbox "$APPDIR/usr/bin/sealbox"
    install -m 0644 packaging/linux/sealbox.desktop "$APPDIR/sealbox.desktop"
    install -m 0644 packaging/linux/sealbox.desktop "$APPDIR/usr/share/applications/sealbox.desktop"
    install -m 0644 packaging/linux/sealbox.png "$APPDIR/sealbox.png"
    install -m 0644 packaging/linux/sealbox.png "$APPDIR/usr/share/icons/hicolor/256x256/apps/sealbox.png"
    cat > "$APPDIR/AppRun" <<'R'
#!/bin/sh
here="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
exec "$here/usr/bin/bundle/sealbox_app" "$@"
R
    chmod +x "$APPDIR/AppRun"
    # appimagetool is itself an AppImage; without FUSE it needs extraction (--appimage-extract-and-run).
    if ARCH=x86_64 "$TOOL" --appimage-extract-and-run "$APPDIR" "$DIST/Sealbox-$VERSION-x86_64.AppImage" >"$DIST/appimage.log" 2>&1 \
       || ARCH=x86_64 "$TOOL" "$APPDIR" "$DIST/Sealbox-$VERSION-x86_64.AppImage" >>"$DIST/appimage.log" 2>&1; then
      echo "AppImage: $DIST/Sealbox-$VERSION-x86_64.AppImage ($(du -h "$DIST/Sealbox-$VERSION-x86_64.AppImage" | cut -f1))"
      appimage_ok=1
    else
      echo "AppImage build failed (optional; log: $DIST/appimage.log)"; tail -n 5 "$DIST/appimage.log"
    fi
  fi
fi

(cd "$DIST" && sha256sum "$NAME.tar.gz" $( [ $appimage_ok -eq 1 ] && echo "Sealbox-$VERSION-x86_64.AppImage" ) > SHA256SUMS)
echo "== done"; cat "$DIST/SHA256SUMS"
