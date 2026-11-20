# packaging/linux

Files that ship next to the Flutter Linux bundle (`app/build/linux/x64/release/bundle`):

| file | purpose |
|---|---|
| `sealbox` | launcher script; `exec`s `bundle/sealbox_app` next to itself (symlink-safe) |
| `sealbox.desktop` | freedesktop entry (`Exec=sealbox`, `StartupWMClass=sealbox_app`, `mailto:` handler) |
| `sealbox.svg`, `sealbox.png`, `sealbox-128.png` | icon (lock on an envelope); PNGs are rendered from the SVG with ImageMagick |

`scripts/package_linux.sh` stages these with the bundle into `dist/sealbox-linux-x64-<version>.tar.gz`
(and an AppImage when `appimagetool` is available). Install by unpacking anywhere and running `./sealbox`,
or `make`-free: `ln -s "$PWD/sealbox" ~/.local/bin/sealbox` plus copying `sealbox.desktop` to
`~/.local/share/applications/` and the icon to `~/.local/share/icons/hicolor/256x256/apps/`.
