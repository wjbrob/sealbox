# Source this to get the Sealbox toolchain on PATH (works from cron, where PATH is minimal).
# Override any of FLUTTER_ROOT, ANDROID_HOME, SEALBOX_DIR in your environment.
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
export PATH="${FLUTTER_ROOT:-$HOME/flutter}/bin:$HOME/.local/bin:$HOME/.npm-global/bin:$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
if [ -d "${ANDROID_HOME:-$HOME/android-sdk}" ]; then
  export ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
  export PATH="$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools"
fi
export SEALBOX_DIR="${SEALBOX_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
