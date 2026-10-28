#!/usr/bin/env bash
# Build everything and install:
#   ~/.local/bin/karambit, ~/.local/bin/karambit-se-helper   (CLI)
#   ~/Applications/Karambit.app                            (GUI, helper bundled inside)
#
# Pin ordering (threat model, "Required owner install ordering"): while the OLD
# trusted daemon/helper pair is still installed, it authenticates you (Touch ID)
# and stages the NEW pair's pins. Only then are the binaries replaced. Replacing
# first would leave no trusted helper to approve the new one.
# Run from a plain terminal (not an agent): pin and daemon stop are human-only.
set -euo pipefail
cd "$(dirname "$0")"

BIN="${KARAMBIT_BIN_DIR:-$HOME/.local/bin}"
APPS="${KARAMBIT_APP_DIR:-$HOME/Applications}"
TRIPLE="$(rustc -vV | awk '/^host/{print $2}')"
TARGET="${CARGO_TARGET_DIR:-$PWD/target}"

echo "==> se-helper (Swift)"
(cd se-helper && swift build -c release)
HELPER="se-helper/.build/release/karambit-se-helper"
mkdir -p app/src-tauri/binaries  # gitignored; absent in fresh worktrees
cp "$HELPER" "app/src-tauri/binaries/karambit-se-helper-$TRIPLE"

echo "==> karambit CLI (Rust)"
cargo build --release -p karambit-cli

echo "==> Karambit.app (Tauri)"
(cd app && npm ci --no-fund --no-audit && npm run build)

NEW_CLI="$TARGET/release/karambit"
NEW_HELPER="$PWD/$HELPER"
mkdir -p "$BIN" "$APPS"

if [ -x "$BIN/karambit" ] && [ -d "${KARAMBIT_DIR:-$HOME/.local/share/karambit}/keys" ]; then
  echo "==> staging pins with the installed (trusted) pair — Touch ID"
  if cmp -s "$NEW_CLI" "$BIN/karambit" && cmp -s "$NEW_HELPER" "$BIN/karambit-se-helper"; then
    echo "    binaries unchanged; nothing to stage"
  elif ! "$BIN/karambit" helper pin --stage-daemon "$NEW_CLI" --stage-helper "$NEW_HELPER"; then
    echo "pin staging failed; NOT replacing binaries (your install is unchanged)." >&2
    exit 1
  fi
fi

install -m 0755 "$NEW_CLI" "$BIN/karambit"
install -m 0755 "$NEW_HELPER" "$BIN/karambit-se-helper"
rm -rf "$APPS/Karambit.app"
cp -R "$TARGET/release/bundle/macos/Karambit.app" "$APPS/"

# Restart the lease daemon on the new binary (ends active leases). Fresh vaults
# (no keys yet) get their first pins from `karambit init`.
"$BIN/karambit" daemon stop >/dev/null 2>&1 || true

echo
echo "installed: $BIN/karambit, $BIN/karambit-se-helper, $APPS/Karambit.app"
"$BIN/karambit" status | head -20
