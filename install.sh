#!/usr/bin/env bash
#
# floppy installer — whoami · floppy
# One-line install on Kali/Linux:
#
#   curl -fsSL https://raw.githubusercontent.com/whoamix1010-glitch/sql-payload-check-/main/install.sh | bash
#
# Builds the static `floppy` binary from source and drops it on your PATH.
# Requires: git and Go (>= 1.21). On Kali:  sudo apt install -y golang git
#
set -euo pipefail

REPO="https://github.com/whoamix1010-glitch/sql-payload-check-.git"
BRANCH="${FLOPPY_BRANCH:-main}"
BIN="floppy"

say()  { printf '\033[32m[floppy]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[floppy] error:\033[0m %s\n' "$*" >&2; exit 1; }

command -v git >/dev/null 2>&1 || die "git not found. Install it (e.g. sudo apt install -y git)."
command -v go  >/dev/null 2>&1 || die "Go not found. Install it (e.g. sudo apt install -y golang)."

# Pick an install dir that is writable and on PATH.
if [ -w /usr/local/bin ] 2>/dev/null; then
  DEST="/usr/local/bin"
elif [ "$(id -u)" = "0" ]; then
  DEST="/usr/local/bin"
else
  DEST="$HOME/.local/bin"
  mkdir -p "$DEST"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "cloning $REPO ($BRANCH) ..."
git clone --depth 1 --branch "$BRANCH" "$REPO" "$TMP/src" >/dev/null 2>&1 \
  || git clone --depth 1 "$REPO" "$TMP/src" >/dev/null 2>&1 \
  || die "clone failed."

say "building (static binary) ..."
( cd "$TMP/src" && CGO_ENABLED=0 go build -ldflags="-s -w" -o "$TMP/$BIN" ./cmd/floppy ) \
  || die "build failed."

install -m 0755 "$TMP/$BIN" "$DEST/$BIN" 2>/dev/null || cp "$TMP/$BIN" "$DEST/$BIN"
say "installed to $DEST/$BIN"

case ":$PATH:" in
  *":$DEST:"*) : ;;
  *) say "NOTE: add $DEST to your PATH:  echo 'export PATH=\"$DEST:\$PATH\"' >> ~/.bashrc" ;;
esac

say "done. Run:  $BIN            # opens the dashboard"
say "       or:  $BIN scan -u 'http://target/item?id=1' --yes"
