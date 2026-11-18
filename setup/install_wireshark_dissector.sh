#!/bin/sh
# Install, check or remove the WIMSE Wireshark/tshark dissector (dissectors/wimse.lua).
#
# The file goes into Wireshark's personal Lua plugins folder, which Wireshark reads at every start,
# so the decoder is on whenever you open a capture. The folder is asked from Wireshark itself, so it
# is right for your version and operating system. Nothing else on your machine is changed.
#
# Usage:  setup/install_wireshark_dissector.sh [install|check|uninstall]      (macOS, Linux)
#   or without cloning the repository:
#   curl -fsSL https://raw.githubusercontent.com/apelov/IETF127-Hackathon-AI2II-WIMSE/main/setup/install_wireshark_dissector.sh -o /tmp/wimse-install.sh && sh /tmp/wimse-install.sh
set -eu
RAW=https://raw.githubusercontent.com/apelov/IETF127-Hackathon-AI2II-WIMSE/main/dissectors/wimse.lua
HERE=$(cd "$(dirname "$0")" && pwd)

find_tshark() {
  if command -v tshark >/dev/null 2>&1; then command -v tshark; return; fi
  for p in /Applications/Wireshark.app/Contents/MacOS/tshark /opt/homebrew/bin/tshark /usr/local/bin/tshark; do
    [ -x "$p" ] && { echo "$p"; return; }
  done
  return 1
}

TSHARK=$(find_tshark || true)
if [ -n "$TSHARK" ]; then
  DIR=$("$TSHARK" -G folders 2>/dev/null | sed -n 's/^Personal Lua Plugins:[[:space:]]*//p' | head -n 1)
fi
DIR=${DIR:-$HOME/.local/lib/wireshark/plugins}
DEST=$DIR/wimse.lua

check() {
  [ -n "$TSHARK" ] || { echo "tshark not found: cannot check. Open Wireshark and look for the filter field wimse.test_case."; return 0; }
  if "$TSHARK" -G fields 2>/dev/null | grep -q "[[:space:]]wimse.test_case[[:space:]]"; then
    echo "OK: tshark knows the WIMSE fields (for example wimse.test_case)."
  else
    echo "Not active: tshark does not know wimse.test_case. Is $DEST in place?" >&2; return 1
  fi
}

case "${1:-install}" in
  install)
    mkdir -p "$DIR"
    if [ -f "$HERE/../dissectors/wimse.lua" ]; then cp "$HERE/../dissectors/wimse.lua" "$DEST"
    else curl -fsSL "$RAW" -o "$DEST"; fi
    echo "Installed: $DEST"
    check || true
    echo "Restart Wireshark (or Analyze > Reload Lua Plugins, Ctrl+Shift+L), open a capture, and filter: wimse.test_case == \"B_CHAIN\""
    ;;
  check) echo "Plugin folder: $DIR"; [ -f "$DEST" ] && echo "File present: $DEST" || echo "File missing: $DEST"; check ;;
  uninstall) rm -f "$DEST"; echo "Removed: $DEST" ;;
  *) echo "usage: $0 [install|check|uninstall]" >&2; exit 2 ;;
esac
