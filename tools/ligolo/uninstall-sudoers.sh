#!/usr/bin/env bash
# tools/ligolo/uninstall-sudoers.sh — remove what install-sudoers.sh wrote.
# Idempotent: safe to run even if nothing is installed.

set -euo pipefail

SUDOERS_PATH="/etc/sudoers.d/pen-agent-ligolo"
BIN_DIR="/usr/local/bin"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (use sudo)." >&2
    exit 1
fi

if [[ -f "$SUDOERS_PATH" ]]; then
    rm -f "$SUDOERS_PATH"
    echo "[uninstall-ligolo] Removed $SUDOERS_PATH"
else
    echo "[uninstall-ligolo] $SUDOERS_PATH not present."
fi

removed_any=0
for name in pen-agent-ligolo-up pen-agent-ligolo-down pen-agent-ligolo-route pen-agent-ligolo-unroute; do
    if [[ -f "$BIN_DIR/$name" ]]; then
        rm -f "$BIN_DIR/$name"
        echo "[uninstall-ligolo] Removed $BIN_DIR/$name"
        removed_any=1
    fi
done
[[ $removed_any -eq 1 ]] || echo "[uninstall-ligolo] No helper scripts to remove."

# Best-effort: tear down the ligolo interface if it's up and we have the tool.
if command -v ip >/dev/null 2>&1 && ip link show ligolo >/dev/null 2>&1; then
    ip link set ligolo down 2>/dev/null || true
    ip tuntap del dev ligolo mode tun 2>/dev/null || true
    echo "[uninstall-ligolo] Tore down ligolo TUN interface."
fi

echo "Done."
