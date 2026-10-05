#!/usr/bin/env bash
# tools/ligolo/install-sudoers.sh — opt-in installer that makes PEN-AGENT's
# ligolo pivot setup operator-free (no password prompt per pivot).
#
# What it does, exactly:
#   1. Copies the four pen-agent-ligolo-* helpers from this directory to
#      /usr/local/bin, with PEN_AGENT_LIGOLO_USER baked into the -up helper.
#   2. Writes /etc/sudoers.d/pen-agent-ligolo granting NOPASSWD execution of
#      ONLY those four absolute paths to the invoking user. No sudoers
#      wildcards on `ip`; the helpers do their own CIDR validation.
#   3. Validates the sudoers file with `visudo -c` before saving so a syntax
#      error can't lock anyone out.
#
# Threat model (what you grant by running this):
#   - The invoking user can, without a password, bring the `ligolo` TUN
#     interface up/down and add/remove ONE route per invocation to it. CIDR
#     is validated as IPv4; 0.0.0.0/0 and 127.0.0.0/8 are refused by the
#     helper itself.
#   - No arbitrary `ip` commands, no other interfaces, no shell escape surface
#     through sudoers patterns.
#   - To revoke: `sudo bash tools/ligolo/uninstall-sudoers.sh`.
#
# Usage:
#   sudo bash tools/ligolo/install-sudoers.sh                   # grants to invoking user ($SUDO_USER)
#   sudo bash tools/ligolo/install-sudoers.sh --user <name>     # grants to a specific user

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SUDOERS_PATH="/etc/sudoers.d/pen-agent-ligolo"
BIN_DIR="/usr/local/bin"

TARGET_USER="${SUDO_USER:-}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --user) TARGET_USER="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,30p' "$0" | sed 's|^# ||;s|^#$||'
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (use sudo)." >&2
    exit 1
fi
if [[ -z "$TARGET_USER" ]] || ! id "$TARGET_USER" >/dev/null 2>&1; then
    echo "ERROR: target user not resolvable. Pass --user <name>, or re-run via 'sudo' as the user you want to grant." >&2
    exit 1
fi

# Required tooling on the attackbox.
for cmd in ip visudo install python3; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "ERROR: '$cmd' not found on this system — required." >&2
        exit 1
    }
done

echo "[install-ligolo] Target user: $TARGET_USER"
echo "[install-ligolo] Installing helpers to $BIN_DIR …"

# Bake the owning user into the -up helper rather than relying on SUDO_USER
# at call time — Claude Code's sudo invocation path may not propagate it.
UP_SRC="$HERE/pen-agent-ligolo-up"
UP_DST="$BIN_DIR/pen-agent-ligolo-up"
tmp="$(mktemp)"
# shellcheck disable=SC2016
sed -E "s|^: \"\\\$\\{PEN_AGENT_LIGOLO_USER:=.*\\}\"|: \"\${PEN_AGENT_LIGOLO_USER:=${TARGET_USER}}\"|" \
    "$UP_SRC" > "$tmp"
install -m 0755 -o root -g root "$tmp" "$UP_DST"
rm -f "$tmp"

for name in pen-agent-ligolo-down pen-agent-ligolo-route pen-agent-ligolo-unroute; do
    install -m 0755 -o root -g root "$HERE/$name" "$BIN_DIR/$name"
done
echo "[install-ligolo] Installed: $BIN_DIR/pen-agent-ligolo-{up,down,route,unroute}"

# Build sudoers content. Grant NOPASSWD to the four absolute paths only.
# Each line is one Cmnd_Alias-style grant; no wildcards.
SUDOERS_TMP="$(mktemp)"
cat > "$SUDOERS_TMP" <<EOF
# Managed by PEN-AGENT (tools/ligolo/install-sudoers.sh). Do not hand-edit —
# re-run the installer with --user to change the grant, or run
# tools/ligolo/uninstall-sudoers.sh to revoke. The four referenced scripts do
# their own argument validation; this file grants NO wildcarded 'ip' commands.
$TARGET_USER ALL=(root) NOPASSWD: $BIN_DIR/pen-agent-ligolo-up
$TARGET_USER ALL=(root) NOPASSWD: $BIN_DIR/pen-agent-ligolo-down
$TARGET_USER ALL=(root) NOPASSWD: $BIN_DIR/pen-agent-ligolo-route *
$TARGET_USER ALL=(root) NOPASSWD: $BIN_DIR/pen-agent-ligolo-unroute *
EOF
chmod 0440 "$SUDOERS_TMP"

# visudo -c validates the file WITHOUT installing it. If it fails, bail
# BEFORE touching /etc/sudoers.d/ — a bad file there can lock the system out
# of sudo for everyone.
if ! visudo -c -f "$SUDOERS_TMP" >/dev/null; then
    echo "ERROR: generated sudoers file failed visudo validation; refusing to install." >&2
    echo "       File left at: $SUDOERS_TMP (inspect, don't move into /etc/sudoers.d/ manually unless you know what you're doing)." >&2
    exit 1
fi

# Move into place atomically.
install -m 0440 -o root -g root "$SUDOERS_TMP" "$SUDOERS_PATH"
rm -f "$SUDOERS_TMP"
echo "[install-ligolo] Wrote $SUDOERS_PATH (0440 root:root)."

# Verify end-to-end: can the target user actually invoke the helper without a password?
if sudo -u "$TARGET_USER" -n /usr/bin/sudo -n "$BIN_DIR/pen-agent-ligolo-up" >/dev/null 2>&1; then
    echo "[install-ligolo] Verification OK: '$TARGET_USER' can run pen-agent-ligolo-up without a password."
    # Leave the interface up — pivoting-tunneling will use it. Harmless if idle.
else
    rc=$?
    echo "[install-ligolo] WARNING: verification probe exited $rc. The sudoers entry is installed, but something" >&2
    echo "                 (iproute2 missing? TUN not enabled in the kernel? SELinux/AppArmor?) prevented the probe." >&2
    echo "                 Diagnose: sudo -u $TARGET_USER sudo -n $BIN_DIR/pen-agent-ligolo-up" >&2
fi

echo
echo "Done. The pivoting-tunneling skill will detect this and bring up ligolo"
echo "without an operator password prompt. Revoke any time: sudo bash tools/ligolo/uninstall-sudoers.sh"
