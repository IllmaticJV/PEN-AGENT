#!/bin/sh
# PEN-AGENT shell_recon — one-shot deterministic recon on a new Linux shell.
# Output is partitioned by `=== SECTION ===` markers that shell_recon.py parses.
# Run it ONCE from send_command right after a shell lands; pipe the output to
# tools/ingestors/shell_recon.py --ip <this-host>.
echo '=== WHOAMI ==='; whoami 2>/dev/null
echo '=== ID ==='; id 2>/dev/null
echo '=== HOSTNAME ==='; hostname 2>/dev/null
echo '=== OS ==='; (lsb_release -ds 2>/dev/null || awk -F= '/^PRETTY_NAME=/{gsub(/"/,"",$2);print $2}' /etc/os-release 2>/dev/null || uname -s)
echo '=== KERNEL ==='; uname -r 2>/dev/null
echo '=== IFACES ==='; ip -o -4 addr show 2>/dev/null || ifconfig -a 2>/dev/null
echo '=== SUDO ==='; sudo -n -l 2>&1 | head -20
echo '=== DOCKER ==='; (groups 2>/dev/null | grep -q docker && echo 'yes (in docker group)') || (test -S /var/run/docker.sock && echo 'yes (socket readable)') || echo 'no'
echo '=== PATH ==='; echo "$PATH"
echo '=== CWD ==='; pwd 2>/dev/null
echo '=== HOME_LS ==='; ls -la "$HOME" 2>/dev/null | head -20
echo '=== CRON ==='; (cat /etc/crontab 2>/dev/null; ls /etc/cron.*/ 2>/dev/null) | head -40
echo '=== WORLD_WRITABLE_INTERESTING ==='
find /etc /opt /var/www /srv -type f -perm -o+w 2>/dev/null | head -20
echo '=== LISTENING ==='; (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | head -30
echo '=== DONE ==='
