#!/usr/bin/env bash
# Pre-engagement configuration wizard.
# Writes engagement/config.yaml so the orchestrator skips its built-in wizard.
# Run before ./run.sh to pre-configure scan type, proxy, spray, cracking, and C2.
set -euo pipefail
cd "$(dirname "$0")"

CONFIG="engagement/config.yaml"
TEMPLATE="operator/templates/config.yaml"

if [[ -f "$CONFIG" ]]; then
    echo "Config already exists: $CONFIG"
    read -rp "Overwrite? [y/N] " ow
    [[ "${ow,,}" == "y" ]] || { echo "Keeping existing config."; exit 0; }
fi

mkdir -p engagement

echo ""
echo "=== PEN-AGENT engagement setup ==="
echo ""

# --- Q1: Scan type ---
echo "Q1 — Default network scan type"
echo "  1) quick  (top 1000 ports)"
echo "  2) full   (all 65535 ports)"
read -rp "  Choice [1]: " q1
case "${q1:-1}" in
    2) scan_type="full" ;;
    *) scan_type="quick" ;;
esac

# --- Q2: Web proxy ---
echo ""
echo "Q2 — Web proxy for HTTP traffic"
echo "  1) Burp 127.0.0.1:8080 (recommended)"
echo "  2) Custom URL"
echo "  3) No proxy"
read -rp "  Choice [1]: " q2
case "${q2:-1}" in
    2) read -rp "  Proxy URL (e.g., http://10.0.0.1:8080): " proxy_url
       proxy_enabled="true" ;;
    3) proxy_enabled="false"; proxy_url="" ;;
    *) proxy_enabled="true"; proxy_url="http://127.0.0.1:8080" ;;
esac

# --- Q3: Spray tier ---
echo ""
echo "Q3 — Password spray default tier"
echo "  1) light   (~30 passwords)"
echo "  2) medium  (~10k passwords)"
echo "  3) heavy   (~100k passwords)"
echo "  4) skip    (no spraying)"
read -rp "  Choice [1]: " q3
case "${q3:-1}" in
    2) spray_tier="medium" ;;
    3) spray_tier="heavy" ;;
    4) spray_tier="skip" ;;
    *) spray_tier="light" ;;
esac

# --- Q4: Hash recovery ---
echo ""
echo "Q4 — Hash recovery method"
echo "  1) local    (hashcat/john on this machine)"
echo "  2) export   (save hashes for external rig)"
echo "  3) skip     (no recovery)"
read -rp "  Choice [1]: " q4
case "${q4:-1}" in
    2) cracking_method="export" ;;
    3) cracking_method="skip" ;;
    *) cracking_method="local" ;;
esac

# --- Q5: Shell backend ---
echo ""
echo "Q5 — Shell backend"
if command -v msfrpcd &>/dev/null; then
    default_q5=2
    if pgrep -f "msfrpcd" &>/dev/null; then
        echo "  1) shell-server  (raw TCP/PTY, always available — fallback)"
        echo "  2) metasploit    (Metasploit C2 — msfrpcd running) [default]"
    else
        echo "  1) shell-server  (raw TCP/PTY, always available — fallback)"
        echo "  2) metasploit    (Metasploit C2 — will auto-start msfrpcd) [default]"
    fi
else
    default_q5=1
    echo "  1) shell-server  (raw TCP/PTY, always available) [default]"
    echo "  2) metasploit    (metasploit-framework not found)"
fi
echo "  3) custom        (your own C2 + MCP server)"
read -rp "  Choice [${default_q5}]: " q5
q5="${q5:-$default_q5}"

shell_backend="shell-server"
msf_config=""
custom_mcp=""
custom_ref=""

case "$q5" in
    2)
        default_cfg="engagement/msfrpc.yaml"
        if ! command -v msfrpcd &>/dev/null; then
            echo "  metasploit-framework not found on PATH."
            echo "  Install it (see docs/installation.md), then re-run ./config.sh."
            echo "  Falling back to shell-server."
        elif [[ -f "$default_cfg" ]]; then
            echo "  Found Metasploit RPC config: $default_cfg"
            shell_backend="metasploit"
            msf_config="$default_cfg"
        else
            if pgrep -f "msfrpcd" &>/dev/null; then
                # Orphaned daemon from a previous run/engagement — it's a
                # detached background process, so it outlives whatever
                # session started it, and nobody has a record of its
                # credentials. Restart clean rather than falling back.
                echo "  msfrpcd is running but no config at $default_cfg —"
                echo "  stale daemon from a previous run. Restarting with fresh credentials."
                pkill -f "msfrpcd" 2>/dev/null || true
                sleep 1
            fi
            # Metasploit is the default backend — auto-start msfrpcd, same as run.sh.
            msf_port="${MSF_RPC_PORT:-55553}"
            msf_pass="$(head -c 24 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)"
            echo "  Starting msfrpcd on 127.0.0.1:${msf_port}..."
            msfrpcd -P "$msf_pass" -U msf -a 127.0.0.1 -p "$msf_port" &>/dev/null &
            cat > "$default_cfg" <<YAML
host: 127.0.0.1
port: ${msf_port}
user: msf
password: ${msf_pass}
ssl: true
YAML
            chmod 600 "$default_cfg"
            echo "  Config saved to $default_cfg"
            shell_backend="metasploit"
            msf_config="$default_cfg"
        fi
        ;;
    3)
        shell_backend="custom"
        read -rp "  MCP server name (as registered in .mcp.json): " custom_mcp
        read -rp "  Reference doc path (markdown): " custom_ref
        if [[ -n "$custom_ref" && ! -f "$custom_ref" ]]; then
            echo "  Warning: $custom_ref not found. shell-mgr will need it at runtime."
        fi
        ;;
esac

# --- Write config ---
cat > "$CONFIG" << YAML
# PEN-AGENT engagement configuration
# Generated by config.sh. Edit at any time.

scan_type: ${scan_type}
YAML

if [[ "$proxy_enabled" == "true" ]]; then
    cat >> "$CONFIG" << YAML

web_proxy:
  enabled: true
  url: "${proxy_url}"
YAML
else
    cat >> "$CONFIG" << YAML

web_proxy:
  enabled: false
YAML
fi

cat >> "$CONFIG" << YAML

spray:
  default_tier: ${spray_tier}

cracking:
  default_method: ${cracking_method}

shell:
  backend: ${shell_backend}
YAML

if [[ "$shell_backend" == "metasploit" && -n "$msf_config" ]]; then
    echo "  msf_config: \"${msf_config}\"" >> "$CONFIG"
fi

if [[ "$shell_backend" == "custom" ]]; then
    [[ -n "$custom_mcp" ]] && echo "  custom_mcp: \"${custom_mcp}\"" >> "$CONFIG"
    [[ -n "$custom_ref" ]] && echo "  custom_ref: \"${custom_ref}\"" >> "$CONFIG"
fi

# --- Patch .mcp.json for C2 backends ---
MCP_JSON=".mcp.json"
if [[ "$shell_backend" == "metasploit" && -f "$MCP_JSON" ]]; then
    MSF_SSE_PORT="${MSF_SSE_PORT:-8024}"
    if ! grep -q '"metasploit-server"' "$MCP_JSON"; then
        echo ""
        echo "Adding metasploit-server to .mcp.json..."
        # Insert metasploit-server SSE entry after shell-server
        python3 -c "
import json, sys
with open('$MCP_JSON') as f:
    cfg = json.load(f)
cfg['mcpServers']['metasploit-server'] = {'type': 'sse', 'url': 'http://127.0.0.1:${MSF_SSE_PORT}/sse'}
with open('$MCP_JSON', 'w') as f:
    json.dump(cfg, f, indent=2)
    f.write('\n')
print('  metasploit-server added to .mcp.json')
" 2>&1
        echo "  Note: restart Claude Code session for MCP changes to take effect."
    else
        echo "  metasploit-server already in .mcp.json"
    fi

    # Ensure metasploit-server tools are auto-allowed in settings.json
    SETTINGS_JSON=".claude/settings.json"
    if [[ -f "$SETTINGS_JSON" ]]; then
        if ! grep -q '"mcp__metasploit-server__\*"' "$SETTINGS_JSON"; then
            echo "Adding metasploit-server to allowedTools in settings.json..."
            python3 -c "
import json
with open('$SETTINGS_JSON') as f:
    cfg = json.load(f)
allow = cfg.get('permissions', {}).get('allow', [])
entry = 'mcp__metasploit-server__*'
if entry not in allow:
    # Insert after shell-server entry if present, else append
    try:
        idx = next(i for i, v in enumerate(allow) if 'shell-server' in v) + 1
    except StopIteration:
        idx = len(allow)
    allow.insert(idx, entry)
    cfg.setdefault('permissions', {})['allow'] = allow
    with open('$SETTINGS_JSON', 'w') as f:
        json.dump(cfg, f, indent=2)
        f.write('\n')
    print('  metasploit-server added to allowedTools')
" 2>&1
        else
            echo "  metasploit-server already in allowedTools"
        fi
    fi
fi

echo ""
echo "Config written to $CONFIG"
echo "Run ./run.sh to start the engagement."
