#!/usr/bin/env bash
set -euo pipefail

# preflight.sh — Check and install attackbox dependencies for PEN-AGENT
#
# Verifies that required tools, wordlists, and target-side binaries are
# available, and (with --install) installs the missing ones. Downloaded /
# non-apt tools go under $TOOLS_DIR (default /opt/PEN-AGENT/tools); system
# packages install via apt.
#
# Usage:
#   bash preflight.sh                    # full check (reports what's missing)
#   bash preflight.sh --install          # install missing REQUIRED tools, then re-check
#   bash preflight.sh --install --optional   # also install the optional tools
#   bash preflight.sh --category         # check one category (e.g. --ad)
#   bash preflight.sh --list             # list available categories
#   bash preflight.sh --json             # machine-readable output
#
# Env: PEN_AGENT_TOOLS_DIR overrides the tool dir;
#      PEN_AGENT_INSTALL_DRYRUN=1 previews --install without changing anything.

# ── Colors ──────────────────────────────────────────────────────────────────

if [[ -t 1 ]]; then
    GREEN=$'\033[0;32m'  RED=$'\033[0;31m'  YELLOW=$'\033[0;33m'
    CYAN=$'\033[0;36m'   BOLD=$'\033[1m'    DIM=$'\033[2m'
    RESET=$'\033[0m'
else
    GREEN="" RED="" YELLOW="" CYAN="" BOLD="" DIM="" RESET=""
fi

# ── Counters ────────────────────────────────────────────────────────────────

PASS=0 FAIL=0 WARN=0
JSON_MODE=false
JSON_RESULTS=()
INSTALL_MODE=false
INSTALL_OPTIONAL=false

# ── Tool directory ────────────────────────────────────────────────────────────
# Downloaded / non-apt tools (go, pipx, gem, npm, git-clone, release binaries,
# uv) live under a single hardcoded directory so the attackbox stays clean.
# apt/system packages install normally into /usr/bin and are found via PATH —
# that's intentional and left alone. This directory's bins are prepended to
# PATH so checks find tools installed here first.
TOOLS_DIR="${PEN_AGENT_TOOLS_DIR:-/opt/PEN-AGENT/tools}"
TOOLS_BIN="${TOOLS_DIR}/bin"
TOOLS_REPOS="${TOOLS_DIR}/repos"
TOOLS_PIPX="${TOOLS_DIR}/pipx"
TOOLS_GEMS="${TOOLS_DIR}/gems"
TOOLS_NPM="${TOOLS_DIR}/npm"
TOOLS_NPM_BIN="${TOOLS_NPM}/bin"
PROFILE_D="/etc/profile.d/pen-agent-tools.sh"
export PATH="${TOOLS_BIN}:${TOOLS_NPM_BIN}:${PATH}"

# ── Helpers ─────────────────────────────────────────────────────────────────

pass() {
    PASS=$((PASS + 1))
    if $JSON_MODE; then
        JSON_RESULTS+=("{\"name\":\"$1\",\"status\":\"pass\",\"path\":\"$2\"}")
    else
        printf "  ${GREEN}✓${RESET} %-28s %s\n" "$1" "${DIM}${2}${RESET}"
    fi
}

fail() {
    FAIL=$((FAIL + 1))
    if $JSON_MODE; then
        JSON_RESULTS+=("{\"name\":\"$1\",\"status\":\"fail\",\"hint\":\"$2\"}")
    else
        printf "  ${RED}✗${RESET} %-28s %s\n" "$1" "${DIM}${2}${RESET}"
    fi
}

warn() {
    WARN=$((WARN + 1))
    if $JSON_MODE; then
        JSON_RESULTS+=("{\"name\":\"$1\",\"status\":\"warn\",\"hint\":\"$2\"}")
    else
        printf "  ${YELLOW}○${RESET} %-28s %s\n" "$1" "${DIM}${2}${RESET}"
    fi
}

section() {
    $JSON_MODE && return
    echo ""
    echo "${BOLD}${CYAN}[$1]${RESET}"
}

# Check if a command exists anywhere in PATH
has_cmd() { command -v "$1" &>/dev/null; }

# Find a command and print its path, or return 1
find_cmd() {
    local path
    path="$(command -v "$1" 2>/dev/null)" && echo "$path" && return 0
    return 1
}

# Check for a pipx-installed package
find_pipx() {
    local name="$1"
    local bin="${2:-$1}"
    local path
    # Check if the binary is in PATH (pipx puts them in ~/.local/bin/)
    path="$(find_cmd "$bin")" && echo "$path" && return 0
    # Check pipx list
    if has_cmd pipx && pipx list --short 2>/dev/null | grep -qi "^${name} "; then
        echo "pipx:${name}"
        return 0
    fi
    return 1
}

# Check for a Go binary
find_go() {
    local bin="$1"
    local path
    path="$(find_cmd "$bin")" && echo "$path" && return 0
    # Common Go binary locations (incl. the PEN-AGENT tool dir)
    for d in "$TOOLS_BIN" "$HOME/go/bin" "/usr/local/go/bin" "${GOPATH:-}/bin" "${GOBIN:-}"; do
        [[ -n "${d:-}" && -x "${d}/${bin}" ]] && echo "${d}/${bin}" && return 0
    done
    return 1
}

# ── Check functions ─────────────────────────────────────────────────────────

check_redrun_prereqs() {
    section "PEN-AGENT prerequisites"

    local p
    # uv (required by install.sh)
    if p=$(find_cmd uv); then pass "uv" "$p"
    else fail "uv" "https://docs.astral.sh/uv/getting-started/installation/"; fi

    # Docker
    if p=$(find_cmd docker); then
        if docker info &>/dev/null 2>&1; then
            pass "docker (daemon running)" "$p"
        else
            warn "docker (daemon not running)" "$p — start with: sudo systemctl start docker"
        fi
    else fail "docker" "https://docs.docker.com/engine/install/"; fi

    # Docker images
    if has_cmd docker && docker info &>/dev/null 2>&1; then
        if docker image inspect pen-agent-nmap:latest &>/dev/null 2>&1; then
            pass "pen-agent-nmap image" "docker"
        else warn "pen-agent-nmap image" "run: ./install.sh"; fi

        if docker image inspect pen-agent-shell:latest &>/dev/null 2>&1; then
            pass "pen-agent-shell image" "docker"
        else warn "pen-agent-shell image" "run: ./install.sh"; fi
    fi

    # Python 3
    if p=$(find_cmd python3); then pass "python3" "$p"
    else fail "python3" "sudo apt install python3"; fi

    # Git
    if p=$(find_cmd git); then pass "git" "$p"
    else fail "git" "sudo apt install git"; fi

    # pipx (needed for many tools)
    if p=$(find_cmd pipx); then pass "pipx" "$p"
    else warn "pipx" "sudo apt install pipx"; fi

    # Go (needed for nuclei, httpx, ffuf, etc.)
    if p=$(find_cmd go); then pass "go" "$p"
    else warn "go" "sudo apt install golang-go"; fi

    # Node/npm (needed for domdig)
    if p=$(find_cmd npm); then pass "npm" "$p"
    else warn "npm" "sudo apt install npm"; fi
}

check_network_scanning() {
    section "Network scanning and enumeration"

    local p
    if p=$(find_cmd nmap); then pass "nmap" "$p"
    else fail "nmap" "sudo apt install nmap"; fi

    if p=$(find_go nuclei); then
        pass "nuclei" "$p"
        # Check that nuclei-templates are installed
        local tpl_dir="${HOME}/nuclei-templates"
        if [[ -d "$tpl_dir" ]] && [[ -n "$(ls -A "$tpl_dir" 2>/dev/null)" ]]; then
            pass "nuclei-templates" "$tpl_dir"
        else
            fail "nuclei-templates" "nuclei -update-templates"
        fi
    else fail "nuclei" "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"; fi

    if p=$(find_go httpx); then pass "httpx" "$p"
    else fail "httpx" "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"; fi

    if p=$(find_pipx netexec nxc); then pass "netexec (nxc)" "$p"
    else fail "netexec (nxc)" "pipx install netexec"; fi

    if p=$(find_pipx enum4linux-ng); then pass "enum4linux-ng" "$p"
    else warn "enum4linux-ng" "pipx install enum4linux-ng"; fi

    if p=$(find_pipx manspider); then pass "manspider" "$p"
    else warn "manspider" "pipx install manspider"; fi

    if p=$(find_cmd snmpwalk); then pass "snmpwalk" "$p"
    else warn "snmpwalk" "sudo apt install snmp"; fi

    if p=$(find_cmd onesixtyone); then pass "onesixtyone" "$p"
    else warn "onesixtyone" "sudo apt install onesixtyone"; fi
}

check_web_testing() {
    section "Web application testing"

    local p
    if p=$(find_go ffuf); then pass "ffuf" "$p"
    else fail "ffuf" "go install github.com/ffuf/ffuf/v2@latest"; fi

    if p=$(find_cmd sqlmap); then pass "sqlmap" "$p"
    else fail "sqlmap" "sudo apt install sqlmap"; fi

    if p=$(find_cmd wpscan); then pass "wpscan" "$p"
    else warn "wpscan" "sudo gem install wpscan"; fi

    if p=$(find_pipx git-dumper); then pass "git-dumper" "$p"
    else warn "git-dumper" "pipx install git-dumper"; fi

    if p=$(find_pipx arjun); then pass "arjun" "$p"
    else warn "arjun" "pipx install arjun"; fi

    if p=$(find_cmd commix); then pass "commix" "$p"
    else warn "commix" "sudo apt install commix"; fi

    if p=$(find_go dalfox); then pass "dalfox" "$p"
    else warn "dalfox" "go install github.com/hahwul/dalfox/v2@latest"; fi

    if p=$(find_cmd xsstrike || find_cmd xsstrike.py); then pass "XSStrike" "$p"
    else warn "XSStrike" "install and add xsstrike to PATH"; fi

    if p=$(find_pipx sstimap); then pass "sstimap" "$p"
    else warn "sstimap" "pipx install sstimap"; fi

    if p=$(find_cmd tplmap || find_cmd tplmap.py); then pass "tplmap" "$p"
    else warn "tplmap" "install and add tplmap to PATH"; fi

    if p=$(find_go TInjA); then pass "TInjA" "$p"
    else warn "TInjA" "go install github.com/Hackmanit/TInjA@latest"; fi

    if p=$(find_pipx fenjing); then pass "fenjing" "$p"
    else warn "fenjing" "pipx install fenjing"; fi

    if p=$(find_cmd ssrfmap || find_cmd ssrfmap.py); then pass "SSRFmap" "$p"
    else warn "SSRFmap" "install and add ssrfmap to PATH"; fi

    if p=$(find_cmd gopherus || find_cmd gopherus.py); then pass "gopherus" "$p"
    else warn "gopherus" "install and add gopherus to PATH"; fi

    if p=$(find_go interactsh-client); then pass "interactsh-client" "$p"
    else warn "interactsh-client" "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"; fi

    if p=$(find_go xxeserv); then pass "xxeserv" "$p"
    else warn "xxeserv" "go install github.com/staaldraad/xxeserv@latest"; fi

    if p=$(find_cmd XXEinjector.rb); then pass "XXEinjector" "$p"
    else warn "XXEinjector" "install and add XXEinjector.rb to PATH"; fi

    if p=$(find_pipx jwt_tool jwt_tool); then pass "jwt-tool" "$p"
    elif p=$(find_cmd jwt_tool); then pass "jwt-tool" "$p"
    else warn "jwt-tool" "pipx install jwt-tool"; fi

    if p=$(find_cmd domdig); then pass "domdig" "$p"
    else warn "domdig" "npm install -g domdig"; fi

    if p=$(find_cmd php_filter_chain_generator.py); then pass "php_filter_chain_gen" "$p"
    else warn "php_filter_chain_gen" "install and add php_filter_chain_generator.py to PATH"; fi
}

check_deserialization() {
    section "Deserialization"

    local p
    if p=$(find_cmd ysoserial || find_cmd ysoserial.jar); then pass "ysoserial (Java)" "$p"
    else warn "ysoserial (Java)" "download JAR and add to PATH"; fi

    if p=$(find_cmd marshalsec || find_cmd marshalsec.jar); then pass "marshalsec" "$p"
    else warn "marshalsec" "build JAR and add to PATH"; fi

    if p=$(find_cmd phpggc); then pass "phpggc" "$p"
    else warn "phpggc" "install and add phpggc to PATH"; fi

    if p=$(find_cmd jexboss || find_cmd jexboss.py); then pass "jexboss" "$p"
    else warn "jexboss" "install and add jexboss to PATH"; fi

    if p=$(find_pipx badsecrets); then pass "badsecrets" "$p"
    else warn "badsecrets" "pipx install badsecrets"; fi
}

check_active_directory() {
    section "Active Directory"

    local p
    if p=$(find_pipx bloodhound bloodhound-python || find_cmd bloodhound-python || find_cmd bloodhound-ce-python); then
        pass "BloodHound CE (collector)" "$p"
    else fail "BloodHound CE" "pipx install bloodhound"; fi

    if p=$(find_cmd rusthound); then pass "rusthound-ce" "$p"
    else warn "rusthound-ce" "download from GitHub releases and add to PATH"; fi

    if p=$(find_pipx certipy-ad certipy); then pass "certipy" "$p"
    elif p=$(find_cmd certipy); then pass "certipy" "$p"
    else fail "certipy" "pipx install certipy-ad"; fi

    if p=$(find_pipx bloodyad bloodyAD || find_cmd bloodyAD); then pass "bloodyAD" "$p"
    else fail "bloodyAD" "pipx install bloodyad"; fi

    if p=$(find_cmd kerbrute || find_go kerbrute); then pass "kerbrute" "$p"
    else fail "kerbrute" "download from https://github.com/ropnop/kerbrute/releases"; fi

    if p=$(find_pipx pywhisker); then pass "pywhisker" "$p"
    else warn "pywhisker" "pipx install pywhisker"; fi

    if p=$(find_cmd targetedKerberoast.py); then pass "targetedKerberoast" "$p"
    else warn "targetedKerberoast" "install and add targetedKerberoast.py to PATH"; fi

    if p=$(find_cmd krbrelayx.py || find_cmd krbrelayx); then pass "krbrelayx" "$p"
    else fail "krbrelayx" "install and add krbrelayx.py to PATH"; fi

    if p=$(find_cmd PetitPotam.py); then pass "PetitPotam" "$p"
    else warn "PetitPotam" "install and add PetitPotam.py to PATH"; fi

    if p=$(find_cmd dfscoerce.py || find_cmd DFSCoerce.py); then pass "DFSCoerce" "$p"
    else warn "DFSCoerce" "install and add DFSCoerce.py to PATH"; fi

    if p=$(find_cmd shadowcoerce.py || find_cmd ShadowCoerce.py); then pass "ShadowCoerce" "$p"
    else warn "ShadowCoerce" "install and add ShadowCoerce.py to PATH"; fi

    if p=$(find_cmd gettgtpkinit.py); then pass "PKINITtools" "$p"
    else fail "PKINITtools" "install and add gettgtpkinit.py to PATH"; fi

    if p=$(find_cmd modifyCertTemplate.py); then pass "modifyCertTemplate" "$p"
    else warn "modifyCertTemplate" "install and add modifyCertTemplate.py to PATH"; fi

    if p=$(find_cmd gMSADumper.py); then pass "gMSADumper" "$p"
    else warn "gMSADumper" "install and add gMSADumper.py to PATH"; fi

    if p=$(find_pipx impacket); then pass "impacket (local)" "$p"
    elif p=$(find_cmd secretsdump.py); then pass "impacket (local)" "$p"
    else fail "impacket (local)" "pipx install impacket"; fi
}

check_sccm_gpo() {
    section "SCCM and GPO"

    local p
    if p=$(find_pipx sccmhunter); then pass "sccmhunter" "$p"
    else warn "sccmhunter" "pipx install sccmhunter"; fi

    if p=$(find_cmd pxethiefy.py || find_cmd pxethiefy); then pass "pxethiefy" "$p"
    else warn "pxethiefy" "install and add pxethiefy to PATH"; fi

    if p=$(find_cmd pygpoabuse.py || find_cmd pyGPOAbuse.py); then pass "pyGPOAbuse" "$p"
    else warn "pyGPOAbuse" "install and add pyGPOAbuse.py to PATH"; fi

    if p=$(find_pipx gpohound || find_cmd gpohound); then pass "GPOHound" "$p"
    else warn "GPOHound" "pipx install gpohound"; fi
}

check_pivoting() {
    section "Pivoting and tunneling"

    local p
    if p=$(find_cmd sshuttle); then pass "sshuttle" "$p"
    else fail "sshuttle" "sudo apt install sshuttle"; fi

    if p=$(find_cmd proxychains4 || find_cmd proxychains); then pass "proxychains" "$p"
    else fail "proxychains" "sudo apt install proxychains4"; fi

    if p=$(find_cmd autossh); then pass "autossh" "$p"
    else warn "autossh" "sudo apt install autossh"; fi

    if p=$(find_cmd msfconsole); then pass "metasploit" "$p"
    else warn "metasploit" "sudo apt install metasploit-framework"; fi
}

check_cracking() {
    section "Credential cracking"

    local p
    if p=$(find_cmd hashcat); then pass "hashcat" "$p"
    else fail "hashcat" "sudo apt install hashcat"; fi

    if p=$(find_cmd john); then
        if "$p" 2>&1 | head -5 | grep -qi jumbo; then
            pass "john (jumbo)" "$p"
        else
            warn "john" "found at $p but not jumbo — *2john tools may be missing. Install: sudo apt install john"
        fi
    else fail "john" "sudo apt install john"; fi

    if p=$(find_cmd hydra); then pass "hydra" "$p"
    else fail "hydra" "sudo apt install hydra"; fi
}

check_evasion() {
    section "Evasion and payload building"

    local p
    if p=$(find_cmd x86_64-w64-mingw32-gcc); then pass "mingw-w64" "$p"
    elif p=$(find_cmd i686-w64-mingw32-gcc); then pass "mingw-w64" "$p"
    else warn "mingw-w64" "sudo apt install mingw-w64"; fi

    if p=$(find_cmd msfvenom); then pass "msfvenom" "$p"
    else warn "msfvenom" "sudo apt install metasploit-framework"; fi

    if p=$(find_cmd gcc); then pass "gcc" "$p"
    else warn "gcc" "sudo apt install build-essential"; fi

    if p=$(find_cmd searchsploit); then pass "searchsploit" "$p"
    else warn "searchsploit" "sudo apt install exploitdb"; fi
}

check_general() {
    section "General utilities"

    local p
    if p=$(find_cmd curl); then pass "curl" "$p"
    else fail "curl" "sudo apt install curl"; fi

    if p=$(find_cmd openssl); then pass "openssl" "$p"
    else fail "openssl" "sudo apt install openssl"; fi

    if p=$(find_cmd ldapsearch); then pass "ldapsearch" "$p"
    else fail "ldapsearch" "sudo apt install ldap-utils"; fi

    if p=$(find_cmd rpcclient); then pass "rpcclient" "$p"
    else warn "rpcclient" "sudo apt install smbclient"; fi

    if p=$(find_cmd jq); then pass "jq" "$p"
    else fail "jq" "sudo apt install jq"; fi

    if p=$(find_cmd exiftool); then pass "exiftool" "$p"
    else warn "exiftool" "sudo apt install libimage-exiftool-perl"; fi

    if p=$(find_cmd ruby); then pass "ruby" "$p"
    else warn "ruby" "sudo apt install ruby"; fi

    if p=$(find_cmd java); then pass "java" "$p"
    else warn "java" "sudo apt install default-jdk"; fi

    if p=$(find_cmd tmux); then pass "tmux" "$p"
    else warn "tmux" "sudo apt install tmux"; fi
}

check_wordlists() {
    section "Wordlists"

    # Skills reference /usr/share/seclists/ paths directly
    if [[ -d /usr/share/seclists ]]; then
        pass "SecLists" "/usr/share/seclists"
    elif [[ -d /usr/share/SecLists ]]; then
        pass "SecLists" "/usr/share/SecLists"
    else
        fail "SecLists" "sudo apt install seclists"
    fi

    # Skills reference /usr/share/wordlists/rockyou.txt directly
    if [[ -f /usr/share/wordlists/rockyou.txt ]]; then
        pass "rockyou.txt" "/usr/share/wordlists/rockyou.txt"
    elif [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
        warn "rockyou.txt (compressed)" "gunzip /usr/share/wordlists/rockyou.txt.gz"
    else
        fail "rockyou.txt" "expected at /usr/share/wordlists/rockyou.txt"
    fi

    if p=$(find_cmd jwt-secrets); then pass "jwt-secrets" "$p"
    else warn "jwt-secrets" "install and add to PATH"; fi
}

check_target_tools() {
    section "Target-side tools (pre-staged on attackbox)"

    local p

    # Linux
    for name in linpeas.sh lse.sh pspy64 pspy32 linux-exploit-suggester.sh deepce.sh; do
        short="${name%%.*}"
        if p=$(find_cmd "$name"); then
            pass "$short" "$p"
        else
            warn "$short" "download and add $name to PATH"
        fi
    done

    # Windows
    for name in winpeas.exe mimikatz.exe Rubeus.exe RunasCs.exe; do
        short="${name%%.*}"
        if p=$(find_cmd "$name"); then
            pass "$short" "$p"
        else
            warn "$short" "download and add $name to PATH"
        fi
    done

    # Tunnel agents (Linux + Windows builds)
    for name in chisel ligolo-agent; do
        if p=$(find_cmd "$name"); then
            pass "$name (agent builds)" "$p"
        else
            warn "$name (agent builds)" "download and add to PATH"
        fi
    done

    if p=$(find_pipx wesng wes || find_cmd wes); then pass "WES-NG" "$p"
    else warn "WES-NG" "pipx install wesng"; fi

    # Potato privesc binaries (SeImpersonate → SYSTEM)
    local potato_dir="/usr/share/windows-binaries/potatoes"
    local potato_missing=0
    for name in GodPotato-NET4.exe PrintSpoofer64.exe JuicyPotatoNG.exe SigmaPotato.exe; do
        short="${name%%.*}"
        if [[ -f "${potato_dir}/${name}" ]]; then
            pass "$short" "${potato_dir}/${name}"
        else
            warn "$short" "download to ${potato_dir}/${name}"
            potato_missing=$((potato_missing + 1))
        fi
    done
    if [[ $potato_missing -gt 0 ]]; then
        $JSON_MODE || printf "  %s   hint: see docs/dependencies.md for download URLs%s\n" "${DIM}" "${RESET}"
    fi
}

# ── Installer (--install) ─────────────────────────────────────────────────────
# Installs missing tools. System packages go via apt (stay in /usr/bin);
# everything else (go, pipx, git-clone, release binaries) goes under
# $TOOLS_DIR. Required tools by default; --optional adds the optional set.

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
    x86_64|amd64) GOARCH=amd64; RELARCH="amd64" ;;
    aarch64|arm64) GOARCH=arm64; RELARCH="arm64" ;;
    *) GOARCH="$ARCH_RAW"; RELARCH="$ARCH_RAW" ;;
esac
ILOG="$(mktemp -t pen-install-XXXXXX.log)"
INSTALLED=() ; IFAILED=() ; IMANUAL=()
TOOLS_OWNER="${SUDO_USER:-$(id -un)}"
DRYRUN="${PEN_AGENT_INSTALL_DRYRUN:-}"   # set to 1 to preview without changing anything

iecho() { $JSON_MODE || echo "$@"; }
istep() { # $1 ok|fail|skip|manual  $2 label
    case "$1" in
        ok)     iecho "  ${GREEN}✓${RESET} $2" ;;
        fail)   iecho "  ${RED}✗${RESET} $2 ${DIM}(see $ILOG)${RESET}" ;;
        skip)   iecho "  ${DIM}• $2 (already present)${RESET}" ;;
        manual) iecho "  ${YELLOW}○${RESET} $2 ${DIM}(manual — see docs/dependencies.md)${RESET}" ;;
    esac
}

_sudo() {
    [[ -n "$DRYRUN" ]] && { echo "[dry] sudo $*" >>"$ILOG"; return 0; }
    if [[ $EUID -eq 0 ]]; then "$@"; else sudo "$@"; fi
}
as_owner() {  # run package managers as the invoking user, not root
    [[ -n "$DRYRUN" ]] && { echo "[dry] $*" >>"$ILOG"; return 0; }
    if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then sudo -u "$SUDO_USER" -H "$@"; else "$@"; fi
}

APT_UPDATED=false
apt_pkg() {  # apt install (idempotent-ish); $1 = package
    $APT_UPDATED || { _sudo apt-get update -qq && APT_UPDATED=true; }
    _sudo apt-get install -y -qq "$1"
}
pipx_tool() { as_owner env "PIPX_HOME=$TOOLS_PIPX" "PIPX_BIN_DIR=$TOOLS_BIN" pipx install --force "$1"; }
go_tool()   { as_owner env "GOBIN=$TOOLS_BIN" go install "$1"; }
gem_tool()  { as_owner env "GEM_HOME=$TOOLS_GEMS" gem install --no-document --bindir "$TOOLS_BIN" "$1"; }
npm_tool()  { as_owner npm install -g --prefix "$TOOLS_NPM" "$1"; }

git_wrap() {  # repo dir entrypoint... : clone to $TOOLS_REPOS/<dir>, wrap python entrypoints into bin
    local repo="$1" name="$2"; shift 2
    [[ -n "$DRYRUN" ]] && { echo "[dry] git clone https://github.com/$repo + wrap: $*" >>"$ILOG"; return 0; }
    local dir="$TOOLS_REPOS/$name"
    if [[ -d "$dir/.git" ]]; then (cd "$dir" && as_owner git pull -q) || true
    else as_owner git clone --depth 1 -q "https://github.com/$repo" "$dir"; fi
    # install requirements if present (into a venv-free user install is messy; rely on system libs)
    local ep
    for ep in "$@"; do
        local base; base="$(basename "$ep")"
        local runner="python3"; [[ "$ep" == *.rb ]] && runner="ruby"; [[ "$ep" == *.jar ]] && runner="java -jar"
        { echo '#!/usr/bin/env bash'; echo "exec $runner \"$dir/$ep\" \"\$@\""; } > "$TOOLS_BIN/$base"
        chmod +x "$TOOLS_BIN/$base"
    done
}

gh_release_bin() {  # repo asset-grep dest-name : download matching latest-release asset to bin
    local repo="$1" pat="$2" dest="$3" url
    [[ -n "$DRYRUN" ]] && { echo "[dry] gh release $repo [$pat] -> $TOOLS_BIN/$dest" >>"$ILOG"; return 0; }
    url="$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" \
        | grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' \
        | cut -d'"' -f4 | grep -iE "$pat" | head -1)"
    [[ -n "$url" ]] || return 1
    if [[ "$url" == *.gz && "$url" != *.tar.gz ]]; then
        curl -fsSL "$url" | gunzip -c > "$TOOLS_BIN/$dest"
    elif [[ "$url" == *.tar.gz || "$url" == *.tgz ]]; then
        local tmp; tmp="$(mktemp -d)"; curl -fsSL "$url" | tar -xz -C "$tmp"
        local found; found="$(find "$tmp" -type f -name "$dest" | head -1)"
        [[ -z "$found" ]] && found="$(find "$tmp" -maxdepth 2 -type f -perm -u+x ! -name '*.txt' ! -name '*.md' | head -1)"
        [[ -n "$found" ]] && cp "$found" "$TOOLS_BIN/$dest"; rm -rf "$tmp"
    else
        curl -fsSL "$url" -o "$TOOLS_BIN/$dest"
    fi
    chmod +x "$TOOLS_BIN/$dest" 2>/dev/null || true
    [[ -s "$TOOLS_BIN/$dest" ]]
}
gh_raw() {
    [[ -n "$DRYRUN" ]] && { echo "[dry] raw $1 -> $TOOLS_BIN/$2" >>"$ILOG"; return 0; }
    curl -fsSL "https://raw.githubusercontent.com/$1" -o "$TOOLS_BIN/$2" && chmod +x "$TOOLS_BIN/$2"
}

_try() {  # present-test label method arg...  — skip if present, else install
    local present="$1" label="$2"; shift 2
    if eval "$present" &>/dev/null; then istep skip "$label"; return 0; fi
    if "$@" >>"$ILOG" 2>&1; then istep ok "$label"; INSTALLED+=("$label")
    else istep fail "$label"; IFAILED+=("$label"); fi
}
_manual() { istep manual "$1"; IMANUAL+=("$1"); }

ensure_tooldir() {
    _sudo mkdir -p "$TOOLS_BIN" "$TOOLS_REPOS" "$TOOLS_PIPX" "$TOOLS_GEMS" "$TOOLS_NPM"
    _sudo chown -R "$TOOLS_OWNER":"$(id -gn "$TOOLS_OWNER" 2>/dev/null || echo "$TOOLS_OWNER")" "$TOOLS_DIR"
    # Persist PATH/env for future shells
    if [[ ! -f "$PROFILE_D" ]]; then
        {
            echo "export PATH=\"$TOOLS_BIN:$TOOLS_NPM_BIN:\$PATH\""
            echo "export GEM_HOME=\"$TOOLS_GEMS\""
        } | _sudo tee "$PROFILE_D" >/dev/null
        iecho "  ${DIM}PATH/env entries written to $PROFILE_D (new shells pick it up)${RESET}"
    fi
}

ensure_base() {  # toolchains many installs need
    _try "has_cmd curl"  "curl"  apt_pkg curl
    _try "has_cmd git"   "git"   apt_pkg git
    _try "has_cmd pipx"  "pipx"  apt_pkg pipx
    _try "has_cmd go"    "go (golang)" apt_pkg golang-go
}

install_uv()     { as_owner env "UV_INSTALL_DIR=$TOOLS_BIN" sh -c 'curl -LsSf https://astral.sh/uv/install.sh | sh'; }
install_docker() {
    apt_pkg docker.io || return 1
    _sudo systemctl enable --now docker 2>/dev/null || true
    _sudo usermod -aG docker "$TOOLS_OWNER" 2>/dev/null || true
}

install_required() {
    section "Installing REQUIRED tools"
    ensure_tooldir
    ensure_base
    # Core prereqs for install.sh / run.sh
    _try "has_cmd uv"     "uv"     install_uv
    _try "has_cmd docker" "docker" install_docker
    # System packages (apt → /usr/bin)
    _try "has_cmd python3"       "python3"       apt_pkg python3
    _try "has_cmd nmap"          "nmap"          apt_pkg nmap
    _try "has_cmd sqlmap"        "sqlmap"        apt_pkg sqlmap
    _try "has_cmd hashcat"       "hashcat"       apt_pkg hashcat
    _try "has_cmd john"          "john"          apt_pkg john
    _try "has_cmd hydra"         "hydra"         apt_pkg hydra
    _try "has_cmd sshuttle"      "sshuttle"      apt_pkg sshuttle
    _try "has_cmd proxychains4"  "proxychains4"  apt_pkg proxychains4
    _try "has_cmd openssl"       "openssl"       apt_pkg openssl
    _try "has_cmd jq"            "jq"            apt_pkg jq
    _try "has_cmd ldapsearch"    "ldap-utils"    apt_pkg ldap-utils
    _try "[[ -d /usr/share/seclists || -d /usr/share/SecLists ]]" "SecLists" apt_pkg seclists
    _try "[[ -f /usr/share/wordlists/rockyou.txt ]]" "rockyou.txt" install_rockyou
    # pipx tools (→ $TOOLS_BIN)
    _try "has_cmd nxc || has_cmd netexec"  "netexec (nxc)" pipx_tool netexec
    _try "has_cmd certipy"                 "certipy"       pipx_tool certipy-ad
    _try "has_cmd bloodyAD"                "bloodyAD"      pipx_tool bloodyAD
    _try "has_cmd bloodhound-ce-python || has_cmd bloodhound-python" "BloodHound CE" pipx_tool bloodhound-ce
    _try "has_cmd secretsdump.py || has_cmd impacket-secretsdump"    "impacket"      pipx_tool impacket
    # go tools (→ $TOOLS_BIN)
    _try "has_cmd ffuf"          "ffuf"          go_tool github.com/ffuf/ffuf/v2@latest
    _try "has_cmd httpx"         "httpx"         go_tool github.com/projectdiscovery/httpx/cmd/httpx@latest
    _try "has_cmd nuclei"        "nuclei"        go_tool github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    _try "[[ -d $HOME/nuclei-templates ]]" "nuclei-templates" nuclei_templates
    # git-clone python toolkits (→ $TOOLS_REPOS, wrappers in $TOOLS_BIN)
    _try "has_cmd krbrelayx.py"  "krbrelayx"     git_wrap dirkjanm/krbrelayx krbrelayx krbrelayx.py addspn.py printerbug.py dnstool.py
    _try "has_cmd gettgtpkinit.py" "PKINITtools" git_wrap dirkjanm/PKINITtools PKINITtools gettgtpkinit.py getnthash.py gets4uticket.py
    # release binary
    _try "has_cmd kerbrute"      "kerbrute"      gh_release_bin ropnop/kerbrute "linux_${RELARCH}\$" kerbrute
}

install_rockyou() {
    apt_pkg wordlists || true
    [[ -f /usr/share/wordlists/rockyou.txt.gz ]] && _sudo gunzip -kf /usr/share/wordlists/rockyou.txt.gz
    [[ -f /usr/share/wordlists/rockyou.txt ]]
}
nuclei_templates() { as_owner "$(command -v nuclei || echo "$TOOLS_BIN/nuclei")" -update-templates; }

install_optional() {
    section "Installing OPTIONAL tools"
    ensure_tooldir
    ensure_base
    # apt
    for pb in "snmpwalk:snmp" "onesixtyone:onesixtyone" "commix:commix" "autossh:autossh" \
              "msfconsole:metasploit-framework" "gcc:build-essential" "searchsploit:exploitdb" \
              "ruby:ruby" "java:default-jdk" "tmux:tmux" "rpcclient:smbclient" \
              "npm:npm" "exiftool:libimage-exiftool-perl" "x86_64-w64-mingw32-gcc:mingw-w64"; do
        _try "has_cmd ${pb%%:*}" "${pb##*:}" apt_pkg "${pb##*:}"
    done
    # pipx
    for pp in "enum4linux-ng:enum4linux-ng:x" "manspider:manspider:manspider" \
              "git-dumper:git-dumper:git-dumper" "arjun:arjun:arjun" "sstimap:sstimap:sstimap" \
              "fenjing:fenjing:fenjing" "badsecrets:badsecrets:badsecrets" "pywhisker:pywhisker:pywhisker" \
              "sccmhunter:sccmhunter:sccmhunter" "gpohound:gpohound:gpohound" "wesng:wesng:wes" \
              "jwt-tool:jwt-tool:jwt_tool"; do
        IFS=: read -r bin pkg _ <<<"$pp"
        _try "has_cmd $bin" "$pkg" pipx_tool "$pkg"
    done
    # go
    _try "has_cmd dalfox"            "dalfox"            go_tool github.com/hahwul/dalfox/v2@latest
    _try "has_cmd TInjA"             "TInjA"             go_tool github.com/Hackmanit/TInjA@latest
    _try "has_cmd interactsh-client" "interactsh-client" go_tool github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
    _try "has_cmd xxeserv"           "xxeserv"           go_tool github.com/staaldraad/xxeserv@latest
    # gem / npm
    _try "has_cmd wpscan"  "wpscan" gem_tool wpscan
    _try "has_cmd domdig"  "domdig" npm_tool domdig
    # git-clone python/ruby/php toolkits
    _try "has_cmd xsstrike.py"       "XSStrike"       git_wrap s0md3v/XSStrike XSStrike xsstrike.py
    _try "has_cmd tplmap.py"         "tplmap"         git_wrap epinna/tplmap tplmap tplmap.py
    _try "has_cmd ssrfmap.py"        "SSRFmap"        git_wrap swisskyrepo/SSRFmap SSRFmap ssrfmap.py
    _try "has_cmd gopherus.py"       "gopherus"       git_wrap tarunkant/Gopherus Gopherus gopherus.py
    _try "has_cmd XXEinjector.rb"    "XXEinjector"    git_wrap enjoiz/XXEinjector XXEinjector XXEinjector.rb
    _try "has_cmd phpggc"            "phpggc"         git_wrap ambionics/phpggc phpggc phpggc
    _try "has_cmd php_filter_chain_generator.py" "php_filter_chain_gen" git_wrap synacktiv/php_filter_chain_generator php_filter_chain_generator php_filter_chain_generator.py
    _try "has_cmd targetedKerberoast.py" "targetedKerberoast" git_wrap ShutdownRepo/targetedKerberoast targetedKerberoast targetedKerberoast.py
    _try "has_cmd PetitPotam.py"     "PetitPotam"     git_wrap topotam/PetitPotam PetitPotam PetitPotam.py
    _try "has_cmd dfscoerce.py"      "DFSCoerce"      git_wrap Wh04m1001/DFSCoerce DFSCoerce dfscoerce.py
    _try "has_cmd gMSADumper.py"     "gMSADumper"     git_wrap micahvandeusen/gMSADumper gMSADumper gMSADumper.py
    _try "has_cmd pygpoabuse.py"     "pyGPOAbuse"     git_wrap Hackndo/pyGPOAbuse pyGPOAbuse pygpoabuse.py
    # release binaries
    _try "has_cmd chisel"            "chisel"         gh_release_bin jpillora/chisel "linux_${RELARCH}.gz\$" chisel
    _try "has_cmd ligolo-agent"      "ligolo-ng (agent+proxy)" gh_release_bin nicocha30/ligolo-ng "linux_${RELARCH}.tar.gz\$" ligolo-agent
    _try "[[ -x $TOOLS_BIN/linpeas.sh ]]" "linpeas.sh" gh_release_bin carlospolop/PEASS-ng "linpeas.sh\$" linpeas.sh
    _try "[[ -x $TOOLS_BIN/pspy64 ]]" "pspy64" gh_release_bin DominicBreuker/pspy "pspy64\$" pspy64
    # raw single-file scripts
    _try "[[ -x $TOOLS_BIN/lse.sh ]]"  "lse.sh"  gh_raw diego-treitos/linux-smart-enumeration/master/lse.sh lse.sh
    _try "[[ -x $TOOLS_BIN/deepce.sh ]]" "deepce.sh" gh_raw stealthcopter/deepce/main/deepce.sh deepce.sh
    _try "[[ -x $TOOLS_BIN/linux-exploit-suggester.sh ]]" "linux-exploit-suggester" gh_raw The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh linux-exploit-suggester.sh
    # Known-good but binary/AV-sensitive or build-required → flag as manual
    for m in "ysoserial.jar (Java gadget chains)" "marshalsec (build from source)" \
             "winPEAS.exe / mimikatz.exe / Rubeus.exe (Windows, AV-sensitive)" \
             "Potato privesc binaries (GodPotato/PrintSpoofer/JuicyPotatoNG/SigmaPotato)" \
             "RunasCs.exe"; do
        _manual "$m"
    done
}

run_install() {
    $JSON_MODE && { echo "preflight --install does not support --json" >&2; exit 2; }
    echo "${BOLD}PEN-AGENT tool installer${RESET}"
    echo "${DIM}Tool dir: ${TOOLS_DIR}  ·  owner: ${TOOLS_OWNER}  ·  arch: ${RELARCH}${RESET}"
    [[ -n "$DRYRUN" ]] && echo "${YELLOW}DRY RUN — nothing will be changed${RESET}"
    if [[ -z "$DRYRUN" && $EUID -ne 0 ]] && ! sudo -v 2>/dev/null; then
        echo "${RED}This needs sudo for apt and to write ${TOOLS_DIR} / ${PROFILE_D}.${RESET}" >&2
        exit 1
    fi
    install_required
    $INSTALL_OPTIONAL && install_optional
    # Normalize ownership of anything written as root.
    _sudo chown -R "$TOOLS_OWNER":"$(id -gn "$TOOLS_OWNER" 2>/dev/null || echo "$TOOLS_OWNER")" "$TOOLS_DIR" 2>/dev/null || true
    echo ""
    echo "${BOLD}Install summary${RESET}"
    echo "  ${GREEN}✓ ${#INSTALLED[@]} installed${RESET}    ${RED}✗ ${#IFAILED[@]} failed${RESET}    ${YELLOW}○ ${#IMANUAL[@]} manual${RESET}"
    [[ ${#IFAILED[@]} -gt 0 ]] && echo "  ${DIM}Failed: ${IFAILED[*]}  (log: $ILOG)${RESET}"
    [[ ${#IMANUAL[@]} -gt 0 ]] && echo "  ${DIM}Manual: see docs/dependencies.md${RESET}"
    echo "  ${DIM}Open a new shell (or: source $PROFILE_D) so $TOOLS_BIN is on PATH.${RESET}"
    echo ""
    echo "${DIM}Re-running checks…${RESET}"
}

# ── Category map ────────────────────────────────────────────────────────────

declare -A CATEGORIES=(
    [prereqs]=check_redrun_prereqs
    [network]=check_network_scanning
    [web]=check_web_testing
    [deser]=check_deserialization
    [ad]=check_active_directory
    [sccm-gpo]=check_sccm_gpo
    [pivoting]=check_pivoting
    [cracking]=check_cracking
    [evasion]=check_evasion
    [general]=check_general
    [wordlists]=check_wordlists
    [target-tools]=check_target_tools
)

CATEGORY_ORDER=(prereqs network web deser ad sccm-gpo pivoting cracking evasion general wordlists target-tools)

# ── Main ────────────────────────────────────────────────────────────────────

print_usage() {
    echo "Usage: bash preflight.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --install       Install missing REQUIRED tools, then re-check"
    echo "  --optional      With --install, also install the optional tools"
    echo "  --list          List available categories"
    echo "  --json          Machine-readable JSON output"
    echo "  --<category>    Check a single category (e.g., --ad, --web)"
    echo ""
    echo "Downloaded tools install under ${TOOLS_DIR} (override: PEN_AGENT_TOOLS_DIR)."
    echo "System packages install via apt. --install needs sudo."
    echo ""
    echo "Categories: ${CATEGORY_ORDER[*]}"
}

run_category=""
for arg in "$@"; do
    case "$arg" in
        --help|-h)   print_usage; exit 0 ;;
        --list)      echo "Categories: ${CATEGORY_ORDER[*]}"; exit 0 ;;
        --json)      JSON_MODE=true ;;
        --install)   INSTALL_MODE=true ;;
        --optional|--all) INSTALL_OPTIONAL=true ;;
        --*)
            cat="${arg#--}"
            if [[ -n "${CATEGORIES[$cat]:-}" ]]; then
                run_category="$cat"
            else
                echo "Unknown category: $cat" >&2
                echo "Available: ${CATEGORY_ORDER[*]}" >&2
                exit 1
            fi
            ;;
    esac
done

# Platform gate
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "PEN-AGENT preflight is designed for Linux attackboxes." >&2
    echo "Detected: $(uname -s)" >&2
    exit 1
fi

# Install mode: install tools first, then fall through to the normal check.
if $INSTALL_MODE; then
    run_install
fi

if ! $JSON_MODE; then
    echo "${BOLD}PEN-AGENT preflight check${RESET}"
    echo "${DIM}$(uname -srm) — $(grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo 'unknown distro')${RESET}"
fi

if [[ -n "$run_category" ]]; then
    ${CATEGORIES[$run_category]}
else
    for cat in "${CATEGORY_ORDER[@]}"; do
        ${CATEGORIES[$cat]}
    done
fi

# ── Summary ─────────────────────────────────────────────────────────────────

if $JSON_MODE; then
    echo "{"
    echo "  \"pass\": $PASS,"
    echo "  \"fail\": $FAIL,"
    echo "  \"warn\": $WARN,"
    echo "  \"results\": ["
    for i in "${!JSON_RESULTS[@]}"; do
        if [[ $i -lt $((${#JSON_RESULTS[@]} - 1)) ]]; then
            echo "    ${JSON_RESULTS[$i]},"
        else
            echo "    ${JSON_RESULTS[$i]}"
        fi
    done
    echo "  ]"
    echo "}"
else
    echo ""
    echo "${BOLD}Summary${RESET}"
    echo "  ${GREEN}✓ $PASS passed${RESET}    ${RED}✗ $FAIL missing${RESET}    ${YELLOW}○ $WARN optional${RESET}"
    if [[ $FAIL -gt 0 ]]; then
        echo ""
        echo "${DIM}Re-run with --<category> to check a specific area.${RESET}"
        echo "${DIM}See docs/dependencies.md for full install commands.${RESET}"
    fi
fi

exit $(( FAIL > 0 ? 1 : 0 ))
