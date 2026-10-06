#!/usr/bin/env bash
# PEN-AGENT local hashcat wrapper — auto-detects hash mode, picks a sensible
# wordlist, runs in the background, and (when done) emits a cracked.txt +
# state-mgr [update-cred] lines for the teammate to relay.
#
# Why: specifying -m <mode> + the right wordlist/rule combo for every hash
# type is annoying boilerplate that teammates were doing per-call. This hides
# the detail and standardizes evidence placement.
#
# Usage:
#   bash tools/crack/crack.sh <hashfile> [--wordlist /path/to/wl] [--rules /path/to/rules]
#                                        [--mode <N>]     # override auto-detect
#                                        [--max-min N]    # bound runtime (default 10)
#                                        [--show-only]    # just print existing cracks
#
# Outputs under engagement/evidence/crack-<basename>-<ts>/:
#   hashcat.log       — full stdout/stderr
#   cracked.txt       — hash:plain pairs (hashcat --show)
#   state-writes.txt  — pre-formatted [update-cred] lines for state-mgr
#
# Teammate workflow:
#   1. Save hashes to engagement/evidence/hashes-<label>.txt (one per line).
#   2. bash tools/crack/crack.sh engagement/evidence/hashes-<label>.txt
#   3. On "cracked N / M", relay state-writes.txt to state-mgr verbatim.

set -euo pipefail

HASHFILE=""
WORDLIST=""
RULES=""
MODE=""
MAX_MIN=10
SHOW_ONLY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --wordlist) WORDLIST="$2"; shift 2;;
        --rules)    RULES="$2";    shift 2;;
        --mode)     MODE="$2";     shift 2;;
        --max-min)  MAX_MIN="$2";  shift 2;;
        --show-only) SHOW_ONLY=1;  shift;;
        -h|--help)
            sed -n '2,30p' "$0"; exit 0;;
        -*) echo "ERROR: unknown flag $1" >&2; exit 2;;
        *)  HASHFILE="$1"; shift;;
    esac
done

if [[ -z "$HASHFILE" || ! -f "$HASHFILE" ]]; then
    echo "ERROR: pass a readable hash file" >&2
    exit 2
fi

if ! command -v hashcat >/dev/null; then
    echo "ERROR: hashcat not on PATH. install it or run in the dockerized" \
         "cracker container." >&2
    exit 2
fi

# Pick a wordlist. Preference order: operator override, rockyou (/usr/share),
# SecLists best1050000, then any .txt under /usr/share/wordlists/.
if [[ -z "$WORDLIST" ]]; then
    for cand in \
        /usr/share/wordlists/rockyou.txt \
        /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt \
        /usr/share/wordlists/SecLists/Passwords/Common-Credentials/best1050000-probable-v2.txt \
        /usr/share/wordlists/fasttrack.txt ; do
        if [[ -r "$cand" ]]; then WORDLIST="$cand"; break; fi
    done
fi
if [[ -z "$WORDLIST" ]]; then
    echo "ERROR: no wordlist found. Pass --wordlist <path>." >&2
    exit 2
fi

# Auto-detect hashcat -m mode by sniffing the first hash line.
auto_mode() {
    local first
    first=$(grep -v '^#' "$HASHFILE" | grep -v '^$' | head -1)
    case "$first" in
        '$krb5tgs$23$'*)       echo 13100 ;;   # Kerberos TGS-REP RC4
        '$krb5tgs$17$'*|'$krb5tgs$18$'*) echo 19600 ;;  # AES
        '$krb5asrep$23$'*)     echo 18200 ;;   # ASREP RC4
        '$NETNTLMv2$'*|'::'*)  echo 5600  ;;   # NetNTLMv2
        '$NTLM$'*)             echo 1000  ;;
        '$6$'*)                echo 1800  ;;   # sha512crypt
        '$5$'*)                echo 7400  ;;   # sha256crypt
        '$2a$'*|'$2b$'*|'$2y$'*) echo 3200 ;;  # bcrypt
        '$1$'*)                echo 500   ;;   # md5crypt
        *)
            # Looks like a bare NT hash? 32 hex chars.
            if [[ "$first" =~ ^[a-fA-F0-9]{32}$ ]]; then echo 1000
            # SAM/NTDS line user:rid:lm:nt:::
            elif [[ "$first" =~ ^[^:]+:[0-9]+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}::: ]]; then echo 1000
            # bare SHA-1?
            elif [[ "$first" =~ ^[a-fA-F0-9]{40}$ ]]; then echo 100
            else echo ""
            fi ;;
    esac
}

if [[ -z "$MODE" ]]; then
    MODE=$(auto_mode)
fi
if [[ -z "$MODE" ]]; then
    echo "ERROR: could not auto-detect hash mode. Pass --mode <N> explicitly." >&2
    echo "  First line: $(head -1 "$HASHFILE")" >&2
    exit 2
fi

TS=$(date -u +%Y%m%d-%H%M%S)
BASE=$(basename "$HASHFILE" .txt)
OUT="engagement/evidence/crack-${BASE}-${TS}"
mkdir -p "$OUT"

echo "mode:     $MODE"
echo "wordlist: $WORDLIST  ($(wc -l <"$WORDLIST") lines)"
echo "rules:    ${RULES:-(none)}"
echo "max_min:  $MAX_MIN"
echo "out:      $OUT/"
echo

if [[ $SHOW_ONLY -eq 1 ]]; then
    hashcat -m "$MODE" "$HASHFILE" --show 2>/dev/null | tee "$OUT/cracked.txt" || true
    cracks=$(wc -l < "$OUT/cracked.txt")
    echo "already cracked: $cracks"
else
    # Run hashcat with a soft timeout. --runtime bounds the attack.
    runtime=$(( MAX_MIN * 60 ))
    cmd=(hashcat -m "$MODE" -a 0 --runtime="$runtime" "$HASHFILE" "$WORDLIST")
    [[ -n "$RULES" ]] && cmd+=(-r "$RULES")
    echo "running: ${cmd[*]}"
    "${cmd[@]}" > "$OUT/hashcat.log" 2>&1 || true
    hashcat -m "$MODE" "$HASHFILE" --show 2>/dev/null > "$OUT/cracked.txt" || true
fi

cracks=$(wc -l < "$OUT/cracked.txt" 2>/dev/null || echo 0)
total=$(grep -cv '^$\|^#' "$HASHFILE")

# Emit state-mgr [update-cred] lines. The teammate must correlate each
# plaintext back to the right credential id in state.db — print the pattern
# and let the LLM match. We just supply the raw hash/plain pairs.
{
    echo "# Cracked: $cracks / $total"
    echo "# Format: hash<TAB>plain — relay to state-mgr as:"
    echo "#   [update-cred] id=<matching cred.id> cracked=true secret=\"<plain>\""
    while IFS=: read -r hash plain; do
        [[ -z "$hash" ]] && continue
        printf '%s\t%s\n' "$hash" "$plain"
    done < "$OUT/cracked.txt"
} > "$OUT/state-writes.txt"

echo
echo "=== RESULT ==="
echo "cracked:  $cracks / $total"
echo "evidence: $OUT/"
echo "writes:   $OUT/state-writes.txt (relay matching lines to state-mgr)"
exit 0
