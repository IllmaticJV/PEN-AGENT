# ligolo — operator-free pivot helpers

Ligolo-ng is PEN-AGENT's preferred pivot (see
`skills/network/pivoting-tunneling/SKILL.md` and the lessons note on
out-of-Framework pivots). It's rock-solid in practice but requires root on
the attackbox for three things: creating the TUN interface, bringing it up,
and adding routes. Without automation, the operator types a sudo password on
every pivot setup.

This directory ships four narrow helper scripts and an opt-in sudoers.d entry
that lets PEN-AGENT bring ligolo up without a password prompt — scoped so
tightly that `sudo` grants nothing beyond "manage the ligolo TUN."

## What gets installed

| Script | What it does | Args |
|---|---|---|
| `pen-agent-ligolo-up` | Creates `ligolo` TUN (owned by the install-time user), brings it up. Idempotent. | none |
| `pen-agent-ligolo-down` | Tears down the `ligolo` TUN. Idempotent. | none |
| `pen-agent-ligolo-route` | Adds `${LIGOLO_SUBNET} dev ligolo`. Validates the CIDR as IPv4; rejects `0.0.0.0/0` and `127.0.0.0/8`. | `LIGOLO_SUBNET=<cidr>` env var (positional `$1` kept as fallback) |
| `pen-agent-ligolo-unroute` | Removes the matching route. Same env + validation. | `LIGOLO_SUBNET=<cidr>` env var |

Plus `/etc/sudoers.d/pen-agent-ligolo` granting NOPASSWD execution of **only
these four absolute paths** to the invoking user.

## Threat model

What the operator grants by running the installer:

- The target user can, without a password, bring the `ligolo` TUN up/down
  and add/remove **one validated-IPv4-CIDR-at-a-time** route through it.
- **No arbitrary `ip` commands.** The sudoers file does not wildcard `ip` or
  any `ip` subcommand. All validation (CIDR shape, IPv4, prefix sanity) lives
  in the helper scripts, which the policy is pinned to.
- **No other interface names.** The scripts hardcode `ligolo`.
- The installer validates the sudoers file with `visudo -c` before saving to
  prevent a syntax error from locking out `sudo` for everyone.
- The CIDR is passed via `LIGOLO_SUBNET` (env var) rather than a positional
  arg, so sudoers doesn't need an argument wildcard. Older sudo + default
  fnmatch flags refuse to match `/` through `*`, which silently falls back
  to a password prompt — the env-var form is portable across every sudo
  version. The `SETENV:` tag on the route rules + a scoped
  `Defaults!…/pen-agent-ligolo-route env_keep += "LIGOLO_SUBNET"` is what
  lets the var cross the `sudo` boundary without widening the general
  env_keep policy.

Revoke any time:

```bash
sudo bash tools/ligolo/uninstall-sudoers.sh
```

## Install

```bash
sudo bash tools/ligolo/install-sudoers.sh
# or, to grant a user other than $SUDO_USER:
sudo bash tools/ligolo/install-sudoers.sh --user alice
```

The installer prints what it did and runs a self-check — invoking
`pen-agent-ligolo-up` as the target user with `sudo -n` and reporting whether
the no-password path works.

## How the skill uses it

`skills/network/pivoting-tunneling/SKILL.md` § **Step 2: Ligolo-ng** detects
the helpers' presence (`command -v pen-agent-ligolo-up`) and when they're
installed takes the operator-free path — `sudo -n pen-agent-ligolo-up`,
`sudo -n LIGOLO_SUBNET=<CIDR> pen-agent-ligolo-route`, etc. — with no handoff. When they're
not present, the skill falls back to the hand-off-to-operator path.

## Not installed by default

`install.sh` **does not** write this file silently. The main installer offers
it as an interactive prompt (default: skip). Run `install-sudoers.sh` yourself
when you're ready — it's a per-attackbox decision, not a repo-level one.
