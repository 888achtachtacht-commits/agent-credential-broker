# Credential broker for AI agents

A local AI agent uses logins and API keys **without ever seeing them**. Sensitive
access is released by a push notification you tap on your phone.

The broker is called *Zentrale* in the code and in file names. Code comments and
identifiers are German; the documentation is English.

## Problem

An agent with browser and shell access needs credentials. Two common approaches,
both unusable:

- **Hand the password to the agent** — it sits in cleartext on disk, gets read,
  and ends up in the model context. It spreads across files.
- **Type the password yourself** — safe, but the agent cannot work when nobody
  is there.

Same for root: `NOPASSWD` hands over the machine, a password prompt ties a human
to the keyboard.

## Requirements

1. The agent never sees a password — not in files, variables, responses or logs.
2. Release by tapping a phone, not by typing a password.
3. Works from anywhere.
4. Sessions expire by themselves.
5. One rule per credential: free / confirm / blocked.
6. The agent keeps its other privileges.

## Solution

A **broker** on a **second machine**, under its own user, unreadable by the
agent. HTTP API, token protected, firewalled to the agent host.

Browser flow:

1. Agent: `POST /browser {zugang, grund}` — the credential name and a reason.
2. Broker sends a Duo push containing that reason in plain text.
3. On yes: password from Proton Pass (token scoped to one vault), login driven
   by Playwright in a Chromium running on the broker.
4. Only then does the CDP relay accept connections from the agent; the session
   is time limited. The port listens from startup, but the relay closes any
   connection while no session is active, and the firewall only lets the agent
   host reach it.
5. The agent works, then `POST /browser/ende`; otherwise the session expires.

API flow: `POST /anfrage {zugang, methode, url, grund}` — the broker injects the
key, performs the request and returns the response only, with secrets redacted.

On no: a cooldown for that credential.

## Components

| Purpose | Used here | Alternatives |
|---|---|---|
| Push approval | Cisco Duo (free tier), `pam_duo` for sudo, Auth API for the broker | ntfy, Pushover, a Telegram bot — you build the question-and-answer logic yourself |
| Secrets | Proton Pass CLI, vault-scoped token | Bitwarden, 1Password, Vault, Infisical |
| Browser | Playwright attached over CDP to a running Chromium | Puppeteer, Selenium |
| Transport | Tailscale, `ufw` limited to the agent host | WireGuard, SSH tunnel |
| Agent side | CLI helper, CDP forwarder, skill file listing the prohibitions | — |

## sudo by push

`pam_duo` before `pam_unix`. What matters:

- `autopush=yes`, `prompts=1` — no method menu an agent could interact with
- `failmode=secure` — the default is often `safe`, i.e. let it through when the
  service is unreachable
- `pushinfo=yes` — the command appears in the push notification
- `timestamp_timeout=0` in sudoers — otherwise the agent rides one approval for
  as many further commands as it likes

## Pitfalls

These are the places where this took hours. They sound small.

- **Do not treat "no password field visible" as a successful login.** Providers
  show interstitials ("set up a passkey" / "no thanks") **at the same URL** as
  the form. There is no password field there. Check that the host **or** the path
  has left the login address, and dismiss interstitials **before** that check,
  not after.
- **A login URL is often single use** (`prompt=none`, `state=…`). Loading the
  same address again lands back on the form. That looks like a wrong password
  and is not one.
- **Screenshots can come out blank** (headless/Xvfb). On failure, dump the page
  state as text: URL, title, every frame, visible inputs and buttons, visible
  text. Clear password fields first, write the dump with mode 600.
- **Webmail lives in an iframe.** Select `iframe[name="…"]`; the bare frame name
  runs into a timeout.
- **Block echo services as targets** (httpbin, postman-echo, webhook.site,
  ngrok …) — they reflect the auth header back. Redact secrets in the **common**
  encodings: Base64 (std + urlsafe, with and without padding), URL, JSON, HTML,
  and the basic-auth pair. Not covered: Base32, hex, UTF-16/7, doubly chained
  Base64. Text substitution does not win that race — the real boundary is the
  per-credential host allowlist.
- **SSRF protection:** https only, port allowlist, never follow redirects,
  resolve DNS and pin the checked IP (SNI and certificate against the original
  host), block private ranges, CGNAT `100.64.0.0/10` and benchmarking
  `198.18.0.0/15` **explicitly**. `is_global` covers CGNAT in current Python
  versions, benchmarking ranges in older ones not — your own check is
  independent of the Python version.
- **Taking the last two labels as the base domain is wrong** for `co.uk`,
  `com.au` and friends. Rule: two labels, a two-letter ccTLD, preceded by
  `co|com|org|…` → demand an explicit host list.
- **VPN software can bypass the firewall** with its own netfilter chain. Turn
  that off, set the rules yourself, verify from outside.
- **State the agent's prohibitions in the skill file:** no password or email
  changes, no passkeys, no forwarding rules, filters or app passwords, no
  deletion, never navigate back to the login page, never re-request after a
  denial.

## Files

| Path | Where it goes |
|---|---|
| `zentrale.py` | the broker, as a systemd service under its own user |
| `zentrale-update` | installs a new version: checks it, backs up, restarts, rolls back on a failed start |
| `agent/zentrale` | CLI helper on the agent host |
| `agent/zentrale-weiterleitung.py` | TCP forwarder 127.0.0.1:19223 → the broker's relay |
| `agent/SKILL.md` | instructions and prohibitions for the agent |
| `setup/` | three systemd units (broker, browser, forwarder), Chromium start script, browser policy, AppArmor profile, polkit rule |
| `examples/` | configuration without contents: credential list, Duo, password manager, ntfy, agent host |
| `SETUP.md` | installation in six steps, including users, firewall and verification |

Deliberately absent and never versioned: `duo.env`, `proton.env`, `ntfy.env`,
`client.token`, `zugaenge.json`, logs, failure dumps.

Requirements: Python 3.11+, `duo_client`, `playwright`, Chromium, `xvfb`,
systemd, AppArmor, polkit, `ufw`, the password manager's CLI, a Duo account
(the free tier is enough).

## Limits

- No protection against a provider that allows account changes without
  re-authentication. Mitigations: short sessions, a restricted account.
- Credentials behind two-factor authentication (SMS or an authenticator app)
  cannot be driven by this. Open.
- The effect depends entirely on maintaining the credential list.
- An approval nobody looks at is not an approval.
- Requirement 1 is a design goal. It is enforced by separating the machines, by
  redaction and by the host allowlist — not proven.
- The rules in `agent/SKILL.md` are instructions to the agent, not technical
  constraints. What is actually enforced: the approval, the time limit, the
  allowed domains, the `file://` block and the firewall.

## Status

In use for one browser credential at a webmail provider with a two-step login
and a passkey interstitial: the agent used the authenticated session, read from
the mailbox and ended the session, never saw the password, and the approval was
one tap.

Whether this holds for every other provider is not claimed. This describes a
state that was reached, not a finished tool. Issues are welcome; this is not
maintained as a product.

## What's next

Intentions, not commitments, and no dates.

- **Second factor.** The design already treats the human tap as the second
  factor; what is missing is the plumbing providers demand. The TOTP secret is
  already fetched from the vault — generating the code and typing it into the
  right field is not implemented yet. SMS codes can be relayed from a phone to
  the broker; that transport works, the integration does not exist yet.
  Passkeys stay out of scope: they are hardware bound, there is no secret to
  broker.
- **Detect changes instead of forbidding them.** During an open session the
  agent can do whatever the account allows without re-authentication. The
  prohibitions in `agent/SKILL.md` are instructions, not enforcement. The
  cheaper control is to compare the account's critical settings before and
  after a session — forwarding rules, filters, recovery address, app passwords,
  linked devices — and push a notification on any change. The agent can still
  do it, but not unnoticed.
- **A watchdog.** Report when the broker or its browser service is down. A
  laptop is a good host for it because its battery outlives a power cut. The
  open problem is that a watchdog cannot report the failure of the machine it
  runs on; that needs a heartbeat to something outside.
- **A restricted account** at the provider wherever one exists. That is the
  only limitation the provider actually enforces.
