# Installation

Two machines: the **agent host** (where the AI agent runs) and the **broker**
(its own machine, holding the credentials). In this order.

## 1. Broker: users and directories

```
sudo useradd -r -s /usr/sbin/nologin -d /opt/zentrale zentrale
sudo useradd -r -s /usr/sbin/nologin -M -d /nonexistent browser
sudo mkdir -p /opt/zentrale /opt/browser
sudo chown zentrale:zentrale /opt/zentrale && sudo chmod 750 /opt/zentrale
```

Python environment and dependencies:

```
sudo -u zentrale python3 -m venv /opt/zentrale/venv
sudo -u zentrale /opt/zentrale/venv/bin/pip install duo_client playwright
```

Chromium for the browser user, separate from the broker:

```
sudo PLAYWRIGHT_BROWSERS_PATH=/opt/browser/ms-playwright \
  /opt/zentrale/venv/bin/playwright install chromium
sudo apt install xvfb
```

## 2. Broker: configuration

Everything under `/opt/zentrale/`, owned by `zentrale`, mode **600**. Templates
in `examples/`.

| File | Contents |
|---|---|
| `duo.env` | `DUO_IKEY`, `DUO_SKEY`, `DUO_HOST`, `DUO_USER` of a Duo application of type *Auth API* |
| `proton.env` | the password manager's token, scoped to **one** vault, plus the vault name |
| `ntfy.env` | optional; if the file is absent, ntfy is skipped |
| `client.token` | shared secret for the agent host, at least 32 characters: `openssl rand -hex 32` |
| `zugaenge.json` | one entry per credential, see the template |

Create them, set ownership and modes, generate the token:

```
sudo cp examples/zugaenge.json /opt/zentrale/zugaenge.json
sudo cp examples/duo.env examples/proton.env /opt/zentrale/
# only if you want ntfy:
# sudo cp examples/ntfy.env /opt/zentrale/
openssl rand -hex 32 | sudo tee /opt/zentrale/client.token >/dev/null
sudo chown zentrale:zentrale /opt/zentrale/*
sudo chmod 600 /opt/zentrale/*.env /opt/zentrale/client.token /opt/zentrale/zugaenge.json
sudo cat /opt/zentrale/client.token     # step 5 needs the same value
```

### The password manager's CLI

The code expects it at a **fixed path**, not on `$PATH`:

```
/opt/zentrale/.local/bin/pass-cli
```

Proton Pass's official script installs into `~/.local/bin`. Since the broker
runs with `HOME=/opt/zentrale`, that lines up if you run it as that user with
that `HOME`.

**Do not pipe `curl` into a shell on this machine.** It holds the credentials;
running a script straight off the network contradicts the whole design.
Download, look at it, then run it:

```
sudo mkdir -p /opt/zentrale/.local/bin
sudo chown -R zentrale:zentrale /opt/zentrale/.local
curl -fsSLo /tmp/pass-cli-install.sh https://proton.me/download/pass-cli/install.sh
sha256sum /tmp/pass-cli-install.sh        # compare with the vendor's published value
less /tmp/pass-cli-install.sh             # read it: where does it install, what does it fetch
sudo -u zentrale env HOME=/opt/zentrale bash /tmp/pass-cli-install.sh
sudo -u zentrale env HOME=/opt/zentrale /opt/zentrale/.local/bin/pass-cli --version
```

If your distribution ships a package, or you have a package manager that
verifies signatures, prefer that and link the binary to
`/opt/zentrale/.local/bin/pass-cli`. The expected checksum is deliberately not
in this repository — a stale value is worse than none.

Log in once by hand to verify (the broker does this itself afterwards):

```
sudo -u zentrale env HOME=/opt/zentrale \
  PROTON_PASS_PERSONAL_ACCESS_TOKEN="$(sudo sed -n 's/^PROTON_PAT=//p' /opt/zentrale/proton.env)" \
  /opt/zentrale/.local/bin/pass-cli login
sudo -u zentrale env HOME=/opt/zentrale /opt/zentrale/.local/bin/pass-cli vault list
```

Two notes:

- The CLI is not part of every plan; with Proton Pass it requires a paid one.
- Reading an item requires an **access reason** when using agent tokens. The
  broker sets `PROTON_PASS_AGENT_REASON` to the credential name plus the reason
  from the request, stripped of control characters and cut to 150 characters.
  Whether and how the vendor records that reason is up to the vendor, not to
  the broker.

Without the CLI the broker still starts, but **every** access fails with "no
password stored for this credential". The actual cause is in the log.

## 3. Broker: services and isolation

```
sudo cp setup/zentrale.service setup/zentrale-browser.service /etc/systemd/system/
sudo install -m 755 -o root setup/browser-start.sh /opt/browser/start.sh
sudo cp setup/50-zentrale-browser.rules /etc/polkit-1/rules.d/
sudo cp setup/apparmor-zentrale-chrome /etc/apparmor.d/zentrale-chrome
sudo apparmor_parser -r /etc/apparmor.d/zentrale-chrome
sudo systemctl daemon-reload && sudo systemctl enable --now zentrale.service
```

Browser policy — **the directory decides.** With Chrome for Testing only this
path takes effect; copies under `/etc/opt/chrome/…` or `/etc/chromium/…` do
nothing:

```
sudo mkdir -p /etc/opt/chrome_for_testing/policies/managed
sudo cp setup/chrome-policy.json /etc/opt/chrome_for_testing/policies/managed/zentrale.json
```

Verify: open `file:///etc/hostname` in the running browser; it must come back
with `ERR_BLOCKED_BY_ADMINISTRATOR`. The broker performs this check itself
before **every** session and refuses otherwise.

**If the check fails, the path is wrong for this Chromium build** — not the
policy. Which directory applies depends on the build; candidates are
`/etc/opt/chrome_for_testing/policies/managed/`,
`/etc/opt/chrome/policies/managed/` and `/etc/chromium/policies/managed/`.
Putting the file in all three does no harm. Without an effective block there is
no session, and that is intended.

## 4. Network

Set up the VPN so that it does not bypass the firewall. Tailscale otherwise
inserts its own chain ahead of your rules:

```
sudo tailscale up --netfilter-mode=off
# 41641/udp is where Tailscale accepts direct connections. It is open to every
# source; Tailscale only answers valid WireGuard handshakes. Without it traffic
# goes through relays and gets slower.
sudo ufw allow 41641/udp
# <agent-host> is the agent host's VPN address, not its LAN address.
# With Tailscale: the 100.x.x.x from `tailscale status`.
sudo ufw allow from <agent-host> to any port 8765 proto tcp
sudo ufw allow from <agent-host> to any port 9223 proto tcp
sudo ufw enable
```

Then verify from a third device that 8765 and 9223 are closed there.

If the machine is a laptop: closing the lid must not suspend it
(`HandleLidSwitch=ignore`), and sleep targets should be masked.

## 5. Agent host

```
install -m 755 agent/zentrale ~/.local/bin/zentrale
install -m 755 agent/zentrale-weiterleitung.py ~/.local/bin/
mkdir -p ~/.config/zentrale && chmod 700 ~/.config/zentrale
printf 'http://<broker>:8765\n' > ~/.config/zentrale/adresse
printf '<broker>:9223\n'        > ~/.config/zentrale/relay
printf '<token>\n'              > ~/.config/zentrale/token
chmod 600 ~/.config/zentrale/*
```

The forwarder as a user service, template included:

```
mkdir -p ~/.config/systemd/user
cp setup/zentrale-weiterleitung.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now zentrale-weiterleitung.service
loginctl enable-linger $USER
ss -ltnp | grep 19223          # must listen on 127.0.0.1:19223
```

The agent's browser profile and skill file: see `examples/config-agent.md` and
`agent/SKILL.md`.

## 6. Verification

```
zentrale status
zentrale browser <credential> "test"
# confirm the push, then work with profile="zentrale"
zentrale ende
```

If the login fails, the broker leaves `fehler-<credential>.txt` with the page
state. That is the fastest route to the cause.

## Security when installing a new version

Without arguments, `zentrale-update` takes the newest `zentrale-v*.py` from
`~/zentrale-neu/` or `~/Downloads/`. Anyone who can write to those directories —
a browser download, for instance — can put code on the machine that holds the
credentials. The script only checks that the file is valid Python and contains
`browser_anmelden`.

So:

- For files from the network, pass the checksum:
  `zentrale-update --pruefsumme <sha256>`. No match, no installation.
- Better: use your own git repository as the source and `zentrale-update --git`.
  The script then shows what changed before installing.
- Do not automate the installation. One command by hand is the point.
