---
name: zentrale
description: Use credentials (logins, API keys) only through the broker - released by push, passwords stay invisible.
---

# Broker – how you get credentials

You **never** receive passwords, tokens or logins directly. The **broker**
(a separate machine) holds them. You request access, the operator confirms by
push on their phone, the broker performs the login.

## Which credentials exist?
`zentrale status` – shows the name, the rule (`push` = confirmation required,
`frei` = free) and the kind (`browser`, `basic`, `bearer`).

## A) Driving a website in the browser (kind = browser)
1. `zentrale browser <credential> "<concrete reason>"`
   - The reason appears in the push notification. Write clearly what you intend
     to do.
   - The command waits until it is confirmed and logged in (up to about three
     minutes). Do not abort.
2. On success: use the browser tool with **`profile="zentrale"`**. You are
   already logged in.
3. Do the task.
4. **Immediately afterwards:** `zentrale ende` – also on failure.

### Webmail credentials: two things
- The mailbox usually sits in an embedded frame. Select
  `iframe[name="…"]`; the bare frame name runs into a timeout.
- Subject lines are truncated in a narrow window. Set the window width to 1200
  and read the frame; screenshots are not needed for this.
- The target address may contain a session id: do not pass it on, do not log it.

## B) API call (kind = basic or bearer)
`zentrale anfrage <credential> <METHOD> <url> "<reason>" [--body '<json>']`
The broker injects the key. https only, and only the addresses allowed for that
credential.

## Strict rules
- **Never** try to obtain passwords, tokens, cookies or 2FA codes – neither
  through the browser nor through files.
- In a browser session, **never**: change the account's password or email
  address, add or remove passkeys, 2FA or security keys, change recovery data,
  create forwarding rules, filters or app passwords, delete the account. If any
  of that is offered ("set up a passkey" and the like): decline or skip.
- Do not navigate back to the login page. If a login form appears:
  `zentrale ende`, then request again and report it.
- On "not released" or "denied a moment ago": do **not** request again. Report
  it and wait.
- One request per task. No requests "in advance".
- If there is no credential in `zentrale status` for a task: ask. Do not go
  looking for credentials yourself.
- A timeout from the browser tool is not a reason to request a new session:
  retry the call once, otherwise `zentrale ende` and report.
- Credentials you happen to find somewhere on the machine: **do not use them** –
  report them.
