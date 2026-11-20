# Files on the agent host

`~/.config/zentrale/` (mode 600):

| File | Contents |
|---|---|
| `adresse` | `http://<broker>:8765` |
| `token` | shared secret, at least 32 characters |
| `relay` | `<broker>:9223` (the forwarder's target) |

The agent's browser profile:

```
cdpUrl:     http://anything:<token>@127.0.0.1:19223
attachOnly: true
```

The part before the colon is the basic-auth username and can be anything; only
the token is checked. Alternatively append `?token=<token>` to the address.
`127.0.0.1:19223` is the local forwarder, not the broker.

Do not make this the default profile. The forwarder runs as a user service so
that the agent framework needs no SSRF exception for a VPN address.
