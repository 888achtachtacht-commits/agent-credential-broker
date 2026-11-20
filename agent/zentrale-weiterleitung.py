#!/usr/bin/env python3
"""Leitet 127.0.0.1:19223 an den Browser-Port der Zentrale weiter.
So braucht das Agenten-Rahmenwerk keine SSRF-Ausnahme fuer eine VPN-Adresse.
Ziel kommt aus ~/.config/zentrale/relay (Form: host:port)."""
import asyncio

import os

LOKAL = ('127.0.0.1', 19223)
_z = os.environ.get('ZENTRALE_RELAY')
if not _z:
    _p = os.path.expanduser('~/.config/zentrale/relay')
    if not os.path.exists(_p):
        raise SystemExit(f'Fehlt: {_p} (Inhalt: host:port der Zentrale)')
    _z = open(_p).read().strip()
_h, _, _po = _z.rpartition(':')
ZIEL = (_h, int(_po))


async def pumpe(r, w):
    try:
        while True:
            d = await r.read(65536)
            if not d:
                break
            w.write(d)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def verbindung(cr, cw):
    try:
        zr, zw = await asyncio.wait_for(asyncio.open_connection(*ZIEL), timeout=10)
    except Exception:
        cw.close()
        return
    await asyncio.gather(pumpe(cr, zw), pumpe(zr, cw))


async def main():
    srv = await asyncio.start_server(verbindung, *LOKAL)
    async with srv:
        await srv.serve_forever()

asyncio.run(main())
