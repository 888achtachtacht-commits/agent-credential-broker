#!/usr/bin/env python3
"""Zentrale: Agenten nutzen Zugaenge, ohne die Passwoerter je zu sehen.

- POST /anfrage  : API-Aufruf, die Zentrale setzt den Schluessel ein (nur https, Port 443, keine internen Ziele)
- POST /browser  : Browser-Sitzung; die Zentrale meldet sich selbst an, erst danach darf der Agent den Browser steuern
- POST /browser/ende, GET /status
Sensible Zugaenge brauchen eine Duo-Push-Freigabe. Passwoerter kommen aus Proton Pass.
"""
import base64
import hmac
import html
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import duo_client

BASE = '/opt/zentrale'
PORT = 8765
SPERRE_NACH_NEIN = 10 * 60      # nach einem Nein 10 Minuten keine neue Anfrage fuer diesen Zugang
ALLE_METHODEN = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
# Diese Angabe liest auch zentrale-update aus der Datei und vergleicht sie mit
# dem Protokoll. Bei jeder Veroeffentlichung erhoehen.
FASSUNG = 'v1.0'
CDP_INTERN = ('127.0.0.1', 9222)      # Chromium (User browser) lauscht nur lokal
RELAY_BIND = '0.0.0.0'                 # auf die VPN-Adresse setzen, wenn gewuenscht
RELAY_PORT = 9223                      # nur waehrend einer Sitzung offen, nur fuer den Agentenhost (Firewall)
BROWSER_START = ['systemctl', 'start', 'zentrale-browser.service']
BROWSER_STOP = ['systemctl', 'stop', 'zentrale-browser.service']
PRUEFE_DATEISPERRE = True              # Browser muss file:// blockieren, sonst keine Sitzung
# Dienste, die Anfragen 1:1 zurueckspiegeln -> nie als Ziel erlaubt (wuerden Schluessel zurueckgeben)
SPIEGEL_DIENSTE = ('httpbin.org', 'httpbingo.org', 'postman-echo.com', 'webhook.site', 'requestbin',
                   'pipedream', 'beeceptor', 'mockbin.org', 'mocky.io', 'reqbin.com',
                   'requestcatcher.com', 'ngrok.io', 'ngrok-free.app', 'ngrok.app',
                   'localtunnel.me', 'loca.lt', 'serveo.net', 'trycloudflare.com', 'surge.sh')


def lade_env(pfad):
    env = {}
    with open(pfad) as f:
        for zeile in f:
            zeile = zeile.strip()
            if '=' in zeile and not zeile.startswith('#'):
                k, v = zeile.split('=', 1)
                env[k.strip()] = v.strip()
    return env


def lade_json(name):
    with open(f'{BASE}/{name}') as f:
        return json.load(f)


DUO = lade_env(f'{BASE}/duo.env')
_NTFY = lade_env(f'{BASE}/ntfy.env') if os.path.exists(f'{BASE}/ntfy.env') else {}
NTFY_TOPIC = _NTFY.get('NTFY_TOPIC', '')
NTFY_URL = (_NTFY.get('NTFY_URL') or 'https://ntfy.sh').rstrip('/')
with open(f'{BASE}/client.token') as f:
    CLIENT_TOKEN = f.read().strip()
if len(CLIENT_TOKEN) < 32:
    raise SystemExit('client.token fehlt oder ist zu kurz (mind. 32 Zeichen) - Zentrale startet nicht')
duo = duo_client.Auth(ikey=DUO['DUO_IKEY'], skey=DUO['DUO_SKEY'], host=DUO['DUO_HOST'])

PASS_CLI = f'{BASE}/.local/bin/pass-cli'
PROTON = lade_env(f'{BASE}/proton.env')
proton_lock = threading.Lock()
log_lock = threading.Lock()      # Umbenennung darf sich nicht mit Schreibern kreuzen

# Gemeinsamer Zustand, geschuetzt durch EINE Sperre (verhindert Zeitfenster-Fehler)
lock = threading.RLock()
freigaben = {}    # zugang -> Zeitpunkt, bis zu dem die Freigabe gilt
gesperrt = {}     # zugang -> Zeitpunkt, bis zu dem nach einem Nein gesperrt ist
laufend = set()   # Zugaenge, fuer die gerade ein Push offen ist
sitzung = {'status': 'frei', 'id': 0, 'zugang': None, 'bis': 0, 'timer': None, 'verbindungen': []}
# status: frei | startet | aktiv | stoppt


def log(text):
    text = str(text).replace('\r', ' ').replace('\n', ' ')
    with log_lock:                        # nicht unbegrenzt wachsen lassen
        try:
            if os.path.getsize(f'{BASE}/protokoll.log') > 5_000_000:
                os.replace(f'{BASE}/protokoll.log', f'{BASE}/protokoll.log.1')
        except OSError:
            pass
        with open(f'{BASE}/protokoll.log', 'a') as f:
            f.write(time.strftime('%Y-%m-%d %H:%M:%S ') + text + '\n')


def ntfy(titel, text, prio='high'):
    if not NTFY_TOPIC:          # ntfy ist aus (keine ntfy.env) -> nur Duo
        return
    try:
        req = urllib.request.Request(
            f'{NTFY_URL}/{NTFY_TOPIC}', data=text.encode('utf-8'),
            headers={'Title': titel, 'Priority': prio})
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        log(f'ntfy-Fehler: {e}')


def frage_mensch(zugang, grund, aktion):
    """Duo-Push (plus ntfy, falls an). True nur bei ausdruecklichem Ja."""
    ntfy('Zentrale: Freigabe noetig',
         f'Zugang: {zugang}\nGrund: {grund}\nAktion: {aktion}\n\nBitte in Duo bestaetigen.')
    info = urllib.parse.urlencode({
        'Zugang': zugang, 'Grund': grund[:150], 'Aktion': aktion[:150]})
    try:
        r = duo.auth(factor='push', username=DUO['DUO_USER'], device='auto',
                     type='Zentrale', pushinfo=info)
        return r.get('result') == 'allow'
    except Exception as e:
        log(f'Duo-Fehler: {e}')
        return False


# ---------------- Proton Pass ----------------
def sauber(text, laenge=200):
    """Steuerzeichen raus, Laenge begrenzen - fuer alles, was nach aussen geht."""
    return re.sub(r'[\x00-\x1f\x7f]', ' ', str(text or '')).strip()[:laenge]


def pass_cli(*args, mit_token=False, grund=None):
    env = dict(os.environ, HOME=BASE)
    # Agent-Tokens verlangen fuer 'item view' einen Zugriffsgrund; er landet im
    # Pruefprotokoll des Passwortmanagers.
    env['PROTON_PASS_AGENT_REASON'] = sauber(grund) or 'Freigegebene Sitzung der Zentrale'
    if mit_token:
        env['PROTON_PASS_PERSONAL_ACCESS_TOKEN'] = PROTON['PROTON_PAT']
    return subprocess.run([PASS_CLI, *args], capture_output=True, text=True, timeout=60, env=env)


def proton_eintrag(titel, grund=None):
    """Login-Eintrag aus dem Tresor (username, email, password, totp_uri). Titel-Leerzeichen egal."""
    tresor = PROTON.get('PROTON_TRESOR', 'Zentrale')
    with proton_lock:
        r = pass_cli('item', 'list', '--vault-name', tresor)
        if r.returncode != 0:
            pass_cli('login', mit_token=True)
            r = pass_cli('item', 'list', '--vault-name', tresor)
        if r.returncode != 0:
            log(f'PROTON-FEHLER Liste: {r.stderr.strip()[:200]}')
            return {}
        item_id = None
        for zeile in r.stdout.splitlines():
            m = re.match(r'^- \[(.+?)\]: (.*) \(state=', zeile)
            if m and m.group(2).strip() == titel.strip():
                item_id = m.group(1)
                break
        if not item_id:
            log(f'PROTON: Eintrag "{titel}" nicht gefunden')
            return {}
        r = pass_cli('item', 'view', '--vault-name', tresor, '--item-id', item_id,
                     '--output', 'json', grund=grund)
    if r.returncode != 0:
        log(f'PROTON-FEHLER {titel}: {r.stderr.strip()[:200]}')
        return {}
    try:
        return json.loads(r.stdout)['item']['content']['content'].get('Login', {}) or {}
    except Exception as e:
        log(f'PROTON: Eintrag "{titel}" ist kein Login-Eintrag ({e})')
        return {}


def hole_geheim(zugang, z, grund=None):
    """Nur aus dem Passwortmanager. Eintragstitel = Zugangsname (oder proton_titel).
    grund wird als Zugriffsgrund an den Passwortmanager weitergegeben."""
    zweck = f'Zugang {zugang}: {sauber(grund, 150)}' if grund else f'Zugang {zugang}'
    e = proton_eintrag(z.get('proton_titel', zugang), grund=zweck)
    if z.get('art') == 'bearer':
        return {'token': e.get('password', ''), 'totp_uri': e.get('totp_uri', '')}
    return {'benutzer': e.get('username') or e.get('email') or '', 'passwort': e.get('password', ''),
            'totp_uri': e.get('totp_uri', '')}


def schwaerzen(text, geheim, auch_benutzer=False):
    """Entfernt Passwort/Token/2FA-Schluessel in allen ueblichen Schreibweisen aus einem Text.
    auch_benutzer: bei API-Zugaengen zusaetzlich den Benutzernamen (v14)."""
    felder = ('passwort', 'token', 'totp_uri', 'benutzer') if auch_benutzer else ('passwort', 'token', 'totp_uri')
    roh = [geheim.get(k) for k in felder]
    roh = [w for w in roh if isinstance(w, str) and w]
    varianten = set()
    for w in roh:
        varianten |= {w, urllib.parse.quote(w, safe=''), urllib.parse.quote_plus(w),
                      json.dumps(w)[1:-1], html.escape(w), html.escape(w, quote=False),
                      base64.b64encode(w.encode()).decode().rstrip('=')}
    if geheim.get('benutzer') and geheim.get('passwort'):
        paar = f"{geheim['benutzer']}:{geheim['passwort']}".encode()
        varianten.add(base64.b64encode(paar).decode().rstrip('='))
        varianten.add(base64.urlsafe_b64encode(paar).decode().rstrip('='))
    for v in sorted(varianten, key=len, reverse=True):
        if len(v) >= 6:
            text = text.replace(v, '***')
    return text


# ---------------- Regeln & Freigabe ----------------
def freigabe(zugang, z, grund, aktion):
    """None wenn ok, sonst (code, fehler). Unbekannte Regel = gesperrt."""
    regel = z.get('regel')
    if regel == 'frei':
        return None
    if regel != 'push':
        log(f'GESPERRT {zugang} (Regel "{regel}")')
        return 403, 'Dieser Zugang ist gesperrt'
    jetzt = time.time()
    with lock:
        if freigaben.get(zugang, 0) > jetzt:
            return None
        if gesperrt.get(zugang, 0) > jetzt:
            return 429, 'Kurz zuvor abgelehnt. Bitte spaeter erneut fragen.'
        if zugang in laufend:
            return 409, 'Es wartet schon eine Freigabe fuer diesen Zugang'
        laufend.add(zugang)
    try:
        ja = frage_mensch(zugang, grund, aktion)
    finally:
        with lock:
            laufend.discard(zugang)
    if not ja:
        with lock:
            gesperrt[zugang] = time.time() + SPERRE_NACH_NEIN
        log(f'NEIN {zugang} ({grund})')
        return 403, 'Nicht freigegeben'
    stunden = float(z.get('gueltig_stunden', 1))
    with lock:
        freigaben[zugang] = time.time() + stunden * 3600
    log(f'JA {zugang} fuer {stunden} h ({grund})')
    return None


# ---------------- Netz-Pruefungen ----------------
def basis_domain(host):
    teile = (host or '').lower().strip('.').split('.')
    return '.'.join(teile[-2:]) if len(teile) >= 2 else (host or '').lower()


def host_passt(host, erlaubte):
    host = (host or '').lower().strip('.')
    for e in erlaubte:
        e = e.lower().strip('.')
        if host == e or host.endswith('.' + e):
            return True
    return False


def ist_spiegeldienst(host):
    host = (host or '').lower()
    return any(s in host for s in SPIEGEL_DIENSTE)


# unabhaengig von der Python-Fassung sperren
ZUSATZ_BLOCK = [ipaddress.ip_network(x) for x in (
    '100.64.0.0/10',          # CGNAT, darin auch Tailscale v4
    'fd7a:115c:a1e0::/48',    # Tailscale v6
    '198.18.0.0/15',          # Benchmarking
)]


def oeffentliche_ip(host, port):
    """Loest den Namen auf. Gibt eine IP zurueck, wenn ALLE Adressen oeffentlich sind, sonst None."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        return None
    ips = [i[4][0] for i in infos]
    if not ips:
        return None
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip.split('%')[0])
        except ValueError:
            return None
        if not a.is_global or any(a in netz for netz in ZUSATZ_BLOCK if netz.version == a.version):
            return None
    return ips[0]


class FesteIPVerbindung(http.client.HTTPSConnection):
    """HTTPS zu einer vorab geprueften IP (gegen DNS-Rebinding), Zertifikat wird fuer den Hostnamen geprueft."""
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._ziel_ip = ip

    def connect(self):
        sock = socket.create_connection((self._ziel_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


# ---------------- Browser-Baustein ----------------
USER_SEL = ('input[autocomplete="username"], input[type="email"], input[name*="user" i], '
            'input[name*="login" i], input[id*="user" i], input[name*="mail" i], input[id*="mail" i]')
PASS_SEL = 'input[type="password"]'
# erlaubte Zeichen fuer Header-Namen nach RFC 7230 (Token)
HDR_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def pruefe_header(name, wert):
    """Wehrt Header-Injection und Steuerzeichen ab. Python prueft selbst mit,
    hier kommt eine klare Fehlermeldung statt eines 500ers heraus."""
    name, wert = str(name), str(wert)
    if not HDR_NAME.match(name) or len(name) > 100:
        raise ValueError(f'Unerlaubter Header-Name: {name[:40]!r}')
    if any(c in wert for c in '\r\n\0') or len(wert) > 4000:
        raise ValueError(f'Unerlaubter Header-Wert fuer {name[:40]!r}')
    try:                       # http.client kodiert Header als latin-1
        wert.encode('latin-1')
    except UnicodeEncodeError:
        raise ValueError(f'Header-Wert fuer {name[:40]!r} enthaelt Zeichen, die in einem Header nicht zulaessig sind')
    return name, wert
LOGIN_KNOEPFE = ['Login', 'Einloggen', 'Anmelden', 'Log in', 'Sign in']
ZWISCHENSEITEN_KNOEPFE = ['Nein danke', 'Später', 'Jetzt nicht', 'Überspringen', 'Not now', 'Skip', 'Maybe later']
COOKIE_KNOEPFE = ['Alle akzeptieren', 'Akzeptieren und weiter', 'Zustimmen und weiter', 'Alle zulassen',
                  'Zustimmen', 'Akzeptieren', 'Einverstanden', 'Accept all', 'Accept', 'I agree']


# bei diesen Endungen waere basis_domain zu weit (co.uk hiesse: alle *.co.uk)
MEHRTEILIGE_ENDUNGEN = frozenset((
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'plc.uk', 'sch.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'net.nz', 'org.nz',
    'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp', 'co.kr', 'or.kr',
    'co.za', 'org.za', 'com.br', 'net.br', 'org.br', 'gov.br',
    'com.mx', 'com.ar', 'com.tr', 'com.cn', 'net.cn', 'org.cn', 'gov.cn',
    'co.in', 'net.in', 'org.in', 'com.sg', 'com.hk', 'com.tw', 'com.pl',
    'co.il', 'com.ua', 'co.id', 'com.my', 'com.ph', 'com.vn', 'co.th',
))


# allgemeine Regel, damit auch unbekannte Landesendungen erkannt werden
ZWEITE_EBENE = frozenset((
    'co', 'com', 'org', 'net', 'ac', 'gov', 'edu', 'mil', 'gob', 'gouv', 'go', 'ne', 'or',
    'sch', 'plc', 'me', 'nom', 'asn', 'priv', 'web', 'info', 'biz', 'firm', 'gen', 'ind',
))


def ist_mehrteilige_endung(basis):
    """co.uk, com.au, co.za ... : zwei Teile, Landeskennung mit zwei Buchstaben,
    davor eine der ueblichen Zweit-Ebenen. Deckt auch Endungen ab, die nicht in der Liste stehen."""
    teile = basis.split('.')
    if len(teile) != 2:
        return False
    vorn, endung = teile
    return len(endung) == 2 and endung.isalpha() and vorn in ZWEITE_EBENE


def login_hosts(z):
    if z.get('login_hosts'):
        return z['login_hosts']
    host = (urllib.parse.urlsplit(z.get('login_url') or '').hostname or '').lower().strip('.')
    basis = basis_domain(host)
    if basis in MEHRTEILIGE_ENDUNGEN or ist_mehrteilige_endung(basis) or '.' not in basis:
        return None          # zu unspezifisch - der Aufrufer lehnt ab
    return [basis]


def url_erlaubt(url, erlaubte):
    u = urllib.parse.urlsplit(url or '')
    return u.scheme == 'https' and host_passt(u.hostname, erlaubte)


def _finde(page, selektor, erlaubte):
    """Sichtbares Feld - nur in Seiten/Rahmen der erlaubten Domain."""
    for frame in page.frames:
        if not url_erlaubt(frame.url, erlaubte):
            continue
        try:
            loc = frame.locator(selektor)
            for i in range(min(loc.count(), 10)):
                el = loc.nth(i)
                if el.is_visible():
                    return el
        except Exception:
            pass
    return None


def _klick_text(page, texte, rollen, erlaubte=None):
    for frame in page.frames:
        if erlaubte is not None and not url_erlaubt(frame.url, erlaubte):
            continue
        for text in texte:
            for rolle in rollen:
                try:
                    el = frame.get_by_role(rolle, name=text, exact=True)
                    for i in range(min(el.count(), 5)):
                        if el.nth(i).is_visible():
                            el.nth(i).click(timeout=5000)
                            return True
                except Exception:
                    pass
    return False


def _cookies_wegklicken(page):
    if _klick_text(page, COOKIE_KNOEPFE, ('button',)):
        page.wait_for_timeout(1500)


def _passwortfelder_leeren(page):
    for frame in page.frames:
        try:
            loc = frame.locator(PASS_SEL)
            for i in range(min(loc.count(), 10)):
                loc.nth(i).fill('')
        except Exception:
            pass


def _foto(page, zugang):
    try:
        _passwortfelder_leeren(page)
        page.screenshot(path=f'{BASE}/fehler-{zugang}.png')
        os.chmod(f'{BASE}/fehler-{zugang}.png', 0o600)
    except Exception:
        pass
    # zusaetzlich Textbefund, Bildschirmfotos bleiben headless oft leer
    try:
        teile = urllib.parse.urlsplit(page.url)
        zeilen = [f'Adresse: {teile.hostname}{teile.path}', f'Titel: {page.title()}', '', 'Rahmen (frames):']
        for fr in page.frames:
            ft = urllib.parse.urlsplit(fr.url)
            zeilen.append(f'  {ft.hostname}{ft.path}')
        zeilen += ['', 'Sichtbare Eingabefelder:']
        for fr in page.frames:
            try:
                for el in fr.locator('input, button').all()[:40]:
                    try:
                        if el.is_visible():
                            zeilen.append('  ' + json.dumps({
                                'tag': el.evaluate('e => e.tagName'),
                                'type': el.get_attribute('type'), 'name': el.get_attribute('name'),
                                'id': el.get_attribute('id'),
                                'text': (el.inner_text() or '')[:40] if el.evaluate('e => e.tagName') == 'BUTTON' else ''},
                                ensure_ascii=False))
                    except Exception:
                        pass
            except Exception:
                pass
        zeilen += ['', 'Sichtbarer Text:']
        for fr in page.frames:
            try:
                zeilen.append(fr.locator('body').inner_text(timeout=3000)[:1500])
            except Exception:
                pass
        pfad = f'{BASE}/fehler-{zugang}.txt'
        with open(pfad, 'w') as f:
            f.write('\n'.join(zeilen))
        os.chmod(pfad, 0o600)   # kann Kontonamen und Seitentext enthalten
    except Exception as e:
        log(f'BROWSER {zugang}: Textbefund fehlgeschlagen ({str(e)[:80]})')


def _dateisperre_ok(ctx):
    """Prueft, ob der Browser lokale Dateien blockiert (Richtlinie wirksam)."""
    p = None
    try:
        p = ctx.new_page()
        p.goto('file:///etc/hostname', timeout=10000)
        return False
    except Exception as e:
        return 'BLOCKED_BY_ADMINISTRATOR' in str(e)
    finally:
        try:
            if p is not None:
                p.close()
        except Exception:
            pass


def browser_anmelden(zugang, z, grund=None):
    """Meldet sich im laufenden Chromium selbst an. Passwort nur in Seiten der erlaubten Domain."""
    from playwright.sync_api import sync_playwright
    erlaubte = login_hosts(z)
    if not erlaubte:
        return False, 'Fuer diese Domain muss login_hosts in zugaenge.json gesetzt werden (mehrteilige Endung wie co.uk)'
    if not url_erlaubt(z.get('login_url'), erlaubte):
        return False, 'login_url muss https sein und zur erlaubten Domain gehoeren'
    g = hole_geheim(zugang, z, grund)
    benutzer, passwort = g.get('benutzer'), g.get('passwort')
    if not (benutzer and passwort):
        return False, 'Fuer diesen Zugang ist kein Passwort hinterlegt (Proton-Eintrag pruefen)'
    with sync_playwright() as p:
        b = p.chromium.connect_over_cdp(f'http://{CDP_INTERN[0]}:{CDP_INTERN[1]}')
        ctx = b.contexts[0] if b.contexts else b.new_context()
        if PRUEFE_DATEISPERRE and not _dateisperre_ok(ctx):
            log('BROWSER: Sperre fuer lokale Dateien NICHT wirksam - Sitzung abgebrochen')
            return False, 'Sicherheitspruefung fehlgeschlagen: Browser sperrt lokale Dateien nicht'
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        try:
            page.goto(z['login_url'], wait_until='domcontentloaded', timeout=45000)
            page.wait_for_timeout(2500)
            _cookies_wegklicken(page)
            fertig = False
            login_geklickt = False
            for _ in range(5):
                if ctx.pages and ctx.pages[-1] is not page:
                    page = ctx.pages[-1]          # Login hat neues Fenster/Tab geoeffnet
                    page.wait_for_timeout(2500)
                    _cookies_wegklicken(page)
                if not url_erlaubt(page.url, erlaubte):
                    _foto(page, zugang)
                    return False, f'Seite gehoert nicht zur erlaubten Domain ({urllib.parse.urlsplit(page.url).hostname}) - abgebrochen'
                feld_u = _finde(page, z.get('feld_benutzer', USER_SEL), erlaubte)
                feld_p = _finde(page, z.get('feld_passwort', PASS_SEL), erlaubte)
                if feld_p:
                    if feld_u and not feld_u.input_value():
                        feld_u.fill(benutzer)
                    feld_p.fill(passwort)
                    url_vor_login = page.url
                    log(f'BROWSER {zugang}: Passwort eingegeben auf {urllib.parse.urlsplit(page.url).hostname}{urllib.parse.urlsplit(page.url).path}')
                    feld_p.press('Enter')
                    fertig = True
                    break
                if feld_u:
                    log(f'BROWSER {zugang}: Benutzername eingegeben auf {urllib.parse.urlsplit(page.url).hostname}{urllib.parse.urlsplit(page.url).path}')
                    feld_u.fill(benutzer)
                    feld_u.press('Enter')
                    page.wait_for_timeout(3000)
                    _cookies_wegklicken(page)
                    continue
                if not login_geklickt and _klick_text(page, [z['login_klick']] if z.get('login_klick') else LOGIN_KNOEPFE,
                                                      ('button', 'link'), erlaubte):
                    login_geklickt = True
                    page.wait_for_timeout(4000)
                    _cookies_wegklicken(page)
                    continue
                page.wait_for_timeout(2000)
                _cookies_wegklicken(page)
            if not fertig:
                _foto(page, zugang)
                return False, 'Login-Formular nicht gefunden (Bildschirmfoto auf der Zentrale)'
            # Erfolg erst, wenn die Seite die Anmelde-Adresse verlassen hat
            # ("kein Passwortfeld sichtbar" allein ist kein Erfolg: Interstitials).
            login_host = (urllib.parse.urlsplit(url_vor_login).hostname or '').lower()
            login_pfad = urllib.parse.urlsplit(url_vor_login).path
            erfolg_teil = z.get('erfolg_url_enthaelt')
            angekommen = False
            zwischen_klicks = 0
            for _ in range(30):                       # bis zu ~30 Sekunden
                page.wait_for_timeout(1000)
                if ctx.pages and ctx.pages[-1] is not page:
                    page = ctx.pages[-1]
                # Zwischenseiten (z.B. "Passkey jetzt einrichten") stehen unter derselben
                # Adresse wie der Login. Deshalb hier wegklicken, nicht erst nach der Pruefung.
                if zwischen_klicks < 3 and _klick_text(page, ZWISCHENSEITEN_KNOEPFE, ('button', 'link'), erlaubte):
                    zwischen_klicks += 1
                    log(f'BROWSER {zugang}: Zwischenseite weggeklickt')
                    page.wait_for_timeout(2000)
                teile = urllib.parse.urlsplit(page.url)
                if erfolg_teil:
                    if erfolg_teil in page.url:
                        angekommen = True
                elif (teile.hostname or '').lower() != login_host or teile.path != login_pfad:
                    if 'login' not in (teile.hostname or '') and 'login' not in teile.path.lower():
                        angekommen = True
                if angekommen:
                    page.wait_for_timeout(3000)   # Weiterleitungen auslaufen lassen
                    break
            if not angekommen or _finde(page, PASS_SEL, erlaubte):
                _foto(page, zugang)
                log(f'BROWSER {zugang}: Anmeldung nicht bestaetigt, Seite blieb bei {urllib.parse.urlsplit(page.url).hostname}{urllib.parse.urlsplit(page.url).path}')
                return False, 'Anmeldung nicht bestaetigt - Seite hat die Anmeldung nicht verlassen (Bildschirmfoto auf der Zentrale)'
            # Nach dem Login: frischer Tab ohne Verlauf, Login-Tabs schliessen
            # (sonst koennte "Zurueck" die Login-Seite samt eingetipptem Passwort aus dem Zwischenspeicher holen)
            ziel_url = page.url
            frisch = ctx.new_page()
            try:
                if url_erlaubt(ziel_url, erlaubte):
                    frisch.goto(ziel_url, wait_until='domcontentloaded', timeout=45000)
                    frisch.wait_for_timeout(3000)
                    for _ in range(2):
                        if _klick_text(frisch, ZWISCHENSEITEN_KNOEPFE, ('button', 'link'), erlaubte):
                            frisch.wait_for_timeout(3000)
            except Exception as e:
                log(f'BROWSER: frischer Tab konnte Zielseite nicht laden ({str(e)[:80]})')
            for alt_seite in list(ctx.pages):
                if alt_seite is not frisch:
                    try:
                        _passwortfelder_leeren(alt_seite)
                        alt_seite.close()
                    except Exception:
                        pass
            # kein Erfolg mit about:blank oder fremder Domain
            if not url_erlaubt(frisch.url, erlaubte):
                log(f'BROWSER {zugang}: Zielseite nach der Anmeldung nicht erlaubt ({urllib.parse.urlsplit(frisch.url).hostname})')
                return False, ('Zielseite nach der Anmeldung liegt nicht in den erlaubten Domains - '
                               'bitte login_hosts in zugaenge.json ergaenzen')
            return True, schwaerzen(frisch.url, g)
        except Exception as e:
            _foto(page, zugang)
            return False, f'Fehler bei der Anmeldung: {schwaerzen(str(e), g)[:200]}'


def _browser_stoppen():
    try:
        subprocess.run(BROWSER_STOP, capture_output=True, timeout=60)
    except Exception as e:
        log(f'BROWSER STOP FEHLER: {e}')


def browser_beenden(grund='Zeit abgelaufen', sitzungs_id=None):
    with lock:
        if sitzungs_id is not None and sitzungs_id != sitzung['id']:
            return                      # alter Timer einer frueheren Sitzung
        if sitzung['status'] != 'aktiv':
            return
        zugang = sitzung['zugang']
        sitzung['status'] = 'stoppt'
        if sitzung['timer']:
            sitzung['timer'].cancel()
        for s in sitzung['verbindungen']:
            try:
                s.close()
            except Exception:
                pass
        sitzung['verbindungen'] = []
        freigaben.pop(zugang, None)     # Freigabe ist mit der Sitzung verbraucht
    _browser_stoppen()
    with lock:
        sitzung.update({'status': 'frei', 'zugang': None, 'bis': 0, 'timer': None})
    log(f'BROWSER ENDE {zugang} ({grund})')
    ntfy('Zentrale: Browser beendet', f'Sitzung fuer {zugang} beendet ({grund}).', prio='default')


def browser_sitzung(zugang, z, grund):
    with lock:
        if sitzung['status'] == 'aktiv' and sitzung['zugang'] == zugang and sitzung['bis'] > time.time():
            return 200, {'status': 'laeuft bereits', 'bis': time.strftime('%d.%m. %H:%M', time.localtime(sitzung['bis']))}
        if sitzung['status'] != 'frei':
            return 409, {'fehler': f'Browser ist belegt ({sitzung["status"]}, {sitzung["zugang"]})'}
        sitzung['status'] = 'startet'
        sitzung['zugang'] = zugang
        sitzung['id'] += 1
        meine_id = sitzung['id']
    erfolg = False
    try:
        fehler = freigabe(zugang, z, grund, f'Browser-Sitzung {z.get("login_url", "")}')
        if fehler:
            return fehler[0], {'fehler': fehler[1]}
        r = subprocess.run(BROWSER_START, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            log(f'BROWSER START FEHLER: {r.stderr.strip()[:200]}')
            return 500, {'fehler': 'Browser konnte nicht gestartet werden'}
        for _ in range(30):
            try:
                socket.create_connection(CDP_INTERN, timeout=1).close()
                break
            except OSError:
                time.sleep(0.5)
        ok, info = browser_anmelden(zugang, z, grund)
        if not ok:
            log(f'BROWSER LOGIN FEHLER {zugang}: {info}')
            return 502, {'fehler': info}
        dauer = float(z.get('gueltig_stunden', 1)) * 3600
        if z.get('regel') == 'push':
            dauer = max(60, freigaben.get(zugang, 0) - time.time())
        with lock:
            sitzung['status'] = 'aktiv'
            sitzung['bis'] = time.time() + dauer
            sitzung['timer'] = threading.Timer(dauer, browser_beenden, kwargs={'sitzungs_id': meine_id})
            sitzung['timer'].daemon = True
            sitzung['timer'].start()
            bis = sitzung['bis']
        erfolg = True
        log(f'BROWSER START {zugang} bis {time.strftime("%H:%M", time.localtime(bis))} ({grund})')
        return 200, {'status': 'angemeldet', 'seite': info, 'bis': time.strftime('%d.%m. %H:%M', time.localtime(bis))}
    finally:
        if not erfolg:
            with lock:
                freigaben.pop(zugang, None)     # fehlgeschlagener Versuch verbraucht die Freigabe
            _browser_stoppen()
            with lock:
                sitzung.update({'status': 'frei', 'zugang': None, 'bis': 0, 'timer': None, 'verbindungen': []})


# ---------------- Relay (Browser-Fernsteuerung fuer den Agentenhost) ----------------
def _relay_token_ok(kopf):
    erste = kopf.split(b'\r\n', 1)[0].decode('latin-1')
    teile = erste.split(' ')
    if len(teile) >= 2:
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(teile[1]).query)
        if hmac.compare_digest(q.get('token', [''])[0], CLIENT_TOKEN):
            return True
    for zeile in kopf.split(b'\r\n')[1:]:
        if zeile.lower().startswith(b'authorization: basic '):
            try:
                paar = base64.b64decode(zeile.split(b' ', 2)[2].strip()).decode()
                if hmac.compare_digest(paar.split(':', 1)[-1], CLIENT_TOKEN):
                    return True
            except Exception:
                pass
    return False


def _token_entfernen(kopf):
    erste, rest = kopf.split(b'\r\n', 1)
    teile = erste.decode('latin-1').split(' ')
    if len(teile) >= 2:
        u = urllib.parse.urlsplit(teile[1])
        q = [(k, v) for k, v in urllib.parse.parse_qsl(u.query) if k != 'token']
        teile[1] = urllib.parse.urlunsplit(('', '', u.path, urllib.parse.urlencode(q), ''))
    neu = [z for z in rest.split(b'\r\n') if not z.lower().startswith(b'authorization:')]
    return ' '.join(teile).encode('latin-1') + b'\r\n' + b'\r\n'.join(neu)


def _pumpe(quelle, ziel):
    try:
        while True:
            daten = quelle.recv(65536)
            if not daten:
                break
            ziel.sendall(daten)
    except Exception:
        pass
    for s in (quelle, ziel):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass


def _sitzung_offen():
    return sitzung['status'] == 'aktiv' and sitzung['bis'] > time.time()


def _relay_verbindung(client):
    ziel = None
    try:
        with lock:
            offen = _sitzung_offen()
        if not offen:
            client.close()
            return
        client.settimeout(10)
        kopf = b''
        while b'\r\n\r\n' not in kopf and len(kopf) < 16384:
            stueck = client.recv(4096)
            if not stueck:
                client.close()
                return
            kopf += stueck
        kopf, rest = kopf.split(b'\r\n\r\n', 1)
        if not _relay_token_ok(kopf):
            log('BROWSER: Verbindung ohne gueltigen Token abgewiesen')
            client.sendall(b'HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            client.close()
            return
        ziel = socket.create_connection(CDP_INTERN, timeout=10)
        neuer_kopf = _token_entfernen(kopf)
        if b'upgrade: websocket' not in kopf.lower():
            # normale Anfrage (z.B. /json/version): Antwort lesen, ws-Adressen um den Token ergaenzen
            ziel.sendall(neuer_kopf + b'\r\n\r\n' + rest)
            antwort = b''
            while b'\r\n\r\n' not in antwort:
                d = ziel.recv(65536)
                if not d:
                    break
                antwort += d
            k2, _, body = antwort.partition(b'\r\n\r\n')
            m = re.search(rb'(?im)^content-length:\s*(\d+)', k2)
            soll = int(m.group(1)) if m else None
            while soll is not None and len(body) < soll:
                d = ziel.recv(65536)
                if not d:
                    break
                body += d
            body = re.sub(rb'(ws://[^"/\s]+/devtools/[^"?\s]+)', rb'\1?token=' + CLIENT_TOKEN.encode(), body)
            k2 = re.sub(rb'(?im)^content-length:[^\r\n]*', b'Content-Length: %d' % len(body), k2)
            client.sendall(k2 + b'\r\n\r\n' + body)
            ziel.close()
            client.close()
            return
        client.settimeout(None)
        ziel.settimeout(None)
        with lock:
            if not _sitzung_offen():
                ziel.close()
                client.close()
                return
            sitzung['verbindungen'] += [client, ziel]
        ziel.sendall(neuer_kopf + b'\r\n\r\n' + rest)
        threading.Thread(target=_pumpe, args=(client, ziel), daemon=True).start()
        threading.Thread(target=_pumpe, args=(ziel, client), daemon=True).start()
    except Exception as e:
        log(f'BROWSER-RELAY-Fehler: {e}')
        for s in (client, ziel):
            try:
                if s:
                    s.close()
            except Exception:
                pass


def relay_starten():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((RELAY_BIND, RELAY_PORT))
    srv.listen(20)

    def schleife():
        while True:
            c, _ = srv.accept()
            threading.Thread(target=_relay_verbindung, args=(c,), daemon=True).start()
    threading.Thread(target=schleife, daemon=True).start()


# ---------------- HTTP-Schnittstelle ----------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def antwort(self, code, daten):
        body = json.dumps(daten, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def token_ok(self):
        if hmac.compare_digest(self.headers.get('X-Zentrale-Token', ''), CLIENT_TOKEN):
            return True
        log(f'FALSCHER TOKEN von {self.client_address[0]}')
        self.antwort(401, {'fehler': 'kein gueltiger Token'})
        return False

    def lies_json(self, maximal):
        try:
            laenge = int(self.headers.get('Content-Length', 0))
        except (TypeError, ValueError):
            raise ValueError('Content-Length fehlt oder ist ungueltig')
        if laenge < 0 or laenge > maximal:
            raise ValueError('Content-Length ungueltig')
        return json.loads(self.rfile.read(laenge))

    def do_GET(self):
        if not self.token_ok():
            return
        if self.path != '/status':
            return self.antwort(404, {'fehler': 'unbekannte Adresse'})
        jetzt = time.time()
        uebersicht = {}
        with lock:
            for name, z in lade_json('zugaenge.json').items():
                bis = freigaben.get(name, 0)
                uebersicht[name] = {
                    'regel': z.get('regel'),
                    'art': z.get('art'),
                    'freigegeben_bis': time.strftime('%d.%m. %H:%M', time.localtime(bis)) if bis > jetzt else None,
                }
            if sitzung['status'] != 'frei':
                uebersicht['_browser'] = {'status': sitzung['status'], 'zugang': sitzung['zugang'],
                                          'bis': time.strftime('%d.%m. %H:%M', time.localtime(sitzung['bis']))
                                          if sitzung['bis'] else None}
        self.antwort(200, uebersicht)

    def do_POST(self):
        if not self.token_ok():
            return
        if self.path == '/browser/ende':
            with lock:
                stand = sitzung['status']
            if stand == 'startet':      # vorher kam hier faelschlich "beendet"
                return self.antwort(409, {'fehler': 'Die Anmeldung laeuft noch - bitte warten, bis /browser antwortet'})
            if stand != 'aktiv':
                return self.antwort(200, {'status': 'frei', 'hinweis': 'Es lief keine Sitzung'})
            browser_beenden('vom Agenten beendet')
            return self.antwort(200, {'status': 'beendet'})
        if self.path == '/browser':
            try:
                a = self.lies_json(100_000)
                zugang, grund = str(a['zugang']), str(a.get('grund', '')).strip()
            except Exception:
                return self.antwort(400, {'fehler': 'Anfrage braucht zugang und grund (JSON)'})
            z = lade_json('zugaenge.json').get(zugang)
            if not z or z.get('art') != 'browser':
                return self.antwort(404, {'fehler': f'Browser-Zugang "{zugang}" gibt es nicht'})
            if not grund:
                return self.antwort(400, {'fehler': 'Bitte einen Grund angeben'})
            code, daten = browser_sitzung(zugang, z, grund)
            return self.antwort(code, daten)
        if self.path != '/anfrage':
            return self.antwort(404, {'fehler': 'unbekannte Adresse'})
        self.api_anfrage()

    def api_anfrage(self):
        try:
            a = self.lies_json(2_000_000)
            zugang = str(a['zugang'])
            url = str(a['url'])
            grund = str(a.get('grund', '')).strip()
            methode = str(a.get('methode', 'GET')).upper()
        except Exception:
            return self.antwort(400, {'fehler': 'Anfrage braucht zugang, url und grund (JSON)'})

        z = lade_json('zugaenge.json').get(zugang)
        if not z:
            return self.antwort(404, {'fehler': f'Zugang "{zugang}" gibt es nicht'})
        if not grund:
            return self.antwort(400, {'fehler': 'Bitte einen Grund angeben'})
        if z.get('art') not in ('basic', 'bearer'):
            return self.antwort(400, {'fehler': 'Dieser Zugang ist kein API-Zugang (Browser: /browser verwenden)'})
        teile = urllib.parse.urlsplit(url)
        host = (teile.hostname or '').lower()
        try:
            port = teile.port or 443
        except ValueError:
            return self.antwort(400, {'fehler': 'Ungueltiger Port'})
        if teile.scheme != 'https' or host not in [h.lower() for h in z.get('erlaubte_hosts', [])]:
            log(f'FALSCHE ADRESSE {zugang} {url}')
            return self.antwort(403, {'fehler': 'Diese Adresse ist fuer den Zugang nicht erlaubt'})
        if port not in z.get('erlaubte_ports', [443]):
            return self.antwort(403, {'fehler': f'Port {port} ist fuer den Zugang nicht erlaubt'})
        if ist_spiegeldienst(host):
            log(f'SPIEGELDIENST abgelehnt {zugang} {host}')
            return self.antwort(403, {'fehler': 'Spiegel-/Testdienste sind als Ziel nicht erlaubt'})
        if methode not in z.get('erlaubte_methoden', ALLE_METHODEN):
            return self.antwort(403, {'fehler': f'Methode {methode} ist fuer den Zugang nicht erlaubt'})

        aktion = f'{methode} {host}{teile.path}'
        fehler = freigabe(zugang, z, grund, aktion)
        if fehler:
            return self.antwort(fehler[0], {'fehler': fehler[1]})

        ip = oeffentliche_ip(host, port)
        if not ip:
            log(f'INTERNE/UNAUFLOESBARE ADRESSE {zugang} {host}')
            return self.antwort(403, {'fehler': 'Ziel nicht aufloesbar oder interne Adresse - abgelehnt'})

        geheim = hole_geheim(zugang, z, grund)
        header = {'User-Agent': 'Zentrale/1.0', 'Host': host if port == 443 else f'{host}:{port}'}
        for k, v in (a.get('header') or {}).items():
            if str(k).lower() in ('authorization', 'cookie', 'host', 'proxy-authorization'):
                continue
            try:
                k2, v2 = pruefe_header(k, v)
            except ValueError as e:
                log(f'HEADER ABGELEHNT {zugang}: {e}')
                return self.antwort(400, {'fehler': str(e)})
            header[k2] = v2
        art = z.get('art')
        if art == 'basic' and geheim.get('benutzer') and geheim.get('passwort'):
            paar = f"{geheim['benutzer']}:{geheim['passwort']}".encode('utf-8')
            header['Authorization'] = 'Basic ' + base64.b64encode(paar).decode()
        elif art == 'bearer' and geheim.get('token'):
            header['Authorization'] = 'Bearer ' + geheim['token']
        else:
            log(f'GEHEIMNIS FEHLT {zugang}')
            return self.antwort(500, {'fehler': 'Fuer diesen Zugang ist kein Passwort hinterlegt (Proton-Eintrag pruefen)'})

        daten = None
        if a.get('body') is not None:
            b = a['body']
            daten = b.encode('utf-8') if isinstance(b, str) else json.dumps(b).encode('utf-8')
            header.setdefault('Content-Type', 'application/json')
        pfad = (teile.path or '/') + (f'?{teile.query}' if teile.query else '')
        try:
            verb = FesteIPVerbindung(host, ip, port, timeout=60)
            verb.request(methode, pfad, body=daten, headers=header)
            r = verb.getresponse()           # Weiterleitungen werden NICHT verfolgt
            status, inhalt = r.status, r.read(5_000_000)
            verb.close()
        except Exception as e:
            log(f'FEHLER {zugang} {aktion}: {schwaerzen(str(e), geheim, True)[:200]}')
            return self.antwort(502, {'fehler': f'Dienst nicht erreichbar: {schwaerzen(str(e), geheim, True)[:200]}'})

        text = schwaerzen(inhalt.decode('utf-8', 'replace'), geheim, True)
        log(f'AUSGEFUEHRT {zugang} {aktion} -> {status}')
        self.antwort(200, {'status': status, 'inhalt': text})


if __name__ == '__main__':
    log(f'Zentrale gestartet ({FASSUNG})')
    _browser_stoppen()
    relay_starten()
    ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
