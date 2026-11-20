#!/bin/sh
# Install as /opt/browser/start.sh, owned by root, mode 755.
# Virtual display: without it some providers refuse the login
# (blank page, consent errors).
BIN=$(ls -d /opt/browser/ms-playwright/chromium-*/chrome-linux*/chrome 2>/dev/null | sort | tail -1)
exec xvfb-run -a -s "-screen 0 1366x900x24" "$BIN" \
  --remote-debugging-port=9222 --user-data-dir=/tmp/profil \
  --no-first-run --no-default-browser-check --disable-dev-shm-usage \
  --lang=de-DE --window-size=1366,900 about:blank
