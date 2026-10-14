#!/bin/sh
# Sets up the Glowport sync server as a service (option A in docs/sync-server.md).
# Run as root in the folder containing `glowport-sync` and `glowport-sync.service`:
#
#   sh install.sh
#
# If the web server runs on another machine or container, pass its internal address:
#
#   PROXY=10.0.0.10 sh install.sh
#
# Running it again only replaces the program and restarts. Data and settings stay.
set -eu

cd "$(dirname "$0")"
unit=/etc/systemd/system/glowport-sync.service

[ "$(id -u)" = 0 ] || { echo "Bitte als root ausführen."; exit 1; }
[ -f glowport-sync ] && [ -f glowport-sync.service ] || { echo "In diesem Ordner fehlen glowport-sync und glowport-sync.service."; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "Dieses System hat kein systemd. Siehe docs/sync-server.md, Weg B."; exit 1; }

install -m 755 glowport-sync /usr/local/bin/glowport-sync
id glowport-sync >/dev/null 2>&1 || useradd --system --home-dir /var/lib/glowport-sync --shell /usr/sbin/nologin glowport-sync

if [ -f "$unit" ]; then
    echo "Die Dienst-Datei gibt es schon; sie bleibt, wie sie ist."
else
    install -m 644 glowport-sync.service "$unit"
    if [ -n "${PROXY:-}" ]; then
        # The web server comes from outside: listen on all addresses, but only believe it about the sender.
        sed -i -e "s|^Environment=GLOWPORT_SYNC_LISTEN=.*|Environment=GLOWPORT_SYNC_LISTEN=0.0.0.0:8787|" \
               -e "s|^Environment=GLOWPORT_SYNC_TRUST_PROXY=.*|Environment=GLOWPORT_SYNC_TRUST_PROXY=$PROXY|" "$unit"
    fi
fi

systemctl daemon-reload
systemctl enable glowport-sync >/dev/null 2>&1
systemctl restart glowport-sync
sleep 2

if ! systemctl is-active --quiet glowport-sync; then
    echo "Der Dienst ist nicht gestartet. Seine letzten Meldungen:"
    journalctl -u glowport-sync -n 15 --no-pager -o cat
    if systemctl status glowport-sync --no-pager 2>/dev/null | grep -q NAMESPACE; then
        echo
        echo "Das liegt an der Abschottung des Dienstes. In einem Container unter Proxmox:"
        echo "Container → Optionen → Features → „Nesting“ einschalten, Container neu starten, noch einmal versuchen."
    fi
    exit 1
fi

# Only this start's output: a setup code from earlier is no longer valid.
echo "Der Dienst läuft:"
journalctl "_SYSTEMD_INVOCATION_ID=$(systemctl show -p InvocationID --value glowport-sync)" --no-pager -o cat
