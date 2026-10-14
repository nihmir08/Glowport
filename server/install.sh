#!/bin/sh
# Richtet den Glowport Sync-Server als Dienst ein (Weg A in docs/sync-server.md).
# Als root in dem Ordner ausführen, in dem `glowport-sync` und `glowport-sync.service` liegen:
#
#   sh install.sh
#
# Läuft der Webserver auf einem anderen Rechner oder Container, seine innere Adresse mitgeben:
#
#   PROXY=10.0.0.10 sh install.sh
#
# Ein weiterer Aufruf tauscht nur das Programm aus und startet neu. Daten und Einstellungen bleiben.
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
        # Der Webserver kommt von außen: auf allen Adressen hören, den Absender aber nur ihm glauben.
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

# Nur die Ausgabe dieses Starts: Ein Einrichtungscode von früher gilt nicht mehr.
echo "Der Dienst läuft:"
journalctl "_SYSTEMD_INVOCATION_ID=$(systemctl show -p InvocationID --value glowport-sync)" --no-pager -o cat
