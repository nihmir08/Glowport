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

[ "$(id -u)" = 0 ] || { echo "Please run as root."; exit 1; }
[ -f glowport-sync ] && [ -f glowport-sync.service ] || { echo "glowport-sync and glowport-sync.service are missing in this folder."; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "This system has no systemd. See docs/sync-server.md, option B."; exit 1; }

install -m 755 glowport-sync /usr/local/bin/glowport-sync
id glowport-sync >/dev/null 2>&1 || useradd --system --home-dir /var/lib/glowport-sync --shell /usr/sbin/nologin glowport-sync

if [ -f "$unit" ]; then
    echo "The service file already exists; it stays as it is."
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
    echo "The service did not start. Its latest messages:"
    journalctl -u glowport-sync -n 15 --no-pager -o cat
    if systemctl status glowport-sync --no-pager 2>/dev/null | grep -q NAMESPACE; then
        echo
        echo "This is caused by the service's sandboxing. In a container under Proxmox:"
        echo "Container → Options → Features → switch on “Nesting”, restart the container, try again."
    fi
    exit 1
fi

# Only this start's output: a setup code from earlier is no longer valid.
echo "The service is running:"
journalctl "_SYSTEMD_INVOCATION_ID=$(systemctl show -p InvocationID --value glowport-sync)" --no-pager -o cat
