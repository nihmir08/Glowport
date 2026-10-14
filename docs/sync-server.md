# Den Sync-Server betreiben

Diese Anleitung richtet `glowport-sync` auf einem eigenen Linux-Server ein. Was der Server tut und was er nie zu sehen bekommt, steht in [`sync.md`](sync.md).

**Stand:** Weg A ist auf einem Ubuntu (WSL) durchlaufen, von Hand und mit `install.sh`, samt Befehlen, Sicherung und Zurückholen; Glowport hat gegen diesen Dienst vollständig abgeglichen. Auf einem Debian-Server läuft er hinter NGINX mit einem Zertifikat von Let's Encrypt (Dienst über `install.sh`, die Seite von Hand mit TLS geschrieben). Noch nicht gelaufen sind Weg B (Docker), `certbot --nginx` mit der Vorlage, Caddy, das Beispiel unter Proxmox und der Dienst mit eigenem Zertifikat auf Port 443.

## Was es ist

- **Ein einzelnes Programm**, `glowport-sync`. Es braucht nichts außer sich selbst.
- **Eine Datei**, `sync.db`, im Datenordner. Darin liegt alles: Konten, Geräte, die verschlüsselten Datensätze.
- Es hört in der Vorgabe auf `127.0.0.1:8787`, also nur für denselben Rechner. Nach außen geht es über einen Webserver, der HTTPS übernimmt. Glowport verbindet sich ausschließlich über `https://`.

## Was du brauchst

- Einen Linux-Rechner (64 Bit, x86), der dauerhaft läuft: der Dedi selbst oder eine VM oder ein Container darauf.
- Eine Adresse für den Server, am besten eine eigene Unteradresse wie `sync.deine-domain.de`, deren DNS-Eintrag auf den Rechner zeigt.
- Von außen erreichbar: Port 443 (und Port 80, damit das Zertifikat ausgestellt werden kann).

In den Beispielen steht überall `sync.example.de`. Ersetze es durch deine Adresse.

## Weg A: als Dienst (empfohlen)

**Kurz:** Den Ordner `dist-server` aus dem Projekt auf den Server laden (Programm, Dienst-Datei, `install.sh`) und dort als `root` ausführen:

```bash
sh install.sh
```

Das Skript macht die Schritte 1 bis 4 von unten und zeigt am Ende den Einrichtungscode. Ein weiterer Aufruf tauscht nur das Programm aus (Aktualisieren). Läuft der Webserver auf einem anderen Rechner oder Container, bekommt das Skript dessen innere Adresse mit: `PROXY=10.0.0.10 sh install.sh`.

**Von Hand, Schritt für Schritt:**

1. **Programm auf den Server legen.** Das Linux-Programm liegt im Projekt unter `dist-server/glowport-sync` (gebaut mit `sh scripts/build-server.sh` in einem Linux, etwa WSL; es läuft auf jedem 64-Bit-Linux ohne weitere Pakete). Lade es hoch, zum Beispiel mit dem Dateimanager von Glowport, und lege es nach `/usr/local/bin`:

   ```bash
   install -m 755 glowport-sync /usr/local/bin/glowport-sync
   ```

2. **Einen eigenen Benutzer anlegen.** Der Dienst läuft nicht als `root`:

   ```bash
   useradd --system --home-dir /var/lib/glowport-sync --shell /usr/sbin/nologin glowport-sync
   ```

3. **Den Dienst einrichten.** Lege `server/glowport-sync.service` aus dem Projekt nach `/etc/systemd/system/` und starte:

   ```bash
   systemctl daemon-reload
   systemctl enable --now glowport-sync
   ```

4. **Nachsehen, ob er läuft:**

   ```bash
   journalctl -u glowport-sync -n 20
   ```

   Dort steht `glowport-sync hört auf 127.0.0.1:8787` und, solange es noch kein Konto gibt, der **Einrichtungscode**.

5. **HTTPS davorsetzen:** siehe den Abschnitt „HTTPS“.

Die Daten liegen in `/var/lib/glowport-sync`. Nur der Dienst darf in diesen Ordner.

## Weg B: mit Docker

1. Kopiere den Projektordner auf den Server. Die Ordner `target`, `node_modules` und `dist` braucht es dafür nicht.
2. Im Ordner `server`:

   ```bash
   docker compose up -d --build
   ```

   Der erste Bau dauert einige Minuten.
3. Einrichtungscode und Lebenszeichen:

   ```bash
   docker compose logs glowport-sync
   ```

Der Container ist nur über `127.0.0.1:8787` erreichbar. Die Daten liegen im Docker-Volume `glowport-sync-data`.

## HTTPS

### Mit Caddy (am einfachsten)

Caddy holt und verlängert das Zertifikat selbst. Die ganze Einrichtung steht in `server/Caddyfile`:

```
sync.example.de {
    reverse_proxy 127.0.0.1:8787
}
```

### Mit NGINX

1. `server/nginx.conf` nach `/etc/nginx/sites-available/glowport-sync` legen, die Adresse eintragen, nach `sites-enabled` verknüpfen.
2. Das Zertifikat holen und eintragen lassen:

   ```bash
   certbot --nginx -d sync.example.de
   ```

Wichtig an der Vorlage sind die Zeilen für den WebSocket (`Upgrade`, `Connection`) und die langen Wartezeiten. Fehlen sie, kommen Änderungen auf anderen Geräten erst nach bis zu einer Minute an statt sofort.

Ob der WebSocket durchgeht, zeigt das Zugriffsprotokoll von NGINX mit einer Zeile für `/v1/live` und dem Ergebnis `101`. NGINX schreibt diese Zeile aber erst, wenn die Verbindung endet, also nachdem Glowport geschlossen wurde:

```bash
grep "/v1/live" /var/log/nginx/access.log | tail -1
```

### Der Webserver läuft auf einem anderen Rechner oder Container

Dann reicht `127.0.0.1` nicht: Der Sync-Server muss dort hören, wo der Webserver ihn erreicht, also auf seiner Adresse im inneren Netz. In den Beispielen hat der Webserver die innere Adresse `10.0.0.10`, der Sync-Server `10.0.0.20`.

- In der Dienst-Datei (oder gleich mit `PROXY=10.0.0.10 sh install.sh`):

  ```
  Environment=GLOWPORT_SYNC_LISTEN=0.0.0.0:8787
  Environment=GLOWPORT_SYNC_TRUST_PROXY=10.0.0.10
  ```

  Die zweite Zeile nennt die Adresse des Webservers: Nur ihm glaubt der Sync-Server, wer der Absender ist. Wer Port 8787 direkt erreicht, kann sich so keine fremde Adresse geben.
- Im Webserver statt `127.0.0.1:8787` die innere Adresse des Sync-Servers eintragen: `proxy_pass http://10.0.0.20:8787;`
- Port 8787 gehört nicht ins Internet. Zwischen Webserver und Sync-Server läuft die Verbindung unverschlüsselt; sie soll das innere Netz des Rechners nie verlassen.

### Beispiel: eigener Container unter Proxmox, NGINX in einem anderen

1. **DNS:** einen Eintrag für die Adresse anlegen (`sync.example.de`), der auf die öffentliche IP zeigt, unter der der NGINX erreichbar ist.
2. **Container anlegen** (Proxmox → „Erstelle CT“): Vorlage Debian 13, „Unprivilegierter Container“ und „Nesting“ angehakt lassen, 1 Kern, 256 MB Arbeitsspeicher, 4 GB Platte, dieselbe Bridge wie der NGINX und eine feste innere Adresse aus demselben Netz. Danach unter Optionen „Beim Booten starten“ einschalten.
3. **Dateien hineinlegen und einrichten.** Den Ordner `dist-server` auf den Proxmox-Host laden, dort in den Ordner wechseln und (mit der Nummer des Containers statt `120` und der inneren Adresse des NGINX):

   ```bash
   pct push 120 glowport-sync /root/glowport-sync
   pct push 120 glowport-sync.service /root/glowport-sync.service
   pct push 120 install.sh /root/install.sh
   pct exec 120 -- env PROXY=10.0.0.10 sh /root/install.sh
   ```

   Am Ende steht der Einrichtungscode.
4. **NGINX:** `server/nginx.conf` als neue Seite ablegen, darin die Adresse und bei `proxy_pass` die innere Adresse des Containers eintragen, `nginx -t`, neu laden, dann `certbot --nginx -d sync.example.de`.
5. **Prüfen** wie unten, dann das erste Konto anlegen.

Befehle der Verwaltung gehen später vom Host aus so: `pct exec 120 -- runuser -u glowport-sync -- glowport-sync accounts`

### Ohne Webserver davor

`glowport-sync` kann HTTPS auch selbst, wenn es Zertifikat und Schlüssel als Dateien bekommt (PEM, wie von Let's Encrypt). In `server/glowport-sync.service` stehen die Zeilen dafür auskommentiert. Zu beachten:

- Der Benutzer `glowport-sync` muss beide Dateien lesen können. Die Dateien unter `/etc/letsencrypt` darf er das nicht; sie müssen nach jeder Verlängerung in seinen Ordner kopiert werden, etwa nach `/var/lib/glowport-sync/tls/`.
- Geänderte Dateien übernimmt der Server binnen einer Stunde von selbst, ohne Neustart.

Für den Anfang ist ein Webserver davor der einfachere Weg.

### Prüfen

```bash
curl https://sync.example.de/v1/info
```

Die Antwort ist eine kurze Zeile in geschweiften Klammern. Dann ist der Server von außen erreichbar und das Zertifikat in Ordnung.

## Das erste Konto

1. In Glowport links auf **Sync**, dann **Sync einrichten**, **Neues Konto**.
2. Bei „Adresse des Sync-Servers“ die Adresse eintragen (`sync.example.de`) und **Prüfen**.
3. Glowport meldet, dass der Server noch kein Konto hat, und fragt nach dem **Einrichtungscode**. Er steht in der Ausgabe des Servers (`journalctl -u glowport-sync` oder `docker compose logs glowport-sync`).

   Der Server gibt bei jedem Start einen neuen Einrichtungscode aus. Es gilt immer nur der letzte.
4. Benutzername wählen, Master-Passwort bestätigen, dem Gerät einen Namen geben, **Sync einrichten**.

Dieses erste Konto verwaltet den Server. Sobald es besteht, gibt es keinen Einrichtungscode mehr.

## Weitere Personen und Geräte

- **Ein weiteres eigenes Gerät:** Auf einem frischen Glowport beim Start „Mit Konto anmelden“ wählen, mit Adresse, Benutzername und Master-Passwort. Hat das Gerät schon einen Tresor: Sync → Sync einrichten → „Ich habe schon ein Konto“. Ein Code ist dafür nicht nötig.
- **Eine weitere Person:** In Glowport unter Sync → **Server verwalten** → **Einladungscode erzeugen**. Der Code gilt einmal und sieben Tage. Die Person wählt bei sich „Neues Konto“ und trägt ihn ein.

## Verwalten per Befehl

Alles, was „Server verwalten“ in Glowport kann, geht auch auf dem Server selbst. Das ist für den Fall gedacht, dass kein Verwalter mehr hineinkommt, etwa weil das Master-Passwort verloren ist.

| Befehl | Wirkung |
|---|---|
| `glowport-sync accounts` | Konten auflisten: Geräte, Speicher, letzter Besuch |
| `glowport-sync invite` | Einladungscode erzeugen |
| `glowport-sync invites` | offene Einladungscodes auflisten |
| `glowport-sync revoke <Code>` | offenen Einladungscode widerrufen |
| `glowport-sync disable <Name>` | Konto sperren: keine Anmeldung, kein Abgleich, die Daten bleiben |
| `glowport-sync enable <Name>` | Konto wieder freigeben |
| `glowport-sync delete <Name>` | Konto samt Geräten und persönlichem Tresor löschen |
| `glowport-sync admin <Name>` | Konto zum Verwalter machen |
| `glowport-sync noadmin <Name>` | einem Konto die Verwaltung nehmen |
| `glowport-sync backup <Datei>` | Sicherung schreiben |

Die Befehle wirken sofort, auch während der Server läuft. So werden sie aufgerufen:

- **Als Dienst:** als Benutzer des Dienstes, damit die Dateien ihm gehören. Der Datenordner wird von selbst gefunden:

  ```bash
  runuser -u glowport-sync -- glowport-sync accounts
  ```

- **Mit Docker**, im Ordner `server`:

  ```bash
  docker compose exec glowport-sync glowport-sync accounts
  ```

Kein Befehl kann ein Passwort zurücksetzen oder in einen Tresor hineinsehen. Wer sein Master-Passwort verliert, braucht ein neues Konto; `admin` macht es dann wieder zum Verwalter.

## Sicherung

```bash
runuser -u glowport-sync -- glowport-sync backup /var/lib/glowport-sync/sicherung-2026-10-10.db
```

Das geht im laufenden Betrieb und schreibt eine vollständige, in sich stimmige Kopie. Nimm dafür immer diesen Befehl: Solange der Server läuft, steht ein Teil der Daten noch nicht in `sync.db` selbst, eine bloße Kopie der Datei wäre unvollständig. Eine vorhandene Datei wird nicht überschrieben. Die Sicherung enthält dasselbe wie der Server: verschlüsselte Datensätze, die ohne die Master-Passwörter niemand lesen kann. Lege sie trotzdem nicht offen ab, und kopiere sie vom Server herunter.

**Zurückholen:** Dienst anhalten, die Sicherung als `sync.db` in den Datenordner legen, die Dateien `sync.db-wal` und `sync.db-shm` löschen, falls vorhanden, Dienst starten.

```bash
systemctl stop glowport-sync
install -o glowport-sync -g glowport-sync -m 600 sicherung-2026-10-10.db /var/lib/glowport-sync/sync.db
rm -f /var/lib/glowport-sync/sync.db-wal /var/lib/glowport-sync/sync.db-shm
systemctl start glowport-sync
```

Geräte, die inzwischen weiter waren als die Sicherung, merken das. Glowport zeigt am betroffenen Tresor „Server älter“ und bietet **Stand dieses Geräts hochladen** an. Verloren geht dabei nichts: Jedes Gerät hat ohnehin eine vollständige Kopie seiner Tresore.

## Aktualisieren

- **Als Dienst:** das neue `glowport-sync` nach `/usr/local/bin` legen, dann `systemctl restart glowport-sync`.
- **Mit Docker:** den neuen Projektordner hochladen, dann `docker compose up -d --build`.

Server und Glowport nennen einander ihre Version. Passt es einmal nicht, sagt Glowport, welche Seite ein Update braucht.

## Protokoll

```bash
journalctl -u glowport-sync -f
```

Eine Zeile für alles, was etwas ändert oder scheitert:

```
2026-10-10 14:03:27 200 POST /v1/vaults/{vault}/records alex
2026-10-10 14:05:02 401 POST /v1/login -
```

Das sind Zeit (UTC), Ergebnis, Art der Anfrage und Konto. Inhalte, Token, Passwörter und die Adressen der Absender stehen nie darin. Reines Lesen wird nicht protokolliert.

## Einstellungen

Als Angabe beim Start oder über die Umgebung (in der Dienst-Datei als `Environment=`, bei Docker unter `environment:`):

| Angabe | Umgebung | Vorgabe | Bedeutung |
|---|---|---|---|
| `--listen` | `GLOWPORT_SYNC_LISTEN` | `127.0.0.1:8787` | wo der Server hört |
| `--data` | `GLOWPORT_SYNC_DATA` | `./data` | Datenordner |
| `--trust-proxy` | `GLOWPORT_SYNC_TRUST_PROXY=1` | aus | hinter einem Webserver auf demselben Rechner: Der Absender steht in `X-Forwarded-For` |
| `--trust-proxy-from` | `GLOWPORT_SYNC_TRUST_PROXY=10.0.0.10` | – | dasselbe, aber geglaubt wird es nur Verbindungen von dieser Adresse (mehrere mit Komma): der Webserver auf einem anderen Rechner |
| `--tls-cert` | `GLOWPORT_SYNC_TLS_CERT` | – | Zertifikat (PEM) für HTTPS ohne Webserver davor |
| `--tls-key` | `GLOWPORT_SYNC_TLS_KEY` | – | zugehöriger privater Schlüssel (PEM) |
| – | `GLOWPORT_SYNC_MAX_RECORD_KIB` | 256 | Größe eines Datensatzes in KiB |
| – | `GLOWPORT_SYNC_MAX_RECORDS` | 20000 | Datensätze je Tresor |
| – | `GLOWPORT_SYNC_MAX_VAULTS` | 50 | Tresore je Konto |

`GLOWPORT_SYNC_TRUST_PROXY=1` nur einschalten, wenn der Server auf `127.0.0.1` hört, ihn also allein der Webserver desselben Rechners erreicht. In jedem anderen Fall die Adresse des Webservers nennen. Sonst könnte sich jeder, der den Server direkt erreicht, eine beliebige Absender-Adresse geben und die Bremse gegen Rateversuche umgehen.

## Wenn etwas nicht geht

| Glowport meldet | Woran es meist liegt |
|---|---|
| „Der Sync-Server ist nicht erreichbar.“ | Der DNS-Eintrag zeigt nicht auf den Rechner, Port 443 ist zu, oder der Dienst läuft nicht. `curl https://sync.example.de/v1/info` zeigt, wie weit man kommt. |
| „Das Zertifikat des Sync-Servers wird nicht anerkannt …“ | Das Zertifikat ist abgelaufen, für eine andere Adresse ausgestellt oder selbst erstellt. Glowport traut denselben Ausstellern wie Windows. |
| „Dieser Code gilt nicht (mehr).“ beim Einrichtungscode | Der Server wurde seitdem neu gestartet. Es gilt der Code vom letzten Start. |
| „Zu viele Fehlversuche. Bitte in einer Viertelstunde noch einmal.“ | Nach fünf falschen Anmeldungen an einem Konto ist für eine Viertelstunde Pause. Steht ein Webserver davor und fehlt `--trust-proxy`, teilen sich alle Absender eine Adresse und bremsen sich gegenseitig. |
| Der Dienst startet nicht, im Journal steht `226/NAMESPACE` | Die Abschottung des Dienstes braucht in einem Container unter Proxmox die Option „Nesting“ (Container → Optionen → Features). Einschalten, Container neu starten. |
| Änderungen kommen erst nach etwa einer Minute an | Der Webserver davor reicht den WebSocket nicht durch. Bei NGINX fehlen die Zeilen `Upgrade` und `Connection` aus der Vorlage. |
