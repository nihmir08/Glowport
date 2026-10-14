# Verwaltung: Docker, Dienste, Prozesse, Proxmox

Beschreibung für Meilenstein 10. **Stand:** vom User freigegeben am 2026-10-12, gebaut und abgenommen am 2026-10-12 (Version 0.10.0).

## Kurzfassung

- **In der Seitenleiste einer SSH-Sitzung** kommen drei Reiter dazu: **Docker**, **Dienste**, **Prozesse**. Sie zeigen, was auf dem Server läuft, und steuern es mit einem Klick. Alles geht über die Verbindung, die schon steht; auf dem Server wird nichts installiert.
- **Eine eigene Seite „Proxmox“** verbindet Glowport mit einem Proxmox-Server über einen Zugriffsschlüssel (API-Token). Sie listet VMs und Container, startet und stoppt sie, verbindet direkt und legt auf Wunsch Hosts an, die Glowport danach aktuell hält.

## Entscheidungen des Users (2026-10-12, über das Auswahl-Werkzeug)

| Frage | Entscheidung |
|---|---|
| Wie werden aus VMs und Containern Hosts? | **Mit Auswahl, danach aktuell halten.** Vorschau mit Haken; was angelegt ist, hält Glowport bei Adresse, Name und Status aktuell. |
| Was darf Glowport in Proxmox tun? | **Ansehen, verbinden, Start/Stopp/Neustart.** Stoppen und Neustarten mit Rückfrage. Nichts, was Daten löscht. Keine Snapshots und Sicherungen. |
| Was, wenn die Sitzung nicht root ist? | **sudo ohne Passwort, sonst im Terminal.** Glowport fasst kein sudo-Passwort an. |
| Wie viel Docker? | **Container:** Liste, starten, stoppen, neu starten, Logs, Shell. Keine Compose-Projekte, keine Images, Volumes, Netze. |

## Seitenleiste

Die Reiter gibt es nur bei SSH-Sitzungen, und jeder nur dort, wo er etwas zu zeigen hat: Glowport sieht beim ersten Öffnen einmal nach, ob es `docker`, `systemctl` und `ps` auf dem Server gibt. Fehlt etwas, fehlt der Reiter. Gemessen und nachgeladen wird nur, solange der Reiter offen ist.

Jede Liste entsteht aus einem einzigen Befehl auf der bestehenden Verbindung (derselbe Weg wie die Server-Info). Glowport liest die Ausgabe; auf dem Server bleibt nichts zurück.

### Docker

- **Liste:** alle Container, laufende zuerst. Je Container Name, Image, Zustand (läuft, gestoppt, startet neu, ungesund), Laufzeit, veröffentlichte Ports; bei laufenden dazu Prozessor und Arbeitsspeicher.
- **Aktionen:** starten, stoppen, neu starten. Stoppen und Neustarten mit Rückfrage.
- **Logs:** öffnet einen neuen Tab am selben Server, in dem die Logs mitlaufen (die letzten 200 Zeilen, dann fortlaufend).
- **Shell:** öffnet einen neuen Tab am selben Server mit einer Shell im Container (`bash`, sonst `sh`).
- Befehle: `docker ps -a`, `docker inspect` und `docker stats --no-stream` mit festen Spalten, `docker start|stop|restart`, für die Tabs `docker logs -f` und `docker exec -it`.

### Dienste

- **Liste:** die systemd-Dienste des Servers. Je Dienst Name, Beschreibung, Zustand (läuft, beendet, fehlgeschlagen, inaktiv) und ob er beim Start mitläuft. Fehlgeschlagene stehen oben. Suche nach Namen, Filter „nur laufende“ und „nur fehlgeschlagene“.
- **Aktionen:** starten, stoppen, neu starten, beim Start ein- und ausschalten. Stoppen, Neustarten und Ausschalten mit Rückfrage.
- **Einzelheiten:** ein Klick klappt den Dienst auf und zeigt seine letzten Meldungen. „Mitlesen“ öffnet einen Tab, in dem das Journal des Dienstes mitläuft.
- Befehle: `systemctl list-units` und `list-unit-files`, `systemctl start|stop|restart|enable|disable`, `journalctl -u`.

### Prozesse

- **Liste:** die Prozesse mit der höchsten Last, höchstens 200. Je Prozess Kennung, Benutzer, Prozessor, Arbeitsspeicher, Laufzeit, Befehl. Sortieren nach Prozessor oder Speicher, Suche nach Name oder Benutzer.
- **Aktionen:** beenden (höflich, `TERM`) und abschießen (`KILL`), beides mit Rückfrage, die den Befehl des Prozesses nennt.
- Befehle: `ps` mit festen Spalten, die verbrauchte Rechenzeit aus `/proc`, `kill`. Die Auslastung ergibt sich aus zwei Messungen nacheinander; beim ersten Öffnen steht sie deshalb erst nach fünf Sekunden da.

### Rechte

1. Glowport führt alles zuerst als der angemeldete Benutzer aus.
2. Reicht das nicht, versucht es `sudo -n`, also sudo ohne Passwortabfrage.
3. Verlangt sudo ein Passwort, schreibt Glowport den Befehl mit `sudo` davor in das Terminal der Sitzung, ohne ihn abzuschicken, und sagt das an. Du drückst die Eingabetaste und gibst das Passwort dort ein. So bleibt sichtbar, was läuft, und Glowport bekommt das Passwort nie zu sehen.

Lässt sich schon die Liste nicht lesen (etwa Docker ohne Mitgliedschaft in der Gruppe `docker` und ohne sudo ohne Passwort), steht das im Reiter, mit dem Grund.

### Grenzen

- Nur Linux mit den genannten Programmen. Kein Podman, kein Kubernetes, kein Windows-Server.
- Bei Telnet, serieller Leitung und lokalem Terminal gibt es die Reiter nicht.
- Aktualisiert wird in festem Abstand (Docker und Prozesse alle fünf Sekunden, Dienste alle zehn), solange der Reiter offen ist.

## Proxmox

### Verbindung

- **Angaben:** Name, Adresse (`https://pve.example.de:8006`), Kennung des Tokens (`benutzer@pve!glowport`) und sein Geheimnis. Mehrere Verbindungen sind möglich.
- **Den Token legst du selbst in Proxmox an** (Rechenzentrum → Berechtigungen → API-Token) und trägst ihn in Glowport ein. Er braucht nur das Recht, VMs und Container zu sehen und ein- und auszuschalten; wie das geht, steht unten unter „Token anlegen“. Glowport prüft beim Einrichten, was der Token darf, und sagt, was fehlt.
- **Anmeldung an den Maschinen:** An der Verbindung lässt sich eine Identität wählen (Benutzer mit Schlüssel oder Passwort, von der Seite „Schlüssel“). Mit ihr meldet sich Glowport an den Maschinen dieser Verbindung an: beim „Verbinden“ auf der Seite „Proxmox“ und an Hosts, die daraus angelegt werden. Nennt Cloud-Init für eine Maschine einen Schlüssel, der in deinem Tresor liegt, gilt Cloud-Init (Benutzer und Schlüssel). Ohne beides bleibt nur der Benutzer, den Proxmox nennt, und Glowport fragt nach dem Passwort, wenn der Server eines annimmt. Name und Identität einer Verbindung lassen sich ändern, ohne sie neu zu prüfen.
- **Gespeichert** wird die Verbindung im persönlichen Tresor, das Geheimnis verschlüsselt wie ein Passwort. Mit dem Sync kommt sie auf deine anderen Geräte. Teilen lässt sie sich in dieser Fassung nicht.
- **Zertifikat:** Proxmox bringt ein selbst erstelltes Zertifikat mit, dem kein Rechner von sich aus traut. Glowport verbindet sich ohne Rückfrage, wenn das Zertifikat anerkannt ist (etwa von Let's Encrypt). Sonst zeigt es beim ersten Mal den Fingerabdruck des Zertifikats, du vergleichst ihn mit dem in der Proxmox-Oberfläche und bestätigst; Glowport merkt ihn sich in der Verbindung. Ändert er sich später, verbindet Glowport nicht und sagt warum. Das ist dasselbe Verfahren wie bei den bekannten Hosts von SSH.
- **„Prüfen“ läuft deshalb in zwei Schritten.** Der erste baut nur die Verbindung auf und zeigt den Fingerabdruck; der Token geht dabei nicht hinaus. Erst nach deinem Haken („Der Fingerabdruck stimmt überein“) schickt „Mit Token prüfen“ den Token und liest Version und Rechte. Bei einem anerkannten Zertifikat entfällt der erste Schritt. Beim Bearbeiten einer Verbindung fragt Glowport nicht erneut, solange der Server dasselbe Zertifikat zeigt.

### Token anlegen

Nachgelesen für Proxmox VE 9, an einem echten Server noch nicht ausprobiert. Am einfachsten in der Shell des Proxmox-Servers (Knoten → Shell):

```
pveum role add Glowport --privs "VM.Audit VM.PowerMgmt VM.GuestAgent.Audit Sys.Audit"
pveum user add glowport@pve
pveum acl modify / --users glowport@pve --roles Glowport
pveum user token add glowport@pve glowport --privsep 0
```

Der letzte Befehl zeigt das Geheimnis des Tokens, und zwar nur dieses eine Mal. In Glowport: Kennung `glowport@pve!glowport`, dazu das Geheimnis.

- `VM.Audit`: Maschinen und ihre Einstellungen sehen (daraus kommen Adresse, Benutzer und Schlüssel aus Cloud-Init).
- `VM.PowerMgmt`: starten, herunterfahren, stoppen, neu starten.
- `VM.GuestAgent.Audit`: den Gastagenten nach den Adressen fragen (vor Proxmox 9 hieß das Recht `VM.Monitor`).
- `Sys.Audit`: Auslastung der Knoten. Ohne dieses Recht zeigt Glowport die Knoten nur mit Namen.
- `--privsep 0`: Der Token darf, was sein Benutzer darf. Mit getrennten Rechten bräuchte der Token dieselbe Rolle noch einmal für sich (`--tokens 'glowport@pve!glowport'`).

Den Fingerabdruck zum Vergleichen zeigt Proxmox unter Knoten → System → Zertifikate (`pve-ssl.pem`), oder in der Shell: `openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256`.

### Die Seite

Ein neuer Eintrag „Proxmox“ in der Leiste links. Je Verbindung die Knoten, darunter ihre VMs und Container:

- Name, Nummer, Art (VM oder Container), Zustand, Prozessor, Arbeitsspeicher, Laufzeit, Tags. Vorlagen sind als solche gekennzeichnet.
- **Aktionen:** starten, herunterfahren, stoppen (hart), neu starten. Herunterfahren, Stoppen und Neustarten mit Rückfrage. Glowport zeigt, ob Proxmox den Auftrag ausgeführt hat. Danach fragt es die Maschine selbst nach ihrem Zustand, damit die Anzeige sofort stimmt: Die Liste aller Maschinen erneuert Proxmox nur alle paar Sekunden.
- **Verbinden:** öffnet eine SSH-Sitzung zur Adresse der Maschine, auch ohne dass sie als Host angelegt ist.
- **Als Hosts anlegen:** siehe unten.
- Aktualisiert wird alle zehn Sekunden, solange die Seite offen ist.

### Woher Glowport Adresse und Anmeldung kennt

Glowport führt zusammen, was Proxmox hergibt, statt sich auf eine Quelle zu verlassen:

| Quelle | Liefert |
|---|---|
| Cloud-Init der VM | feste Adresse, Benutzer, hinterlegte öffentliche Schlüssel |
| Gastagent der VM (wenn er läuft) | die Adressen, die die VM gerade wirklich hat; das Betriebssystem |
| Einstellungen des Containers | feste Adresse |
| Laufender Container | die Adressen, die er gerade hat |

- Eine feste Adresse aus Cloud-Init oder den Einstellungen gilt vor einer gemessenen. Ohne feste Adresse (DHCP) zählt, was Gastagent oder Container melden; dabei kommt eine IPv4-Adresse vor IPv6, und Adressen, die nur innerhalb der Maschine gelten, zählen nicht.
- Findet Glowport einen hinterlegten öffentlichen Schlüssel auch im Tresor (über den Fingerabdruck), trägt es diesen Schlüssel am Host ein. Sonst trägt es die Identität ein, die an der Verbindung gewählt ist.
- Nimmt ein Server nur Schlüssel an und ist für die Verbindung keiner vorgesehen, endet die Anmeldung sofort; Glowport sagt dann, dass es daran liegt.
- Das Passwort aus Cloud-Init gibt Proxmox nicht heraus.
- Kennt Proxmox keine Adresse (kein Cloud-Init, kein Gastagent, Maschine aus), sagt Glowport das; die Adresse lässt sich dann von Hand eintragen.

### Hosts anlegen und aktuell halten

- **Vorschau:** alle VMs und Container einer Verbindung mit dem, was Glowport über sie weiß (Adresse, Benutzer, Schlüssel, Betriebssystem). Du hakst an, was ein Host werden soll, und wählst die Gruppe. Vorlagen und Maschinen ohne Adresse sind nicht vorausgewählt.
- **Im persönlichen Tresor:** Die Hosts liegen dort, wo auch die Verbindung liegt; zur Wahl stehen deshalb nur Gruppen des persönlichen Tresors. Verschiebst du einen solchen Host in einen geteilten Tresor, fällt seine Verknüpfung weg (die anderen Mitglieder hätten die Verbindung nicht).
- **Ohne bekannte Adresse** steht am neuen Host vorerst der Name der Maschine. Sobald Proxmox eine Adresse kennt (die Maschine läuft, der Gastagent antwortet), trägt Glowport sie ein.
- **Verknüpfung:** Ein so angelegter Host merkt sich, zu welcher Maschine er gehört. Er trägt in der Host-Übersicht eine Marke mit ihrem Zustand und in seinen Einzelheiten ihren Zustand samt den Knöpfen zum Starten, Herunterfahren und Neustarten. Ist die Maschine aus, gibt es dort „Starten und verbinden“: Glowport startet sie und öffnet den Tab, sobald sie Verbindungen annimmt (es wartet bis zu zwei Minuten). „Verknüpfung lösen“ trennt Host und Maschine wieder; der Host bleibt.
- **Wiedererkannt** wird eine Maschine an ihrer Nummer. Zieht sie im Cluster auf einen anderen Knoten um, bleibt die Verknüpfung.
- **Aktuell halten:** Ändert sich in Proxmox die Adresse oder der Name, zieht der Host nach. Was du am Host selbst geändert hast, bleibt: Ein von Hand gesetzter Name oder eine von Hand gesetzte Adresse wird nicht überschrieben. Kennt Proxmox gerade keine Adresse (Maschine aus, kein Cloud-Init), bleibt die letzte bekannte.
- **Wie oft gefragt wird:** Die Liste der Maschinen liest Glowport alle zehn Sekunden. Die Einstellungen einer Maschine und ihre Adresse merkt es sich eine Minute, damit der Server nicht bei jedem Nachlesen für jede Maschine gefragt wird; „Neu lesen“ fragt sofort alles neu.
- **Neue Maschinen** werden nicht von selbst zu Hosts. Die Seite zeigt, wie viele noch nicht angelegt sind.
- **Gelöschte Maschinen:** Der Host bleibt und ist als „in Proxmox nicht mehr vorhanden“ gekennzeichnet. Glowport löscht nie von selbst einen Host.
- Abgeglichen wird, wenn die Seite „Proxmox“ oder die Host-Übersicht offen ist, nicht im Hintergrund.

## Sicherheit

- Das Geheimnis des Tokens liegt verschlüsselt im Tresor und geht nur an den Proxmox-Server, zu dem es gehört, über HTTPS.
- Glowport fragt kein sudo-Passwort ab und speichert keines.
- Alles, was etwas anhält oder beendet, hat eine Rückfrage, die das Ziel beim Namen nennt.
- Namen von Containern, Diensten und Prozessen kommen vom Server. Sie gehen nie ungeprüft in einen Befehl: Glowport setzt nur Kennungen ein, die es selbst gelesen und auf ihre Form geprüft hat.
- In einem geteilten Tresor mit Leserecht gilt weiter: verbinden ja, ändern nein. Die Reiter der Seitenleiste gehören zur Sitzung und stehen jedem offen, der verbunden ist; was er dort darf, bestimmen seine Rechte auf dem Server.

## Nicht in dieser Fassung

- Docker: Compose-Projekte, Images, Volumes, Netze, Podman.
- Proxmox: Konsole im Fenster, Snapshots, Sicherungen, Anlegen und Löschen von Maschinen, Speicher, Cluster-Verwaltung, Anmeldung mit Benutzer und Passwort statt Token, Verbindungen in geteilten Tresoren.
- Das einstellbare Aktualisierungsintervall (vorgemerkter Wunsch) kommt nicht stillschweigend mit; es bleibt vorgemerkt.

## Offene Punkte

- **Die Proxmox-Schnittstelle ist bisher nur nachgelesen, nichts davon ausprobiert.** Welche Wege und Rechte Proxmox 9 genau verlangt, zeigt sich am Server des Users; dafür legt er einen Token an und trägt ihn in Glowport ein.
- Docker gibt es auf diesem PC nicht. Das Lesen der Ausgaben wird an aufgezeichneten Beispielen geprüft, der Rest am Server des Users.
- Fünf Reiter in einer schmalen Leiste: Wie sie aussehen, zeigen die Entwürfe vor dem Bau.

## Reihenfolge des Baus

1. **Kern für die Seitenleiste:** Befehle und das Lesen ihrer Ausgaben für Docker, Dienste und Prozesse, die Stufen der Rechte, Prüfung der Kennungen. Tests an aufgezeichneten Ausgaben; Dienste und Prozesse zusätzlich am Ubuntu im WSL.
2. **Entwürfe** der neuen Bildschirme (Reiter, Proxmox-Seite, Vorschau, Marke am Host) als Bilder zur Abnahme.
3. **Seitenleiste anschließen:** Brücke, drei Reiter, Tabs für Logs und Shell, Ende-zu-Ende mit dem Testserver.
4. **Proxmox im Kern:** Zugriff auf die Schnittstelle, Prüfung des Zertifikats mit gemerktem Fingerabdruck, Zusammenführen von Adresse und Anmeldung, Tests gegen einen nachgebauten Proxmox-Server.
5. **Proxmox im Tresor:** Verbindung als neuer Datensatz, Verknüpfung am Host, Aktuell-Halten.
6. **Proxmox-Seite, Vorschau, Marke und Knöpfe am Host**, Ende-zu-Ende gegen den nachgebauten Server.
7. **Am Server des Users:** Token anlegen, ausprobieren, nachziehen, was sich dort anders verhält. Übergabe mit Prüfliste.
