# Mosh

Beschreibung für Meilenstein 12. **Stand:** vom User freigegeben am 2026-10-14.

## Kurzfassung

- **Mosh ist ein Schalter an einem SSH-Host:** „Über Mosh verbinden“. Angemeldet wird wie immer per SSH (Passwort, Schlüssel, Agent, Sprung-Server, alle Rückfragen wie gewohnt). Danach startet Glowport auf dem Server `mosh-server`, und das Terminal läuft über Mosh: verschlüsselt über UDP, übersteht WLAN-Wechsel, Ruhezustand und Aussetzer, und Getipptes erscheint sofort, auch bei langsamer Leitung.
- **Seitenleiste, Dateien und Snippets** laufen über eine SSH-Verbindung daneben. Reißt sie ab, läuft das Terminal weiter; die SSH-Verbindung baut Glowport bei Bedarf von selbst neu auf.
- **Fehlt `mosh-server` auf dem Server**, verbindet Glowport ganz normal per SSH und zeigt im Tab einen Hinweis mit dem Befehl zum Installieren.
- Schnellverbindung: `mosh benutzer@host`.

## Entscheidungen des Users (2026-10-14, über das Auswahl-Werkzeug)

| Frage | Entscheidung |
|---|---|
| Welche Bibliothek? | **`mosh-client`** (MIT oder Apache-2.0). Glowport bleibt MIT. Mosh geht damit nur über IPv4. Die übrigen Rust-Umsetzungen sind GPL-3 und hätten Glowport insgesamt zu GPL gemacht. |
| Wie wählt man Mosh? | **Schalter am SSH-Host**, dazu Schnellverbindung `mosh benutzer@host`. Kein eigenes Protokoll in der Auswahl. |
| Seitenleiste, Dateien, Snippets im Mosh-Tab? | **SSH-Verbindung daneben offen**, die sich nach einem Abriss selbst neu aufbaut. |
| `mosh-server` fehlt auf dem Server? | **Per SSH verbinden mit Hinweis** samt Installationsbefehl. |

## Ergebnis des Versuchs (2026-10-14)

`mosh-client` 0.1.4 gegen `mosh-server` 1.4.0 im WSL-Ubuntu dieses PCs: Sitzung steht 25–40 ms nach dem Start des Servers. Eingabe und Ausgabe, Umlaute, neue Fenstergröße, viel Ausgabe (`seq 1 200000` in 30 ms, Mosh schickt nur den Endstand des Bildschirms), Vollbild-Programme, sauberes Ende nach `exit`. **Sechs Sekunden ohne Leitung** (UDP im WSL verworfen): Was der Server währenddessen schrieb, kam 0,13 s nach der Freigabe an. Nicht geprüft: ein echter Netzwechsel mit neuer Adresse (laut der Bibliothek getestet), fremde Server.

## Host anlegen

Im Host-Editor bei SSH, im Bereich der Verbindung:

- **Schalter „Über Mosh verbinden“** (Vorgabe aus). Wie die anderen SSH-Einstellungen auch an einer Gruppe einstellbar und vererbt.
- Darunter, nur bei eingeschaltetem Schalter, unter „Erweitert“:
  - **Lokales Echo:** Automatisch (Vorgabe, wie Mosh selbst: zeigt Getipptes sofort, sobald die Leitung langsam ist), Immer, Aus.
  - **UDP-Port oder Bereich** (leer = Mosh wählt selbst, 60000–61000). Für Server hinter einer Firewall, die nur einen Port freigibt, etwa `60001` oder `60001:60010`.
  - **Pfad zu `mosh-server`** (leer = wie auf dem Server gefunden). Für Installationen außerhalb des Suchpfads, etwa `~/.local/bin/mosh-server`.

Die Host-Karte und die Liste zeigen ein kleines „Mosh“ neben „SSH“.

## Verbinden

1. SSH-Verbindung wie bisher, mit allen Rückfragen (unbekannter Server, Passwort, Einmalcode).
2. Glowport ruft auf dem Server `mosh-server new -s -c 256 -l LANG=…` auf (Sprache aus der Umgebung des Hosts, sonst `C.UTF-8`; mit Port und Pfad aus den Einstellungen). Der Server antwortet mit Port und einem frischen Sitzungsschlüssel.
3. **Adresse für UDP:** bei direkter Verbindung die IPv4-Adresse, mit der die SSH-Verbindung tatsächlich zustande kam; mit Proxy oder Sprung-Server die IPv4-Adresse des Hosts, wie dieser PC sie auflöst.
4. Das Terminal wechselt auf Mosh. Die SSH-Verbindung bleibt für die Seitenleiste offen.

**Geht Mosh nicht zustande, wird es eine normale SSH-Sitzung mit Hinweis im Tab** (die SSH-Verbindung steht ja schon). Gründe und Hinweise:

| Lage | Hinweis |
|---|---|
| `mosh-server` fehlt | „mosh-server ist auf dem Server nicht installiert. Per SSH verbunden.“ Dazu der passende Befehl, je nach erkanntem System: `sudo apt install mosh` (Debian, Ubuntu), `sudo dnf install mosh` (Fedora, RHEL), `sudo pacman -S mosh` (Arch), `sudo apk add mosh` (Alpine), sonst ein Verweis auf mosh.org. Kopierbar. |
| Keine IPv4-Adresse | „Mosh braucht eine IPv4-Adresse; dieser Host hat nur IPv6. Per SSH verbunden.“ |
| Keine Antwort über UDP (10 s) | „Mosh-Server antwortet nicht über UDP (Port …). Meist sperrt eine Firewall die Ports 60000–61000. Per SSH verbunden.“ |
| `mosh-server` meldet einen Fehler | Seine erste Zeile, gekürzt, dazu „Per SSH verbunden.“ |

Der Hinweis steht als Leiste oben im Terminal, schließbar; der Tab trägt dann kein „Mosh“.

## Der Tab

- Im Kopf des Terminals ein Zeichen **„Mosh“** neben „Verbunden“.
- **Unterbrochene Leitung:** Hört Glowport länger als ein paar Sekunden nichts vom Server, erscheint oben eine Leiste wie beim Original: „Keine Verbindung zum Server seit 12 s. Mosh verbindet von selbst wieder.“ Tippen geht weiter, das Lokale Echo zeigt es unterstrichen an, bis der Server es bestätigt. Kommt die Leitung zurück, verschwindet die Leiste. Der Tab endet nicht; die Einstellung „Verhalten bei Abriss“ betrifft Mosh-Tabs nicht.
- **Ende:** wenn die Shell endet (`exit`), wenn man den Tab schließt, oder wenn der Server die Sitzung beendet. Schließen beendet `mosh-server` sauber.
- **Seitenleiste, Dateien, Snippets, Port-Regeln dieser Sitzung** nutzen die SSH-Verbindung daneben. Ist sie gerade getrennt, zeigen sie „SSH-Verbindung getrennt, das Terminal läuft weiter über Mosh“ und versuchen es beim nächsten Öffnen oder Aktualisieren neu, mit denselben Anmeldedaten wie beim ersten Mal (aus dem Tresor oder aus dem Speicher dieser Sitzung, nie auf die Platte). Wäre dafür eine neue Rückfrage nötig (Einmalcode), fragt Glowport erst, wenn man in der Seitenleiste auf „Neu verbinden“ klickt.
- **Zurückscrollen:** Mosh überträgt nur den sichtbaren Bildschirm, keinen Verlauf. Der Verlauf im Tab enthält, was Glowport zu sehen bekam; bei viel Ausgabe auf einmal fehlen Zeilen. Das ist eine Eigenart von Mosh; wer Verlauf braucht, nimmt `tmux` oder `screen`. Steht einmal im Tab, als Hinweis beim ersten Mosh-Tab.
- **Mitschnitt** zeichnet auf, was im Terminal ankommt (also ohne die übersprungenen Zwischenstände).
- **Teilen, Mehrfach-Eingabe, eigenes Fenster** gehen wie bei SSH.

## Schnellverbindung

`mosh benutzer@host` und `mosh benutzer@host:port` (Port ist der SSH-Port) in der Suche oder Schnellverbindung. Angemeldet wird wie bei `ssh benutzer@host`.

## Importe

- CSV-Tabelle: Die Spalte Protokoll „mosh“ wird ein SSH-Host mit eingeschaltetem Mosh (heute wird daraus ein gewöhnlicher SSH-Host).
- MobaXterm: Sitzungen der Art Mosh werden SSH-Hosts mit Mosh, sofern sich die Art in der Datei sicher erkennen lässt; sonst wie bisher als SSH mit Hinweis in der Vorschau.
- Export als Tabelle schreibt „mosh“ in die Spalte Protokoll.

## Abgleich (Sync)

Die neuen Einstellungen sind gewöhnliche Felder am Host und gehen mit. Ältere Glowport-Fassungen auf anderen Geräten verbinden solche Hosts einfach per SSH. Der Sync-Server ändert sich nicht.

## Sicherheit

- Der Sitzungsschlüssel kommt über die schon geprüfte SSH-Verbindung, lebt nur im Speicher und wird nirgends gespeichert. Jedes UDP-Paket ist mit AES-128-OCB verschlüsselt und geprüft; fremde Pakete verwirft die Bibliothek.
- Mosh vertraut nur der Adresse, die aus der SSH-Verbindung stammt; Pakete von anderswo nimmt es erst an, wenn sie gültig verschlüsselt sind (so funktioniert der Netzwechsel).
- Die Ausgabe von `mosh-server` gilt als nicht vertrauenswürdig: begrenzt gelesen, nur die eine Zeile `MOSH CONNECT` wird ausgewertet.
- Agent-Weiterleitung und Umgebungsvariablen wirken wie bei SSH auf die Shell, die `mosh-server` startet.

## Prüfung

- Kern: Tests gegen `mosh-server` im WSL, wenn er da ist (sonst übersprungen, mit Meldung): Aufbau, Eingabe, Ausgabe, Größe, Ausfall der Leitung, Ende, fehlender `mosh-server`, Rückfall auf SSH.
- Ende-zu-Ende: Der Testserver bekommt eine Weiterleitung für UDP (`127.0.0.1` → WSL), weil WSL kein UDP über `127.0.0.1` durchreicht. Damit lassen sich Aussetzer und ein Wechsel des Absender-Ports nachstellen. Ohne WSL-Mosh werden diese Fälle übersprungen und als übersprungen gezählt.
- Am Ende ein Versuch von dir gegen einen deiner echten Server.

## Nicht in dieser Fassung

- IPv6 für Mosh (kann die Bibliothek nicht).
- Mosh ohne SSH (etwa mit einem von Hand gestarteten `mosh-server`).
- Weiterleiten von Ports über Mosh (gibt es bei Mosh nicht; Port-Regeln laufen über die SSH-Verbindung daneben).

## Offene Punkte

- Die Bibliothek ist jung (ein Entwickler, Version 0.1.4, nur als Git-Abhängigkeit). Sie nagelt `aes` auf 0.9.1; russh nimmt damit dieselbe Fassung (0.9.2 und 0.9.3 bringen nur Leistung, keine Sicherheitskorrekturen).
- Wann die Leiste „Keine Verbindung“ erscheint, richtet sich nach der Meldung der Bibliothek; die Schwelle prüfe ich beim Bau.

## Reihenfolge des Baus

1. **Kern:** `mosh-client` einbinden; im Netz-Teil nach dem Anmelden `mosh-server` starten, Antwort lesen, Adresse bestimmen, Mosh-Sitzung mit denselben Ereignissen und Befehlen wie eine SSH-Sitzung (Ausgabe, Eingabe, Größe, Schließen, Kanal für Seitenleiste über SSH); Rückfall auf die Shell bei jedem Fehlschlag vor dem ersten Bild; neues Ereignis für Erreichbarkeit. Tests gegen den WSL-Server.
2. **SSH daneben:** Neuaufbau nach Abriss für die Kanäle der Seitenleiste.
3. **Tresor und Modell:** Felder `mosh`, `mosh_predict`, `mosh_port`, `mosh_server` an den SSH-Einstellungen, vererbt über Gruppen; Brücke.
4. **Oberfläche:** Schalter und Felder im Host-Editor, „Mosh“ an Karte, Liste und Tab, Leiste bei Unterbrechung, Hinweis beim Rückfall, Schnellverbindung `mosh …`, Texte deutsch und englisch.
5. **Importe und Export** (CSV, MobaXterm).
6. **Testserver mit UDP-Weiterleitung**, Ende-zu-Ende-Fälle, „Glowport Dev“ bauen und dir mit Prüfliste übergeben.
