# RDP und FTP/FTPS

Beschreibung für Meilenstein 11. **Stand:** vom User freigegeben am 2026-10-12. **FTP und FTPS sind vollständig gebaut** (samt Importen und Schnellverbindung) und liegen ihm zum Testen vor. **RDP ruht auf seine Entscheidung** (2026-10-12 „Warten, erst FTP bauen“, am 2026-10-13 bestätigt: kein Hilfsprogramm): Der Baukasten lässt sich noch nicht ins selbe Programm bauen wie die SSH-Bibliothek; der RDP-Kern liegt fertig geprüft bereit.

## Kurzfassung

- **RDP:** Ein Windows-Rechner (oder ein Linux mit xrdp) öffnet sich als eigener Tab, wie ein Terminal. Bild, Tastatur, Maus; die Größe folgt dem Tab; Text und Dateien gehen über die Zwischenablage; der Ton des entfernten Rechners läuft über deine Lautsprecher.
- **FTP und FTPS:** Ein FTP-Server öffnet sich im Dateimanager, den es schon gibt: zwei Spalten, Übertragungen mit Warteschlange, Ansehen und Bearbeiten. FTPS ist die Vorgabe, unverschlüsseltes FTP geht mit deutlicher Warnung.
- **Proxmox:** Windows-Maschinen verbinden per RDP statt SSH.

## Entscheidungen des Users (2026-10-12, über das Auswahl-Werkzeug)

| Frage | Entscheidung |
|---|---|
| Was kann RDP außer Bild, Tastatur, Maus? | **Text-Zwischenablage, Ton und Dateien über die Zwischenablage.** |
| Wohin gehen Windows-Taste, Alt+Tab und Ähnliches? | **Nur im Vollbild an den entfernten Rechner**, sonst bleiben sie bei deinem PC. |
| Unverschlüsseltes FTP? | **Ja, mit Warnung.** FTPS ist die Vorgabe. |
| Windows-Maschinen auf der Proxmox-Seite per RDP? | **Ja, in diesem Meilenstein.** |

## Ergebnis des Versuchs zu RDP (2026-10-12)

Der Plan sah vor, den Baukasten IronRDP erst auszuprobieren. Ergebnis: **Er trägt.** In einem Wegwerf-Programm hat sich der Client an einem nachgebauten RDP-Server angemeldet (über TLS und über NLA), ein falsches Passwort wurde abgelehnt, das Bild kam Pixel für Pixel richtig an, Tasten, Zeichen und Maus kamen beim Server an.

Zwei Dinge baue ich anders, als der Baukasten sie fertig mitbringt:

- **Zertifikat:** Der fertige Client nimmt jedes Zertifikat an, ohne es zu zeigen. Glowport zeigt den Fingerabdruck beim ersten Verbinden und merkt ihn sich (siehe „Sicherheit“).
- **Bild:** Der fertige Client schickt bei jeder Änderung das ganze Bild. Glowport schickt nur die geänderten Bereiche ans Fenster.

Nicht ausprobiert, weil es dafür ein echtes Windows braucht: Größenänderung im Betrieb, Zwischenablage, Ton, Tempo bei großem Bild. Das zeigt sich beim Bau und bei deiner Prüfung.

## RDP

### Host anlegen

Im Host-Editor gibt es beim Protokoll neben SSH, Telnet und Seriell jetzt **RDP** (Port 3389). Ein RDP-Host hat:

- **Adresse, Port, Gruppe, Name, Betriebssystem-Symbol** wie jeder Host.
- **Anmeldung:** Benutzer und Passwort, direkt am Host oder über eine Identität aus dem Tresor (dieselben Identitäten wie bei SSH; Schlüssel spielen bei RDP keine Rolle). Eine Domäne schreibst du in den Benutzer: `FIRMA\emir` oder `emir@firma.local`.
- **Größe:** „an den Tab anpassen“ (Vorgabe) oder eine feste Auflösung, die dann passend verkleinert gezeigt wird.
- **Ton:** an (Vorgabe) oder aus.
- **Sprung-Server:** Ein RDP-Host kann wie ein SSH-Host über einen Sprung-Server laufen. Glowport baut dann den SSH-Tunnel selbst auf; der RDP-Port muss nicht offen im Netz stehen.

Die Schnellverbindung versteht `rdp://adresse` und `adresse:3389`.

### Verbinden

- Anmeldung mit **NLA** (das verlangt Windows von sich aus); bietet der Server das nicht an, mit TLS. Die alte, unverschlüsselte RDP-Sicherheit baut Glowport nicht.
- Fehlt das Passwort, fragt Glowport wie bei SSH, mit dem Haken „im Tresor speichern“.
- Verständliche Meldungen für die üblichen Fälle: falsches Passwort, Konto gesperrt oder Passwort abgelaufen, Benutzer darf sich nicht per Remotedesktop anmelden, Server nicht erreichbar, Zertifikat hat sich geändert.
- Ist an dem Rechner schon jemand angemeldet, entscheidet Windows wie gewohnt (bei Windows 11 Pro wird die andere Sitzung getrennt). Glowport ändert daran nichts.

### Der Tab

- Ein RDP-Tab steht in der Tab-Leiste neben den Terminals, mit eigenem Symbol. Er lässt sich umbenennen, verschieben und in ein anderes Fenster ziehen, ohne dass die Verbindung abreißt.
- Über dem Bild liegt eine schmale Leiste: **Strg+Alt+Entf**, **Vollbild**, **Ton an/aus**, **Trennen**, dazu die Anzeige der Auflösung.
- **Größe:** Ziehst du am Fenster, bekommt der entfernte Rechner nach einem kurzen Moment die neue Auflösung, ohne neue Anmeldung. Kann der Server das nicht (ältere Windows-Fassungen, manche xrdp), wird das Bild passend verkleinert oder vergrößert.
- **Skalierung:** Auf einem Bildschirm mit Vergrößerung (z. B. 150 %) bekommt der entfernte Rechner dieselbe Vergrößerung mitgeteilt, damit die Schrift nicht winzig wird.
- **Mauszeiger:** Glowport zeigt den Zeiger des entfernten Rechners (Pfeil, Textmarke, Größe ändern …).
- **Abriss:** Reißt die Verbindung ab, bleibt das letzte Bild abgedunkelt stehen, mit „Neu verbinden“. Trennst du selbst, schließt der Tab mit der gewohnten Rückfrage.
- Ein RDP-Tab lässt sich nicht teilen, hat keine Seitenleiste (Info, Snippets, Docker …), keinen Mitschnitt und nimmt an der Eingabe an mehrere Terminals nicht teil.

### Tastatur

- Glowport schickt die **Tasten**, nicht die Zeichen. Welches Zeichen daraus wird, entscheidet die Tastaturbelegung des entfernten Rechners, genau wie bei der Remotedesktop-App von Windows.
- **Im Fenster** bleiben Windows-Taste, Alt+Tab, Alt+F4, Strg+Esc und die Kürzel von Glowport selbst (Tab wechseln, Palette) bei deinem PC. Alles andere geht an den entfernten Rechner.
- **Im Vollbild** gehen auch diese Kürzel an den entfernten Rechner. Heraus kommst du mit **Strg+Alt+Pause** oder über die Leiste, die erscheint, wenn die Maus den oberen Rand berührt.
- Strg+Alt+Entf fängt Windows immer selbst ab; dafür gibt es den Knopf in der Leiste.

### Zwischenablage: Text

Kopierst du auf einer Seite Text, kannst du ihn auf der anderen einfügen, in beide Richtungen, auch mit Umlauten und Zeilenumbrüchen. Je Host abschaltbar.

### Zwischenablage: Dateien

- **Von deinem PC auf den entfernten Rechner:** Dateien oder Ordner im Explorer kopieren, im entfernten Rechner einfügen. Der entfernte Rechner holt sie sich dann von Glowport.
- **Vom entfernten Rechner auf deinen PC:** Kopierst du dort Dateien, zeigt die Leiste des Tabs „3 Dateien in der Zwischenablage – Herunterladen“. Glowport lädt sie in den Download-Ordner (oder einen Ordner deiner Wahl), zeigt den Fortschritt und legt sie danach in deine Zwischenablage; dann fügst du sie im Explorer ein, wo du willst.
  Der Umweg hat denselben Grund wie beim Ziehen in den Explorer aus Meilenstein 5: Dateien, die erst beim Einfügen geladen werden, sind unter Windows aufwendig. Die elegante Fassung (direkt Strg+V im Explorer) kann später folgen.
- Je Host abschaltbar, zusammen mit der Text-Zwischenablage.

**Das ist der unsicherste Teil des Meilensteins.** Der Baukasten kann es dem Aufbau nach, erprobt ist es am wenigsten. Zeigt sich beim Bau, dass es gegen ein echtes Windows nicht verlässlich läuft, sage ich dir das, und die Dateien bleiben vorerst draußen, statt dass du eine wacklige Fassung bekommst.

### Ton

Der Ton des entfernten Rechners läuft über das Standard-Ausgabegerät deines PCs. Knopf in der Leiste zum Stummschalten, Schalter am Host. Nur Wiedergabe; dein Mikrofon geht nicht an den entfernten Rechner.

## FTP und FTPS

### Host anlegen

Beim Protokoll gibt es außerdem **FTP**. Ein FTP-Host hat:

- **Verschlüsselung:**
  - **FTPS, ausdrücklich** (Vorgabe, Port 21): Die Verbindung beginnt normal und schaltet sofort auf TLS um. Das können fast alle heutigen Server.
  - **FTPS, von Anfang an** (Port 990): die ältere Art, bei manchen Hostern noch üblich.
  - **Keine** (Port 21): unverschlüsselt, siehe „Warnung“.
- **Anmeldung:** Benutzer und Passwort (direkt oder über eine Identität) oder „anonym“.
- **Startordner** (wahlweise).

### Verbinden

Ein FTP-Host hat kein Terminal. „Verbinden“ öffnet ihn im **Dateimanager** (Seite „Dateien“), links dein PC, rechts der Server. In der Auswahl der Orte dort steht er neben den SSH-Hosts.

**Schnellverbindung** (Suche, Strg+K) ohne gespeicherten Host: `ftp://benutzer@adresse:port/ordner` ist unverschlüsselt (mit Warnung, ohne „nicht erneut fragen“), `ftps://…` und `ftpes://…` sind FTPS, ausdrücklich; `ftps://` auf Port 990 heißt FTPS von Anfang an. Ohne Benutzer wird anonym angemeldet. Das Passwort fragt Glowport und speichert es nicht; ein Passwort in der Adresse wird nicht angenommen, weil es lesbar im Suchfeld stünde. Ein bestätigtes Zertifikat steht wie sonst bei den bekannten Hosts. Kann ein mit `ftp://` geöffneter Server FTPS, bietet die Warnung an, ihn verschlüsselt zu öffnen.

### Was im Dateimanager geht

| Geht wie bei SFTP | Geht eingeschränkt | Gibt es bei FTP nicht |
|---|---|---|
| Ordner ansehen, sortieren, Pfadleiste | **Rechte ändern:** nur, wenn der Server es anbietet; sonst fehlt der Menüpunkt | Suche im Inhalt von Dateien |
| Hoch- und Herunterladen mit Warteschlange, Anhalten, **Fortsetzen** | **Suche nach Namen:** Glowport geht die Ordner selbst durch (höchstens 5000 Einträge), das dauert länger | „Folgen“ (dem Ordner eines Terminals) |
| Ordner anlegen, umbenennen, löschen (auch samt Inhalt) | **Änderungszeit erhalten:** nur, wenn der Server es anbietet | Namen der Besitzer |
| Ansehen und Bearbeiten im eingebauten Editor oder im eigenen Programm | **Verknüpfungen** werden gezeigt, aber nicht aufgelöst | |
| Ordner vergleichen | | |
| Ziehen zwischen den Spalten, Ziehen aus dem Explorer | | |

- Glowport arbeitet im **passiven Modus** (der Server öffnet keinen Rückweg zu dir); das geht durch Router und Firewalls. Den aktiven Modus gibt es nicht.
- FTP kann je Verbindung nur eine Datei gleichzeitig übertragen. Für gleichzeitige Übertragungen meldet sich Glowport mehrfach an, höchstens so oft wie die Warteschlange gleichzeitig arbeitet. Erlaubt der Server weniger, wartet die nächste Übertragung und versucht es erneut (bis zu sechsmal, alle zwei Sekunden); so wird der Rest nacheinander abgearbeitet.
- Kopieren zwischen FTP und SFTP (rechts FTP, links ein SSH-Host) geht; die Daten laufen dabei über deinen PC.

### Warnung bei unverschlüsseltem FTP

- Im Host-Editor steht bei „Keine“ in Rot, dass **Passwort und Dateien für jeden auf dem Weg lesbar** sind.
- Auf der Host-Karte und in der Pfadleiste des Dateimanagers steht ein offenes rotes Schloss.
- Beim ersten Verbinden fragt Glowport nach, mit „Für diesen Host nicht erneut fragen“.
- Bietet ein Server, der als „Keine“ angelegt ist, TLS an, schlägt Glowport beim Verbinden vor, auf FTPS umzustellen.

## Proxmox

- Bei Maschinen, die Proxmox als Windows führt, heißt „Verbinden“ **RDP**: Adresse vom Gastagenten, Port 3389, Anmeldung mit der Identität der Proxmox-Verbindung oder per Rückfrage.
- „Hosts anlegen“ legt sie als RDP-Hosts an und hält sie wie die anderen aktuell.
- „Starten und verbinden“ wartet bei Windows, bis der RDP-Port antwortet.
- Eine eigene Identität für Windows-Maschinen lässt sich an der Proxmox-Verbindung hinterlegen (neben der für Linux), weil dort selten derselbe Benutzer gilt.

## Importe

MobaXterm, WinSCP, FileZilla, Xshell und die CSV-Tabelle haben FTP-Einträge bisher ausgelassen und in der Vorschau genannt. Sie werden jetzt übernommen (Adresse, Port, Benutzer, Verschlüsselung; Passwörter wie bisher nur, wo die Quelle sie lesbar enthält; ohne Benutzer anonym). Nennt die Quelle die Verschlüsselung nicht sicher (MobaXterm, Xshell, „FTP“ bei FileZilla, das dort „verschlüsselt, wenn möglich“ heißt), wird der Host FTPS und trägt in der Vorschau den Hinweis „Verschlüsselung prüfen“. In der CSV-Tabelle heißt `ftp` unverschlüsselt, `ftps` und `ftpes` verschlüsselt. Glowports eigenes Format und die Tabelle tragen FTP-Hosts auch beim Export. RDP-Einträge bleiben ausgelassen, solange RDP ruht.

## Abgleich (Sync)

RDP- und FTP-Hosts gleichen sich ab wie alle Hosts. Am Sync-Server ändert sich nichts. **Ein Gerät mit einer älteren Fassung von Glowport kennt die neuen Protokolle nicht**; es zeigt solche Hosts, kann sie aber nicht öffnen. Ich prüfe, dass es sie beim Bearbeiten nicht beschädigt.

## Sicherheit

- **Zertifikate wie bei Proxmox und bekannten Hosts:** Ist das Zertifikat des Servers anerkannt, geht es ohne Rückfrage. Ist es selbst erstellt (bei RDP fast immer), zeigt Glowport beim ersten Mal den Fingerabdruck; nach deinem Haken wird er gemerkt. **Ändert er sich später, verbindet Glowport nicht** und sagt es deutlich. Gemerkte Fingerabdrücke stehen auf der Seite „Bekannte Hosts“.
- **Das Passwort geht erst an den Server, wenn das Zertifikat anerkannt oder bestätigt ist.** Das gilt für RDP und FTPS.
- Passwörter liegen im Tresor und kommen nie in die Oberfläche; die Anmeldung macht der Kern.
- Dateien vom entfernten Rechner werden nur auf deinen Knopfdruck geladen, nie von selbst. Dateinamen werden bereinigt, damit nichts außerhalb des Zielordners landet.
- Der entfernte Rechner sieht deine Zwischenablage nur, solange der RDP-Tab den Fokus hat.

## Nicht in dieser Fassung

- RDP: Drucker, Laufwerke und Smartcards durchreichen, Mikrofon, mehrere Bildschirme, Remotedesktop-Gateway, einzelne Programme statt des ganzen Bildschirms (RemoteApp), `.rdp`-Dateien öffnen, Aufzeichnen der Sitzung.
- FTP: aktiver Modus, direktes Kopieren von Server zu Server, Anmeldung mit Zertifikat.
- Dateien vom entfernten Rechner direkt mit Strg+V im Explorer einfügen (siehe oben).

## Offene Punkte

- **Alles am echten Windows.** Der Versuch lief gegen einen nachgebauten Server. Ob Größenänderung, Zwischenablage und Ton gegen Windows 10/11 und Windows Server so laufen, zeigt sich erst dort. Dafür brauche ich am Ende deine Prüfung an einer deiner Windows-Maschinen.
- **Dateien über die Zwischenablage** (siehe dort).
- **Tempo bei großem Bild** (Video, 4K): Der Baukasten rechnet ohne Grafikkarte. Für Verwaltung reicht das sicher, für Filme wahrscheinlich nicht.
- **Kürzel im Vollbild:** Das Abfangen von Windows-Taste und Alt+Tab braucht einen eigenen Tastatur-Haken unter Windows. Manche Virenscanner beäugen so etwas; er ist nur aktiv, solange ein RDP-Tab im Vollbild den Fokus hat.
- **Eigenheiten von FTP-Servern:** Ältere Server liefern Ordnerlisten in eigenen Formaten. Geprüft wird gegen einen eigenen Test-Server und die verbreiteten Formate; Exoten zeigen sich im Betrieb.

## Reihenfolge des Baus

1. **RDP im Kern:** neue Crate, Verbinden (TLS, NLA, Fingerabdruck), Bild als geänderte Bereiche, Eingaben, Größenänderung; nachgebauter RDP-Server im Testserver; Tests.
2. **Entwürfe:** RDP-Tab mit Leiste, Vollbild, Rückfragen, Host-Editor für RDP und FTP, FTP im Dateimanager mit Warnung, Proxmox. Zum Ansehen, gebaut gegen Beispieldaten.
3. **RDP in der Oberfläche:** Tab, Zeichnen, Tastatur und Maus, Vollbild mit Kürzeln, Abriss und neu verbinden, Sprung-Server; Ende-zu-Ende-Prüfung.
4. **Zwischenablage: Text.**
5. **FTP und FTPS:** Kern, gemeinsame Form für SFTP und FTP im Dateimanager und in den Übertragungen, nachgebauter FTP-Server, Warnung; Ende-zu-Ende-Prüfung.
6. **Ton.**
7. **Zwischenablage: Dateien.**
8. **Proxmox und Importe.**
9. **Deine Prüfung** mit Checkliste an einem echten Windows und einem echten FTP-Server.
