# Tresor-Format von Glowport

Stand: 2026-10-10 · Version des Formats: 2 (Datensätze und Schlüsselkette unverändert seit 1) · Status: **umgesetzt in `crates/core`**

Dieses Dokument legt fest, wie Glowport Daten verschlüsselt ablegt. Es wird vor dem Code geschrieben, weil ein Fehler hier später am teuersten wäre: Das Format wird ab Meilenstein 9 unverändert synchronisiert und geteilt.

## In Kürze

- Alles, was du anlegst (Hosts, Gruppen, Identitäten, Schlüssel, Snippets, Port-Regeln, bekannte Hosts, Arbeitsbereiche), ist ein einzeln verschlüsselter Datensatz in einer Datei `vault.db`.
- Geöffnet wird der Tresor nur mit dem Master-Passwort. Es wird nirgends gespeichert und lässt sich nicht zurücksetzen.
- Wer die Datei, eine Sicherung oder später den Sync-Server in die Hand bekommt, sieht: wie viele Datensätze es gibt, wie groß sie sind und wann sie geändert wurden. Inhalt, Art und Namen sieht er nicht.
- Verwendet werden ausschließlich etablierte Verfahren aus geprüften Bibliotheken: Argon2id, HKDF-SHA-256, XChaCha20-Poly1305, X25519, Ed25519.

## Wovor der Tresor schützt und wovor nicht

| Schützt vor | Schützt nicht vor |
| --- | --- |
| Diebstahl von PC, Platte oder Sicherungsdatei | Schadsoftware, die unter deinem Benutzer läuft, während der Tresor offen ist |
| Anderen Benutzern am selben PC, die den Datenordner lesen | Jemandem, der am entsperrten Programm sitzt |
| Einem neugierigen oder gehackten Sync-Server (ab Meilenstein 9) | Einem schwachen Master-Passwort (Argon2id bremst das Raten, verhindert es aber nicht) |
| Vertauschen oder Verändern von Datensätzen in der Datei | Verlust des Master-Passworts (dann sind die Daten weg) |

## Schlüsselkette

```
Master-Passwort ─Argon2id(salt, Parameter)→ master_key (32 Byte)
master_key ─HKDF-SHA-256, info "glowport/kek/v1"──→ kek       entsperrt den Kontoschlüssel
master_key ─HKDF-SHA-256, info "glowport/auth/v1"─→ auth_key  Anmeldung am Sync-Server (ab M9)
kek ─entschlüsselt→ account_key (32 Byte, zufällig)
account_key ─entschlüsselt→ privater X25519-Schlüssel (Empfang geteilter Tresor-Schlüssel)
account_key ─entschlüsselt→ privater Ed25519-Schlüssel (Signatur eigener Datensätze)
account_key ─entschlüsselt→ vault_key (32 Byte, zufällig, einer je Tresor)
vault_key ─entschlüsselt→ jeden Datensatz dieses Tresors
```

- **Argon2id:** 256 MiB Speicher, 4 Durchläufe, 4 Fäden, Salz 16 zufällige Byte. Gemessen am 2026-10-04 auf dem PC des Users: 385 ms fürs Entsperren (mit den ursprünglich geplanten 64 MiB und 3 Durchläufen waren es nur 67 ms, deshalb angehoben). Die Werte stehen in der Datei und lassen sich bei einer Passwortänderung anheben.
- **Zwei abgeleitete Schlüssel aus dem master_key:** Der Sync-Server bekommt später nur `auth_key` zu sehen. Daraus lässt sich `kek` nicht berechnen.
- **Passwort ändern** heißt: neues Salz, neuer `kek`, `account_key` neu verpacken. Die Datensätze bleiben unangetastet. Alte Sicherungen bleiben mit dem alten Passwort lesbar.
- **Schlüsselpaare entstehen schon beim Anlegen des Tresors**, obwohl sie erst mit dem Teilen gebraucht werden. So ändert sich das Format in Meilenstein 9 nicht.
- **Teilen (ab M9):** Der `vault_key` eines geteilten Tresors wird für jedes Mitglied mit dessen öffentlichem X25519-Schlüssel verpackt (einmaliges Schlüsselpaar des Absenders, HKDF, XChaCha20-Poly1305). Einzelheiten kommen in `sync.md`.

## Verschlüsselung

Ein Verfahren für alles: **XChaCha20-Poly1305** mit 24 zufälligen Byte als Nonce je Vorgang (die Länge macht zufällige Nonces sicher).

Jeder Schlüsseltext ist an seinen Zweck gebunden. Die gebundenen Angaben (AAD) werden mitgeprüft, aber nicht verschlüsselt:

| Schlüsseltext | Schlüssel | Gebundene Angaben |
| --- | --- | --- |
| `account_key` | `kek` | `"glowport/account/v1"`, die Zahl 1 (die Fassung, mit der die Schlüsselkette festgelegt wurde; sie folgt der Formatversion der Datei nicht), Salz, Argon2-Parameter |
| private Schlüssel | `account_key` | `"glowport/x25519/v1"` bzw. `"glowport/ed25519/v1"`, zugehöriger öffentlicher Schlüssel |
| `vault_key` (eigener Tresor) | `account_key` | `"glowport/vault/v1"`, Tresor-ID |
| Datensatz | `vault_key` | `"glowport/record/v1"`, Tresor-ID, Datensatz-ID, Revision, Löschmarke |

Folgen daraus:

- Ein Datensatz lässt sich nicht an die Stelle eines anderen setzen und nicht in einen anderen Tresor verschieben, ohne dass das Entschlüsseln scheitert.
- Eine alte Fassung lässt sich nicht als neuere ausgeben. Das vollständige Zurückdrehen auf einen alten Stand durch einen böswilligen Server erkennt der Client daran, dass er sich je Datensatz die höchste gesehene Revision merkt (Thema von `sync.md`).
- Die Löschmarke ist mitgebunden und Grabsteine werden beim Lesen mitgeprüft. Ein Löschen lässt sich also weder vortäuschen noch rückgängig machen, ohne aufzufallen.
- Jedes Teil der gebundenen Angaben wird mit seiner Länge davor geschrieben, damit zwei verschiedene Aufteilungen nie dieselben Bytes ergeben.
- Ein falsches Master-Passwort zeigt sich beim Entpacken des `account_key`. Es gibt keinen gespeicherten Passwort-Vergleichswert.

**Signatur:** Jeder Datensatz trägt eine Ed25519-Signatur seines Autors über gebundene Angaben, Nonce und Schlüsseltext. Lokal ist das eine zusätzliche Prüfung, in geteilten Tresoren verhindert es, dass der Server Datensätze unterschiebt.

## Datensätze

Der Klartext eines Datensatzes ist JSON:

```json
{ "t": "host", "v": 1, "name": "web-01", "address": "10.0.10.11", "group": "…", "own": { "user": "deploy" } }
```

- `t` ist die Art, `v` die Fassung des Aufbaus dieser Art. **Die Art steht im verschlüsselten Teil**, von außen ist nicht zu sehen, ob ein Datensatz ein Host oder ein Schlüssel ist.
- **Unbekannte Felder bleiben erhalten.** Eine ältere Programmversion, die einen Datensatz einer neueren speichert, wirft nichts weg.
- **Löschen** hinterlässt einen Grabstein (leerer Inhalt, Markierung „gelöscht“, höhere Revision), damit das Löschen später auf anderen Geräten ankommt. Grabsteine werden lokal nach 90 Tagen entfernt, solange kein Sync eingerichtet ist.
- Arten in Meilenstein 1: `vault-info` (Name des Tresors), `group`, `host`. Meilenstein 2: `known-host`. Meilenstein 3: `key`, `identity`, `authority`. Meilenstein 4: `workspace`. Meilenstein 6: `forward`, `snippet`. Meilenstein 10: `proxmox`. Später: `color-scheme`.
- `host` trägt seit Meilenstein 8 in `protocol` eines von `ssh` (Vorgabe, wenn das Feld fehlt), `telnet`, `serial`. Ein anderes Wort hat eine neuere Programmversion gespeichert; es bleibt stehen, verbinden lässt sich damit nicht. Bei `serial` steht in `address` der Name des Ports (`COM3`, `/dev/ttyUSB0`) und in `serial` die Leitung: `{ "baud": 50…4000000, "dataBits": 5…8, "parity": "none" | "odd" | "even", "stopBits": 1 | 2, "flow": "none" | "software" | "hardware" }`. Die Leitung wird nicht vererbt. Von den vererbbaren Werten speichert ein Telnet-Host nur `user`, `port`, `reconnect`, `timeout`, `term`, `charset`, `scheme`, ein serieller nur `reconnect`, `charset`, `scheme`; `user` und `port` eines Telnet-Hosts gelten nur, wenn er sie selbst trägt (die Vorgaben einer Gruppe meinen SSH; ohne eigenen Port gilt 23). Ein Passwort trägt nur ein SSH-Host. Sprung-Server und Träger einer Port-Regel kann nur ein SSH-Host sein; ein Host, der das ist, lässt sich nicht auf ein anderes Protokoll umstellen.
- `workspace` trägt Name, `multi` (Multi-Exec beim Öffnen einschalten) und `layout`: einen Baum, dessen Knoten `{ "dir": "row" | "col", "ratio": 0…1, "a": …, "b": … }` eine Fläche in zwei Teile schneiden und dessen Blätter `{ "pane": { "kind": "host", "id": "…" } }` einen gespeicherten Host nennen oder, seit Meilenstein 8, mit `{ "pane": { "kind": "local", "shell": "wsl:Ubuntu" } }` ein lokales Terminal (die Kennung einer Shell des Rechners, höchstens 80 Zeichen; welche Shells es gibt, steht nicht im Tresor). Höchstens 32 Bereiche. Wird ein Host gelöscht, verliert jeder Arbeitsbereich dessen Bereiche im selben Schreibvorgang; einer ohne Bereiche wird gelöscht. Eingetippte Adressen (Schnellverbindungen) stehen nie im Tresor.
- `forward` ist eine Port-Regel: `name`, `kind` (`local`, `remote`, `dynamic`), `host` (Kennung des Hosts, über den sie läuft), `bindAddress` und `bindPort` (wo gelauscht wird: auf diesem Rechner, bei `remote` am Server), `destHost` und `destPort` (Ziel vom anderen Ende aus gesehen; bei `dynamic` leer und 0). Ob eine Regel läuft, steht nicht im Tresor. Wird ein Host gelöscht, verschwinden seine Regeln im selben Schreibvorgang.
- `snippet` ist ein gespeicherter Befehl oder ein Makro: `name`, `package` (Name des Pakets als Text, leer = keines; Pakete sind kein eigener Datensatz), `kind` (`command` oder `macro`), `command` (auch mehrzeilig, Variablen als `{{name}}` oder `{{name:vorgabe}}`, höchstens 16 KiB), `steps` (bei einem Makro: Liste aus `{ "wait": Millisekunden, "keys": Text }`, höchstens 2000 Schritte und 64 KiB Tasten), `hotkey` (fehlt oder etwa `Ctrl+Alt+R`; ein Kürzel gehört höchstens einem Snippet). Ein Makro enthält alles, was getippt wurde, also womöglich ein Passwort; es liegt wie jeder Datensatz verschlüsselt im Tresor, und seine Tasten erscheinen in keiner Debug-Ausgabe.
- `proxmox` ist eine Verbindung zu einem Proxmox-Server (`docs/verwaltung.md`): `name`, `address` (`https://host[:port]`, sonst nichts), `tokenId` (`benutzer@realm!name`), `secret` (das Geheimnis des Tokens; es erscheint in keiner Ansicht und in keiner Debug-Ausgabe), `fingerprint` (fehlt oder der bestätigte SHA-256-Fingerabdruck eines selbst erstellten Zertifikats, 32 Paare mit Doppelpunkten), `identity` (fehlt oder die Kennung der Identität, mit der sich Glowport an den Maschinen dieser Verbindung anmeldet; wird die Identität gelöscht, verschwindet der Verweis im selben Schreibvorgang). Sie liegt immer im persönlichen Tresor. Ein `host` kann mit einer Maschine verknüpft sein: `proxmox: { connection, node, vmid, kind, name, address }`; `kind` ist `qemu` oder `lxc`, `name` und `address` halten fest, was Glowport dem Host zuletzt selbst gegeben hat (nur solange der Host diesen Wert noch trägt, zieht er nach). Nur Hosts im persönlichen Tresor tragen eine Verknüpfung; beim Verschieben in einen geteilten Tresor und beim Duplizieren fällt sie weg, beim Löschen der Verbindung im selben Schreibvorgang auch. Eine Verknüpfung, deren Verbindung fehlt, zählt nicht.
- Das vererbbare Feld `scheme` an Hosts und Gruppen nennt die Kennung eines Farbschemas für das Terminal (Kleinbuchstaben, Ziffern, Bindestrich). Welche Schemata es gibt, weiß nur die Oberfläche. Selbst importierte Schemata liegen bis auf Weiteres in `settings.json` und nicht im Tresor; mit dem Sync (Meilenstein 9) sollen sie als `color-scheme` hierher umziehen, damit ein Host auf jedem Gerät gleich aussieht.
- `key` trägt Name, Art (`ed25519`, `ecdsa`, `rsa`), Länge, Fingerabdruck, den öffentlichen Schlüssel ohne Kommentar, den **privaten Schlüssel im OpenSSH-Format ohne eigene Passphrase** (ihn schützt die Verschlüsselung des Datensatzes), Herkunft (`generated`, `imported`) und den Zeitpunkt `addedAt`.
- `identity` trägt Name, Benutzer, optional die Kennung eines Schlüssels und optional ein Passwort.
- Hosts und Gruppen verweisen in ihren vererbbaren Werten mit `identity` und `key` auf diese Datensätze (leer = ausdrücklich keine(r)). Wird ein Schlüssel oder eine Identität gelöscht, löst der Kern die Verweise im selben Schreibvorgang.
- Vererbung wird nicht gespeichert, sondern beim Lesen berechnet: Ein Host speichert nur, was er selbst festlegt (`own`); alles andere kommt aus dem Gruppenpfad.

## Ablage

SQLite-Datei `vault.db` im Datenordner (`%APPDATA%\Glowport`, portabel im Ordner `data`).

| Tabelle | Inhalt |
| --- | --- |
| `meta` | Formatversion, Salz, Argon2-Parameter, verpackter `account_key`, öffentliche und verpackte private Schlüssel, Geräte-ID |
| `vaults` | Tresor-ID, verpackter `vault_key` |
| `records` | Datensatz-ID (16 zufällige Byte), Tresor-ID, Revision, Löschmarke, Änderungszeit, Autor, Nonce, Schlüsseltext, Signatur, Abgleichstand |

**Fassung 2 (Meilenstein 9, 2026-10-10)** ergänzt die Datei um das, was mehrere Tresore und der Abgleich brauchen; Einzelheiten in `sync.md`. Das Format der Datensätze, die Schlüsselkette und alle Prüfwerte sind dieselben geblieben.

| Neu | Inhalt |
| --- | --- |
| `vaults.kind`, `epoch`, `cursor`, `roster` | Art (persönlich, geteilt), Schlüsselstand, bis zu welcher Nummer des Servers geholt ist, signierte Mitgliederliste |
| `records.synced` | die Revision, die der Server zuletzt bestätigt oder geliefert hat (0 = kennt er nicht) |
| `base` | der zuletzt abgeglichene Stand jedes Datensatzes, dessen Änderung noch nicht beim Server ist (Grundlage beim Zusammenführen) |
| `contacts`, `notices` | einmal gesehene öffentliche Schlüssel anderer Konten; Hinweise aus dem Abgleich. Beides mit dem Kontoschlüssel verschlüsselt, ebenso die Mitgliederliste in `vaults.roster` |
| `meta.next_…` | eine vorgemerkte Verpackung des Kontoschlüssels nach einer Passwortänderung auf einem anderen Gerät; sie wird zur geltenden, sobald sich mit ihr entsperren lässt |
| `meta.link` | die Anmeldung am Sync-Server, mit dem Kontoschlüssel verschlüsselt und an die `device_id` gebunden |

- **Umstellung:** Eine Datei der Fassung 1 stellt das Programm beim Öffnen um und legt vorher eine Kopie daneben (`vault.db.format1`). Ältere Programmversionen öffnen eine umgestellte Datei nicht mehr und sagen das. Geprüft an einer Datei, die die Version 0.8.0 geschrieben hat (`crates/core/tests/fixtures/format1.db`).
- Eine neue Datei entsteht aus dem Aufbau der Fassung 1 und demselben Umstellungsschritt; neu und umgestellt sehen also gleich aus.
- Jede Änderung läuft in einer Transaktion. SQLite sorgt dafür, dass ein Absturz mittendrin keinen halben Stand hinterlässt.
- **Sicherung:** eine folgerichtige Kopie der Datei (`glowport-sicherung-JJJJ-MM-TT.gpvault`). Sie ist genauso verschlüsselt wie das Original und braucht dasselbe Master-Passwort. Die Anmeldung am Sync-Server geht nicht mit: Wer eine Sicherung einspielt, meldet sich neu an.
- Einstellungen ohne Geheimniswert (Design, Sprache, Aussehen des Terminals, eigene Farbschemata) bleiben außerhalb in `settings.json`.
- Ebenfalls außerhalb und **nicht verschlüsselt**: Mitschnitte als Textdateien im Ordner `logs`, das Hintergrundbild des Terminals (`background-….png` und ähnlich) und `open-tabs.json` mit den gerade offenen Tabs (Kennungen von Hosts und eingetippte Adressen, keine Geheimnisse) für die Rückfrage nach einem Abbruch.

## Entsperren, Sperren, Speicher

0. **Beim Start** verlangt Glowport das Master-Passwort, außer der Nutzer hat das abgeschaltet (siehe „Start ohne Master-Passwort“).
1. **Entsperren:** `meta` lesen → Argon2id → HKDF → `account_key` entpacken → Tresor-Schlüssel entpacken → Datensätze entschlüsseln und im Kern im Speicher halten. `master_key` und `kek` werden sofort danach überschrieben.
2. **Sperren** (Knopf, Auto-Sperre, Beenden): alle Schlüssel und entschlüsselten Daten im Kern überschreiben, die Oberfläche verwirft ihre Kopien. Laufende Sitzungen bleiben verbunden; ein erneutes Verbinden braucht den offenen Tresor.
3. **Auto-Sperre:** einstellbar (aus, 5, 15, 60 Minuten ohne Eingabe), Vorgabe aus. Die Uhr läuft im Kern.
4. **Geheimnisse und die Oberfläche:** Passwörter und private Schlüssel verlassen den Kern nur, wenn du dir eines ausdrücklich anzeigen lässt. Listen und Editoren bekommen nur „ist gesetzt“.
5. **Im Speicher:** Schlüssel und Geheimnisse liegen in Behältern, die beim Freigeben überschrieben werden (`zeroize`). Nichts davon erscheint in Protokollen oder Fehlermeldungen.

## Start ohne Master-Passwort (Einstellung, Vorgabe: aus)

Vom User am 2026-10-05 gewünscht: Es soll einstellbar sein, ob das Master-Passwort bei jedem Start verlangt wird.

- **Schalter:** Optionen → Tresor → „Master-Passwort beim Start verlangen“. Vorgabe an. Das Ausschalten braucht eine Rückfrage, die die Folgen nennt; das Einschalten nicht.
- **Was hinterlegt wird:** der `account_key` (`Vault::device_key`), geschützt mit Windows-DPAPI für das angemeldete Benutzerkonto, in der Datei `start-unlock.bin` im Datenordner. Als Zusatz-Entropie dient die `device_id` des Tresors, die Datei passt also nur zu genau diesem Tresor. Sie steht **nicht** in `vault.db` und damit weder in Sicherungen noch später im Abgleich.
- **Beim Start:** Gibt es die Datei, öffnet der Kern den Tresor damit (`Vault::unlock_with_key`). Passt der Schlüssel nicht (anderer Tresor, anderes Windows-Konto, veränderte Datei), wird die Datei gelöscht und das Master-Passwort verlangt.
- **Sperren bleibt sperren:** Nach „Tresor sperren“ und nach der Auto-Sperre hilft nur das Master-Passwort. Der hinterlegte Schlüssel wird nur beim Programmstart benutzt.
- **Master-Passwort ändern** lässt den hinterlegten Schlüssel gültig, weil sich der `account_key` dabei nicht ändert.
- **Was das für den Schutz heißt:** Mit ausgeschalteter Abfrage schützt nur noch die Windows-Anmeldung. Wer am angemeldeten PC sitzt und jedes Programm unter diesem Konto kann den Tresor öffnen. Gegen Diebstahl des ausgeschalteten Geräts hilft dann nur ein gutes Windows-Passwort (besser: Laufwerksverschlüsselung). Sicherungsdateien und andere Geräte brauchen weiterhin das Master-Passwort.
- **Umsetzung:** Die Ablage wird nicht beim Aufbau des Fensters gelesen, sondern beim ersten `vault_status` der Oberfläche; dieser Befehl und `vault_set_start_unlock` laufen mit `#[tauri::command(async)]` abseits des Fenster-Threads, damit Datei- und DPAPI-Aufrufe das Fenster nicht aufhalten.
- **Andere Systeme:** Für macOS (Schlüsselbund) und Linux (Secret Service) fehlt die Anbindung noch; dort meldet das Einschalten einen Fehler. Kommt mit deren Veröffentlichung (Meilenstein 13).

## Bibliotheken

`argon2`, `hkdf`, `sha2`, `chacha20poly1305`, `x25519-dalek`, `ed25519-dalek`, `rand` (Zufall des Betriebssystems), `zeroize`, `rusqlite` (SQLite fest eingebaut). Keine selbst geschriebenen Verfahren.

## Prüfungen vor der Abnahme von Meilenstein 1

- Feste Prüfwerte: gleiche Eingaben ergeben in jeder Version dieselben Ableitungen (Argon2id, HKDF) und entschlüsseln fest hinterlegte Beispiel-Schlüsseltexte.
- Rundlauf: anlegen, speichern, sperren, entsperren, alles wieder da.
- Falsches Passwort wird abgelehnt, ohne etwas zu verändern.
- Jedes veränderte Byte in Schlüsseltext, Nonce, gebundenen Angaben oder Signatur wird erkannt.
- Vertauschte Datensätze, verschobene Datensätze und zurückgedrehte Revisionen werden erkannt.
- Passwortänderung: altes Passwort öffnet nicht mehr, neues öffnet alles.
- Absturz mitten im Schreiben hinterlässt eine lesbare Datei.
- Messung der Entsperrzeit auf dem PC des Users.

## Offene Punkte

- Ob die Zwischenablage nach dem Kopieren eines Geheimnisses nach einer Zeit geleert wird (Vorschlag: ja, nach 30 Sekunden, abschaltbar) – Entscheidung des Users in Meilenstein 3.
- Erledigt: Aufbewahrung der Grabsteine mit Sync steht in `sync.md` (180 Tage; ein Grabstein, von dem der Server noch nichts weiß, bleibt, bis er dort ist).
