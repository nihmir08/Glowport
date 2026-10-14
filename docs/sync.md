# Sync und geteilte Tresore von Glowport

Stand: 2026-10-10 · Version des Protokolls: 1 · Status: **vom User freigegeben am 2026-10-10, im Bau**

Dieses Dokument legt fest, wie Glowport Tresore über einen eigenen Server abgleicht und mit anderen teilt. Es wird vor dem Code geschrieben, aus demselben Grund wie `tresor.md`: Ein Fehler hier wäre später am teuersten. Grundlage sind `tresor.md` (das Format der Datensätze bleibt unverändert) und die Grundsätze des Projekts: eigener Server, Ende-zu-Ende-verschlüsselt, Teilen mit Rechten.

## In Kürze

- **Ein Server, den du selbst betreibst** (`glowport-sync`, ein einzelnes Programm oder ein Docker-Abbild für deinen Dedi). Ohne Server arbeitet Glowport genau wie bisher.
- **Ein Konto je Person**, angemeldet mit Benutzername und Master-Passwort. Das Master-Passwort verlässt nie das Gerät; der Server bekommt nur einen daraus abgeleiteten Anmeldeschlüssel, mit dem sich nichts entschlüsseln lässt.
- **Der Server sieht nur verschlüsselte Datensätze.** Er weiß, wer mit wem einen Tresor teilt und wie viele Datensätze es gibt, aber nicht, was darin steht, auch nicht die Namen der Tresore.
- **Änderungen kommen sofort an:** Jede Änderung geht direkt an den Server, die anderen Geräte holen sie binnen etwa einer Sekunde. Ohne Netz arbeitest du weiter; abgeglichen wird, sobald der Server wieder erreichbar ist.
- **Mehrere Tresore:** dein persönlicher (nur du, auf all deinen Geräten) und beliebig viele geteilte, jeder mit Mitgliedern in den Rollen Besitzer, Schreiben oder Lesen.
- **Gleichzeitige Änderungen** führt Glowport Feld für Feld zusammen. Nur wenn zwei dasselbe Feld ändern, gewinnt die neuere Änderung, und du bekommst einen Hinweis.
- **Kein Zurücksetzen**, wie beim Tresor: Wer sein Master-Passwort vergisst, kommt auch über den Server nicht mehr an seine Daten.

## Entscheidungen des Users (2026-10-10)

| Frage | Entscheidung |
| --- | --- |
| Wie kommen andere zu einem Konto? | **Einladungscode aus der App.** Der Verwalter des Servers erzeugt in Glowport Codes, sieht alle Konten und kann sie sperren oder löschen. |
| Mehrere Tresore in der Host-Übersicht | **Umschalter mit „Alle“** (Alle · Persönlich · jeder geteilte Tresor), Vorgabe „Alle“; jeder Host trägt die Marke seines Tresors. |
| Leserecht und Geheimnisse | **Verbinden ja, ansehen nein:** Mitglieder mit Leserecht können sich verbinden, aber Passwörter und private Schlüssel weder anzeigen noch kopieren noch exportieren. |
| Zweiter Faktor bei der Anmeldung | **Später nachrüsten.** Das Protokoll sieht den zusätzlichen Schritt schon vor. |

## Wovor der Sync schützt und wovor nicht

| Schützt vor | Schützt nicht vor |
| --- | --- |
| Einem gehackten oder neugierigen Server: Er kann nichts lesen und nichts unbemerkt verändern oder unterschieben | Einem Mitglied, das die Daten eines geteilten Tresors abschreibt, solange es Mitglied ist |
| Mitlesen auf der Leitung (TLS, darunter ohnehin nur Schlüsseltexte) | Einem Mitglied mit Leserecht, das gespeicherte Passwörter mit eigenen Mitteln aus seinem Rechner holt (die Sperre ist eine des Programms, siehe „Rechte“) |
| Einem Server, der einen alten Stand als aktuell ausgibt (jedes Gerät merkt sich, was es schon gesehen hat) | Einem Server, der Änderungen zurückhält oder nicht erreichbar ist (er kann aufhalten, nicht fälschen) |
| Rateversuchen am Konto über das Netz (der Server bremst sie) | Einem schwachen Master-Passwort, wenn die Datenbank des Servers gestohlen wird (dann gilt dasselbe wie bei einer gestohlenen Tresor-Datei) |
| Schreiben durch Mitglieder, die nur lesen dürfen (der Server lehnt ab, und die anderen Geräte prüfen die Signatur selbst) | Verlust des Master-Passworts |

## Konto und Geräte

### Konto anlegen

Ein Konto ist der Tresor, den es heute schon gibt, plus ein Benutzername auf dem Server. Neue Schlüssel entstehen dabei nicht: Kontoschlüssel und die beiden Schlüsselpaare (X25519, Ed25519) liegen seit Meilenstein 1 in jedem Tresor.

- **Einstellungen → Sync → „Sync einrichten“:** Adresse des Servers, Einladungscode, Benutzername (3 bis 32 Zeichen: Kleinbuchstaben, Ziffern, `-`, `_`, `.`), Master-Passwort zur Bestätigung.
- Hochgeladen werden: Salz und Aufwand von Argon2id, der verpackte Kontoschlüssel, die öffentlichen und die verpackten privaten Schlüssel, der verpackte Schlüssel des persönlichen Tresors und alle Datensätze. Alles davon ist schon in der Tresor-Datei verschlüsselt und geht unverändert hinüber.
- **Das allererste Konto** eines frischen Servers braucht statt einer Einladung den Einrichtungscode, den der Server beim ersten Start einmal ausgibt. Dieses Konto ist der Verwalter.

### Anmelden

```
Gerät → Server   Benutzername
Server → Gerät   Salz, Aufwand von Argon2id          (für unbekannte Namen erfundene, aber feste Werte)
Gerät            Master-Passwort ─Argon2id→ master_key ─HKDF "glowport/auth/v1"→ auth_key
Gerät → Server   auth_key
Server → Gerät   Geräte-Token, verpackter Kontoschlüssel, Schlüsselpaare, Liste der Tresore
Gerät            master_key ─HKDF "glowport/kek/v1"→ kek → Kontoschlüssel entpacken → weiter wie beim Entsperren
```

- Der Server speichert von `auth_key` nur einen Prüfwert (SHA-256 mit eigenem Salz). Aus `auth_key` lässt sich `kek` nicht berechnen (`tresor.md`, Schlüsselkette); wer nur den Server hat, muss das Master-Passwort raten wie bei einer gestohlenen Tresor-Datei, mit dem vollen Aufwand von Argon2id je Versuch.
- **Rateversuche über das Netz:** höchstens fünf Fehlversuche je Konto in fünfzehn Minuten, dazu eine Bremse je Absender-Adresse (dreißig). Hinter einem vorgeschalteten Webserver liest der Server die Adresse aus `X-Forwarded-For` (`--trust-proxy`).
- **Der Name des Geräts** kommt gleich nach der Anmeldung dazu: Er ist mit dem Kontoschlüssel verschlüsselt, und den hat ein neues Gerät erst danach.
- **Kein zu kleiner Aufwand:** Salz und Aufwand nennt der Server. Nennt er weniger als die übliche Untergrenze für Argon2id (19 MiB, 2 Durchläufe), meldet sich Glowport nicht an. Sonst könnte ein böswilliger Server winzige Werte vorgeben und das Master-Passwort aus dem Anmeldeschlüssel billig erraten.
- **Zweiter Faktor (später):** Die Antwort auf die Anmeldung kann einen weiteren Schritt verlangen (`needs`). Heutige Programme kennen keinen und melden dann „Dieser Server verlangt eine neuere Version“.

### Geräte

- Jede Anmeldung legt ein Gerät an: Kennung, Name (mit dem Kontoschlüssel verschlüsselt, der Server sieht ihn nicht), zuletzt gesehen. Das **Geräte-Token** (32 zufällige Byte) weist das Gerät bei jeder Anfrage aus. Der Server speichert nur dessen Prüfwert; auf dem Gerät liegt es mit dem Kontoschlüssel verschlüsselt in der Tresor-Datei.
- **Einstellungen → Sync → Geräte** zeigt alle Geräte des Kontos. „Abmelden“ macht das Token ungültig: Das Gerät bekommt nichts Neues mehr. Was es schon hat, bleibt dort lesbar, solange jemand das Master-Passwort kennt. Geht ein Gerät verloren: abmelden und Master-Passwort ändern.
- **Abgeglichen wird nur bei offenem Tresor.** Ein gesperrtes Glowport hat keine Schlüssel und spricht nicht mit dem Server. Nach dem Entsperren wird zuerst geholt.

### Drei Wege auf ein Gerät

| Lage auf dem Gerät | Weg |
| --- | --- |
| Tresor vorhanden, noch kein Konto | „Sync einrichten“ wie oben. Der Tresor wird zum persönlichen Tresor des Kontos. |
| Noch kein Tresor (neuer PC) | Beim ersten Start steht neben „Tresor anlegen“ und „Sicherung einspielen“ der dritte Weg **„Mit Konto anmelden“**: Adresse, Benutzername, Master-Passwort. |
| Tresor vorhanden, das Konto gibt es schon (zwei getrennt gewachsene Geräte) | „Ich habe schon ein Konto“. Vorher schreibt Glowport eine Sicherung in den Datenordner (`glowport-vor-konto-<Datum>.gpvault`, mit dem bisherigen Master-Passwort). Dann die Wahl: die lokalen Datensätze **in den persönlichen Tresor des Kontos übernehmen** (neu verschlüsselt, Verweise untereinander bleiben erhalten; Doppelte werden nicht erkannt) oder **verwerfen**. Danach gilt das Master-Passwort des Kontos, und der Start ohne Master-Passwort ist aus. |

### Master-Passwort ändern

Neues Salz, Kontoschlüssel neu verpackt, neuer `auth_key`. Mit Abgleich geht das Paket **zuerst an den Server** (ausgewiesen mit dem bisherigen `auth_key`: Ein gestohlenes Geräte-Token allein ändert kein Passwort) und wird erst danach hier übernommen; so kennt nie nur ein Gerät das neue Passwort. Kästchen im Dialog: „Alle anderen Geräte abmelden“.

Die anderen Geräte bleiben angemeldet und **merken das neue Paket beim nächsten Abgleich vor**. Dort öffnet das alte Passwort die lokale Datei weiter, bis das neue zum ersten Mal benutzt wird; ab dann gilt nur noch das neue. Das Paket kommt vom Server und lässt sich ohne das neue Passwort nicht prüfen; deshalb ersetzt es das alte erst, wenn sich damit entsperren lässt und der Schlüssel darin wirklich der dieses Kontos ist. Ein Server, der hier Unsinn schickt, sperrt also niemanden aus.

Grenze: Der Kontoschlüssel selbst bleibt derselbe. Wer ihn schon erbeutet hat, wird durch ein neues Passwort nicht ausgesperrt. Einen Tausch des Kontoschlüssels gibt es in dieser Fassung nicht.

## Was der Server sieht

| Sieht | Sieht nicht |
| --- | --- |
| Benutzernamen, Zahl der Geräte, wann sie zuletzt da waren, Absender-Adressen | Master-Passwort, Kontoschlüssel, Tresor-Schlüssel |
| Je Tresor: Kennung, Mitglieder und ihre Rollen | Namen der Tresore und der Geräte |
| Je Datensatz: Kennung, Revision, Löschmarke, Änderungszeit, Autor, Größe | Art des Datensatzes (Host, Schlüssel, Snippet …) und jeden Inhalt |
| Öffentliche Schlüssel der Konten | Private Schlüssel (nur verpackt) |

Der Verwalter des Servers sieht in Glowport dasselbe wie der Server und nicht mehr: Konten, Speicherverbrauch, Einladungscodes. Er kann Konten sperren und löschen, aber kein Passwort zurücksetzen und in keinen Tresor hineinsehen.

## Abgleich

### Grundsatz

- Der Server führt je Tresor einen Zähler (`seq`). Jede angenommene Änderung bekommt die nächste Nummer. Ein Gerät merkt sich je Tresor, bis zu welcher Nummer es alles hat.
- **Holen:** „alles in diesem Tresor nach Nummer N“. Der Server liefert je Datensatz nur die neueste Fassung, Grabsteine eingeschlossen.
- **Schicken:** Das Gerät schickt geänderte Datensätze so, wie sie in der Tresor-Datei liegen (Kennung, Revision, Löschmarke, Nonce, Schlüsseltext, Signatur). Der Server nimmt an, wenn
  1. das Konto in diesem Tresor schreiben darf,
  2. die Signatur zum öffentlichen Schlüssel des Kontos passt (der Server kann sie prüfen, ohne etwas zu entschlüsseln),
  3. die Änderung auf seinem Stand aufsetzt: Das Gerät nennt die Revision, auf der sie beruht; sie muss die sein, die der Server hat, und die neue muss darüber liegen (einen Datensatz, den er noch nicht kennt, nimmt er mit jeder Revision an),
  4. der Schlüsselstand des Tresors stimmt (siehe „Schlüsseltausch“).
- **Alles oder nichts:** Was das Programm lokal als eine Änderung schreibt (Host löschen samt seiner Port-Regeln), geht als ein Paket und wird ganz angenommen oder ganz abgelehnt.
- **Revisionen:** Solange die Änderung an einem Datensatz, den der Server schon kennt, noch nicht angenommen ist, erhöht eine weitere lokale Änderung seine Revision nicht noch einmal. Lokal liegt er also immer genau eins über dem zuletzt abgeglichenen Stand. Diesen Stand hebt das Gerät auf, bis die Änderung angenommen ist; er ist die Grundlage beim Zusammenführen.

### Sofort

- Jede lokale Änderung geht nach 300 ms Sammelzeit an den Server.
- Jedes Gerät hält eine WebSocket-Verbindung. Darüber kommt nur die Nachricht „Tresor X steht bei Nummer N“ oder „an deinem Konto hat sich etwas geändert“ (Einladung, Rolle, Passwort); geholt wird dann über die gewöhnliche Anfrage. Nach jedem Neuverbinden (1, 2, 5, 10, 30 Sekunden) wird ohnehin geholt. Lässt sich kein WebSocket halten, fragt das Gerät jede Minute nach.
- Die Statusleiste zeigt den Stand: abgeglichen, gleicht ab, ohne Verbindung (mit Zahl der wartenden Änderungen), Fehler.
- Laufende Sitzungen berührt der Abgleich nicht. Ein geänderter Host gilt für die nächste Verbindung.

### Gleichzeitige Änderungen

Lehnt der Server ab, weil ein anderes Gerät schneller war, liefert er dessen Fassung mit. Das Gerät führt dann drei Fassungen zusammen: den gemeinsamen Ausgangsstand, die eigene und die des Servers.

- **Feld für Feld.** Der Inhalt eines Datensatzes ist JSON. Objekte werden Schlüssel für Schlüssel verglichen (so auch die eigenen Werte eines Hosts in `own`), Listen und einfache Werte gelten als ein Feld. Hat nur eine Seite ein Feld geändert, gilt deren Wert. Ändert A den Port und B das Farbschema desselben Hosts, bleibt beides.
- **Dasselbe Feld auf beiden Seiten:** Die neuere Änderung gewinnt (nach der Änderungszeit; bei Gleichstand die des Servers). Glowport zeigt einen Hinweis: welcher Eintrag, welches Feld, wessen Wert gilt. Hinweise sammeln sich unter Einstellungen → Sync.
- **Ändern gegen Löschen:** Die Änderung gewinnt, der Eintrag bleibt oder kommt zurück, mit Hinweis.
- Felder, die das Programm nicht kennt, gehen denselben Weg. Eine ältere Version zerstört also nichts, was eine neuere angelegt hat.
- Das Ergebnis bekommt die nächste Revision und geht erneut an den Server.

**Regeln über mehrere Datensätze** (eine Gruppe darf nicht in sich selbst liegen, ein Tastenkürzel gehört einem Snippet, ein Verweis zeigt auf etwas Vorhandenes) kann der Server nicht prüfen, weil er nichts lesen kann. Zwei Geräte können sie gemeinsam verletzen. Jedes Gerät entschärft das beim Lesen und schreibt nichts von selbst um: Ein Verweis ins Leere gilt als „nicht gesetzt“, eine Gruppe im Kreis erscheint auf oberster Ebene, ein doppeltes Kürzel gilt für den Eintrag mit der kleineren Kennung. Wer den Eintrag das nächste Mal speichert, bereinigt ihn.

Grenze: Löscht A einen Host samt seinen Port-Regeln und ändert B denselben Host zur selben Zeit, bleibt der Host, seine Port-Regeln sind aber gelöscht.

### Grabsteine

Der Server hebt Grabsteine 180 Tage auf. Ein Gerät, das länger weg war, bekommt statt der Änderungen den ganzen Stand und entfernt lokal, was es als abgeglichen kannte und der Server nicht mehr hat. Auf den Geräten gilt mit Sync dieselbe Frist statt der bisherigen 90 Tage.

### Prüfsumme und ein Server, der zurückdreht

Nummern allein zeigen nicht sicher, ob Gerät und Server dasselbe haben: Nach dem Zurückholen des Servers aus einer Sicherung vergibt er Nummern, die es schon einmal gab. Deshalb schickt der Server bei jedem Holen eine **Prüfsumme über seinen ganzen Stand** des Tresors mit (Kennung und Revision jedes lebenden Datensatzes), und das Gerät rechnet dieselbe über das, was es für den Stand des Servers hält.

- **Stimmen beide überein,** ist alles in Ordnung.
- **Stimmen sie nicht überein** (oder nennt der Server eine kleinere Nummer als zuletzt), holt das Gerät den ganzen Stand und vergleicht Datensatz für Datensatz. Hat der Server nur Neueres, wird es übernommen: Das Gerät hatte etwas verpasst.
- **Fehlt dem Server etwas, das hier als abgeglichen gilt,** oder hat er es in einer älteren Fassung, dann hat er einen älteren Stand als dieses Gerät. Das Gerät übernimmt nichts davon, schickt nichts in diesen Tresor und meldet: „Der Server hat einen älteren Stand als dieses Gerät.“ Das ist entweder ein Angriff oder ein Server, den du aus einer Sicherung zurückgeholt hast.
- Für den zweiten Fall gibt es den Knopf **„Stand dieses Geräts hochladen“**: Was hier neuer ist, geht eine Revision höher wieder hinauf, damit es auch jedes andere Gerät als neu annimmt. Die übrigen Geräte finden danach von selbst zurück. Wer in einem Tresor nur lesen darf, kann nichts hochladen und übernimmt nur.

Einzelne Datensätze dreht ohnehin niemand zurück: Eine ältere Revision als die bekannte nimmt kein Gerät an.

## Mehrere Tresore

- **Persönlicher Tresor:** genau einer je Konto, nicht teilbar. Sein Schlüssel ist wie heute mit dem Kontoschlüssel verpackt.
- **Geteilte Tresore:** beliebig viele. Wer einen anlegt, ist sein Besitzer. Der Name steht verschlüsselt im Tresor (`vault-info`).
- **Oberfläche:** Umschalter „Alle · Persönlich · <geteilte Tresore>“ auf den Seiten Hosts, Schlüssel, Snippets und Port-Regeln, Vorgabe „Alle“. Jeder Eintrag trägt die Marke seines Tresors. Die Suche findet immer alles. Beim Anlegen wählt man den Tresor; vorgeschlagen wird der gerade gezeigte.
- **Verschieben zwischen Tresoren:** Ein Host zieht um, indem er im Ziel neu entsteht (ohne Gruppe) und in der Quelle gelöscht wird. Hängen Identität oder Schlüssel aus einem anderen Tresor daran, kommen sie auf Wunsch als Kopie mit, sonst wird der Verweis gelöst; ein Sprung-Server von anderswo wird immer gelöst. Port-Regeln, Arbeitsbereiche und Sprung-Verweise anderer Hosts folgen ihm, soweit sie dorthin verweisen dürfen. Schlüssel, Identitäten und Snippets für sich lassen sich noch nicht verschieben; man legt sie im gewünschten Tresor an.
- **Ein Eintrag liegt im selben Tresor wie seine Gruppe.** Wer einen Host in einer Gruppe anlegt, legt ihn damit in deren Tresor.
- **Verweise:** Ein Datensatz eines geteilten Tresors verweist nur auf Datensätze desselben Tresors (Schlüssel, Identität, Gruppe, Sprung-Server, eigenes Farbschema), sonst fehlten sie den anderen Mitgliedern. Der persönliche Tresor darf auf alles verweisen: Arbeitsbereiche und Port-Regeln können geteilte Hosts nennen.
- **Persönlich bleiben immer:** bekannte Hosts, Arbeitsbereiche.
- **Eigene Farbschemata** ziehen aus `settings.json` als Datensätze `color-scheme` in den Tresor um, damit ein Host auf jedem Gerät gleich aussieht (in `tresor.md` so angekündigt).
- **Nicht abgeglichen werden:** Einstellungen des Programms (Design, Sprache, Schrift), Mitschnitte, offene Tabs, Transfers, der Start ohne Master-Passwort. Sie gehören zum Gerät.

## Teilen

### Rollen

| Rolle | Darf |
| --- | --- |
| **Besitzer** (genau einer) | alles im Tresor, Mitglieder einladen und entfernen, Rollen ändern, Besitz übertragen, Tresor löschen |
| **Schreiben** | Einträge anlegen, ändern, löschen; Geheimnisse ansehen |
| **Lesen** | alles sehen und sich verbinden; nichts ändern; Passwörter und private Schlüssel weder anzeigen noch kopieren noch exportieren, Einträge mit Geheimnissen nicht in andere Tresore kopieren |

**Ehrlich zum Leserecht:** Wer sich verbinden kann, hat den Tresor-Schlüssel und damit jedes Geheimnis des Tresors auf seinem Rechner. Glowport zeigt es ihm nicht, aber das ist eine Sperre im Programm und kein Verschluss. Hart durchgesetzt ist beim Leserecht das **Schreiben**: Der Server lehnt es ab, und jedes Gerät prüft selbst, ob der Autor eines Datensatzes schreiben durfte.

### Mitgliederliste

Je geteiltem Tresor gibt es eine Mitgliederliste: Tresor-Kennung, Schlüsselstand, laufende Nummer, je Mitglied Konto, öffentliche Schlüssel und Rolle. **Der Besitzer signiert sie** (Ed25519). Der Server bewahrt sie auf, kann sie aber nicht ändern: Jedes Gerät nimmt nur eine Liste an, deren Nummer höher ist als die zuletzt gesehene und die der Besitzer signiert hat, den das Gerät kennt. Ein Server kann sich also weder selbst zum Mitglied machen noch jemandem das Schreibrecht geben.

**Übergabe des Besitzes:** Der bisherige Besitzer signiert eine Übergabe an ein Mitglied und ein letztes Mal die Liste; ab der nächsten signiert der neue. Jede Liste trägt alle Übergaben, die es je gab, als Kette. So kann auch ein Gerät, das eine Übergabe verpasst hat, vom Besitzer, den es kennt, bis zum heutigen prüfen, und eine alte Übergabe lässt sich nicht ein zweites Mal verwenden (Stelle in der Kette und Nummer der Liste sind mitsigniert).

Datensätze eines geteilten Tresors gelten nur, wenn ihr Autor laut dieser Liste Besitzer ist oder schreiben darf.

### Einladen

1. Der Besitzer tippt den Benutzernamen (das Konto muss es auf demselben Server geben) und wählt die Rolle.
2. Sein Gerät holt die öffentlichen Schlüssel des Kontos und zeigt dessen **Sicherheitscode** (sechs Wörter aus einem Prüfwert beider Schlüssel; die Wörter stammen aus einer festen Liste von 512, zusammen 54 Bit). Der Eingeladene sieht denselben Code unter Einstellungen → Sync. Wer sichergehen will, vergleicht ihn über einen anderen Weg (Discord, Telefon). Das schützt davor, dass ein gehackter Server falsche Schlüssel unterschiebt und so an den Tresor-Schlüssel käme. Einmal gesehene Schlüssel merkt sich das Gerät; ändern sie sich, warnt es.
3. Das Gerät verpackt den Tresor-Schlüssel für den Eingeladenen und schickt ihn mit der neuen Mitgliederliste.
4. Der Eingeladene bekommt eine Einladung mit Namen des Tresors, Besitzer und dessen Sicherheitscode und nimmt an oder lehnt ab. Damit sein Gerät den Namen zeigen kann, darf es die Datensätze schon vor dem Annehmen holen; den Schlüssel hat es mit der Einladung ohnehin. Schreiben kann es erst danach.

**Verpacken des Tresor-Schlüssels** (in `tresor.md` angekündigt): einmaliges X25519-Schlüsselpaar des Absenders → gemeinsames Geheimnis mit dem öffentlichen Schlüssel des Empfängers → HKDF-SHA-256 (Salz: beide öffentlichen Schlüssel, Info `"glowport/share/v1"`) → XChaCha20-Poly1305. Gebunden sind Tresor-Kennung, Schlüsselstand und der öffentliche Schlüssel des Empfängers. Auch der Besitzer bekommt seinen Schlüssel so; auf dem Gerät liegt er danach wie jeder Tresor-Schlüssel mit dem Kontoschlüssel verpackt.

### Rechte entziehen: Schlüsseltausch

Wird ein Mitglied entfernt oder verliert es das Schreibrecht, tauscht das Gerät des Besitzers den Schlüssel des Tresors. Eine Mitgliederliste, die jemandem Rechte nimmt, ohne den Schlüsselstand zu erhöhen, nimmt kein Gerät an. Der Ablauf:

1. neuer Tresor-Schlüssel, Schlüsselstand plus eins,
2. alle Datensätze (auch Grabsteine) mit dem neuen Schlüssel verschlüsselt und vom Besitzer signiert, Revisionen unverändert,
3. neue Mitgliederliste, der neue Schlüssel für jedes verbleibende Mitglied verpackt,
4. alles als ein Paket an den Server, der es nur annimmt, wenn seit dem Lesen niemand geschrieben hat (sonst von vorn).

- Der Server gibt dem entfernten Mitglied ab diesem Moment nichts mehr. Dessen Glowport löscht seine Kopie des Tresors, sobald es davon erfährt.
- Die anderen Geräte holen Liste, Schlüssel und Datensätze. Änderungen, die bei ihnen noch warteten, verschlüsseln sie neu und schicken sie nach.
- Nach dem Tausch gibt es keinen Datensatz mehr, den das entfernte Mitglied signiert hat. Deshalb reicht den Geräten immer die aktuelle Mitgliederliste.
- **Was der Tausch nicht kann:** zurückholen, was das Mitglied schon gesehen hat. Glowport zeigt nach dem Entfernen die Hosts des Tresors mit gespeichertem Passwort oder Schlüssel und rät, diese Zugänge auf den Servern zu ändern.

Verlässt ein Mitglied den Tresor von sich aus, entfernt der Server es sofort; den Schlüssel tauscht das Gerät des Besitzers, sobald es das nächste Mal online ist. Der Besitzer kann nicht gehen, ohne den Besitz zu übertragen oder den Tresor zu löschen. Löscht der Verwalter das Konto eines Besitzers, bleibt der Tresor für die übrigen Mitglieder lesbar und lässt sich in einen eigenen Tresor kopieren.

Führt der Server einen Tresor für ein Konto nicht mehr (entfernt, oder der Besitzer hat ihn gelöscht), entfernt Glowport die Kopie auf dessen Geräten. Die Kopie des Besitzers bleibt, bis er sie selbst entfernt: Ein Server soll niemanden dazu bringen können, seinen eigenen Tresor zu verlieren.

## Der Server

### Aufbau

- **Ein Programm** `glowport-sync` (Rust, axum, SQLite in einer Datei), dazu ein Docker-Abbild mit demselben Programm. Eigene Crates: `crates/sync-proto` (Nachrichten, von beiden Seiten benutzt), `crates/sync-server`, `crates/sync` (die Seite des Programms).
- **Schnittstelle:** HTTPS mit JSON unter `/v1/…`, WebSocket unter `/v1/live` (die erste Nachricht ist das Geräte-Token, so steht es in keiner Adresse). Die Wege im Einzelnen stehen in `crates/sync-server/src/lib.rs`, die Nachrichten in `crates/sync-proto`. Der Server nennt seine Version und die älteste, die er noch bedient; passt es nicht, sagt Glowport, welche Seite ein Update braucht.
- **TLS:** Vorgesehen ist ein vorgeschalteter Webserver (NGINX oder Caddy) mit eigenem Zertifikat; `glowport-sync` lauscht dann nur auf `127.0.0.1`. Für den Betrieb ohne Vorschaltung nimmt das Programm auch selbst Zertifikat und Schlüssel als Dateien (`--tls-cert`, `--tls-key`); geänderte Dateien übernimmt es binnen einer Stunde ohne Neustart. Glowport verbindet sich nur über `https://`; `http://` gilt allein für Adressen des eigenen Rechners (Tests). Geprüft wird gegen den Zertifikatsspeicher des Systems; ein abgelehntes Zertifikat meldet Glowport als solches („Das Zertifikat des Sync-Servers wird nicht anerkannt …“), nicht als „nicht erreichbar“.
- **Grenzen:** 256 KiB je Datensatz, 20 000 Datensätze je Tresor, 50 Tresore je Konto (einstellbar über die Umgebung, siehe `sync-server.md`); 50 Mitglieder je Tresor (fest).
- **Protokoll des Servers:** eine Zeile für alles, was etwas ändert oder scheitert, mit Zeit, Ergebnis, Art der Anfrage (als Muster, ohne Kennungen) und Konto. Nie Inhalte, Token oder `auth_key`, und keine Adressen der Absender. Reines Lesen bleibt still.
- **Hinter einem Webserver** bremst der Server Rateversuche nach der Adresse aus `X-Forwarded-For`. Geglaubt wird sie nur, wenn es eingeschaltet ist: jeder Verbindung (der Webserver auf demselben Rechner, der Server hört auf `127.0.0.1`) oder nur Verbindungen von genannten Adressen (der Webserver auf einem anderen Rechner).
- **Betrieb:** Einrichten, Befehle, Sicherung und Fehlersuche stehen in [`sync-server.md`](sync-server.md); Vorlagen (Dienst-Datei, Einrichtungsskript, Docker, NGINX, Caddy) im Ordner `server/`.

### Verwalten (in Glowport, nur für den Verwalter)

Einstellungen → Sync → „Server verwalten“: Einladungscodes erzeugen (einmal gültig, sieben Tage), offene Codes widerrufen, Konten mit Geräten, letztem Besuch und Speicher sehen, Konto sperren (keine Anmeldung, kein Abgleich; Daten bleiben), Konto löschen (samt persönlichem Tresor). Dieselben Handgriffe gibt es als Befehle des Programms auf dem Server, falls kein Verwalter mehr hineinkommt (`glowport-sync invite`, `invites`, `revoke`, `accounts`, `disable`, `enable`, `delete`, `backup`). Nur dort gibt es außerdem `admin <Name>` und `noadmin <Name>`: Wer an der Kommandozeile des Servers sitzt, kann ein Konto zum Verwalter machen, damit ein Server nach einem verlorenen Master-Passwort wieder einen bekommt. Glowport erfährt es mit dem nächsten Abgleich.

### Sicherung

- `glowport-sync backup <Datei>` schreibt im Betrieb eine folgerichtige Kopie der Datenbank. Sie enthält nur, was der Server sieht, ist also so verschlüsselt wie die Tresore selbst.
- Zurückholen: Server anhalten, Datei ersetzen, starten. Geräte, die inzwischen weiter waren, melden den älteren Stand und bieten „Stand dieses Geräts hochladen“ an.
- Jedes Gerät hält ohnehin eine vollständige Kopie seiner Tresore. Fällt der Server aus, arbeitet jeder mit seinem Stand weiter.

## Änderungen an der Tresor-Datei

Das Format der Datensätze, die Schlüsselkette und alle Prüfwerte aus `tresor.md` bleiben, wie sie sind. Die Datei bekommt die **Formatversion 2**:

- `vaults` trägt zusätzlich Art (persönlich, geteilt), Schlüsselstand, die zuletzt geholte Nummer und die signierte Mitgliederliste (aus ihr folgen Besitzer und eigene Rolle).
- Neu: `base` (der zuletzt abgeglichene Stand jedes Datensatzes mit wartender Änderung), `contacts` (einmal gesehene öffentliche Schlüssel anderer Konten), `notices` (Hinweise aus dem Abgleich).
- Mitgliederlisten, Kontakte und Hinweise nennen Namen. Sie liegen deshalb mit dem Kontoschlüssel verschlüsselt in der Datei: Wer die Datei hat, sieht nicht, mit wem geteilt wird.
- Eine vorgemerkte Verpackung des Kontoschlüssels (siehe „Master-Passwort ändern“) liegt in `meta` neben der geltenden.
- `records` trägt zusätzlich die Revision, die der Server zuletzt bestätigt oder geliefert hat.
- `meta` trägt zusätzlich die Anmeldung am Server (Adresse, Konto, Geräte-Kennung, Geräte-Token) als ein mit dem Kontoschlüssel verschlüsseltes Stück.
- Datensätze fremder Autoren gelten in geteilten Tresoren nach der Mitgliederliste; im persönlichen Tresor bleibt es dabei, dass nur die eigene Signatur zählt.
- Beim ersten Start der neuen Version stellt Glowport um und legt vorher eine Kopie daneben (`vault.db.format1`). Ältere Versionen öffnen eine umgestellte Datei nicht mehr und sagen das.
- **Sicherungsdateien** enthalten alle Tresore, aber kein Geräte-Token: Wer eine Sicherung einspielt, meldet sich am Server neu an und zählt als neues Gerät.

## Prüfungen vor der Abnahme

- Feste Prüfwerte für das Verpacken des Tresor-Schlüssels und für die Signatur der Mitgliederliste.
- Server und zwei bis drei Geräte in einem Test: anlegen, ändern, löschen, in jeder Reihenfolge und mit Unterbrechungen; am Ende haben alle denselben Stand.
- Zusammenführen: jede Paarung aus Ändern, Löschen und Anlegen, dasselbe Feld und verschiedene Felder, unbekannte Felder.
- Regeln über mehrere Datensätze: Gruppen im Kreis, doppeltes Kürzel, Verweis ins Leere.
- Ein Server, der fälscht: veränderte, vertauschte, alte und erfundene Datensätze, eine gefälschte Mitgliederliste, ein falscher Schlüsselstand, ein zurückgedrehter Stand. Alles wird erkannt, nichts übernommen.
- Rechte: Schreiben mit Leserecht wird vom Server und von den anderen Geräten abgelehnt; ein entferntes Mitglied bekommt nichts mehr und kann nach dem Schlüsseltausch nichts Neues lesen.
- Schlüsseltausch, während ein anderes Gerät offline Änderungen hält.
- Anmeldung: falsches Passwort, Bremse, abgemeldetes Gerät, Passwortänderung auf einem Gerät und Entsperren auf dem anderen.
- Ende-zu-Ende mit zwei laufenden Programmen gegen einen Server auf diesem PC, danach gegen den Server auf dem Dedi.
- Messwerte: erster Abgleich mit 1000 Datensätzen, Zeit von der Änderung bis zur Anzeige auf dem zweiten Gerät, Speicher des Servers.

## Bewusst nicht in dieser Fassung

- Zweiter Faktor (vorbereitet, Entscheidung des Users).
- Verlauf alter Fassungen eines Eintrags und Wiederherstellen daraus (der Server hält nur die neueste).
- Tausch des Kontoschlüssels.
- Teilen über Servergrenzen hinweg: Alle Mitglieder eines Tresors haben ihr Konto auf demselben Server.
- Einzelne Einträge teilen: Geteilt wird immer ein ganzer Tresor.
- Mehr als ein Konto oder Server je Glowport.

## Offene Punkte

- Adresse und Zertifikat des Servers auf dem Dedi (bei der Einrichtung mit dem User).
- Wie das Linux-Programm gebaut wird: vorbereitet sind beide Wege, `scripts/build-server.sh` (in einem Linux, etwa WSL; ergibt `dist-server/glowport-sync`) und `server/Dockerfile` (Bau auf dem Server). Welcher genommen wird, entscheidet der User.
