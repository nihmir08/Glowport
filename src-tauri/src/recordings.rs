//! Mitschnitte: die Ausgabe einer Sitzung als lesbare Textdatei im Ordner `logs` des Datenordners.
//!
//! Geschrieben wird, was ein Mensch am Bildschirm lesen würde: ohne Farben und Steuerzeichen, Zeile für Zeile.
//! Programme, die den ganzen Bildschirm übernehmen (Editoren, `htop`), werden übersprungen. Was sie zeichnen,
//! ergäbe als Text keinen Sinn. Die Dateien sind nicht verschlüsselt.
//!
//! Jede Datei beginnt mit Kopfzeilen (Host, Adresse, Beginn, nach dem Umbenennen auch ein Titel) und einer Leerzeile.
//! Daraus und aus Größe und Änderungszeit entsteht die Liste; eine eigene Verzeichnisdatei gibt es nicht. Wer Dateien
//! von Hand löscht, bringt deshalb nichts durcheinander.

use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use chrono::{Local, TimeZone};
use serde::Serialize;

const FOLDER: &str = "logs";
const EXTENSION: &str = "log";
const HEADER: &str = "# Glowport-Mitschnitt";
const TITLE: &str = "# Titel: ";
const TEMP: &str = "umbenennen.neu";
/// Mehr Text zeigt die Oberfläche nicht auf einmal; bei größeren Dateien das Ende.
const MAX_READ: u64 = 4 * 1024 * 1024;
/// Eine einzelne Zeile ohne Ende (etwa ein Binärstrom) wird spätestens hier umbrochen.
const MAX_LINE: usize = 16 * 1024;

pub fn folder(data_dir: &Path) -> PathBuf {
    data_dir.join(FOLDER)
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Recording {
    /// Dateiname; zugleich die Kennung.
    pub id: String,
    /// Name des Hosts oder die eingetippte Adresse.
    pub name: String,
    /// Eigener Name, den der Nutzer dem Mitschnitt nachträglich gegeben hat.
    pub title: Option<String>,
    pub address: String,
    /// Millisekunden seit 1970.
    pub started_at: i64,
    /// Fehlt, solange der Mitschnitt läuft.
    pub ended_at: Option<i64>,
    pub bytes: u64,
    pub file: String,
}

/// Wo der Leser der Ausgabe gerade steht.
#[derive(Clone, Copy, PartialEq)]
enum State {
    Text,
    /// Nach ESC.
    Escape,
    /// In einer Folge `ESC [ … Buchstabe`.
    Csi,
    /// In einer Folge `ESC ] … BEL` oder `… ESC \` (Fenstertitel und Ähnliches), ebenso bei `ESC P`, `ESC _`, `ESC ^`.
    String,
    /// Nach ESC innerhalb einer solchen Folge.
    StringEscape,
    /// Nach `ESC (` und Verwandten folgt genau ein Zeichen.
    Skip,
}

/// Macht aus dem Strom des Terminals lesbare Zeilen.
struct Plain {
    state: State,
    /// Die bisher gelesenen Parameter einer `ESC [`-Folge.
    params: Vec<u8>,
    line: Vec<u8>,
    /// Nach einem Wagenrücklauf ohne Zeilenende beginnt die Zeile von vorn (Fortschrittsbalken, neu gezeichnete Eingabe).
    restart: bool,
    /// Ein Programm hat den ganzen Bildschirm übernommen.
    full_screen: bool,
}

impl Plain {
    fn new() -> Self {
        Self { state: State::Text, params: Vec::new(), line: Vec::new(), restart: false, full_screen: false }
    }

    /// Liest ein Stück Ausgabe und übergibt jede fertige Zeile (ohne Zeilenende) an `emit`.
    fn feed(&mut self, bytes: &[u8], mut emit: impl FnMut(&[u8])) {
        for &byte in bytes {
            match self.state {
                State::Text => match byte {
                    0x1b => self.state = State::Escape,
                    b'\n' => {
                        if !self.full_screen {
                            emit(&self.line);
                        }
                        self.line.clear();
                        self.restart = false;
                    }
                    b'\r' => self.restart = true,
                    0x08 => {
                        // Rückschritt: das letzte Zeichen samt seiner Folgebytes entfernen.
                        while let Some(last) = self.line.pop() {
                            if last & 0xC0 != 0x80 {
                                break;
                            }
                        }
                    }
                    b'\t' => self.push(b'\t', &mut emit),
                    0x00..=0x1f | 0x7f => {}
                    _ => self.push(byte, &mut emit),
                },
                State::Escape => {
                    self.state = match byte {
                        b'[' => {
                            self.params.clear();
                            State::Csi
                        }
                        b']' | b'P' | b'_' | b'^' | b'X' => State::String,
                        b'(' | b')' | b'*' | b'+' | b'#' | b'%' | b' ' => State::Skip,
                        _ => State::Text,
                    }
                }
                State::Csi => match byte {
                    0x20..=0x3f => {
                        if self.params.len() < 32 {
                            self.params.push(byte);
                        }
                    }
                    _ => {
                        self.csi(byte);
                        self.state = State::Text;
                    }
                },
                State::String => match byte {
                    0x07 => self.state = State::Text,
                    0x1b => self.state = State::StringEscape,
                    _ => {}
                },
                State::StringEscape => self.state = if byte == b'\\' { State::Text } else { State::String },
                State::Skip => self.state = State::Text,
            }
        }
    }

    fn push(&mut self, byte: u8, emit: &mut impl FnMut(&[u8])) {
        if self.restart {
            self.line.clear();
            self.restart = false;
        }
        self.line.push(byte);
        // Nur an einer Zeichengrenze umbrechen, damit kein Zeichen aus mehreren Bytes zerrissen wird.
        if self.line.len() >= MAX_LINE && byte & 0x80 == 0 {
            if !self.full_screen {
                emit(&self.line);
            }
            self.line.clear();
        }
    }

    /// Wertet das Ende einer `ESC [`-Folge aus. Von Belang ist nur das Umschalten auf den zweiten Bildschirm.
    fn csi(&mut self, last: u8) {
        if (last == b'h' || last == b'l') && self.params.first() == Some(&b'?') {
            let alternate = self.params[1..].split(|b| *b == b';').any(|mode| matches!(mode, b"47" | b"1047" | b"1049"));
            if alternate {
                self.full_screen = last == b'h';
                self.line.clear();
                self.restart = false;
            }
        }
    }

    /// Der Rest einer Zeile ohne Zeilenende, etwa die Eingabeaufforderung am Schluss.
    fn rest(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.line)
    }
}

/// Schreibt die Ausgabe einer Sitzung in ihre Datei.
pub struct Recorder {
    id: String,
    file: BufWriter<File>,
    plain: Plain,
    failed: bool,
}

/// Für Dateinamen: nur Zeichen, die jedes Dateisystem annimmt.
fn file_part(name: &str) -> String {
    let cleaned: String = name.chars().map(|c| if c.is_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' }).take(60).collect();
    let cleaned = cleaned.trim_matches(|c| c == '.' || c == '_').to_string();
    if cleaned.is_empty() {
        "sitzung".into()
    } else {
        cleaned
    }
}

/// Eine Kopfzeile darf keine Zeilenenden tragen.
fn one_line(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(200).collect()
}

impl Recorder {
    /// Legt die Datei an und schreibt den Kopf. `name` und `address` stehen später in der Liste.
    pub fn start(data_dir: &Path, name: &str, address: &str) -> io::Result<Self> {
        let dir = folder(data_dir);
        fs::create_dir_all(&dir)?;
        let now = Local::now();
        let base = format!("{}_{}", now.format("%Y-%m-%d_%H-%M-%S"), file_part(name));
        // Zwei Mitschnitte desselben Hosts in derselben Sekunde bekommen eine Zählnummer.
        let (id, file) = (0..100)
            .find_map(|n| {
                let id = if n == 0 { format!("{base}.{EXTENSION}") } else { format!("{base}_{n}.{EXTENSION}") };
                fs::OpenOptions::new().write(true).create_new(true).open(dir.join(&id)).ok().map(|file| (id, file))
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::AlreadyExists, "kein freier Dateiname"))?;
        let mut file = BufWriter::new(file);
        writeln!(file, "{HEADER}")?;
        writeln!(file, "# Host: {}", one_line(name))?;
        writeln!(file, "# Adresse: {}", one_line(address))?;
        writeln!(file, "# Beginn: {} ({})", now.format("%Y-%m-%d %H:%M:%S"), now.timestamp_millis())?;
        writeln!(file)?;
        file.flush()?;
        Ok(Self { id, file, plain: Plain::new(), failed: false })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Nimmt ein Stück Ausgabe (UTF-8) auf. Ein Schreibfehler beendet den Mitschnitt still; die Sitzung läuft weiter.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed {
            return;
        }
        let file = &mut self.file;
        let mut ok = true;
        self.plain.feed(bytes, |line| {
            ok &= file.write_all(String::from_utf8_lossy(line).trim_end().as_bytes()).is_ok() && file.write_all(b"\n").is_ok();
        });
        // Fertige Zeilen sollen gleich in der Datei stehen: Wer mitliest oder nach einem Absturz nachsieht, findet sie.
        self.failed = !ok || self.file.flush().is_err();
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        let rest = self.plain.rest();
        if !rest.is_empty() {
            let _ = writeln!(self.file, "{}", String::from_utf8_lossy(&rest).trim_end());
        }
        let _ = self.file.flush();
    }
}

/// Prüft eine Kennung aus der Oberfläche: ein schlichter Dateiname im Ordner der Mitschnitte, nichts sonst.
fn path_of(data_dir: &Path, id: &str) -> Option<PathBuf> {
    let plain = !id.is_empty() && id.len() <= 200 && !id.starts_with('.') && id.chars().all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'));
    (plain && id.ends_with(&format!(".{EXTENSION}"))).then(|| folder(data_dir).join(id))
}

fn millis(time: io::Result<std::time::SystemTime>) -> Option<i64> {
    time.ok()?.duration_since(UNIX_EPOCH).ok().map(|d| d.as_millis() as i64)
}

/// Liest den Kopf einer Datei. `None`, wenn sie kein Mitschnitt von Glowport ist.
fn describe(path: &Path, running: &[String]) -> Option<Recording> {
    let id = path.file_name()?.to_str()?.to_string();
    let meta = fs::metadata(path).ok()?;
    let mut lines = BufReader::new(File::open(path).ok()?).lines();
    if lines.next()?.ok()? != HEADER {
        return None;
    }
    // Der Kopf reicht bis zur ersten Leerzeile; die Reihenfolge seiner Zeilen spielt keine Rolle.
    let head: Vec<String> = lines.take(8).map_while(Result::ok).take_while(|line| !line.is_empty()).collect();
    let field = |label: &str| head.iter().find_map(|line| line.strip_prefix(label)).map(str::to_string);
    let name = field("# Host: ")?;
    let address = field("# Adresse: ")?;
    let begin = field("# Beginn: ")?;
    let title = field(TITLE).filter(|title| !title.trim().is_empty());
    // Die Zahl in Klammern ist der Beginn in Millisekunden; fehlt sie, gilt das lesbare Datum davor.
    let started_at = begin
        .rsplit_once('(')
        .and_then(|(_, tail)| tail.trim_end_matches(')').parse::<i64>().ok())
        .or_else(|| chrono::NaiveDateTime::parse_from_str(begin.get(..19)?, "%Y-%m-%d %H:%M:%S").ok().and_then(|t| Local.from_local_datetime(&t).single()).map(|t| t.timestamp_millis()))?;
    let ended_at = if running.contains(&id) { None } else { Some(millis(meta.modified()).unwrap_or(started_at).max(started_at)) };
    Some(Recording { id, name, title, address, started_at, ended_at, bytes: meta.len(), file: path.display().to_string() })
}

/// Alle Mitschnitte, der jüngste zuerst. `running` nennt die Dateien, in die gerade geschrieben wird.
pub fn list(data_dir: &Path, running: &[String]) -> Vec<Recording> {
    let Ok(entries) = fs::read_dir(folder(data_dir)) else { return Vec::new() };
    let mut found: Vec<Recording> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|e| e == EXTENSION))
        .filter_map(|path| describe(&path, running))
        .collect();
    found.sort_by(|a, b| b.started_at.cmp(&a.started_at).then_with(|| b.id.cmp(&a.id)));
    found
}

/// Der Text eines Mitschnitts ohne den Kopf. Von sehr großen Dateien das Ende.
pub fn read(data_dir: &Path, id: &str) -> io::Result<String> {
    let path = path_of(data_dir, id).ok_or(io::ErrorKind::NotFound)?;
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    let mut bytes = Vec::new();
    if size > MAX_READ {
        io::Seek::seek(&mut file, io::SeekFrom::Start(size - MAX_READ))?;
        file.read_to_end(&mut bytes)?;
        // Ab der ersten vollständigen Zeile.
        let start = bytes.iter().position(|b| *b == b'\n').map_or(0, |i| i + 1);
        return Ok(String::from_utf8_lossy(&bytes[start..]).into_owned());
    }
    file.read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);
    // Kopf: alle Zeilen bis einschließlich der ersten Leerzeile.
    Ok(match text.strip_prefix(HEADER).and_then(|rest| rest.split_once("\n\n")) {
        Some((_, body)) => body.to_string(),
        None => text.into_owned(),
    })
}

/// Gibt einem fertigen Mitschnitt einen eigenen Namen; ein leerer nimmt ihn wieder weg. Der Name steht danach im
/// Kopf der Datei, und die Datei heißt auch so, damit man sie im Dateimanager wiederfindet. Liefert die neue Kennung.
/// Der Inhalt und der Zeitpunkt des Endes (die Änderungszeit der Datei) bleiben, wie sie sind.
pub fn rename(data_dir: &Path, id: &str, title: &str) -> io::Result<String> {
    let path = path_of(data_dir, id).ok_or(io::ErrorKind::NotFound)?;
    let modified = fs::metadata(&path)?.modified()?;
    let bytes = fs::read(&path)?;
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "kein Mitschnitt von Glowport");
    let split = bytes.windows(2).position(|pair| pair == b"\n\n").filter(|_| bytes.starts_with(HEADER.as_bytes())).ok_or_else(invalid)?;
    let head = String::from_utf8_lossy(&bytes[..split]);
    let host = head.lines().find_map(|line| line.strip_prefix("# Host: ")).ok_or_else(invalid)?.to_string();
    let title = one_line(title.trim());

    let mut lines: Vec<String> = head.lines().filter(|line| !line.starts_with(TITLE)).map(str::to_string).collect();
    if !title.is_empty() {
        lines.insert(1, format!("{TITLE}{title}"));
    }
    // Der Zeitstempel am Anfang des Dateinamens bleibt; dahinter steht der neue Name, sonst wieder der Host.
    let stamp = id.get(..19).filter(|stamp| stamp.len() == 19 && stamp.chars().all(|c| c.is_ascii_digit() || c == '-' || c == '_')).unwrap_or("mitschnitt");
    let base = format!("{stamp}_{}", file_part(if title.is_empty() { &host } else { &title }));
    let dir = folder(data_dir);
    let new_id = (0..100)
        .map(|n| if n == 0 { format!("{base}.{EXTENSION}") } else { format!("{base}_{n}.{EXTENSION}") })
        .find(|candidate| candidate == id || !dir.join(candidate).exists())
        .ok_or_else(|| io::Error::new(io::ErrorKind::AlreadyExists, "kein freier Dateiname"))?;

    let temp = dir.join(TEMP);
    let mut file = File::create(&temp)?;
    file.write_all(lines.join("\n").as_bytes())?;
    file.write_all(&bytes[split..])?;
    file.set_modified(modified)?;
    drop(file);
    fs::rename(&temp, dir.join(&new_id))?;
    if new_id != id {
        fs::remove_file(&path)?;
    }
    Ok(new_id)
}

pub fn delete(data_dir: &Path, id: &str) -> io::Result<()> {
    fs::remove_file(path_of(data_dir, id).ok_or(io::ErrorKind::NotFound)?)
}

/// Pfad einer Datei zum Zeigen im Dateimanager; ohne Kennung der Ordner (er wird dafür angelegt).
pub fn reveal_target(data_dir: &Path, id: Option<&str>) -> io::Result<PathBuf> {
    match id {
        Some(id) => path_of(data_dir, id).filter(|path| path.exists()).ok_or_else(|| io::ErrorKind::NotFound.into()),
        None => {
            let dir = folder(data_dir);
            fs::create_dir_all(&dir)?;
            Ok(dir)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(chunks: &[&[u8]]) -> Vec<String> {
        let mut reader = Plain::new();
        let mut lines = Vec::new();
        for chunk in chunks {
            reader.feed(chunk, |line| lines.push(String::from_utf8_lossy(line).into_owned()));
        }
        let rest = reader.rest();
        if !rest.is_empty() {
            lines.push(String::from_utf8_lossy(&rest).into_owned());
        }
        lines
    }

    #[test]
    fn colours_titles_and_control_characters_are_removed() {
        let shell = b"\x1b]0;deploy@web-01: ~\x07\x1b[1;32mdeploy@web-01\x1b[0m:\x1b[1;34m~\x1b[0m$ ls\r\n\x1b[01;34mapp\x1b[0m  notes.md\r\n";
        assert_eq!(plain(&[shell]), ["deploy@web-01:~$ ls", "app  notes.md"]);
        assert_eq!(plain(&[b"a\x07b\x1b(Bc\x1b=d\x1b[?2004h\r\n"]), ["abcd"]);
        assert_eq!(plain(&[b"\x1bP1$r0m\x1b\\sichtbar\n"]), ["sichtbar"], "auch Folgen, die mit ESC \\ enden");
    }

    #[test]
    fn a_sequence_split_across_packets_stays_invisible() {
        assert_eq!(plain(&[b"vor\x1b[1;3", b"2mnach\x1b", b"[0m\n"]), ["vornach"]);
        // Ein Zeichen aus mehreren Bytes, auf zwei Pakete verteilt.
        let text = "Größe\n".as_bytes();
        assert_eq!(plain(&[&text[..3], &text[3..]]), ["Größe"]);
    }

    #[test]
    fn redrawn_lines_keep_only_their_last_state() {
        assert_eq!(plain(&[b"10 %\r50 %\r100 %\r\nfertig\r\n"]), ["100 %", "fertig"]);
        assert_eq!(plain(&[b"lss\x08 \x08 -la\r\n"]), ["ls -la"], "Rueckschritt entfernt das vertippte Zeichen");
        assert_eq!(plain(&["gr\u{f6}\x08\x08\u{fc}n\n".as_bytes()]), ["g\u{fc}n"], "auch Zeichen aus mehreren Bytes");
    }

    #[test]
    fn full_screen_programs_are_left_out() {
        let session = b"$ vim notes.md\r\n\x1b[?1049h\x1b[2J~ viel Bildschirm\r\n~ noch mehr\x1b[?1049l$ echo fertig\r\nfertig\r\n";
        assert_eq!(plain(&[session]), ["$ vim notes.md", "$ echo fertig", "fertig"]);
    }

    #[test]
    fn recordings_are_written_listed_read_and_deleted() {
        let dir = std::env::temp_dir().join(format!("glowport-rec-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        assert!(list(&dir, &[]).is_empty(), "ohne Ordner gibt es keine Mitschnitte");

        let mut recorder = Recorder::start(&dir, "web/01: prod", "deploy@10.0.10.11").unwrap();
        let id = recorder.id().to_string();
        assert!(id.ends_with("_web_01__prod.log"), "{id}");
        recorder.feed(b"\x1b[32mdeploy@web-01\x1b[0m:~$ uptime\r\n 17:42 up 13 days\r\n");
        recorder.feed(b"deploy@web-01:~$ ");

        let running = list(&dir, std::slice::from_ref(&id));
        assert_eq!((running.len(), running[0].ended_at, running[0].name.as_str(), running[0].address.as_str()), (1, None, "web/01: prod", "deploy@10.0.10.11"));
        assert_eq!(read(&dir, &id).unwrap(), "deploy@web-01:~$ uptime\n 17:42 up 13 days\n", "fertige Zeilen stehen sofort in der Datei");

        drop(recorder);
        let done = list(&dir, &[]);
        assert!(done[0].ended_at.is_some_and(|end| end >= done[0].started_at));
        assert_eq!(read(&dir, &id).unwrap(), "deploy@web-01:~$ uptime\n 17:42 up 13 days\ndeploy@web-01:~$\n");

        // Fremde Dateien im Ordner und Pfade nach draußen zählen nicht.
        fs::write(folder(&dir).join("notiz.log"), "kein Mitschnitt").unwrap();
        assert_eq!(list(&dir, &[]).len(), 1);
        assert!(read(&dir, "../vault.db").is_err() && read(&dir, "..\\vault.db").is_err() && delete(&dir, "C:\\Windows\\win.ini").is_err());
        assert_eq!(reveal_target(&dir, Some(&id)).unwrap(), folder(&dir).join(&id));
        assert_eq!(reveal_target(&dir, None).unwrap(), folder(&dir));

        // Umbenennen: Der Name steht in der Liste und im Dateinamen, Inhalt und Zeiten bleiben.
        let before = list(&dir, &[]).remove(0);
        let renamed = rename(&dir, &id, "  Deploy vor dem Release: Größe prüfen  ").unwrap();
        assert!(renamed.starts_with(&id[..19]) && renamed.ends_with("_Deploy_vor_dem_Release__Größe_prüfen.log"), "{renamed}");
        assert!(!folder(&dir).join(&id).exists() && !folder(&dir).join(TEMP).exists());
        let after = list(&dir, &[]).remove(0);
        assert_eq!((after.id.as_str(), after.title.as_deref(), after.name.as_str()), (renamed.as_str(), Some("Deploy vor dem Release: Größe prüfen"), "web/01: prod"));
        assert_eq!((after.started_at, after.ended_at), (before.started_at, before.ended_at), "Beginn und Ende bleiben");
        assert_eq!(read(&dir, &renamed).unwrap(), "deploy@web-01:~$ uptime\n 17:42 up 13 days\ndeploy@web-01:~$\n");
        // Ein zweites Mal mit demselben Namen ändert nichts; ein leerer Name gibt der Datei wieder den des Hosts.
        assert_eq!(rename(&dir, &renamed, "Deploy vor dem Release: Größe prüfen").unwrap(), renamed);
        let plain = rename(&dir, &renamed, " ").unwrap();
        assert_eq!((plain.as_str(), list(&dir, &[])[0].title.as_deref()), (id.as_str(), None));
        assert!(rename(&dir, "../vault.db", "x").is_err() && rename(&dir, "notiz.log", "x").is_err(), "nur Mitschnitte lassen sich umbenennen");

        delete(&dir, &id).unwrap();
        assert!(list(&dir, &[]).is_empty() && delete(&dir, &id).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
