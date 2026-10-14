//! Zusammenführen gleichzeitiger Änderungen an einem Datensatz. Regeln: `docs/sync.md`, „Gleichzeitige Änderungen“.
//!
//! Drei Fassungen: der gemeinsame Ausgangsstand, die eigene, die des Servers. Objekte werden Schlüssel für
//! Schlüssel verglichen, alles andere (Listen, Texte, Zahlen) gilt als ein Feld. Der Inhalt wird nicht
//! gedeutet; unbekannte Felder und unbekannte Arten gehen denselben Weg.

use serde_json::{Map, Value};
use zeroize::Zeroizing;

/// Wessen Wert bei einem Widerspruch gilt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Mine,
    Theirs,
}

/// Ein Feld, das beide Seiten verschieden geändert haben, etwa `own.port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clash {
    pub path: String,
    pub winner: Side,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Das Ergebnis ist genau die Fassung des Servers; es gibt nichts zu schicken.
    Theirs,
    /// Das Ergebnis weicht von der Fassung des Servers ab und geht als neue Revision hinaus.
    Merged(Zeroizing<Vec<u8>>),
    /// Der Datensatz bleibt gelöscht, obwohl der Server ihn noch führt.
    Deleted,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Merge {
    pub outcome: Outcome,
    pub clashes: Vec<Clash>,
    /// Eine Seite hatte gelöscht, die andere geändert: Die Änderung hat gewonnen.
    pub restored: bool,
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

/// Führt ein Feld zusammen. `None` heißt: Das Feld gibt es in dieser Fassung nicht.
fn field(base: Option<&Value>, mine: Option<&Value>, theirs: Option<&Value>, prefer: Side, path: &str, clashes: &mut Vec<Clash>) -> Option<Value> {
    if mine == theirs || mine == base {
        return theirs.cloned();
    }
    if theirs == base {
        return mine.cloned();
    }
    if let (Some(Value::Object(mine)), Some(Value::Object(theirs))) = (mine, theirs) {
        let empty = Map::new();
        let base = base.and_then(Value::as_object).unwrap_or(&empty);
        return Some(Value::Object(object(base, mine, theirs, prefer, path, clashes)));
    }
    clashes.push(Clash { path: path.to_string(), winner: prefer });
    match prefer {
        Side::Mine => mine.cloned(),
        Side::Theirs => theirs.cloned(),
    }
}

fn object(base: &Map<String, Value>, mine: &Map<String, Value>, theirs: &Map<String, Value>, prefer: Side, path: &str, clashes: &mut Vec<Clash>) -> Map<String, Value> {
    let mut out = Map::new();
    // Reihenfolge wie beim Server, eigene neue Felder dahinter: So bleibt ein unverändertes Ergebnis erkennbar.
    for key in theirs.keys().chain(mine.keys().filter(|k| !theirs.contains_key(*k))) {
        if let Some(value) = field(base.get(key), mine.get(key), theirs.get(key), prefer, &join(path, key), clashes) {
            out.insert(key.clone(), value);
        }
    }
    out
}

fn parse(bytes: &[u8]) -> Option<Value> {
    serde_json::from_slice(bytes).ok()
}

/// Führt drei Fassungen eines Datensatzes zusammen. `None` steht für „gelöscht“, bei `base` auch für „gab es
/// noch nicht“. `mine_newer`: Die eigene Änderung ist die jüngere und gewinnt, wo beide dasselbe Feld ändern.
pub fn merge(base: Option<&[u8]>, mine: Option<&[u8]>, theirs: Option<&[u8]>, mine_newer: bool) -> Merge {
    let done = |outcome| Merge { outcome, clashes: Vec::new(), restored: false };
    let (mine, theirs) = match (mine, theirs) {
        (None, None) => return done(Outcome::Theirs),
        // Löschen gegen Ändern: Die Änderung gewinnt. Hat die andere Seite nichts geändert, gilt das Löschen.
        (None, Some(theirs)) => {
            return match base {
                Some(base) if parse(base) == parse(theirs) => done(Outcome::Deleted),
                _ => Merge { restored: true, ..done(Outcome::Theirs) },
            }
        }
        (Some(mine), None) => {
            return match base {
                Some(base) if parse(base) == parse(mine) => done(Outcome::Theirs),
                _ => Merge { restored: true, ..done(Outcome::Merged(Zeroizing::new(mine.to_vec()))) },
            }
        }
        (Some(mine), Some(theirs)) => (mine, theirs),
    };
    let prefer = if mine_newer { Side::Mine } else { Side::Theirs };
    let (Some(mine_value), Some(theirs_value)) = (parse(mine), parse(theirs)) else {
        // Kein JSON: als ein einziges Feld behandeln.
        return match (prefer, mine == theirs) {
            (_, true) | (Side::Theirs, _) => done(Outcome::Theirs),
            (Side::Mine, _) => done(Outcome::Merged(Zeroizing::new(mine.to_vec()))),
        };
    };
    let mut clashes = Vec::new();
    let merged = field(base.and_then(parse).as_ref(), Some(&mine_value), Some(&theirs_value), prefer, "", &mut clashes).unwrap_or(Value::Null);
    let outcome = if merged == theirs_value {
        Outcome::Theirs
    } else {
        Outcome::Merged(Zeroizing::new(serde_json::to_vec(&merged).expect("JSON lässt sich immer schreiben")))
    };
    Merge { outcome, clashes, restored: false }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    fn run(base: Option<Value>, mine: Option<Value>, theirs: Option<Value>, mine_newer: bool) -> (Option<Value>, Merge) {
        let (base, mine, theirs) = (base.as_ref().map(bytes), mine.as_ref().map(bytes), theirs.as_ref().map(bytes));
        let merge = merge(base.as_deref(), mine.as_deref(), theirs.as_deref(), mine_newer);
        let value = match &merge.outcome {
            Outcome::Theirs => theirs.as_deref().map(|t| parse(t).unwrap()),
            Outcome::Merged(bytes) => Some(parse(bytes).unwrap()),
            Outcome::Deleted => None,
        };
        (value, merge)
    }

    #[test]
    fn different_fields_both_survive() {
        let base = json!({"t": "host", "name": "web", "own": {"port": 22, "user": "root"}});
        let mine = json!({"t": "host", "name": "web", "own": {"port": 2222, "user": "root"}});
        let theirs = json!({"t": "host", "name": "web-01", "own": {"port": 22, "user": "root", "scheme": "nord"}});
        let (value, merge) = run(Some(base), Some(mine), Some(theirs), false);
        assert_eq!(value.unwrap(), json!({"t": "host", "name": "web-01", "own": {"port": 2222, "user": "root", "scheme": "nord"}}));
        assert!(merge.clashes.is_empty() && !merge.restored);
        assert!(matches!(merge.outcome, Outcome::Merged(_)));
    }

    #[test]
    fn the_same_field_goes_to_the_newer_change() {
        let base = json!({"name": "web", "own": {"port": 22}});
        let mine = json!({"name": "web", "own": {"port": 2222}});
        let theirs = json!({"name": "web", "own": {"port": 2200}});
        let (value, merge) = run(Some(base.clone()), Some(mine.clone()), Some(theirs.clone()), true);
        assert_eq!(value.unwrap()["own"]["port"], 2222);
        assert_eq!(merge.clashes, [Clash { path: "own.port".into(), winner: Side::Mine }]);

        let (value, merge) = run(Some(base), Some(mine), Some(theirs), false);
        assert_eq!(value.unwrap()["own"]["port"], 2200);
        assert_eq!(merge.clashes, [Clash { path: "own.port".into(), winner: Side::Theirs }]);
        assert_eq!(merge.outcome, Outcome::Theirs, "nichts Eigenes übrig, also nichts zu schicken");
    }

    #[test]
    fn removed_fields_lists_and_unknown_fields() {
        // Ein Feld entfernen ist eine Änderung; Listen gelten als Ganzes; Unbekanntes bleibt.
        let base = json!({"color": "#FE9803", "env": [["A", "1"]], "zukunft": {"x": 1}});
        let mine = json!({"env": [["A", "1"], ["B", "2"]], "zukunft": {"x": 1}});
        let theirs = json!({"color": "#FE9803", "env": [["A", "1"]], "zukunft": {"x": 1, "y": 2}});
        let (value, merge) = run(Some(base.clone()), Some(mine), Some(theirs), false);
        assert_eq!(value.unwrap(), json!({"env": [["A", "1"], ["B", "2"]], "zukunft": {"x": 1, "y": 2}}));
        assert!(merge.clashes.is_empty());

        // Beide ändern dieselbe Liste: ein Feld, eine Seite gewinnt.
        let mine = json!({"color": "#FE9803", "env": [["B", "2"]], "zukunft": {"x": 1}});
        let theirs = json!({"color": "#FE9803", "env": [["C", "3"]], "zukunft": {"x": 1}});
        let (value, merge) = run(Some(base), Some(mine), Some(theirs), true);
        assert_eq!(value.unwrap()["env"], json!([["B", "2"]]));
        assert_eq!(merge.clashes.len(), 1);
    }

    #[test]
    fn the_same_change_on_both_sides_is_no_clash() {
        let base = json!({"name": "a"});
        let both = json!({"name": "b"});
        let (_, merge) = run(Some(base), Some(both.clone()), Some(both), true);
        assert_eq!(merge, Merge { outcome: Outcome::Theirs, clashes: vec![], restored: false });
    }

    #[test]
    fn change_beats_delete() {
        let base = json!({"name": "a"});
        let changed = json!({"name": "b"});
        // Ich lösche, die anderen ändern: ihr Stand bleibt.
        let (value, merge) = run(Some(base.clone()), None, Some(changed.clone()), true);
        assert_eq!((value, merge.restored, &merge.outcome), (Some(changed.clone()), true, &Outcome::Theirs));
        // Ich lösche, die anderen haben nichts geändert (nur neu verschlüsselt): Es bleibt gelöscht.
        let (value, merge) = run(Some(base.clone()), None, Some(base.clone()), true);
        assert_eq!((value, merge.restored, &merge.outcome), (None, false, &Outcome::Deleted));
        // Die anderen löschen, ich ändere: Mein Stand kommt zurück.
        let (value, merge) = run(Some(base.clone()), Some(changed.clone()), None, false);
        assert_eq!((value, merge.restored), (Some(changed), true));
        // Die anderen löschen, ich habe nichts geändert.
        let (value, merge) = run(Some(base.clone()), Some(base), None, false);
        assert_eq!((value, merge.restored, &merge.outcome), (None, false, &Outcome::Theirs));
        // Beide löschen.
        assert_eq!(run(Some(json!({})), None, None, true).1.outcome, Outcome::Theirs);
    }

    #[test]
    fn without_a_common_start_every_difference_is_a_clash() {
        let mine = json!({"name": "a", "own": {"port": 1}});
        let theirs = json!({"name": "b", "own": {"user": "x"}});
        let (value, merge) = run(None, Some(mine), Some(theirs), false);
        assert_eq!(value.unwrap(), json!({"name": "b", "own": {"user": "x", "port": 1}}));
        assert_eq!(merge.clashes, [Clash { path: "name".into(), winner: Side::Theirs }]);
    }

    #[test]
    fn content_that_is_not_json_counts_as_one_field() {
        let merge = super::merge(Some(b"a"), Some(b"b"), Some(b"c"), true);
        assert_eq!(merge.outcome, Outcome::Merged(Zeroizing::new(b"b".to_vec())));
        assert_eq!(super::merge(Some(b"a"), Some(b"b"), Some(b"c"), false).outcome, Outcome::Theirs);
    }
}
