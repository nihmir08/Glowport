//! Die Warteschlange der Transfers: Dateien und Ordner zwischen diesem PC und Servern, auch von Server zu Server.
//!
//! Jeder Auftrag ist ein Eintrag der Liste (eine Datei oder ein Ordner samt Inhalt). Bis zu `parallel` Dateien
//! laufen gleichzeitig, in der Reihenfolge der Liste. Ein angehaltener oder unterbrochener Auftrag merkt sich je
//! Datei, wie weit er war, und macht dort weiter; unfertige Aufträge werden in `transfers.json` vorgemerkt und
//! nach einem Neustart angehalten wieder angeboten.
//!
//! Die Warteschlange kennt weder Fenster noch Tresor: Wie ein Ort erreicht wird, sagt ihr [`Resolve`], und den
//! Stand gibt sie über [`Publish`] heraus. So lässt sie sich ohne Programmfenster prüfen.

use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant, UNIX_EPOCH},
};

use glowport_net::files::{FileError, Kind};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt},
    sync::Notify,
};

use crate::{
    app::{AppState, CmdError, CmdResult},
    files::{self, Place},
    sessions,
};
use crate::store::Store as Remote;

const CHUNK: usize = 256 * 1024;
const TICK: Duration = Duration::from_millis(250);
/// Nach so vielen Bytes hält eine laufende Kopie ihren Stand fest. Endet das Programm hart, geht höchstens das verloren.
const CHECKPOINT: u64 = 8 * 1024 * 1024;

/// Wie ein Ort erreicht wird. Scheitert es, kommt der Fehlercode für die Oberfläche zurück.
pub type Resolve = Arc<dyn Fn(Place) -> Pin<Box<dyn Future<Output = Result<Endpoint, &'static str>> + Send>> + Send + Sync>;
pub type Publish = Arc<dyn Fn(Vec<TransferView>) + Send + Sync>;
/// Sagt Bescheid, dass die Verbindung zu einem Ort abgerissen ist und beim nächsten Mal neu aufgebaut werden muss.
pub type Forget = Arc<dyn Fn(Place) + Send + Sync>;

/// Ein erreichbarer Ort: dieser PC oder ein Server über SFTP.
#[derive(Clone)]
pub enum Endpoint {
    Local,
    Remote(Arc<Remote>),
}

struct Meta {
    dir: bool,
    size: u64,
    /// Sekunden seit 1970.
    modified: u64,
}

fn seconds(time: std::io::Result<std::time::SystemTime>) -> u64 {
    time.ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs())
}

impl Endpoint {
    fn join(&self, dir: &str, name: &str) -> String {
        match self {
            Endpoint::Local => Path::new(dir).join(name).to_string_lossy().into_owned(),
            Endpoint::Remote(_) if dir.ends_with('/') => format!("{dir}{name}"),
            Endpoint::Remote(_) => format!("{dir}/{name}"),
        }
    }

    /// Angaben zu einem Pfad; `None`, wenn es ihn nicht gibt. Verknüpfungen zählen als ihr Ziel.
    async fn stat(&self, path: &str) -> Result<Option<Meta>, FileError> {
        let found = match self {
            Endpoint::Local => tokio::fs::metadata(path).await.map(|m| Meta { dir: m.is_dir(), size: m.len(), modified: seconds(m.modified()) }).map_err(FileError::from),
            Endpoint::Remote(remote) => remote.stat(path, true).await.map(|e| Meta { dir: e.kind == Kind::Dir, size: e.size, modified: e.modified }),
        };
        match found {
            Ok(meta) => Ok(Some(meta)),
            Err(FileError::NoSuchFile) => Ok(None),
            Err(other) => Err(other),
        }
    }

    async fn list(&self, path: &str) -> Result<Vec<(String, Meta)>, FileError> {
        let mut out = Vec::new();
        match self {
            Endpoint::Local => {
                let mut dir = tokio::fs::read_dir(path).await?;
                while let Some(item) = dir.next_entry().await? {
                    // Was sich nicht lesen lässt oder ins Leere zeigt, bleibt liegen.
                    if let Ok(meta) = tokio::fs::metadata(item.path()).await {
                        out.push((item.file_name().to_string_lossy().into_owned(), Meta { dir: meta.is_dir(), size: meta.len(), modified: seconds(meta.modified()) }));
                    }
                }
            }
            Endpoint::Remote(remote) => {
                for entry in remote.list(path).await? {
                    let meta = match entry.kind {
                        Kind::Link => match self.stat(&self.join(path, &entry.name)).await {
                            Ok(Some(meta)) => meta,
                            _ => continue,
                        },
                        kind => Meta { dir: kind == Kind::Dir, size: entry.size, modified: entry.modified },
                    };
                    out.push((entry.name, meta));
                }
            }
        }
        Ok(out)
    }

    /// Legt einen Ordner an; gibt es ihn schon, ist das recht.
    async fn mkdir(&self, path: &str) -> Result<(), FileError> {
        if self.stat(path).await?.is_some_and(|meta| meta.dir) {
            return Ok(());
        }
        match self {
            Endpoint::Local => Ok(tokio::fs::create_dir_all(path).await?),
            Endpoint::Remote(remote) => remote.mkdir(path).await,
        }
    }

    async fn reader(&self, path: &str, offset: u64) -> Result<Box<dyn AsyncRead + Unpin + Send>, FileError> {
        Ok(match self {
            Endpoint::Local => {
                let mut file = tokio::fs::File::open(path).await?;
                file.seek(std::io::SeekFrom::Start(offset)).await?;
                Box::new(file)
            }
            Endpoint::Remote(remote) => remote.reader(path, offset).await?,
        })
    }

    async fn writer(&self, path: &str, offset: u64) -> Result<Box<dyn AsyncWrite + Unpin + Send>, FileError> {
        Ok(match self {
            Endpoint::Local => {
                let mut file = tokio::fs::OpenOptions::new().write(true).create(true).truncate(offset == 0).open(path).await?;
                file.seek(std::io::SeekFrom::Start(offset)).await?;
                Box::new(file)
            }
            Endpoint::Remote(remote) => remote.writer(path, offset).await?,
        })
    }

    /// Gibt der Kopie die Änderungszeit des Originals, damit ein späterer Abgleich sie als gleich erkennt.
    async fn touch(&self, path: &str, modified: u64) {
        match self {
            Endpoint::Local => {
                let path = PathBuf::from(path);
                let _ = tokio::task::spawn_blocking(move || std::fs::OpenOptions::new().write(true).open(path).and_then(|file| file.set_modified(UNIX_EPOCH + Duration::from_secs(modified)))).await;
            }
            Endpoint::Remote(remote) => drop(remote.touch(path, modified).await),
        }
    }

    async fn remove(&self, path: &str) {
        match self {
            Endpoint::Local => drop(tokio::fs::remove_file(path).await),
            Endpoint::Remote(remote) => drop(remote.remove(path).await),
        }
    }
}

/// Was geschieht, wenn es am Ziel schon etwas unter dem Namen gibt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Policy {
    Overwrite,
    Skip,
    /// Daneben legen: „name (2).txt“.
    Rename,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Queued,
    Running,
    Paused,
    Done,
    Failed,
    Cancelled,
}

impl State {
    fn text(self) -> &'static str {
        match self {
            State::Queued => "queued",
            State::Running => "running",
            State::Paused => "paused",
            State::Done => "done",
            State::Failed => "failed",
            State::Cancelled => "cancelled",
        }
    }

    fn open(self) -> bool {
        matches!(self, State::Queued | State::Running | State::Paused)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Step {
    Pending,
    Running,
    Done,
}

/// Eine einzelne Datei eines Auftrags.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Item {
    from: String,
    to: String,
    size: u64,
    modified: u64,
    /// So viele Bytes stehen schon am Ziel.
    done: u64,
    step: Step,
}

const RUN: u8 = 0;
const PAUSE: u8 = 1;
const CANCEL: u8 = 2;

/// Ein Auftrag, wie ihn [`Engine::start`] bekommt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub from: Place,
    /// Datei oder Ordner an der Quelle.
    pub source: String,
    pub to: Place,
    /// Zielordner.
    pub dest: String,
    pub policy: Policy,
    /// Quelle und Ziel zum Anzeigen.
    pub source_label: String,
    pub dest_label: String,
    /// Dieselben Orte ohne laufende Sitzung: der Host dahinter. Über sie geht es weiter, wenn die Sitzung endet,
    /// und nur mit ihnen lässt sich der Auftrag nach einem Neustart fortsetzen (`None` bei eingetippten Adressen).
    pub keep_from: Option<Place>,
    pub keep_to: Option<Place>,
}

impl Order {
    fn durable(&self) -> bool {
        self.keep_from.is_some() && self.keep_to.is_some()
    }
}

struct Job {
    id: u64,
    order: Order,
    name: String,
    state: State,
    /// Die Dateien des Auftrags; `None`, solange die Quelle noch nicht durchgesehen ist.
    items: Option<Vec<Item>>,
    scanning: bool,
    bytes: u64,
    /// Fortschritt, von den laufenden Kopien hochgezählt.
    done: Arc<AtomicU64>,
    last: u64,
    speed: u64,
    error: Option<&'static str>,
    resumed: bool,
    control: Arc<AtomicU8>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TransferView {
    pub id: u64,
    pub name: String,
    pub direction: &'static str,
    pub source: String,
    pub dest: String,
    pub bytes: u64,
    pub done: u64,
    pub files: usize,
    pub files_done: usize,
    pub state: &'static str,
    pub speed: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'static str>,
    pub resumed: bool,
}

impl Job {
    fn view(&self) -> TransferView {
        let items = self.items.as_deref().unwrap_or_default();
        TransferView {
            id: self.id,
            name: self.name.clone(),
            direction: match (&self.order.from, &self.order.to) {
                (Place::Local, _) => "upload",
                (_, Place::Local) => "download",
                _ => "remote",
            },
            source: self.order.source_label.clone(),
            dest: self.order.dest_label.clone(),
            bytes: self.bytes,
            done: self.done.load(Ordering::Relaxed).min(self.bytes),
            files: items.len().max(1),
            files_done: items.iter().filter(|item| item.step == Step::Done).count(),
            state: self.state.text(),
            speed: if self.state == State::Running { self.speed } else { 0 },
            error: self.error,
            resumed: self.resumed,
        }
    }
}

/// Was von einem unfertigen Auftrag vorgemerkt wird.
#[derive(Serialize, Deserialize)]
struct Saved {
    order: Order,
    name: String,
    bytes: u64,
    items: Option<Vec<Item>>,
}

struct Shared {
    jobs: Mutex<Vec<Job>>,
    wake: Notify,
    resolve: Resolve,
    forget: Forget,
    publish: Publish,
    next: AtomicU64,
    parallel: AtomicUsize,
    /// Laufende Kopien und Durchsichten zusammen.
    active: AtomicUsize,
    /// Datei, in der unfertige Aufträge vorgemerkt werden.
    store: Option<PathBuf>,
    dirty: AtomicBool,
    /// Pause in Millisekunden nach jedem Stück; nur Tests bremsen damit, um einen Transfer mittendrin zu erwischen.
    brake: AtomicU64,
}

impl Shared {
    fn jobs(&self) -> MutexGuard<'_, Vec<Job>> {
        self.jobs.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn changed(&self) {
        self.dirty.store(true, Ordering::Relaxed);
        self.wake.notify_one();
    }

    fn views(&self) -> Vec<TransferView> {
        self.jobs().iter().map(Job::view).collect()
    }

    /// Schreibt die unfertigen Aufträge auf, die einen Neustart überstehen können.
    fn save(&self) {
        let Some(path) = &self.store else { return };
        let saved: Vec<Saved> = self
            .jobs()
            .iter()
            .filter(|job| job.state.open() && job.order.durable())
            // Vorgemerkt wird mit den Orten, die es nach einem Neustart noch gibt.
            .map(|job| Saved { order: Order { from: job.order.keep_from.clone().unwrap_or(Place::Local), to: job.order.keep_to.clone().unwrap_or(Place::Local), ..job.order.clone() }, name: job.name.clone(), bytes: job.bytes, items: job.items.as_ref().map(|items| items.iter().map(|item| Item { step: if item.step == Step::Done { Step::Done } else { Step::Pending }, ..item.clone() }).collect()) })
            .collect();
        let result = if saved.is_empty() { std::fs::remove_file(path).or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(e) }) } else { serde_json::to_vec(&saved).map_err(std::io::Error::other).and_then(|bytes| std::fs::write(path, bytes)) };
        if let Err(error) = result {
            eprintln!("Transfers nicht vorgemerkt: {error}");
        }
    }
}

#[derive(Clone)]
pub struct Engine {
    shared: Arc<Shared>,
}

enum Next {
    Scan(u64),
    Copy(u64, usize),
}

/// Wie eine Kopie endet, wenn sie nicht fertig wird.
enum Stop {
    /// Angehalten oder abgebrochen; der zweite Fall räumt die halbe Datei weg.
    Halted,
    Failed(&'static str),
}

impl From<FileError> for Stop {
    fn from(error: FileError) -> Self {
        Stop::Failed(error.code())
    }
}

impl From<std::io::Error> for Stop {
    fn from(error: std::io::Error) -> Self {
        Stop::Failed(FileError::from(error).code())
    }
}

impl Engine {
    /// Startet die Warteschlange. `store` nennt die Datei für unfertige Aufträge; was darin vom letzten Mal steht,
    /// erscheint angehalten in der Liste. Muss in einem tokio-Runtime aufgerufen werden.
    pub fn new(resolve: Resolve, forget: Forget, publish: Publish, store: Option<PathBuf>) -> Engine {
        let shared = Arc::new(Shared { jobs: Mutex::new(Vec::new()), wake: Notify::new(), resolve, forget, publish, next: AtomicU64::new(0), parallel: AtomicUsize::new(4), active: AtomicUsize::new(0), store, dirty: AtomicBool::new(false), brake: AtomicU64::new(0) });
        let saved: Vec<Saved> = shared.store.as_ref().and_then(|path| std::fs::read(path).ok()).and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default();
        {
            let mut jobs = shared.jobs();
            for entry in saved {
                let done: u64 = entry.items.as_deref().unwrap_or_default().iter().map(|item| item.done).sum();
                jobs.push(Job { id: shared.next.fetch_add(1, Ordering::Relaxed) + 1, order: entry.order, name: entry.name, state: State::Paused, items: entry.items, scanning: false, bytes: entry.bytes, done: Arc::new(AtomicU64::new(done)), last: done, speed: 0, error: None, resumed: true, control: Arc::new(AtomicU8::new(PAUSE)) });
            }
        }
        tokio::spawn(dispatch(shared.clone()));
        Engine { shared }
    }

    pub fn set_parallel(&self, parallel: usize) {
        self.shared.parallel.store(parallel.clamp(1, 8), Ordering::Relaxed);
        self.shared.wake.notify_one();
    }

    /// Reiht Aufträge ein und liefert ihre Nummern.
    pub fn start(&self, orders: Vec<Order>, name: impl Fn(&Order) -> String) -> Vec<u64> {
        let mut ids = Vec::new();
        {
            let mut jobs = self.shared.jobs();
            for order in orders {
                let id = self.shared.next.fetch_add(1, Ordering::Relaxed) + 1;
                jobs.push(Job { id, name: name(&order), order, state: State::Queued, items: None, scanning: false, bytes: 0, done: Arc::default(), last: 0, speed: 0, error: None, resumed: false, control: Arc::new(AtomicU8::new(RUN)) });
                ids.push(id);
            }
        }
        self.shared.changed();
        ids
    }

    pub fn list(&self) -> Vec<TransferView> {
        self.shared.views()
    }

    /// Hält an, setzt fort, bricht ab oder versucht es erneut; ohne Nummern gilt es für alle Aufträge.
    pub fn control(&self, ids: Option<&[u64]>, action: &str) {
        for job in self.shared.jobs().iter_mut().filter(|job| ids.is_none_or(|ids| ids.contains(&job.id))) {
            match (action, job.state) {
                ("pause", State::Queued | State::Running) => {
                    job.state = State::Paused;
                    job.control.store(PAUSE, Ordering::Relaxed);
                }
                ("resume", State::Paused) | ("retry", State::Failed | State::Cancelled) => {
                    job.resumed = job.done.load(Ordering::Relaxed) > 0;
                    job.state = State::Queued;
                    job.error = None;
                    job.control.store(RUN, Ordering::Relaxed);
                }
                ("cancel", state) if state.open() || state == State::Failed => {
                    job.state = State::Cancelled;
                    job.control.store(CANCEL, Ordering::Relaxed);
                }
                _ => {}
            }
        }
        self.shared.changed();
    }

    /// Nimmt alles Fertige, Abgebrochene und Gescheiterte aus der Liste.
    pub fn clear(&self) {
        self.shared.jobs().retain(|job| job.state.open());
        self.shared.changed();
    }

    /// Anzahl der Aufträge, die laufen oder warten.
    #[cfg(test)]
    fn busy(&self) -> usize {
        self.shared.jobs().iter().filter(|job| matches!(job.state, State::Queued | State::Running)).count()
    }

    /// Vor dem Beenden: alles anhalten und vormerken, was sich fortsetzen lässt.
    pub fn shutdown(&self) {
        self.control(None, "pause");
        self.shared.save();
    }
}

/// Verteilt die Arbeit: startet Durchsichten und Kopien, solange Plätze frei sind, und meldet regelmäßig den Stand.
async fn dispatch(shared: Arc<Shared>) {
    let mut last_tick = Instant::now();
    let mut last_views: Vec<TransferView> = Vec::new();
    loop {
        loop {
            let next = {
                let mut jobs = shared.jobs();
                if shared.active.load(Ordering::Relaxed) >= shared.parallel.load(Ordering::Relaxed) {
                    break;
                }
                let mut found = None;
                for job in jobs.iter_mut().filter(|job| matches!(job.state, State::Queued | State::Running)) {
                    if job.scanning {
                        continue;
                    }
                    let Some(items) = job.items.as_mut() else {
                        job.scanning = true;
                        job.state = State::Running;
                        found = Some(Next::Scan(job.id));
                        break;
                    };
                    if let Some(index) = items.iter().position(|item| item.step == Step::Pending) {
                        items[index].step = Step::Running;
                        job.state = State::Running;
                        found = Some(Next::Copy(job.id, index));
                        break;
                    }
                }
                if found.is_some() {
                    shared.active.fetch_add(1, Ordering::Relaxed);
                }
                found
            };
            match next {
                Some(Next::Scan(id)) => drop(tokio::spawn(scan(shared.clone(), id))),
                Some(Next::Copy(id, index)) => drop(tokio::spawn(copy(shared.clone(), id, index))),
                None => break,
            }
        }

        // Tempo aus dem Zuwachs seit der letzten Meldung.
        let elapsed = last_tick.elapsed();
        if elapsed >= TICK {
            for job in shared.jobs().iter_mut() {
                let done = job.done.load(Ordering::Relaxed);
                job.speed = (done.saturating_sub(job.last) as f64 / elapsed.as_secs_f64()) as u64;
                job.last = done;
            }
            last_tick = Instant::now();
        }
        let views = shared.views();
        if views != last_views {
            (shared.publish)(views.clone());
            last_views = views;
        }
        if shared.dirty.swap(false, Ordering::Relaxed) {
            shared.save();
        }

        let running = shared.active.load(Ordering::Relaxed) > 0;
        tokio::select! {
            () = shared.wake.notified() => {}
            () = tokio::time::sleep(TICK), if running => {}
        }
    }
}

/// Erreicht einen Ort. Hängt er an einer Sitzung, die es nicht mehr gibt, geht es über den Host dahinter weiter.
async fn reach(shared: &Shared, place: &Place, keep: &Option<Place>) -> Result<Endpoint, Stop> {
    match (shared.resolve)(place.clone()).await {
        Err("not_connected") => match keep {
            Some(other) if other != place => (shared.resolve)(other.clone()).await.map_err(Stop::Failed),
            _ => Err(Stop::Failed("not_connected")),
        },
        other => other.map_err(Stop::Failed),
    }
}

/// Nach einem Abriss sollen die Verbindungen der beiden Orte beim nächsten Versuch neu entstehen.
fn dropped(shared: &Shared, order: &Order, code: &str) {
    if code == "not_connected" {
        (shared.forget)(order.from.clone());
        (shared.forget)(order.to.clone());
    }
}

/// Ein Name daneben, den es am Ziel noch nicht gibt: „bericht (2).pdf“.
async fn free_name(to: &Endpoint, dir: &str, name: &str) -> Result<String, FileError> {
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => (stem, format!(".{extension}")),
        _ => (name, String::new()),
    };
    for number in 2..1000 {
        let candidate = format!("{stem} ({number}){extension}");
        if to.stat(&to.join(dir, &candidate)).await?.is_none() {
            return Ok(candidate);
        }
    }
    Err(FileError::Exists)
}

/// Sieht die Quelle eines Auftrags durch: Aus einer Datei wird ein Eintrag, aus einem Ordner alle Dateien darin.
/// Die Ordner am Ziel entstehen dabei gleich mit.
async fn scan(shared: Arc<Shared>, id: u64) {
    let order = shared.jobs().iter().find(|job| job.id == id).map(|job| (job.order.clone(), job.name.clone(), job.control.clone()));
    let result = match order {
        Some((order, name, control)) => plan(&shared, &order, &name, &control).await,
        None => Err(Stop::Halted),
    };
    if let Some(job) = shared.jobs().iter_mut().find(|job| job.id == id) {
        job.scanning = false;
        match result {
            Ok(items) => {
                job.bytes = items.iter().map(|item| item.size).sum();
                if items.is_empty() && job.state == State::Running {
                    job.state = State::Done;
                }
                job.items = Some(items);
            }
            Err(Stop::Failed(code)) => {
                job.state = State::Failed;
                job.error = Some(code);
                dropped(&shared, &job.order, code);
            }
            // Angehalten oder abgebrochen, bevor es losging: Beim nächsten Mal wird neu durchgesehen.
            Err(Stop::Halted) => {}
        }
    }
    shared.active.fetch_sub(1, Ordering::Relaxed);
    shared.changed();
}

async fn plan(shared: &Shared, order: &Order, name: &str, control: &AtomicU8) -> Result<Vec<Item>, Stop> {
    let from = reach(shared, &order.from, &order.keep_from).await?;
    let to = reach(shared, &order.to, &order.keep_to).await?;
    let source = from.stat(&order.source).await?.ok_or(FileError::NoSuchFile)?;
    let mut target = to.join(&order.dest, name);
    if to.stat(&target).await?.is_some() {
        match order.policy {
            Policy::Rename => target = to.join(&order.dest, &free_name(&to, &order.dest, name).await?),
            Policy::Skip if !source.dir => return Ok(Vec::new()),
            _ => {}
        }
    }
    if !source.dir {
        return Ok(vec![Item { from: order.source.clone(), to: target, size: source.size, modified: source.modified, done: 0, step: Step::Pending }]);
    }
    let mut items = Vec::new();
    let mut folders = vec![(order.source.clone(), target)];
    while let Some((source_dir, target_dir)) = folders.pop() {
        if control.load(Ordering::Relaxed) != RUN {
            return Err(Stop::Halted);
        }
        to.mkdir(&target_dir).await?;
        let mut entries = from.list(&source_dir).await?;
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (entry, meta) in entries {
            let (source_path, target_path) = (from.join(&source_dir, &entry), to.join(&target_dir, &entry));
            if meta.dir {
                folders.push((source_path, target_path));
            } else if order.policy == Policy::Skip && to.stat(&target_path).await?.is_some() {
                continue;
            } else {
                items.push(Item { from: source_path, to: target_path, size: meta.size, modified: meta.modified, done: 0, step: Step::Pending });
            }
        }
    }
    Ok(items)
}

/// Überträgt eine Datei eines Auftrags, ab der Stelle, an der sie zuletzt stand.
async fn copy(shared: Arc<Shared>, id: u64, index: usize) {
    let picked = shared.jobs().iter().find(|job| job.id == id).and_then(|job| Some((job.order.clone(), job.items.as_ref()?.get(index)?.clone(), job.done.clone(), job.control.clone())));
    let mut written = 0;
    let result = match &picked {
        Some((order, item, done, control)) => transfer(&shared, (id, index), order, item, done, control, &mut written).await,
        None => Err(Stop::Halted),
    };
    if let Some(job) = shared.jobs().iter_mut().find(|job| job.id == id) {
        let cancelled = job.control.load(Ordering::Relaxed) == CANCEL;
        if let Some(item) = job.items.as_mut().and_then(|items| items.get_mut(index)) {
            item.done = written;
            item.step = if result.is_ok() { Step::Done } else { Step::Pending };
            if cancelled {
                // Ein abgebrochener Auftrag beginnt beim erneuten Versuch diese Datei von vorn.
                job.done.fetch_sub(written.min(job.done.load(Ordering::Relaxed)), Ordering::Relaxed);
                item.done = 0;
            }
        }
        match result {
            Err(Stop::Failed(code)) if job.state == State::Running => {
                job.state = State::Failed;
                job.error = Some(code);
                dropped(&shared, &job.order, code);
                // Die übrigen Dateien des Auftrags laufen nicht weiter, bis der Nutzer es erneut versucht.
                job.control.store(PAUSE, Ordering::Relaxed);
            }
            Ok(()) if job.state == State::Running && job.items.as_ref().is_some_and(|items| items.iter().all(|item| item.step == Step::Done)) => job.state = State::Done,
            _ => {}
        }
    }
    shared.active.fetch_sub(1, Ordering::Relaxed);
    shared.changed();
}

async fn transfer(shared: &Shared, (id, index): (u64, usize), order: &Order, item: &Item, done: &AtomicU64, control: &AtomicU8, written: &mut u64) -> Result<(), Stop> {
    *written = item.done;
    let from = reach(shared, &order.from, &order.keep_from).await?;
    let to = reach(shared, &order.to, &order.keep_to).await?;

    // Fortsetzen nur, wenn am Ziel wirklich so viel steht und die Quelle noch dieselbe ist; sonst von vorn.
    let source = from.stat(&item.from).await?.ok_or(FileError::NoSuchFile)?;
    let partial = if item.done > 0 { to.stat(&item.to).await?.map_or(0, |meta| meta.size) } else { 0 };
    let offset = if source.size == item.size && source.modified == item.modified && partial >= item.done { item.done } else { 0 };
    if offset < item.done {
        done.fetch_sub((item.done - offset).min(done.load(Ordering::Relaxed)), Ordering::Relaxed);
    }
    *written = offset;

    let mut reader = from.reader(&item.from, offset).await?;
    let mut writer = to.writer(&item.to, offset).await?;
    let mut buffer = vec![0u8; CHUNK];
    let mut noted = offset;
    loop {
        match control.load(Ordering::Relaxed) {
            RUN => {}
            stop => {
                let _ = writer.shutdown().await;
                drop(writer);
                if stop == CANCEL {
                    to.remove(&item.to).await;
                }
                return Err(Stop::Halted);
            }
        }
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        writer.write_all(&buffer[..count]).await?;
        *written += count as u64;
        done.fetch_add(count as u64, Ordering::Relaxed);
        if *written - noted >= CHECKPOINT {
            noted = *written;
            if let Some(entry) = shared.jobs().iter_mut().find(|job| job.id == id).and_then(|job| job.items.as_mut()?.get_mut(index)) {
                entry.done = noted;
            }
            shared.dirty.store(true, Ordering::Relaxed);
        }
        let brake = shared.brake.load(Ordering::Relaxed);
        if brake > 0 {
            tokio::time::sleep(Duration::from_millis(brake)).await;
        }
    }
    writer.shutdown().await?;
    drop(writer);
    to.touch(&item.to, item.modified).await;
    Ok(())
}

// ---------- Anbindung an das Programm ----------

/// Die Warteschlange des Programms. Sie gehört keinem Fenster; jedes zeigt denselben Stand.
pub struct Queue(pub Engine);

/// Startet die Warteschlange mit den Verbindungen der Brücke und meldet ihren Stand als Ereignis `transfers`.
pub fn init(app: &AppHandle, store: PathBuf) -> Queue {
    let reach = app.clone();
    let resolve: Resolve = Arc::new(move |place| {
        let app = reach.clone();
        Box::pin(async move {
            match place {
                Place::Local => Ok(Endpoint::Local),
                place => files::remote(&app, &place).await.map(Endpoint::Remote).map_err(|error| error.code()),
            }
        })
    });
    let gone = app.clone();
    let forget: Forget = Arc::new(move |place| {
        let app = gone.clone();
        tauri::async_runtime::spawn(async move { files::forget(&app, &place).await });
    });
    let shown = app.clone();
    let publish: Publish = Arc::new(move |views| drop(shown.emit("transfers", views)));
    Queue(tauri::async_runtime::block_on(async move { Engine::new(resolve, forget, publish, Some(store)) }))
}

/// Wie ein Ort in der Liste heißt und unter welchem Ort er nach einem Neustart noch zu erreichen ist.
fn describe(app: &AppHandle, place: &Place) -> (String, Option<Place>) {
    match place {
        Place::Local => (String::new(), Some(Place::Local)),
        Place::Host { id } => (app.state::<AppState>().session().directory().ok().and_then(|d| d.host_name(id)).unwrap_or_default(), Some(place.clone())),
        Place::Ftp { host, user, .. } => (if user.is_empty() { host.clone() } else { format!("{user}@{host}") }, Some(place.clone())),
        Place::Session { id } => match sessions::origin(app, *id) {
            Some((host, label)) => (label, host.map(|id| Place::Host { id })),
            None => (String::new(), None),
        },
    }
}

fn join(place: &Place, dir: &str, name: &str) -> String {
    match place {
        Place::Local => Path::new(dir).join(name).to_string_lossy().into_owned(),
        _ if dir.ends_with('/') => format!("{dir}{name}"),
        _ => format!("{dir}/{name}"),
    }
}

fn base_name(place: &Place, path: &str) -> String {
    match place {
        Place::Local => Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.trim_end_matches(['\\', '/']).to_string()),
        _ => path.trim_end_matches('/').rsplit('/').next().unwrap_or_default().to_string(),
    }
}

/// Bei diesem PC genügt der Pfad; bei einem Server steht sein Name davor.
fn labelled(label: &str, path: &str) -> String {
    if label.is_empty() {
        path.to_string()
    } else {
        format!("{label}:{path}")
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    from: Place,
    paths: Vec<String>,
    to: Place,
    /// Zielordner; leer bei Ziel „dieser PC“ heißt Download-Ordner.
    dest: String,
    #[serde(default)]
    policy: Option<Policy>,
    #[serde(default)]
    parallel: Option<usize>,
}

fn orders(app: &AppHandle, from: &Place, to: &Place, policy: Policy, pairs: Vec<(String, String)>) -> Vec<Order> {
    let (from_label, keep_from) = describe(app, from);
    let (to_label, keep_to) = describe(app, to);
    pairs
        .into_iter()
        .map(|(source, dest)| Order {
            source_label: labelled(&from_label, &source),
            dest_label: labelled(&to_label, &join(to, &dest, &base_name(from, &source))),
            from: from.clone(),
            source,
            to: to.clone(),
            dest,
            policy,
            keep_from: keep_from.clone(),
            keep_to: keep_to.clone(),
        })
        .collect()
}

/// Holt Dateien und Ordner eines Servers in einen Ordner dieses Rechners, damit sie sich danach aus dem Fenster
/// ziehen lassen. Liefert die Nummern der Transfers und wo die Dateien danach liegen.
pub(crate) fn stage(app: &AppHandle, queue: &Queue, from: &Place, paths: Vec<String>, dir: &Path) -> (Vec<u64>, Vec<String>) {
    let dest = dir.to_string_lossy().into_owned();
    let staged = paths.iter().map(|source| join(&Place::Local, &dest, &base_name(from, source))).collect();
    let mut orders = orders(app, from, &Place::Local, Policy::Overwrite, paths.into_iter().map(|source| (source, dest.clone())).collect());
    for order in &mut orders {
        order.dest_label = "Explorer".into();
        // Nach einem Neustart ist der Zug vorbei; so ein Auftrag wird nicht vorgemerkt.
        order.keep_to = None;
    }
    let source = from.clone();
    (queue.0.start(orders, |order| base_name(&source, &order.source)), staged)
}

/// Reiht Dateien und Ordner in die Warteschlange ein.
#[tauri::command]
pub fn transfer_start(app: AppHandle, queue: tauri::State<'_, Queue>, request: Request) -> CmdResult<Vec<u64>> {
    if request.from == request.to && request.paths.iter().any(|path| join(&request.from, &request.dest, &base_name(&request.from, path)) == *path) {
        return Err(CmdError::new("same_place", "Quelle und Ziel sind derselbe Ort"));
    }
    if let Some(parallel) = request.parallel {
        queue.0.set_parallel(parallel);
    }
    let dest = if request.to == Place::Local && request.dest.trim().is_empty() { app.path().download_dir().map(|dir| dir.to_string_lossy().into_owned()).map_err(|e| CmdError::new("internal", e.to_string()))? } else { request.dest };
    let pairs = request.paths.into_iter().map(|source| (source, dest.clone())).collect();
    let from = request.from.clone();
    Ok(queue.0.start(orders(&app, &request.from, &request.to, request.policy.unwrap_or(Policy::Overwrite), pairs), |order| base_name(&from, &order.source)))
}

#[tauri::command]
pub fn transfer_list(queue: tauri::State<'_, Queue>) -> Vec<TransferView> {
    queue.0.list()
}

#[tauri::command]
pub fn transfer_control(queue: tauri::State<'_, Queue>, ids: Option<Vec<u64>>, action: String) {
    queue.0.control(ids.as_deref(), &action);
}

#[tauri::command]
pub fn transfer_clear(queue: tauri::State<'_, Queue>) {
    queue.0.clear();
}

// ---------- Ordner abgleichen ----------

/// Mehr Einträge vergleicht der Abgleich nicht; dann ist der Ordner zu groß für eine Liste.
const MAX_COMPARED: usize = 20_000;
/// Um so viele Sekunden dürfen die Änderungszeiten gleicher Dateien auseinanderliegen (Dateisysteme runden verschieden).
const SAME_WITHIN: u64 = 2;

#[derive(Serialize)]
pub struct Side {
    path: String,
    size: u64,
    /// Millisekunden seit 1970.
    modified: u64,
}

#[derive(Serialize)]
pub struct Diff {
    /// Pfad unterhalb der verglichenen Ordner, mit `/` getrennt.
    rel: String,
    kind: &'static str,
    state: &'static str,
    left: Option<Side>,
    right: Option<Side>,
}

async fn endpoint(app: &AppHandle, place: &Place) -> CmdResult<Endpoint> {
    match place {
        Place::Local => Ok(Endpoint::Local),
        place => files::remote(app, place).await.map(Endpoint::Remote),
    }
}

/// Größe von allem, was in einem Ordner liegt.
async fn total(at: &Endpoint, path: &str, budget: &mut usize) -> Result<u64, FileError> {
    let mut sum = 0;
    let mut folders = vec![path.to_string()];
    while let Some(dir) = folders.pop() {
        for (name, meta) in at.list(&dir).await? {
            *budget = budget.checked_sub(1).ok_or_else(|| FileError::Failure("too many entries".into()))?;
            if meta.dir {
                folders.push(at.join(&dir, &name));
            } else {
                sum += meta.size;
            }
        }
    }
    Ok(sum)
}

async fn compare(left: &Endpoint, left_path: &str, right: &Endpoint, right_path: &str) -> Result<Vec<Diff>, FileError> {
    let mut out = Vec::new();
    let mut budget = MAX_COMPARED;
    let mut folders = vec![(String::new(), left_path.to_string(), right_path.to_string())];
    while let Some((rel, l_dir, r_dir)) = folders.pop() {
        let mut l = left.list(&l_dir).await?;
        let mut r = right.list(&r_dir).await?;
        budget = budget.checked_sub(l.len() + r.len()).ok_or_else(|| FileError::Failure("too many entries".into()))?;
        let mut names: Vec<String> = l.iter().chain(r.iter()).map(|(name, _)| name.clone()).collect();
        names.sort();
        names.dedup();
        for name in names {
            let x = l.iter().position(|(n, _)| *n == name).map(|i| l.swap_remove(i).1);
            let y = r.iter().position(|(n, _)| *n == name).map(|i| r.swap_remove(i).1);
            let path = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
            let (l_path, r_path) = (left.join(&l_dir, &name), right.join(&r_dir, &name));
            // Auf beiden Seiten ein Ordner: Verglichen wird, was darin liegt.
            if x.as_ref().is_some_and(|m| m.dir) && y.as_ref().is_some_and(|m| m.dir) {
                folders.push((path, l_path, r_path));
                continue;
            }
            let dir = x.as_ref().or(y.as_ref()).is_some_and(|m| m.dir);
            let mut side = Vec::new();
            for (at, meta, full) in [(left, &x, &l_path), (right, &y, &r_path)] {
                side.push(match meta {
                    Some(meta) => Some(Side { size: if meta.dir { total(at, full, &mut budget).await? } else { meta.size }, modified: meta.modified * 1000, path: full.clone() }),
                    None => None,
                });
            }
            let state = match (&x, &y) {
                (Some(_), None) => "left",
                (None, Some(_)) => "right",
                (Some(a), Some(b)) if a.dir == b.dir && a.size == b.size && a.modified.abs_diff(b.modified) <= SAME_WITHIN => "same",
                (Some(a), Some(b)) if a.modified >= b.modified => "newerLeft",
                _ => "newerRight",
            };
            let right_side = side.pop().flatten();
            out.push(Diff { rel: path, kind: if dir { "dir" } else { "file" }, state, left: side.pop().flatten(), right: right_side });
        }
    }
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(out)
}

/// Vergleicht zwei Ordner samt Unterordnern nach Größe und Änderungszeit.
#[tauri::command]
pub async fn fs_compare(app: AppHandle, left: Place, left_path: String, right: Place, right_path: String) -> CmdResult<Vec<Diff>> {
    let (l, r) = (endpoint(&app, &left).await?, endpoint(&app, &right).await?);
    compare(&l, &left_path, &r, &right_path).await.map_err(Into::into)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncItem {
    rel: String,
    to_right: bool,
}

/// Gleicht zwei Ordner an: Jede Zeile nennt den Pfad unterhalb der Ordner und die Richtung. Gelöscht wird nichts.
#[tauri::command]
pub fn sync_start(app: AppHandle, queue: tauri::State<'_, Queue>, left: Place, left_path: String, right: Place, right_path: String, items: Vec<SyncItem>) -> CmdResult<Vec<u64>> {
    let mut ids = Vec::new();
    for to_right in [true, false] {
        let (from, from_base, to, to_base) = if to_right { (&left, &left_path, &right, &right_path) } else { (&right, &right_path, &left, &left_path) };
        let mut pairs = Vec::new();
        for item in items.iter().filter(|item| item.to_right == to_right) {
            let parts: Vec<&str> = item.rel.split('/').collect();
            if parts.iter().any(|part| part.is_empty() || *part == "." || *part == "..") {
                return Err(CmdError::invalid("name_required"));
            }
            let under = |place: &Place, base: &String, parts: &[&str]| parts.iter().fold(base.clone(), |at, part| join(place, &at, part));
            pairs.push((under(from, from_base, &parts), under(to, to_base, &parts[..parts.len() - 1])));
        }
        let source = from.clone();
        ids.extend(queue.0.start(orders(&app, from, to, Policy::Overwrite, pairs), |order| base_name(&source, &order.source)));
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    static SEQ: AtomicU32 = AtomicU32::new(0);

    /// Zwei Ordner auf diesem Rechner als Quelle und Ziel; sie verschwinden mit dem Test.
    struct Bench {
        root: PathBuf,
        seen: Arc<Mutex<Vec<Vec<TransferView>>>>,
    }

    impl Bench {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("glowport-transfers-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("quelle")).unwrap();
            std::fs::create_dir_all(root.join("ziel")).unwrap();
            Bench { root, seen: Arc::default() }
        }

        fn engine(&self) -> Engine {
            let seen = self.seen.clone();
            Engine::new(Arc::new(|_| Box::pin(async { Ok(Endpoint::Local) })), Arc::new(|_| {}), Arc::new(move |views| seen.lock().unwrap().push(views)), Some(self.root.join("transfers.json")))
        }

        fn put(&self, path: &str, bytes: &[u8]) {
            let full = self.root.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, bytes).unwrap();
        }

        fn order(&self, source: &str, policy: Policy) -> Order {
            Order { from: Place::Local, source: self.root.join("quelle").join(source).to_string_lossy().into_owned(), to: Place::Local, dest: self.root.join("ziel").to_string_lossy().into_owned(), policy, source_label: source.into(), dest_label: "ziel".into(), keep_from: Some(Place::Local), keep_to: Some(Place::Local) }
        }

        fn read(&self, path: &str) -> Option<Vec<u8>> {
            std::fs::read(self.root.join(path)).ok()
        }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn named(order: &Order) -> String {
        Path::new(&order.source).file_name().unwrap().to_string_lossy().into_owned()
    }

    async fn until(engine: &Engine, done: impl Fn(&[TransferView]) -> bool) -> Vec<TransferView> {
        for _ in 0..400 {
            let views = engine.list();
            if done(&views) {
                return views;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("Zustand nicht erreicht: {:?}", engine.list());
    }

    fn all(state: &'static str) -> impl Fn(&[TransferView]) -> bool {
        move |views| !views.is_empty() && views.iter().all(|view| view.state == state)
    }

    #[tokio::test]
    async fn copies_a_file_and_a_whole_folder_and_reports_progress() {
        let bench = Bench::new();
        bench.put("quelle/einzeln.txt", b"hallo");
        bench.put("quelle/ordner/a.txt", b"aaa");
        bench.put("quelle/ordner/tief/b.bin", &vec![7u8; 600_000]);
        std::fs::create_dir_all(bench.root.join("quelle/ordner/leer")).unwrap();
        let engine = bench.engine();

        let ids = engine.start(vec![bench.order("einzeln.txt", Policy::Overwrite), bench.order("ordner", Policy::Overwrite)], named);
        assert_eq!(ids.len(), 2);
        let views = until(&engine, all("done")).await;

        assert_eq!(bench.read("ziel/einzeln.txt").as_deref(), Some(&b"hallo"[..]));
        assert_eq!(bench.read("ziel/ordner/a.txt").as_deref(), Some(&b"aaa"[..]));
        assert_eq!(bench.read("ziel/ordner/tief/b.bin").map(|b| b.len()), Some(600_000));
        assert!(bench.root.join("ziel/ordner/leer").is_dir(), "auch leere Ordner kommen mit");
        let folder = &views[1];
        assert_eq!((folder.name.as_str(), folder.files, folder.files_done, folder.bytes, folder.done, folder.direction), ("ordner", 2, 2, 600_003, 600_003, "upload"));
        // Die Kopie ist so alt wie das Original.
        let age = |path: &str| std::fs::metadata(bench.root.join(path)).unwrap().modified().unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(age("ziel/einzeln.txt"), age("quelle/einzeln.txt"));
        assert!(bench.seen.lock().unwrap().len() >= 2, "der Stand wird gemeldet");
        assert!(!bench.root.join("transfers.json").exists(), "nichts Unfertiges, nichts vorgemerkt");
    }

    #[tokio::test]
    async fn skips_overwrites_or_puts_next_to_what_is_already_there() {
        let bench = Bench::new();
        bench.put("quelle/plan.txt", b"neu");
        bench.put("quelle/web/index.html", b"neu");
        bench.put("quelle/web/neu.css", b"css");
        bench.put("ziel/plan.txt", b"alt");
        bench.put("ziel/web/index.html", b"alt");
        let engine = bench.engine();

        engine.start(vec![bench.order("plan.txt", Policy::Skip), bench.order("web", Policy::Skip)], named);
        until(&engine, all("done")).await;
        assert_eq!(bench.read("ziel/plan.txt").as_deref(), Some(&b"alt"[..]));
        assert_eq!(bench.read("ziel/web/index.html").as_deref(), Some(&b"alt"[..]), "Vorhandenes im Ordner bleibt");
        assert_eq!(bench.read("ziel/web/neu.css").as_deref(), Some(&b"css"[..]), "Fehlendes kommt dazu");

        engine.clear();
        engine.start(vec![bench.order("plan.txt", Policy::Rename), bench.order("web", Policy::Rename)], named);
        until(&engine, all("done")).await;
        assert_eq!(bench.read("ziel/plan.txt").as_deref(), Some(&b"alt"[..]));
        assert_eq!(bench.read("ziel/plan (2).txt").as_deref(), Some(&b"neu"[..]));
        assert_eq!(bench.read("ziel/web (2)/index.html").as_deref(), Some(&b"neu"[..]));

        engine.clear();
        engine.start(vec![bench.order("plan.txt", Policy::Overwrite), bench.order("web", Policy::Overwrite)], named);
        until(&engine, all("done")).await;
        assert_eq!(bench.read("ziel/plan.txt").as_deref(), Some(&b"neu"[..]));
        assert_eq!(bench.read("ziel/web/index.html").as_deref(), Some(&b"neu"[..]));
    }

    #[tokio::test]
    async fn pauses_keeps_the_place_and_continues_even_after_a_restart() {
        let bench = Bench::new();
        let content: Vec<u8> = (0..6_000_000u32).map(|i| (i % 251) as u8).collect();
        bench.put("quelle/gross.bin", &content);
        let engine = bench.engine();
        engine.shared.brake.store(15, Ordering::Relaxed);
        engine.start(vec![bench.order("gross.bin", Policy::Overwrite)], named);

        until(&engine, |views| views[0].done > 0).await;
        engine.control(None, "pause");
        let paused = until(&engine, |views| views[0].state == "paused").await;
        // Warten, bis die laufende Kopie wirklich steht und ihr Stand festgehalten ist.
        until(&engine, |_| engine.shared.active.load(Ordering::Relaxed) == 0).await;
        let halfway = engine.list()[0].done;
        assert!(halfway > 0 && halfway < content.len() as u64, "mittendrin angehalten: {halfway} (gemeldet {})", paused[0].done);
        assert_eq!(bench.read("ziel/gross.bin").map(|b| b.len() as u64), Some(halfway), "am Ziel steht genau das Übertragene");
        tokio::time::sleep(TICK * 2).await;
        assert!(bench.root.join("transfers.json").exists(), "der unfertige Auftrag ist vorgemerkt");

        // Neustart: Eine neue Warteschlange liest das Vorgemerkte und bietet es angehalten an.
        drop(engine);
        let again = bench.engine();
        let offered = again.list();
        assert_eq!((offered.len(), offered[0].state, offered[0].done, offered[0].resumed), (1, "paused", halfway, true));
        again.control(None, "resume");
        let views = until(&again, all("done")).await;
        assert_eq!(views[0].done, content.len() as u64);
        assert!(bench.read("ziel/gross.bin").is_some_and(|copy| copy == content), "die fortgesetzte Datei ist vollständig und unverändert");
        tokio::time::sleep(TICK * 2).await;
        assert!(!bench.root.join("transfers.json").exists(), "nach dem Ende ist nichts mehr vorgemerkt");
    }

    #[tokio::test]
    async fn starts_over_when_the_source_changed_in_between() {
        let bench = Bench::new();
        bench.put("quelle/daten.bin", &vec![1u8; 6_000_000]);
        let engine = bench.engine();
        engine.shared.brake.store(15, Ordering::Relaxed);
        engine.start(vec![bench.order("daten.bin", Policy::Overwrite)], named);
        until(&engine, |views| views[0].done > 0).await;
        engine.control(None, "pause");
        until(&engine, |views| views[0].state == "paused" && engine.shared.active.load(Ordering::Relaxed) == 0).await;

        bench.put("quelle/daten.bin", &vec![2u8; 1_000_000]);
        engine.shared.brake.store(0, Ordering::Relaxed);
        engine.control(None, "resume");
        until(&engine, all("done")).await;
        assert!(bench.read("ziel/daten.bin").is_some_and(|copy| copy == vec![2u8; 1_000_000]), "kein Gemisch aus altem Anfang und neuem Ende");
    }

    #[tokio::test]
    async fn cancels_cleans_up_and_can_be_tried_again() {
        let bench = Bench::new();
        bench.put("quelle/film.bin", &vec![9u8; 6_000_000]);
        let engine = bench.engine();
        engine.shared.brake.store(15, Ordering::Relaxed);
        let ids = engine.start(vec![bench.order("film.bin", Policy::Overwrite)], named);
        until(&engine, |views| views[0].done > 0).await;
        engine.control(Some(&ids), "cancel");
        until(&engine, |views| views[0].state == "cancelled" && engine.shared.active.load(Ordering::Relaxed) == 0).await;
        assert!(bench.read("ziel/film.bin").is_none(), "die halbe Datei ist weggeräumt");

        engine.shared.brake.store(0, Ordering::Relaxed);
        engine.control(Some(&ids), "retry");
        until(&engine, all("done")).await;
        assert_eq!(bench.read("ziel/film.bin").map(|b| b.len()), Some(6_000_000));
        engine.clear();
        assert!(engine.list().is_empty());
    }

    #[tokio::test]
    async fn reports_what_went_wrong_and_keeps_the_rest_of_the_queue_going() {
        let bench = Bench::new();
        bench.put("quelle/da.txt", b"da");
        let engine = bench.engine();
        engine.start(vec![bench.order("fehlt.txt", Policy::Overwrite), bench.order("da.txt", Policy::Overwrite)], named);
        let views = until(&engine, |views| views[0].state == "failed" && views[1].state == "done").await;
        assert_eq!(views[0].error, Some("no_such_file"));
        assert_eq!(engine.busy(), 0);
    }

    /// Kein Test, sondern Messwerte: wie schnell Transfers gegen den eigenen Testserver auf diesem Rechner laufen,
    /// daneben `scp` von OpenSSH gegen denselben Server als Maßstab. Aufruf:
    /// `cargo test --release -p glowport measures_throughput -- --ignored --nocapture`
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn measures_throughput() {
        use glowport_net::{Connect, Secret};
        use glowport_testserver::{self as server, Options};
        use std::process::Command;

        const BIG: usize = 512 * 1024 * 1024;
        const SMALL: usize = 2000;
        let root = std::env::temp_dir().join(format!("glowport-tempo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (files, local, home) = (root.join("server"), root.join("lokal"), root.join("home"));
        for dir in [files.join("srv"), local.join("viele"), local.join("zurueck"), home.join(".ssh")] {
            std::fs::create_dir_all(dir).unwrap();
        }
        // Unregelmäßiger Inhalt, damit weder Kompression noch gleiche Blöcke das Bild schönen.
        let mut seed = 0x2545_F491_4F6C_DD1D_u64;
        let noise: Vec<u8> = (0..BIG).map(|_| { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed as u8 }).collect();
        std::fs::write(local.join("gross.bin"), &noise).unwrap();
        for i in 0..SMALL {
            std::fs::write(local.join("viele").join(format!("datei-{i:04}.txt")), &noise[i * 4096..(i + 1) * 4096]).unwrap();
        }
        drop(noise);

        // Schlüssel für `scp`; der Testserver liest ihn aus dem Heimatverzeichnis.
        let key = root.join("schluessel");
        let keyed = Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).status().is_ok_and(|status| status.success());
        if keyed {
            std::fs::copy(key.with_extension("pub"), home.join(".ssh").join("authorized_keys")).unwrap();
        }
        let options = Options { password: Some(("tester".into(), "richtig".into())), files: Some(files.clone()), home: Some(home.clone()), ..Options::default() };
        let running = server::start(options, server::key(1)).await.unwrap();
        let port = running.address.port();
        let connect = Connect { host: "127.0.0.1".into(), port, user: "tester".into(), password: Some(Secret::new("richtig".into())), detect_os: false, ..Connect::default() };
        let remote = Arc::new(Remote::Sftp(glowport_net::files::Remote::connect(&connect, |_, _, _| true).await.unwrap()));
        let reach = remote.clone();
        let engine = Engine::new(
            Arc::new(move |place| {
                let remote = reach.clone();
                Box::pin(async move { Ok(if place == Place::Local { Endpoint::Local } else { Endpoint::Remote(remote) }) })
            }),
            Arc::new(|_| {}),
            Arc::new(|_| {}),
            None,
        );
        let server_place = Place::Host { id: "tempo".into() };
        let text = |path: &Path| path.to_string_lossy().into_owned();
        let order = |from: &Place, source: String, to: &Place, dest: String| Order { from: from.clone(), source, to: to.clone(), dest, policy: Policy::Overwrite, source_label: String::new(), dest_label: String::new(), keep_from: None, keep_to: None };
        // Lässt einen Auftrag laufen und liefert die Dauer in Sekunden.
        let run = |job: Order, parallel: usize| {
            let engine = engine.clone();
            async move {
                engine.clear();
                engine.set_parallel(parallel);
                let started = Instant::now();
                engine.start(vec![job], |order| Path::new(&order.source).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| order.source.rsplit('/').next().unwrap_or_default().to_string()));
                loop {
                    let views = engine.list();
                    if views.iter().all(|view| view.state == "done") {
                        break;
                    }
                    assert!(views.iter().all(|view| view.state != "failed"), "{views:?}");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                started.elapsed().as_secs_f64()
            }
        };
        let megabytes = BIG as f64 / (1024.0 * 1024.0);

        println!("\nGlowport gegen den eigenen Testserver auf diesem Rechner (127.0.0.1, optimiert gebaut)");
        let up = run(order(&Place::Local, text(&local.join("gross.bin")), &server_place, "/srv".into()), 4).await;
        println!("  große Datei hoch      {megabytes:.0} MB in {up:5.2} s = {:6.1} MB/s", megabytes / up);
        let down = run(order(&server_place, "/srv/gross.bin".into(), &Place::Local, text(&local.join("zurueck"))), 4).await;
        println!("  große Datei herunter  {megabytes:.0} MB in {down:5.2} s = {:6.1} MB/s", megabytes / down);
        for parallel in [1, 4, 8] {
            let _ = std::fs::remove_dir_all(files.join("srv").join("viele"));
            let seconds = run(order(&Place::Local, text(&local.join("viele")), &server_place, "/srv".into()), parallel).await;
            println!("  {SMALL} kleine hoch, {parallel} gleichzeitig      {seconds:5.2} s = {:6.0} Dateien/s", SMALL as f64 / seconds);
        }
        for parallel in [1, 4] {
            let _ = std::fs::remove_dir_all(local.join("zurueck").join("viele"));
            let seconds = run(order(&server_place, "/srv/viele".into(), &Place::Local, text(&local.join("zurueck"))), parallel).await;
            println!("  {SMALL} kleine herunter, {parallel} gleichzeitig  {seconds:5.2} s = {:6.0} Dateien/s", SMALL as f64 / seconds);
        }

        // Derselbe Weg mit `scp` von OpenSSH, das heute ebenfalls SFTP spricht.
        let scp = |from: String, to: String, recursive: bool| {
            let mut command = Command::new("scp");
            // Im Ordner der Quelle und mit Namen statt Pfaden: `C:\…` hielte scp für einen Rechner namens C.
            command.current_dir(&local);
            command.args(["-q", "-P", &port.to_string(), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-i"]).arg(&key);
            if recursive {
                command.arg("-r");
            }
            let started = Instant::now();
            command.arg(from).arg(to).status().ok().filter(|status| status.success()).map(|_| started.elapsed().as_secs_f64())
        };
        if keyed {
            println!("scp von OpenSSH gegen denselben Server");
            let target = |path: &str| format!("tester@127.0.0.1:{path}");
            match tokio::task::block_in_place(|| scp("gross.bin".into(), target("/srv/scp-gross.bin"), false)) {
                Some(seconds) => println!("  große Datei hoch      {megabytes:.0} MB in {seconds:5.2} s = {:6.1} MB/s", megabytes / seconds),
                None => println!("  große Datei hoch: scp ließ sich nicht messen"),
            }
            std::fs::create_dir_all(files.join("srv").join("scp")).unwrap();
            match tokio::task::block_in_place(|| scp("viele".into(), target("/srv/scp"), true)) {
                Some(seconds) => println!("  {SMALL} kleine hoch                       {seconds:5.2} s = {:6.0} Dateien/s", SMALL as f64 / seconds),
                None => println!("  kleine Dateien hoch: scp ließ sich nicht messen"),
            }
        } else {
            println!("scp: ohne ssh-keygen kein Vergleich");
        }
        drop(running);
        let _ = std::fs::remove_dir_all(&root);
    }
}
