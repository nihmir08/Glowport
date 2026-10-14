//! The transfer queue: files and folders between this PC and servers, also from server to server.
//!
//! Every job is one entry of the list (a file or a folder with its content). Up to `parallel` files
//! run at the same time, in the order of the list. A paused or interrupted job remembers per
//! file how far it got and continues there; unfinished jobs are noted in `transfers.json` and
//! offered again, paused, after a restart.
//!
//! The queue knows neither windows nor vault: how a location is reached it is told by [`Resolve`], and it
//! hands out its state through [`Publish`]. That way it can be tested without a program window.

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
/// After this many bytes a running copy records its state. If the program ends hard, at most this is lost.
const CHECKPOINT: u64 = 8 * 1024 * 1024;

/// How a location is reached. If it fails, the error code for the interface comes back.
pub type Resolve = Arc<dyn Fn(Place) -> Pin<Box<dyn Future<Output = Result<Endpoint, &'static str>> + Send>> + Send + Sync>;
pub type Publish = Arc<dyn Fn(Vec<TransferView>) + Send + Sync>;
/// Reports that the connection to a location broke and has to be re-established next time.
pub type Forget = Arc<dyn Fn(Place) + Send + Sync>;

/// A reachable location: this PC or a server over SFTP.
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

    /// Details about a path; `None` if it does not exist. Links count as their target.
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
                    // What cannot be read or points into nothing is left behind.
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

    /// Creates a folder; if it already exists, that is fine.
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

    /// Gives the copy the original's modification time, so a later comparison recognises them as equal.
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

/// What happens if something with that name already exists at the destination.
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

/// A single file of a job.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Item {
    from: String,
    to: String,
    size: u64,
    modified: u64,
    /// This many bytes are already at the destination.
    done: u64,
    step: Step,
}

const RUN: u8 = 0;
const PAUSE: u8 = 1;
const CANCEL: u8 = 2;

/// A job as [`Engine::start`] receives it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub from: Place,
    /// File or folder at the source.
    pub source: String,
    pub to: Place,
    /// Zielordner.
    pub dest: String,
    pub policy: Policy,
    /// Source and destination for display.
    pub source_label: String,
    pub dest_label: String,
    /// The same locations without a running session: the host behind it. Through them it continues when the session ends,
    /// and only with them can the job be resumed after a restart (`None` for typed addresses).
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
    /// The job's files; `None` as long as the source has not been scanned yet.
    items: Option<Vec<Item>>,
    scanning: bool,
    bytes: u64,
    /// Progress, counted up by the running copies.
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

/// What is noted of an unfinished job.
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
    /// Running copies and scans together.
    active: AtomicUsize,
    /// File in which unfinished jobs are noted.
    store: Option<PathBuf>,
    dirty: AtomicBool,
    /// Pause in milliseconds after every chunk; only tests slow down with it, to catch a transfer midway.
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

    /// Writes down the unfinished jobs that can survive a restart.
    fn save(&self) {
        let Some(path) = &self.store else { return };
        let saved: Vec<Saved> = self
            .jobs()
            .iter()
            .filter(|job| job.state.open() && job.order.durable())
            // Noted with the locations that still exist after a restart.
            .map(|job| Saved { order: Order { from: job.order.keep_from.clone().unwrap_or(Place::Local), to: job.order.keep_to.clone().unwrap_or(Place::Local), ..job.order.clone() }, name: job.name.clone(), bytes: job.bytes, items: job.items.as_ref().map(|items| items.iter().map(|item| Item { step: if item.step == Step::Done { Step::Done } else { Step::Pending }, ..item.clone() }).collect()) })
            .collect();
        let result = if saved.is_empty() { std::fs::remove_file(path).or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(e) }) } else { serde_json::to_vec(&saved).map_err(std::io::Error::other).and_then(|bytes| std::fs::write(path, bytes)) };
        if let Err(error) = result {
            eprintln!("Transfers not noted: {error}");
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

/// How a copy ends if it does not finish.
enum Stop {
    /// Paused or cancelled; the second case clears away the half file.
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
    /// Starts the queue. `store` names the file for unfinished jobs; what is in it from last time
    /// appears paused in the list. Must be called within a tokio runtime.
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

    /// Queues jobs and returns their numbers.
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

    /// Pauses, resumes, cancels or retries; without numbers it applies to all jobs.
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

    /// Removes everything finished, cancelled and failed from the list.
    pub fn clear(&self) {
        self.shared.jobs().retain(|job| job.state.open());
        self.shared.changed();
    }

    /// Number of jobs that are running or waiting.
    #[cfg(test)]
    fn busy(&self) -> usize {
        self.shared.jobs().iter().filter(|job| matches!(job.state, State::Queued | State::Running)).count()
    }

    /// Before quitting: pause everything and note what can be resumed.
    pub fn shutdown(&self) {
        self.control(None, "pause");
        self.shared.save();
    }
}

/// Distributes the work: starts scans and copies as long as slots are free, and reports the state regularly.
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

        // Speed from the growth since the last report.
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

/// Reaches a location. If it hangs on a session that no longer exists, it continues through the host behind it.
async fn reach(shared: &Shared, place: &Place, keep: &Option<Place>) -> Result<Endpoint, Stop> {
    match (shared.resolve)(place.clone()).await {
        Err("not_connected") => match keep {
            Some(other) if other != place => (shared.resolve)(other.clone()).await.map_err(Stop::Failed),
            _ => Err(Stop::Failed("not_connected")),
        },
        other => other.map_err(Stop::Failed),
    }
}

/// After a break, the connections of both locations should be created anew on the next attempt.
fn dropped(shared: &Shared, order: &Order, code: &str) {
    if code == "not_connected" {
        (shared.forget)(order.from.clone());
        (shared.forget)(order.to.clone());
    }
}

/// A name beside it that does not exist at the destination yet: “report (2).pdf”.
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

/// Scans a job's source: a file becomes one entry, a folder all files in it.
/// The folders at the destination are created along the way.
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
            // Paused or cancelled before it started: next time it is scanned anew.
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

/// Transfers one file of a job, from the point where it last stood.
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
                // A cancelled job starts this file from the beginning when retried.
                job.done.fetch_sub(written.min(job.done.load(Ordering::Relaxed)), Ordering::Relaxed);
                item.done = 0;
            }
        }
        match result {
            Err(Stop::Failed(code)) if job.state == State::Running => {
                job.state = State::Failed;
                job.error = Some(code);
                dropped(&shared, &job.order, code);
                // The job's other files do not continue until the user retries.
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

    // Resume only if that much is really at the destination and the source is still the same; otherwise from the start.
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

// ---------- Connection to the program ----------

/// The program's queue. It belongs to no window; every one shows the same state.
pub struct Queue(pub Engine);

/// Starts the queue with the bridge's connections and reports its state as the `transfers` event.
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

/// What a location is called in the list and under which location it can still be reached after a restart.
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

/// For this PC the path is enough; for a server its name comes before it.
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
    /// Destination folder; empty with destination “this PC” means the downloads folder.
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

/// Fetches a server's files and folders into a folder on this computer, so they can then be dragged out of the
/// window. Returns the transfers' numbers and where the files will be afterwards.
pub(crate) fn stage(app: &AppHandle, queue: &Queue, from: &Place, paths: Vec<String>, dir: &Path) -> (Vec<u64>, Vec<String>) {
    let dest = dir.to_string_lossy().into_owned();
    let staged = paths.iter().map(|source| join(&Place::Local, &dest, &base_name(from, source))).collect();
    let mut orders = orders(app, from, &Place::Local, Policy::Overwrite, paths.into_iter().map(|source| (source, dest.clone())).collect());
    for order in &mut orders {
        order.dest_label = "Explorer".into();
        // After a restart the drag is over; such a job is not noted.
        order.keep_to = None;
    }
    let source = from.clone();
    (queue.0.start(orders, |order| base_name(&source, &order.source)), staged)
}

/// Queues files and folders.
#[tauri::command]
pub fn transfer_start(app: AppHandle, queue: tauri::State<'_, Queue>, request: Request) -> CmdResult<Vec<u64>> {
    if request.from == request.to && request.paths.iter().any(|path| join(&request.from, &request.dest, &base_name(&request.from, path)) == *path) {
        return Err(CmdError::new("same_place", "Source and destination are the same location"));
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

/// The comparison does not compare more entries; then the folder is too big for a list.
const MAX_COMPARED: usize = 20_000;
/// By this many seconds the modification times of equal files may differ (file systems round differently).
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
    /// Path below the compared folders, separated by `/`.
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

/// Size of everything in a folder.
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
            // A folder on both sides: what is inside is compared.
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

/// Compares two folders including subfolders by size and modification time.
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

/// Syncs two folders: every line names the path below the folders and the direction. Nothing is deleted.
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

    /// Two folders on this computer as source and destination; they disappear with the test.
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
        panic!("State not reached: {:?}", engine.list());
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
        assert!(bench.root.join("ziel/ordner/leer").is_dir(), "empty folders come along too");
        let folder = &views[1];
        assert_eq!((folder.name.as_str(), folder.files, folder.files_done, folder.bytes, folder.done, folder.direction), ("ordner", 2, 2, 600_003, 600_003, "upload"));
        // The copy is as old as the original.
        let age = |path: &str| std::fs::metadata(bench.root.join(path)).unwrap().modified().unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(age("ziel/einzeln.txt"), age("quelle/einzeln.txt"));
        assert!(bench.seen.lock().unwrap().len() >= 2, "the progress is reported");
        assert!(!bench.root.join("transfers.json").exists(), "nichts Unfertiges, nichts vorgemerkt");
    }

    #[tokio::test]
    async fn skips_overwrites_or_puts_next_to_what_is_already_there() {
        let bench = Bench::new();
        bench.put("quelle/plan.txt", b"new");
        bench.put("quelle/web/index.html", b"new");
        bench.put("quelle/web/new.css", b"css");
        bench.put("ziel/plan.txt", b"old");
        bench.put("ziel/web/index.html", b"old");
        let engine = bench.engine();

        engine.start(vec![bench.order("plan.txt", Policy::Skip), bench.order("web", Policy::Skip)], named);
        until(&engine, all("done")).await;
        assert_eq!(bench.read("ziel/plan.txt").as_deref(), Some(&b"old"[..]));
        assert_eq!(bench.read("ziel/web/index.html").as_deref(), Some(&b"old"[..]), "what exists in the folder stays");
        assert_eq!(bench.read("ziel/web/new.css").as_deref(), Some(&b"css"[..]), "what is missing is added");

        engine.clear();
        engine.start(vec![bench.order("plan.txt", Policy::Rename), bench.order("web", Policy::Rename)], named);
        until(&engine, all("done")).await;
        assert_eq!(bench.read("ziel/plan.txt").as_deref(), Some(&b"old"[..]));
        assert_eq!(bench.read("ziel/plan (2).txt").as_deref(), Some(&b"new"[..]));
        assert_eq!(bench.read("ziel/web (2)/index.html").as_deref(), Some(&b"new"[..]));

        engine.clear();
        engine.start(vec![bench.order("plan.txt", Policy::Overwrite), bench.order("web", Policy::Overwrite)], named);
        until(&engine, all("done")).await;
        assert_eq!(bench.read("ziel/plan.txt").as_deref(), Some(&b"new"[..]));
        assert_eq!(bench.read("ziel/web/index.html").as_deref(), Some(&b"new"[..]));
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
        // Wait until the running copy really stands still and its state is recorded.
        until(&engine, |_| engine.shared.active.load(Ordering::Relaxed) == 0).await;
        let halfway = engine.list()[0].done;
        assert!(halfway > 0 && halfway < content.len() as u64, "mittendrin angehalten: {halfway} (gemeldet {})", paused[0].done);
        assert_eq!(bench.read("ziel/gross.bin").map(|b| b.len() as u64), Some(halfway), "exactly what was transferred is at the destination");
        tokio::time::sleep(TICK * 2).await;
        assert!(bench.root.join("transfers.json").exists(), "the unfinished job is noted");

        // Restart: a new queue reads what was noted and offers it paused.
        drop(engine);
        let again = bench.engine();
        let offered = again.list();
        assert_eq!((offered.len(), offered[0].state, offered[0].done, offered[0].resumed), (1, "paused", halfway, true));
        again.control(None, "resume");
        let views = until(&again, all("done")).await;
        assert_eq!(views[0].done, content.len() as u64);
        assert!(bench.read("ziel/gross.bin").is_some_and(|copy| copy == content), "the resumed file is complete and unchanged");
        tokio::time::sleep(TICK * 2).await;
        assert!(!bench.root.join("transfers.json").exists(), "after the end nothing is noted any more");
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
        assert!(bench.read("ziel/daten.bin").is_some_and(|copy| copy == vec![2u8; 1_000_000]), "no mix of an old beginning and a new end");
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
        assert!(bench.read("ziel/film.bin").is_none(), "the half file is cleared away");

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

    /// Not a test but measurements: how fast transfers run against our own test server on this computer,
    /// with OpenSSH's `scp` against the same server as a yardstick. Run:
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
        // Irregular content, so neither compression nor equal blocks make the picture look better.
        let mut seed = 0x2545_F491_4F6C_DD1D_u64;
        let noise: Vec<u8> = (0..BIG).map(|_| { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed as u8 }).collect();
        std::fs::write(local.join("gross.bin"), &noise).unwrap();
        for i in 0..SMALL {
            std::fs::write(local.join("viele").join(format!("datei-{i:04}.txt")), &noise[i * 4096..(i + 1) * 4096]).unwrap();
        }
        drop(noise);

        // Key for `scp`; the test server reads it from the home directory.
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
        // Runs a job and returns the duration in seconds.
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

        println!("\nGlowport against our own test server on this computer (127.0.0.1, optimised build)");
        let up = run(order(&Place::Local, text(&local.join("gross.bin")), &server_place, "/srv".into()), 4).await;
        println!("  large file up        {megabytes:.0} MB in {up:5.2} s = {:6.1} MB/s", megabytes / up);
        let down = run(order(&server_place, "/srv/gross.bin".into(), &Place::Local, text(&local.join("zurueck"))), 4).await;
        println!("  large file down      {megabytes:.0} MB in {down:5.2} s = {:6.1} MB/s", megabytes / down);
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

        // The same route with OpenSSH's `scp`, which nowadays speaks SFTP as well.
        let scp = |from: String, to: String, recursive: bool| {
            let mut command = Command::new("scp");
            // In the source's folder and with names instead of paths: scp would take `C:\…` for a computer named C.
            command.current_dir(&local);
            command.args(["-q", "-P", &port.to_string(), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-i"]).arg(&key);
            if recursive {
                command.arg("-r");
            }
            let started = Instant::now();
            command.arg(from).arg(to).status().ok().filter(|status| status.success()).map(|_| started.elapsed().as_secs_f64())
        };
        if keyed {
            println!("OpenSSH's scp against the same server");
            let target = |path: &str| format!("tester@127.0.0.1:{path}");
            match tokio::task::block_in_place(|| scp("gross.bin".into(), target("/srv/scp-gross.bin"), false)) {
                Some(seconds) => println!("  large file up        {megabytes:.0} MB in {seconds:5.2} s = {:6.1} MB/s", megabytes / seconds),
                None => println!("  large file up: scp could not be measured"),
            }
            std::fs::create_dir_all(files.join("srv").join("scp")).unwrap();
            match tokio::task::block_in_place(|| scp("viele".into(), target("/srv/scp"), true)) {
                Some(seconds) => println!("  {SMALL} kleine hoch                       {seconds:5.2} s = {:6.0} Dateien/s", SMALL as f64 / seconds),
                None => println!("  small files up: scp could not be measured"),
            }
        } else {
            println!("scp: no comparison without ssh-keygen");
        }
        drop(running);
        let _ = std::fs::remove_dir_all(&root);
    }
}
