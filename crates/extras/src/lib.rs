//! Terminals jenseits von SSH: Shells dieses Rechners, Telnet, serielle Leitung.
//!
//! Jede Art liefert dieselbe [`Session`] wie der Verbindungskern (`glowport-net`): einen Strom von [`Event`]s und
//! einen Kanal für [`Command`]s. Wer Sitzungen verwaltet, braucht deshalb nicht zu wissen, was dahintersteckt.
//! Von den Ereignissen kommen hier nur Phase, Ausgabe, Hinweis und Ende vor; Rückfragen gibt es keine, und einen
//! zusätzlichen Kanal ([`Command::Open`]) gibt keine dieser Arten her.

pub mod local;
pub mod serial;
pub mod telnet;

use std::time::Duration;

use glowport_net::{Command, End, Event, Session};
use tokio::{
    sync::{mpsc, oneshot},
    time::{sleep_until, Instant},
};

/// Wie lange nach dem Ende eines Geräts noch auf den Rest seiner Ausgabe gewartet wird.
const DRAIN: Duration = Duration::from_secs(2);

/// Die Kanäle einer Sitzung: Der Aufrufer bekommt die [`Session`], die Arbeit die Gegenstücke.
pub(crate) fn channels() -> (Session, mpsc::Sender<Event>, mpsc::UnboundedReceiver<Command>) {
    let (event_tx, events) = mpsc::channel(256);
    let (commands, command_rx) = mpsc::unbounded_channel();
    (Session { commands, events }, event_tx, command_rx)
}

/// Ein Gerät, das mit blockierenden Aufrufen gelesen und geschrieben wird (Shell, serieller Port). Seine Threads
/// hängen an diesen Enden.
pub(crate) struct Wires {
    /// Bytes vom Gerät. Der Kanal ist begrenzt: Hält das Terminal an, staut es sich bis zum Gerät zurück.
    pub data: mpsc::Receiver<Vec<u8>>,
    /// Warum das Gerät endete, sobald das feststeht.
    pub end: oneshot::Receiver<End>,
    pub write: Box<dyn FnMut(Vec<u8>) + Send>,
    pub resize: Box<dyn FnMut(u32, u32) + Send>,
    /// Beendet das Gerät auf Wunsch des Nutzers.
    pub close: Box<dyn FnOnce() + Send>,
}

/// Reicht Ausgabe und Eingabe durch, bis das Gerät endet oder der Nutzer schließt.
pub(crate) async fn pump(wires: Wires, events: &mpsc::Sender<Event>, commands: &mut mpsc::UnboundedReceiver<Command>) -> End {
    let Wires { mut data, end: mut ending, mut write, mut resize, close } = wires;
    let mut close = Some(close);
    let mut paused = false;
    // Steht das Ende fest, kommt noch der Rest der Ausgabe; danach, spätestens nach einer Gnadenfrist, ist Schluss.
    let mut end: Option<(End, Instant)> = None;
    loop {
        let deadline = end.as_ref().map(|(_, at)| *at);
        tokio::select! {
            chunk = data.recv(), if !paused => match chunk {
                Some(bytes) => {
                    if events.send(Event::Output(bytes)).await.is_err() {
                        break;
                    }
                }
                None => {
                    return match end {
                        Some((end, _)) => end,
                        None => ending.await.unwrap_or_else(|_| End::ConnectionLost("the device is gone".into())),
                    };
                }
            },
            result = &mut ending, if end.is_none() => {
                end = Some((result.unwrap_or_else(|_| End::ConnectionLost("the device is gone".into())), Instant::now() + DRAIN));
            }
            () = sleep_until(deadline.unwrap_or_else(Instant::now)), if deadline.is_some() && !paused => {
                return end.map_or(End::User, |(end, _)| end);
            }
            command = commands.recv() => match command {
                Some(Command::Input(bytes)) => write(bytes),
                Some(Command::Resize(columns, rows)) => resize(columns, rows),
                Some(Command::Pause(pause)) => paused = pause,
                Some(Command::Open(reply)) => drop(reply.send(None)),
                Some(Command::Relink) => {}
                Some(Command::Close) | None => break,
            },
        }
    }
    if let Some(close) = close.take() {
        close();
    }
    End::User
}
