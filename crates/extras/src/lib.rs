//! Terminals beyond SSH: shells on this machine, Telnet, serial line.
//!
//! Every kind returns the same [`Session`] as the connection core (`glowport-net`): a stream of [`Event`]s and
//! a channel for [`Command`]s. Whoever manages sessions therefore does not need to know what is behind them.
//! Of the events, only phase, output, notice and end occur here; there are no prompts, and none of these
//! kinds offers an additional channel ([`Command::Open`]).

pub mod local;
pub mod serial;
pub mod telnet;

use std::time::Duration;

use glowport_net::{Command, End, Event, Session};
use tokio::{
    sync::{mpsc, oneshot},
    time::{sleep_until, Instant},
};

/// How long to wait for the rest of a device's output after it ended.
const DRAIN: Duration = Duration::from_secs(2);

/// The channels of a session: the caller gets the [`Session`], the work the counterparts.
pub(crate) fn channels() -> (Session, mpsc::Sender<Event>, mpsc::UnboundedReceiver<Command>) {
    let (event_tx, events) = mpsc::channel(256);
    let (commands, command_rx) = mpsc::unbounded_channel();
    (Session { commands, events }, event_tx, command_rx)
}

/// A device read and written with blocking calls (shell, serial port). Its threads
/// hang on these ends.
pub(crate) struct Wires {
    /// Bytes from the device. The channel is bounded: if the terminal stops, it backs up to the device.
    pub data: mpsc::Receiver<Vec<u8>>,
    /// Why the device ended, as soon as that is known.
    pub end: oneshot::Receiver<End>,
    pub write: Box<dyn FnMut(Vec<u8>) + Send>,
    pub resize: Box<dyn FnMut(u32, u32) + Send>,
    /// Ends the device at the user's request.
    pub close: Box<dyn FnOnce() + Send>,
}

/// Passes output and input through until the device ends or the user closes.
pub(crate) async fn pump(wires: Wires, events: &mpsc::Sender<Event>, commands: &mut mpsc::UnboundedReceiver<Command>) -> End {
    let Wires { mut data, end: mut ending, mut write, mut resize, close } = wires;
    let mut close = Some(close);
    let mut paused = false;
    // Once the end is known, the rest of the output still comes; after that, at the latest after a grace period, it is over.
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
