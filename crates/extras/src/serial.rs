//! Serial line: a terminal on a COM port, for the console of routers, switches and hobby boards.
//!
//! A serial line has no connection: the port is opened and whatever arrives is shown. If the
//! adapter is unplugged, the session ends as dropped; nobody knows whether a device is attached and listening.

use std::{
    io::{ErrorKind, Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use glowport_net::{End, Event, Phase, Session};
use serialport::{DataBits, FlowControl, SerialPortType, StopBits};
use tokio::sync::{mpsc, oneshot};

use crate::{channels, pump, Wires};

/// A read or write waits at most this long; after that it checks whether the session is still wanted.
/// On Windows the timeout belongs to the port and therefore applies to both directions at once.
const POLL: Duration = Duration::from_millis(100);
/// Writing may stall this long (e.g. because the device slows down with flow control) before the rest is discarded.
const WRITE_PATIENCE: Duration = Duration::from_secs(3);

/// This many bytes go to the port at once: what the line manages in half the timeout. A larger piece
/// would run into the timeout on a slow line although nothing stalls (300 baud is 30 characters per second).
fn chunk_size(baud: u32) -> usize {
    usize::try_from(baud / 200).unwrap_or(usize::MAX).clamp(1, 4096)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parity {
    None,
    Odd,
    Even,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    None,
    /// XON/XOFF
    Software,
    /// RTS/CTS
    Hardware,
}

/// Settings of the line. Both sides must have the same ones, otherwise garbage arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Line {
    pub baud: u32,
    /// 5 to 8.
    pub data_bits: u8,
    pub parity: Parity,
    /// 1 or 2.
    pub stop_bits: u8,
    pub flow: Flow,
}

impl Default for Line {
    fn default() -> Self {
        Self { baud: 9600, data_bits: 8, parity: Parity::None, stop_bits: 1, flow: Flow::None }
    }
}

/// A serial port on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    /// `COM3`, `/dev/ttyUSB0`
    pub name: String,
    /// What is attached, as far as the system names it: “USB-SERIAL CH340”. Otherwise empty.
    pub label: String,
}

/// Sorts `COM10` after `COM9`: by the name without digits, then by the number at the end.
fn natural(name: &str) -> (String, u64) {
    let digits = name.chars().rev().take_while(char::is_ascii_digit).count();
    let (stem, number) = name.split_at(name.len() - digits);
    (stem.to_lowercase(), number.parse().unwrap_or(0))
}

/// The ports that exist right now. A USB adapter only appears once it is plugged in.
pub fn ports() -> Vec<Port> {
    let mut found: Vec<Port> = serialport::available_ports()
        .unwrap_or_default()
        .into_iter()
        .map(|info| {
            let label = match info.port_type {
                SerialPortType::UsbPort(usb) => usb.product.or(usb.manufacturer).unwrap_or_else(|| "USB".into()),
                SerialPortType::BluetoothPort => "Bluetooth".into(),
                SerialPortType::PciPort | SerialPortType::Unknown => String::new(),
            };
            // Windows appends the port name in brackets to the description; it is already in front.
            let label = label.strip_suffix(&format!("({})", info.port_name)).map_or(label.as_str(), str::trim_end).trim().to_string();
            Port { name: info.port_name, label }
        })
        .collect();
    found.sort_by_cached_key(|port| natural(&port.name));
    found.dedup_by(|a, b| a.name == b.name);
    found
}

/// Opens a port as a session. Must be called inside a tokio runtime.
pub fn open(port: String, line: Line) -> Session {
    let (session, events, mut commands) = channels();
    tokio::spawn(async move {
        let _ = events.send(Event::Phase(Phase::Connecting)).await;
        // Opening a port can take a while (Bluetooth); not on a runtime thread.
        let end = match tokio::task::spawn_blocking(move || start(&port, line)).await.unwrap_or_else(|e| Err(e.to_string())) {
            Ok(wires) => {
                let _ = events.send(Event::Phase(Phase::Connected)).await;
                pump(wires, &events, &mut commands).await
            }
            Err(message) => End::ConnectFailed(message),
        };
        let _ = events.send(Event::End(end)).await;
    });
    session
}

fn start(name: &str, line: Line) -> Result<Wires, String> {
    let data_bits = match line.data_bits {
        5 => DataBits::Five,
        6 => DataBits::Six,
        7 => DataBits::Seven,
        8 => DataBits::Eight,
        other => return Err(format!("{other} data bits are not possible")),
    };
    let stop_bits = match line.stop_bits {
        1 => StopBits::One,
        2 => StopBits::Two,
        other => return Err(format!("{other} stop bits are not possible")),
    };
    let parity = match line.parity {
        Parity::None => serialport::Parity::None,
        Parity::Odd => serialport::Parity::Odd,
        Parity::Even => serialport::Parity::Even,
    };
    let flow = match line.flow {
        Flow::None => FlowControl::None,
        Flow::Software => FlowControl::Software,
        Flow::Hardware => FlowControl::Hardware,
    };
    let mut port = serialport::new(name, line.baud).data_bits(data_bits).stop_bits(stop_bits).parity(parity).flow_control(flow).timeout(POLL).open().map_err(|e| e.to_string())?;
    // Like other terminal programs: the “ready” lines are set, otherwise some devices do not answer.
    // With hardware flow control RTS belongs to the driver.
    let _ = port.write_data_terminal_ready(true);
    if line.flow != Flow::Hardware {
        let _ = port.write_request_to_send(true);
    }
    let mut writer = port.try_clone().map_err(|e| e.to_string())?;

    let stop = Arc::new(AtomicBool::new(false));
    let (data_tx, data) = mpsc::channel::<Vec<u8>>(64);
    let (end_tx, end) = oneshot::channel();
    let reading = Arc::clone(&stop);
    thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        let end = loop {
            if reading.load(Ordering::Relaxed) {
                break End::User;
            }
            match port.read(&mut buffer) {
                // Nothing arrived: on a serial line that is the normal case.
                Ok(0) => {}
                Ok(n) => {
                    if data_tx.blocking_send(buffer[..n].to_vec()).is_err() {
                        break End::User;
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                // The port is gone: adapter unplugged, device removed from the system.
                Err(e) => break End::ConnectionLost(e.to_string()),
            }
        };
        // First the reason, then the data channel closes with `data_tx`.
        let _ = end_tx.send(end);
    });

    let (input_tx, input_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let writing = Arc::clone(&stop);
    let chunk = chunk_size(line.baud);
    thread::spawn(move || {
        'input: for bytes in input_rx {
            let mut rest = bytes.as_slice();
            let mut stalled = Instant::now();
            while !rest.is_empty() && !writing.load(Ordering::Relaxed) {
                match writer.write(&rest[..rest.len().min(chunk)]) {
                    Ok(sent @ 1..) => {
                        rest = &rest[sent..];
                        stalled = Instant::now();
                    }
                    // The device accepts nothing right now. If that takes too long, the rest is dropped; the session stays.
                    Ok(_) => {}
                    Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                    // If the port is gone, reading notices too and reports the end.
                    Err(_) => break 'input,
                }
                if stalled.elapsed() > WRITE_PATIENCE {
                    break;
                }
            }
        }
    });

    Ok(Wires {
        data,
        end,
        write: Box::new(move |bytes| drop(input_tx.send(bytes))),
        // A serial line has no window size.
        resize: Box::new(|_, _| {}),
        close: Box::new(move || stop.store(true, Ordering::Relaxed)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_lines_get_small_pieces() {
        // A piece needs at most half the timeout: at 10 bits per character that is baud / 200 bytes.
        assert_eq!((chunk_size(300), chunk_size(9600), chunk_size(115_200), chunk_size(4_000_000)), (1, 48, 576, 4096));
        assert_eq!(chunk_size(50), 1, "never less than one byte");
    }

    #[test]
    fn ports_sort_by_their_number() {
        let mut names = ["COM10", "COM3", "com1", "/dev/ttyUSB1", "/dev/ttyUSB0", "COM9"];
        names.sort_by_cached_key(|name| natural(name));
        assert_eq!(names, ["/dev/ttyUSB0", "/dev/ttyUSB1", "com1", "COM3", "COM9", "COM10"]);
    }
}
