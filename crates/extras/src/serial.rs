//! Serielle Leitung: ein Terminal an einem COM-Port, für die Konsole von Routern, Switches und Bastelrechnern.
//!
//! Eine serielle Leitung kennt keine Verbindung: Der Port wird geöffnet, und was ankommt, wird angezeigt. Wird der
//! Adapter abgezogen, endet die Sitzung als abgerissen; ob ein Gerät dranhängt und zuhört, weiß niemand.

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

/// So lange wartet ein Lesen oder Schreiben höchstens; danach wird nachgesehen, ob die Sitzung noch gewünscht ist.
/// Die Frist gehört unter Windows dem Port und gilt deshalb für beide Richtungen zugleich.
const POLL: Duration = Duration::from_millis(100);
/// So lange darf das Schreiben stocken (etwa weil das Gerät mit Flusskontrolle bremst), bevor der Rest verworfen wird.
const WRITE_PATIENCE: Duration = Duration::from_secs(3);

/// So viele Bytes gehen auf einmal an den Port: was die Leitung in der halben Frist schafft. Ein größeres Stück
/// liefe bei langsamer Leitung in die Frist, obwohl nichts stockt (300 Baud sind 30 Zeichen in der Sekunde).
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

/// Einstellungen der Leitung. Beide Seiten müssen dieselben haben, sonst kommt Zeichensalat an.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Line {
    pub baud: u32,
    /// 5 bis 8.
    pub data_bits: u8,
    pub parity: Parity,
    /// 1 oder 2.
    pub stop_bits: u8,
    pub flow: Flow,
}

impl Default for Line {
    fn default() -> Self {
        Self { baud: 9600, data_bits: 8, parity: Parity::None, stop_bits: 1, flow: Flow::None }
    }
}

/// Ein serieller Port dieses Rechners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    /// `COM3`, `/dev/ttyUSB0`
    pub name: String,
    /// Was daran hängt, soweit das System es nennt: „USB-SERIAL CH340“. Sonst leer.
    pub label: String,
}

/// Sortiert `COM10` hinter `COM9`: nach dem Namen ohne Ziffern, dann nach der Zahl am Ende.
fn natural(name: &str) -> (String, u64) {
    let digits = name.chars().rev().take_while(char::is_ascii_digit).count();
    let (stem, number) = name.split_at(name.len() - digits);
    (stem.to_lowercase(), number.parse().unwrap_or(0))
}

/// Die Ports, die es gerade gibt. Ein USB-Adapter erscheint erst, wenn er steckt.
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
            // Windows hängt den Namen des Ports in Klammern an die Bezeichnung; er steht schon davor.
            let label = label.strip_suffix(&format!("({})", info.port_name)).map_or(label.as_str(), str::trim_end).trim().to_string();
            Port { name: info.port_name, label }
        })
        .collect();
    found.sort_by_cached_key(|port| natural(&port.name));
    found.dedup_by(|a, b| a.name == b.name);
    found
}

/// Öffnet einen Port als Sitzung. Muss in einem tokio-Runtime aufgerufen werden.
pub fn open(port: String, line: Line) -> Session {
    let (session, events, mut commands) = channels();
    tokio::spawn(async move {
        let _ = events.send(Event::Phase(Phase::Connecting)).await;
        // Das Öffnen eines Ports kann dauern (Bluetooth); nicht auf einem Thread des Runtimes.
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
    // Wie andere Terminal-Programme: Die Leitungen „bereit“ sind gesetzt, sonst antworten manche Geräte nicht.
    // RTS gehört bei Hardware-Flusskontrolle dem Treiber.
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
                // Nichts gekommen: Das ist bei einer seriellen Leitung der Normalfall.
                Ok(0) => {}
                Ok(n) => {
                    if data_tx.blocking_send(buffer[..n].to_vec()).is_err() {
                        break End::User;
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                // Der Port ist weg: Adapter abgezogen, Gerät vom System entfernt.
                Err(e) => break End::ConnectionLost(e.to_string()),
            }
        };
        // Erst der Grund, dann schließt sich mit `data_tx` der Kanal der Daten.
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
                    // Das Gerät nimmt gerade nichts an. Dauert das zu lange, verfällt der Rest; die Sitzung bleibt.
                    Ok(_) => {}
                    Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                    // Ist der Port weg, merkt es auch das Lesen und meldet das Ende.
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
        // Eine serielle Leitung kennt keine Fenstergröße.
        resize: Box::new(|_, _| {}),
        close: Box::new(move || stop.store(true, Ordering::Relaxed)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_lines_get_small_pieces() {
        // Ein Stück braucht höchstens die halbe Frist: bei 10 Bit je Zeichen sind das Baud / 200 Bytes.
        assert_eq!((chunk_size(300), chunk_size(9600), chunk_size(115_200), chunk_size(4_000_000)), (1, 48, 576, 4096));
        assert_eq!(chunk_size(50), 1, "nie weniger als ein Byte");
    }

    #[test]
    fn ports_sort_by_their_number() {
        let mut names = ["COM10", "COM3", "com1", "/dev/ttyUSB1", "/dev/ttyUSB0", "COM9"];
        names.sort_by_cached_key(|name| natural(name));
        assert_eq!(names, ["/dev/ttyUSB0", "/dev/ttyUSB1", "com1", "COM3", "COM9", "COM10"]);
    }
}
