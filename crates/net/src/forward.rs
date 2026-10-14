//! Port-Weiterleitungen über eine eigene Verbindung, ohne Terminal.
//!
//! [`open`] verbindet wie eine Sitzung (Rückfragen kommen als Ereignisse) und richtet danach die Regel ein.
//! Steht sie, kommt als letztes Ereignis [`Event::Forward`] mit dem [`Tunnel`]; er läuft, bis er fallen
//! gelassen wird oder die Verbindung abreißt.
//!
//! - `Local`: Ein Port dieses Rechners nimmt Verbindungen an; jede geht über den Server (`direct-tcpip`) zum Ziel.
//! - `Dynamic`: dasselbe, nur nennt jede Verbindung ihr Ziel selbst (SOCKS 5, 4 und 4a).
//! - `Remote`: Der Server lauscht (`tcpip-forward`) und reicht Verbindungen hierher; sie gehen von hier zum Ziel.

use std::pin::Pin;
use std::sync::{
    atomic::{AtomicU32, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::task::{Context, Poll};
use std::time::Duration;

use russh::{client, Channel, Disconnect};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

use crate::{closed_early, establish, Command, Connect, End, Event, Link, Phase, Session};

/// Was weitergeleitet wird. Adressen und Ports sind schon geprüft, wenn sie hier ankommen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// Verbindungen an `listener` gehen über den Server nach `host:port`.
    Local { host: String, port: u16 },
    /// Verbindungen an `listener` nennen ihr Ziel selbst (SOCKS).
    Dynamic,
    /// Der Server lauscht an `bind:bind_port`; was dort ankommt, geht von diesem Rechner aus nach `host:port`.
    Remote { bind: String, bind_port: u16, host: String, port: u16 },
}

/// Zähler einer laufenden Regel. Sie gehören dem Aufrufer und überleben ein Neuverbinden.
#[derive(Debug, Default)]
pub struct Counters {
    /// Gerade offene Verbindungen.
    pub open: AtomicU32,
    /// Alle Verbindungen seit dem Einschalten.
    pub total: AtomicU64,
    /// Bytes in Richtung Ziel und zurück.
    pub sent: AtomicU64,
    pub received: AtomicU64,
}

/// Eine laufende Weiterleitung. Fallen lassen beendet sie und trennt die Verbindung.
pub struct Tunnel {
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<End>,
}

impl Tunnel {
    /// Wartet, bis die Weiterleitung endet: [`End::ConnectionLost`] nach einem Abriss, sonst [`End::User`].
    pub async fn closed(&mut self) -> End {
        (&mut self.task).await.unwrap_or(End::User)
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // Die Aufgabe räumt selbst auf (trennen, offene Verbindungen schließen), sobald das Signal kommt.
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

/// Wie lange das Ziel einer einzelnen Verbindung Zeit hat, erreichbar zu sein.
const DIAL_TIMEOUT: Duration = Duration::from_secs(20);
/// Wie lange ein Programm für seine SOCKS-Begrüßung Zeit hat.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Wie oft nachgesehen wird, ob die Verbindung zum Server noch steht.
const WATCH_INTERVAL: Duration = Duration::from_secs(1);

/// Verbindet zu `connect` und betreibt darüber `rule`.
///
/// Für `Local` und `Dynamic` bringt der Aufrufer den schon geöffneten `listener` mit: So zeigt sich ein belegter
/// Port, bevor irgendeine Rückfrage gestellt wird. Ereignisse wie bei [`crate::open`]; das letzte ist bei Erfolg
/// [`Event::Forward`], sonst [`Event::End`]. Lehnt der Server das Lauschen ab, endet es mit [`End::Refused`].
pub fn open(connect: Connect, rule: Rule, listener: Option<TcpListener>, counters: Arc<Counters>) -> Session {
    let (event_tx, events) = mpsc::channel(64);
    let (commands, mut command_rx) = mpsc::unbounded_channel::<Command>();
    tokio::spawn(async move {
        let _ = event_tx.send(Event::Phase(Phase::Connecting)).await;
        let size = Mutex::new((0, 0));
        let work = async {
            let link = establish(&connect, &event_tx).await?;
            start(link, rule, listener, counters).await
        };
        let result = tokio::select! {
            result = work => result,
            () = closed_early(&mut command_rx, &size) => Err(End::User),
        };
        match result {
            Ok(tunnel) => drop(event_tx.send(Event::Forward(tunnel)).await),
            Err(end) => drop(event_tx.send(Event::End(end)).await),
        }
    });
    Session { commands, events }
}

/// Richtet die Regel auf einer stehenden Verbindung ein und lässt sie in einer eigenen Aufgabe laufen.
async fn start(link: Link, rule: Rule, listener: Option<TcpListener>, counters: Arc<Counters>) -> Result<Tunnel, End> {
    let mut incoming = None;
    if let Rule::Remote { bind, bind_port, .. } = &rule {
        // Erst die Annahmestelle, dann die Bitte an den Server: So geht keine frühe Verbindung verloren.
        let (sender, receiver) = mpsc::unbounded_channel();
        *link.forwarded.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(sender);
        incoming = Some(receiver);
        link.handle.tcpip_forward(bind.clone(), u32::from(*bind_port)).await.map_err(|error| match error {
            russh::Error::RequestDenied => End::Refused(format!("{bind}:{bind_port}")),
            other => End::ConnectionLost(other.to_string()),
        })?;
    } else if listener.is_none() {
        return Err(End::ConnectFailed("no listener".into()));
    }
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(serve(Arc::new(link), rule, listener, incoming, counters, stopped));
    Ok(Tunnel { stop: Some(stop), task })
}

/// Nimmt Verbindungen an, bis die Regel ausgeschaltet wird oder die Verbindung zum Server abreißt.
async fn serve(link: Arc<Link>, rule: Rule, listener: Option<TcpListener>, mut incoming: Option<mpsc::UnboundedReceiver<Channel<client::Msg>>>, counters: Arc<Counters>, mut stopped: oneshot::Receiver<()>) -> End {
    // Jede Verbindung ist eine eigene Aufgabe; mit dieser Sammlung enden sie alle, sobald die Regel endet.
    let mut connections = JoinSet::new();
    let mut watch = tokio::time::interval(WATCH_INTERVAL);
    let end = loop {
        tokio::select! {
            _ = &mut stopped => break End::User,
            _ = watch.tick() => {
                if link.handle.is_closed() {
                    break End::ConnectionLost("the connection was lost".into());
                }
                // Fertige Verbindungen abräumen, damit die Sammlung nicht wächst.
                while connections.try_join_next().is_some() {}
            }
            accepted = next_local(&listener) => {
                let Some((stream, peer)) = accepted else { continue };
                let _ = stream.set_nodelay(true);
                let (link, counters, rule) = (Arc::clone(&link), Arc::clone(&counters), rule.clone());
                connections.spawn(async move {
                    let _guard = Open::new(&counters);
                    let origin = (peer.ip().to_string(), u32::from(peer.port()));
                    match rule {
                        Rule::Local { host, port } => {
                            if let Ok(Ok(channel)) = timeout(DIAL_TIMEOUT, link.handle.channel_open_direct_tcpip(host, u32::from(port), origin.0, origin.1)).await {
                                pipe(stream, channel.into_stream(), &counters).await;
                            }
                        }
                        Rule::Dynamic => socks(stream, &link, origin, &counters).await,
                        Rule::Remote { .. } => {}
                    }
                });
            }
            channel = next_remote(&mut incoming) => {
                let Some(channel) = channel else { break End::ConnectionLost("the connection was lost".into()) };
                let Rule::Remote { host, port, .. } = &rule else { continue };
                let (counters, target) = (Arc::clone(&counters), (host.clone(), *port));
                connections.spawn(async move {
                    let _guard = Open::new(&counters);
                    // Ist das Ziel hier nicht erreichbar, schließt sich der Kanal; der Server meldet das seinem Gegenüber.
                    if let Ok(Ok(stream)) = timeout(DIAL_TIMEOUT, TcpStream::connect(target)).await {
                        let _ = stream.set_nodelay(true);
                        pipe(channel.into_stream(), stream, &counters).await;
                    }
                });
            }
        }
    };
    connections.shutdown().await;
    if end == End::User {
        if let Rule::Remote { bind, bind_port, .. } = &rule {
            let _ = timeout(Duration::from_secs(2), link.handle.cancel_tcpip_forward(bind.clone(), u32::from(*bind_port))).await;
        }
        let _ = link.handle.disconnect(Disconnect::ByApplication, "", "en").await;
    }
    end
}

/// Die nächste Verbindung am eigenen Port; ohne eigenen Port (Regel `Remote`) kommt nie eine.
async fn next_local(listener: &Option<TcpListener>) -> Option<(TcpStream, std::net::SocketAddr)> {
    match listener {
        Some(listener) => listener.accept().await.ok(),
        None => std::future::pending().await,
    }
}

/// Die nächste Verbindung, die der Server hereinreicht; ohne Regel `Remote` kommt nie eine.
async fn next_remote(incoming: &mut Option<mpsc::UnboundedReceiver<Channel<client::Msg>>>) -> Option<Channel<client::Msg>> {
    match incoming {
        Some(incoming) => incoming.recv().await,
        None => std::future::pending().await,
    }
}

/// Zählt eine Verbindung als offen, solange der Wächter lebt.
struct Open<'a>(&'a Counters);

impl<'a> Open<'a> {
    fn new(counters: &'a Counters) -> Self {
        counters.open.fetch_add(1, Ordering::Relaxed);
        counters.total.fetch_add(1, Ordering::Relaxed);
        Self(counters)
    }
}

impl Drop for Open<'_> {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Reicht Daten in beide Richtungen durch, bis beide Seiten fertig sind, und zählt mit.
/// `near` ist die Seite, an der gelauscht wurde, `far` das Ziel.
async fn pipe<A, B>(near: A, mut far: B, counters: &Counters)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    // Das Durchreichen selbst macht tokio; gezählt wird an der nahen Seite.
    let mut near = Counted { inner: near, counters };
    let _ = tokio::io::copy_bidirectional_with_sizes(&mut near, &mut far, BUFFER, BUFFER).await;
}

/// Puffer je Richtung einer Verbindung. Größer ist hier langsamer: Der Kanal der SSH-Bibliothek kommt mit kleinen
/// Stücken am besten zurecht. Gemessen am 2026-10-08 mit `measures_tunnel_throughput`, 512 MB über 127.0.0.1:
/// 4 KiB 192 MB/s, 8 KiB rund 500 MB/s, 16 KiB 170 MB/s, 24 KiB 128 MB/s, 64 KiB 61 MB/s.
const BUFFER: usize = 8 * 1024;

/// Zählt mit, was durch einen Strom geht: Gelesenes ist auf dem Weg zum Ziel, Geschriebenes kommt von dort zurück.
struct Counted<'a, S> {
    inner: S,
    counters: &'a Counters,
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<'_, S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        if let Poll::Ready(Ok(())) = &result {
            self.counters.sent.fetch_add((buffer.filled().len() - before) as u64, Ordering::Relaxed);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<'_, S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(written)) = &result {
            self.counters.received.fetch_add(*written as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------- SOCKS ----------

/// Das Ziel, das ein Programm über SOCKS nennt, und in welcher Fassung es gefragt hat.
#[derive(Debug, PartialEq, Eq)]
struct Request {
    version: u8,
    host: String,
    port: u16,
}

/// Liest die Begrüßung und die Bitte eines SOCKS-Clients. `None`: Die Anfrage ist unbrauchbar oder verlangt etwas,
/// das es hier nicht gibt (Anmeldung, `BIND`, UDP); die passende Absage ist dann schon geschrieben.
async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Option<Request> {
    let version = stream.read_u8().await.ok()?;
    match version {
        5 => {
            let count = stream.read_u8().await.ok()?;
            let mut methods = vec![0u8; usize::from(count)];
            stream.read_exact(&mut methods).await.ok()?;
            // Nur „ohne Anmeldung“: Der Port hört ohnehin nur auf diesem Rechner.
            if !methods.contains(&0) {
                let _ = stream.write_all(&[5, 0xFF]).await;
                return None;
            }
            stream.write_all(&[5, 0]).await.ok()?;
            let mut head = [0u8; 4];
            stream.read_exact(&mut head).await.ok()?;
            if head[0] != 5 || head[1] != 1 {
                // 7 = Befehl nicht unterstützt
                let _ = stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                return None;
            }
            let host = match head[3] {
                1 => {
                    let mut ip = [0u8; 4];
                    stream.read_exact(&mut ip).await.ok()?;
                    std::net::Ipv4Addr::from(ip).to_string()
                }
                3 => {
                    let length = stream.read_u8().await.ok()?;
                    let mut name = vec![0u8; usize::from(length)];
                    stream.read_exact(&mut name).await.ok()?;
                    String::from_utf8(name).ok().filter(|name| !name.is_empty())?
                }
                4 => {
                    let mut ip = [0u8; 16];
                    stream.read_exact(&mut ip).await.ok()?;
                    std::net::Ipv6Addr::from(ip).to_string()
                }
                _ => {
                    // 8 = Adressart nicht unterstützt
                    let _ = stream.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                    return None;
                }
            };
            let port = stream.read_u16().await.ok()?;
            Some(Request { version, host, port })
        }
        4 => {
            let command = stream.read_u8().await.ok()?;
            let port = stream.read_u16().await.ok()?;
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await.ok()?;
            read_until_zero(stream).await?;
            // 4a: Eine Adresse der Form 0.0.0.x heißt, dass der Name als Text folgt.
            let host = if ip[..3] == [0, 0, 0] && ip[3] != 0 { String::from_utf8(read_until_zero(stream).await?).ok().filter(|name| !name.is_empty())? } else { std::net::Ipv4Addr::from(ip).to_string() };
            if command != 1 {
                let _ = stream.write_all(&[0, 0x5B, 0, 0, 0, 0, 0, 0]).await;
                return None;
            }
            Some(Request { version, host, port })
        }
        _ => None,
    }
}

/// Liest bis zum Nullbyte; es selbst gehört nicht zum Ergebnis. Länger als ein Name sein kann, wird es nicht.
async fn read_until_zero<S: AsyncRead + Unpin>(stream: &mut S) -> Option<Vec<u8>> {
    let mut text = Vec::new();
    loop {
        match stream.read_u8().await.ok()? {
            0 => return Some(text),
            _ if text.len() >= 255 => return None,
            byte => text.push(byte),
        }
    }
}

/// Antwort auf eine SOCKS-Bitte: Die Verbindung zum Ziel steht oder kam nicht zustande.
async fn answer<S: AsyncWrite + Unpin>(stream: &mut S, version: u8, connected: bool) -> std::io::Result<()> {
    match (version, connected) {
        (5, true) => stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await,
        // 5 = Verbindung abgelehnt
        (5, false) => stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await,
        (_, true) => stream.write_all(&[0, 0x5A, 0, 0, 0, 0, 0, 0]).await,
        (_, false) => stream.write_all(&[0, 0x5B, 0, 0, 0, 0, 0, 0]).await,
    }
}

/// Bedient eine Verbindung an einem dynamischen Port: Ziel erfragen, über den Server öffnen, durchreichen.
async fn socks(mut stream: TcpStream, link: &Link, origin: (String, u32), counters: &Counters) {
    let Ok(Some(request)) = timeout(HANDSHAKE_TIMEOUT, handshake(&mut stream)).await else { return };
    let opened = timeout(DIAL_TIMEOUT, link.handle.channel_open_direct_tcpip(request.host, u32::from(request.port), origin.0, origin.1)).await;
    match opened {
        Ok(Ok(channel)) => {
            if answer(&mut stream, request.version, true).await.is_ok() {
                pipe(stream, channel.into_stream(), counters).await;
            }
        }
        _ => drop(answer(&mut stream, request.version, false).await),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Schickt Bytes an `handshake` und liefert, was er daraus liest und was er antwortet.
    async fn greet(bytes: &[u8]) -> (Option<Request>, Vec<u8>) {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(bytes).await.unwrap();
        // Mehr kommt nicht: Eine abgeschnittene Anfrage soll enden statt zu warten.
        client.shutdown().await.unwrap();
        let request = handshake(&mut server).await;
        drop(server);
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        (request, reply)
    }

    #[tokio::test]
    async fn socks5_names_addresses_and_refusals() {
        let (request, reply) = greet(&[5, 1, 0, 5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'o', b'r', b'g', 0x01, 0xBB]).await;
        assert_eq!(request, Some(Request { version: 5, host: "example.org".into(), port: 443 }));
        assert_eq!(reply, [5, 0], "„ohne Anmeldung“ wird angenommen; die Antwort auf die Bitte kommt erst nach dem Verbinden");

        let (request, _) = greet(&[5, 2, 2, 0, 5, 1, 0, 1, 10, 0, 0, 7, 0x1F, 0x90]).await;
        assert_eq!(request, Some(Request { version: 5, host: "10.0.0.7".into(), port: 8080 }));

        let mut v6 = vec![5, 1, 0, 5, 1, 0, 4];
        v6.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&[0, 22]);
        assert_eq!(greet(&v6).await.0, Some(Request { version: 5, host: "::1".into(), port: 22 }));

        // Nur Anmeldung mit Passwort angeboten: abgelehnt.
        assert_eq!(greet(&[5, 1, 2]).await, (None, vec![5, 0xFF]));
        // BIND statt CONNECT: „Befehl nicht unterstützt“.
        assert_eq!(greet(&[5, 1, 0, 5, 2, 0, 1, 1, 2, 3, 4, 0, 80]).await, (None, vec![5, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0]));
        // Unbekannte Adressart.
        assert_eq!(greet(&[5, 1, 0, 5, 1, 0, 9]).await.1[2..4], [5, 8]);
        // Abgeschnitten oder kein SOCKS.
        assert_eq!(greet(&[5, 1, 0, 5, 1, 0, 3, 5, b'a']).await.0, None);
        assert_eq!(greet(b"GET / HTTP/1.1\r\n").await, (None, vec![]));
    }

    #[tokio::test]
    async fn socks4_and_4a() {
        let (request, reply) = greet(&[4, 1, 0, 80, 192, 168, 1, 20, b'i', b'c', b'h', 0]).await;
        assert_eq!((request, reply), (Some(Request { version: 4, host: "192.168.1.20".into(), port: 80 }), vec![]));

        let mut named = vec![4, 1, 0x01, 0xBB, 0, 0, 0, 1, 0];
        named.extend_from_slice(b"intern.example\0");
        assert_eq!(greet(&named).await.0, Some(Request { version: 4, host: "intern.example".into(), port: 443 }));

        assert_eq!(greet(&[4, 2, 0, 80, 1, 2, 3, 4, 0]).await, (None, vec![0, 0x5B, 0, 0, 0, 0, 0, 0]));
    }

    #[tokio::test]
    async fn answers_match_the_version() {
        let reply = |version: u8, connected: bool| async move {
            let mut out = Vec::new();
            answer(&mut out, version, connected).await.unwrap();
            out
        };
        assert_eq!(reply(5, true).await[..2], [5, 0]);
        assert_eq!(reply(5, false).await[..2], [5, 5]);
        assert_eq!(reply(4, true).await[..2], [0, 0x5A]);
        assert_eq!(reply(4, false).await[..2], [0, 0x5B]);
    }

    #[tokio::test]
    async fn pipes_count_both_directions() {
        let counters = Counters::default();
        let (mut app, near) = tokio::io::duplex(64);
        let (far, mut target) = tokio::io::duplex(64);
        let work = pipe(near, far, &counters);
        let talk = async {
            app.write_all(b"hallo ziel").await.unwrap();
            let mut got = [0u8; 10];
            target.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"hallo ziel");
            target.write_all(b"antwort").await.unwrap();
            let mut back = [0u8; 7];
            app.read_exact(&mut back).await.unwrap();
            assert_eq!(&back, b"antwort");
            // Beide Seiten schließen: Erst dann ist die Verbindung zu Ende.
            app.shutdown().await.unwrap();
            target.shutdown().await.unwrap();
        };
        tokio::join!(work, talk);
        assert_eq!((counters.sent.load(Ordering::Relaxed), counters.received.load(Ordering::Relaxed)), (10, 7));
    }
}
