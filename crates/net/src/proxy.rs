//! Connections through a proxy: HTTP (`CONNECT`) and SOCKS5, optionally with authentication at the proxy.
//!
//! The destination's name goes to the proxy unresolved; it looks it up. That way names only known
//! behind the proxy work too.

use std::{
    fmt,
    io::{Error, ErrorKind, Result},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::Secret;

/// User and password for the proxy.
#[derive(Clone, PartialEq, Eq)]
pub struct Login {
    pub user: String,
    pub password: Secret,
}

impl fmt::Debug for Login {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Login({}, …)", self.user)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proxy {
    Http { host: String, port: u16, login: Option<Login> },
    Socks5 { host: String, port: u16, login: Option<Login> },
}

/// No proxy sends more than this in reply to `CONNECT`; anything beyond it is not a proxy.
const MAX_HTTP_REPLY: usize = 8 * 1024;

fn refused(text: impl Into<String>) -> Error {
    Error::new(ErrorKind::ConnectionRefused, text.into())
}

/// Base64 per RFC 4648 for the `Proxy-Authorization` header.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let bits = u32::from(chunk[0]) << 16 | u32::from(*chunk.get(1).unwrap_or(&0)) << 8 | u32::from(*chunk.get(2).unwrap_or(&0));
        for (index, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            out.push(if index <= chunk.len() { char::from(ALPHABET[(bits >> shift & 63) as usize]) } else { '=' });
        }
    }
    out
}

/// Opens a connection to `host:port` through the proxy. After that the stream behaves like a direct connection.
pub(crate) async fn connect(proxy: &Proxy, host: &str, port: u16) -> Result<TcpStream> {
    match proxy {
        Proxy::Http { host: proxy_host, port: proxy_port, login } => {
            let mut stream = TcpStream::connect((proxy_host.as_str(), *proxy_port)).await?;
            // IPv6 addresses are in square brackets in an address with a port.
            let target = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
            let login = login.as_ref().map(|l| format!("Proxy-Authorization: Basic {}\r\n", base64(format!("{}:{}", l.user, l.password.as_str()).as_bytes()))).unwrap_or_default();
            stream.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{login}\r\n").as_bytes()).await?;
            // Byte by byte up to the empty line: whatever comes after it already belongs to the SSH server.
            let mut reply = Vec::new();
            while !reply.ends_with(b"\r\n\r\n") {
                if reply.len() >= MAX_HTTP_REPLY {
                    return Err(refused("the proxy sent no valid reply"));
                }
                reply.push(stream.read_u8().await?);
            }
            let status = String::from_utf8_lossy(&reply).lines().next().unwrap_or_default().to_string();
            if status.split_whitespace().nth(1) != Some("200") {
                return Err(refused(format!("the proxy refused: {status}")));
            }
            Ok(stream)
        }
        Proxy::Socks5 { host: proxy_host, port: proxy_port, login } => {
            let name = u8::try_from(host.len()).map_err(|_| Error::new(ErrorKind::InvalidInput, "host name too long for SOCKS5"))?;
            let mut stream = TcpStream::connect((proxy_host.as_str(), *proxy_port)).await?;
            // Version 5 and the methods offered: no authentication (0), user and password (2).
            stream.write_all(if login.is_some() { &[5, 2, 0, 2] } else { &[5, 1, 0] }).await?;
            let mut chosen = [0u8; 2];
            stream.read_exact(&mut chosen).await?;
            match (chosen, login) {
                ([5, 0], _) => {}
                ([5, 2], Some(login)) => {
                    // RFC 1929: version 1, then user and password, each preceded by a length byte.
                    let too_long = || Error::new(ErrorKind::InvalidInput, "user or password too long for SOCKS5");
                    let mut request = vec![1, u8::try_from(login.user.len()).map_err(|_| too_long())?];
                    request.extend_from_slice(login.user.as_bytes());
                    request.push(u8::try_from(login.password.len()).map_err(|_| too_long())?);
                    request.extend_from_slice(login.password.as_bytes());
                    stream.write_all(&request).await?;
                    let mut verdict = [0u8; 2];
                    stream.read_exact(&mut verdict).await?;
                    if verdict[1] != 0 {
                        return Err(refused("the proxy rejected user or password"));
                    }
                }
                _ => return Err(refused("the proxy wants a login")),
            }
            // Connect (1) with a name (3) the proxy resolves itself.
            let mut request = vec![5, 1, 0, 3, name];
            request.extend_from_slice(host.as_bytes());
            request.extend_from_slice(&port.to_be_bytes());
            stream.write_all(&request).await?;
            let mut head = [0u8; 4];
            stream.read_exact(&mut head).await?;
            if head[1] != 0 {
                return Err(refused(format!("the proxy could not connect (SOCKS5 code {})", head[1])));
            }
            // The answer also names the address the proxy connected from; its length depends on the type.
            let rest = match head[3] {
                1 => 4 + 2,
                4 => 16 + 2,
                3 => usize::from(stream.read_u8().await?) + 2,
                _ => return Err(refused("the proxy sent no valid reply")),
            };
            stream.read_exact(&mut vec![0u8; rest]).await?;
            Ok(stream)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::base64;

    #[test]
    fn base64_matches_the_rfc_examples() {
        for (plain, encoded) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy"), ("tester:geheim", "dGVzdGVyOmdlaGVpbQ==")] {
            assert_eq!(base64(plain.as_bytes()), encoded);
        }
    }
}
