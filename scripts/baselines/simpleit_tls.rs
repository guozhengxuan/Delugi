//! Evaluation adapter for the authenticated point-to-point channel assumption.
//! Native messages and certificates remain unchanged. Forwarded objects are not
//! re-labelled as originating from the forwarding connection.
use once_cell::sync::Lazy;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::{collections::BTreeMap, fs, io, net::SocketAddr, path::Path, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{rustls, TlsAcceptor, TlsConnector};

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type Stream = Box<dyn Io>;
tokio::task_local! { pub static PEER: Option<Vec<u8>>; }

use std::{
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};
static WINDOW_START: AtomicU64 = AtomicU64::new(0);
static WINDOW_END: AtomicU64 = AtomicU64::new(0);
static WRITTEN: AtomicU64 = AtomicU64::new(0);
static READ: AtomicU64 = AtomicU64::new(0);
static WINDOW_WRITTEN: AtomicU64 = AtomicU64::new(0);
static WINDOW_READ: AtomicU64 = AtomicU64::new(0);
fn clock_us() -> u64 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) },
        0
    );
    t.tv_sec as u64 * 1_000_000 + t.tv_nsec as u64 / 1000
}
pub fn arm_traffic(start: u64, end: u64) {
    assert!(start < end);
    assert_eq!(WINDOW_END.load(Ordering::Acquire), 0);
    WINDOW_START.store(start, Ordering::Release);
    WINDOW_END.store(end, Ordering::Release);
}
fn measure(write: bool, bytes: usize) {
    let (total, window) = if write {
        (&WRITTEN, &WINDOW_WRITTEN)
    } else {
        (&READ, &WINDOW_READ)
    };
    total.fetch_add(bytes as u64, Ordering::Relaxed);
    let at = clock_us();
    if WINDOW_START.load(Ordering::Acquire) <= at && at < WINDOW_END.load(Ordering::Acquire) {
        window.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}
pub fn traffic() -> serde_json::Value {
    let start = clock_us();
    let value = serde_json::json!({"written_bytes":WRITTEN.load(Ordering::Relaxed),"read_bytes":READ.load(Ordering::Relaxed),
        "window_written_bytes":WINDOW_WRITTEN.load(Ordering::Relaxed),"window_read_bytes":WINDOW_READ.load(Ordering::Relaxed)});
    serde_json::json!({"window_start_us":WINDOW_START.load(Ordering::Acquire),"window_end_us":WINDOW_END.load(Ordering::Acquire),
        "sample_start_us":start,"sample_end_us":clock_us(),"counters":value,
        "boundary":"successful underlying TCP bytes including TLS, native framing, ACKs and repair; per-operation measurement-window filtering"})
}
struct MeteredSocket(TcpStream);
impl AsyncRead for MeteredSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.0).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            measure(false, buf.filled().len() - before);
        }
        result
    }
}
impl AsyncWrite for MeteredSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.0).poll_write(cx, bytes);
        if let Poll::Ready(Ok(n)) = &result {
            measure(true, *n);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: u32,
    ca_pem: String,
    certificate_pem: String,
    private_key_pem: String,
    // DER leaf certificate SHA256 -> native public-key bytes in hex.
    members: BTreeMap<String, String>,
    // Exact protocol listen address -> DER leaf certificate SHA256.
    destinations: BTreeMap<String, String>,
}
struct Tls {
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
    members: BTreeMap<String, Vec<u8>>,
    destinations: BTreeMap<String, String>,
}
fn invalid(message: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}
fn certs(path: &str) -> io::Result<Vec<rustls::Certificate>> {
    let mut input = io::BufReader::new(fs::File::open(path)?);
    Ok(rustls_pemfile::certs(&mut input)?
        .into_iter()
        .map(rustls::Certificate)
        .collect())
}
fn key(path: &str) -> io::Result<rustls::PrivateKey> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            return Err(invalid("TLS private key must be mode0600"));
        }
    }
    let mut input = io::BufReader::new(fs::File::open(path)?);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut input)?;
    if keys.len() != 1 {
        return Err(invalid("exactly one PKCS8 key required"));
    }
    Ok(rustls::PrivateKey(keys.remove(0)))
}
fn load(path: &Path) -> io::Result<Tls> {
    let raw = fs::read(path)?;
    if raw.len() > 1024 * 1024 {
        return Err(invalid("TLS configuration exceeds1MiB"));
    }
    let cfg: Configuration = serde_json::from_slice(&raw).map_err(invalid)?;
    if cfg.schema != 1 || !(4..=50).contains(&cfg.members.len()) || cfg.destinations.is_empty() {
        return Err(invalid("invalid authenticated committee"));
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certs(&cfg.ca_pem)? {
        roots.add(&certificate).map_err(invalid)?;
    }
    let chain = certs(&cfg.certificate_pem)?;
    let secret = key(&cfg.private_key_pem)?;
    if chain.is_empty()
        || !cfg
            .members
            .contains_key(&hex::encode(Sha256::digest(&chain[0].0)))
    {
        return Err(invalid("own certificate is outside the current committee"));
    }
    let members: BTreeMap<_, _> = cfg
        .members
        .into_iter()
        .map(|(hash, value)| {
            let hash_bytes = hex::decode(&hash).map_err(invalid)?;
            let bytes = hex::decode(value).map_err(invalid)?;
            if hash_bytes.len() != 32 || bytes.len() != 32 {
                return Err(invalid("invalid certificate/public key identity"));
            }
            Ok((hash, bytes))
        })
        .collect::<io::Result<_>>()?;
    let unique: std::collections::BTreeSet<_> = members.values().collect();
    if unique.len() != members.len() {
        return Err(invalid("duplicate native public key"));
    }
    for (address, hash) in &cfg.destinations {
        let _: SocketAddr = address.parse().map_err(invalid)?;
        if !members.contains_key(hash) {
            return Err(invalid("unknown destination identity"));
        }
    }
    let client = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots.clone())
        .with_client_auth_cert(chain.clone(), secret.clone())
        .map_err(invalid)?;
    let verifier = rustls::server::AllowAnyAuthenticatedClient::new(roots);
    let server = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(chain, secret)
        .map_err(invalid)?;
    Ok(Tls {
        client: Arc::new(client),
        server: Arc::new(server),
        members,
        destinations: cfg.destinations,
    })
}
static TLS: Lazy<Option<Tls>> = Lazy::new(|| {
    std::env::var_os("DELUGI_SIMPLEIT_TLS")
        .map(|p| load(Path::new(&p)).expect("invalid explicit TLS profile"))
});

pub fn enabled() -> bool {
    TLS.is_some()
}
fn identity(
    tls: &Tls,
    certificates: Option<&[rustls::Certificate]>,
) -> io::Result<(String, Vec<u8>)> {
    let leaf = certificates
        .and_then(|c| c.first())
        .ok_or_else(|| invalid("no peer certificate"))?;
    let hash = hex::encode(Sha256::digest(&leaf.0));
    let peer = tls
        .members
        .get(&hash)
        .ok_or_else(|| invalid("certificate is not in current committee"))?;
    Ok((hash, peer.clone()))
}
pub async fn connect(address: SocketAddr) -> io::Result<Stream> {
    let socket = TcpStream::connect(address).await?;
    socket.set_nodelay(true)?;
    let socket = MeteredSocket(socket);
    if let Some(tls) = &*TLS {
        let expected = tls
            .destinations
            .get(&address.to_string())
            .ok_or_else(|| invalid("unconfigured destination"))?;
        let server_name = rustls::ServerName::try_from("delugi-eval").map_err(invalid)?;
        let channel = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TlsConnector::from(tls.client.clone()).connect(server_name, socket),
        )
        .await??;
        let (hash, _) = identity(tls, channel.get_ref().1.peer_certificates())?;
        if &hash != expected {
            return Err(invalid(
                "destination certificate does not match addressed replica",
            ));
        }
        Ok(Box::new(channel))
    } else {
        Ok(Box::new(socket))
    }
}
pub async fn accept(socket: TcpStream) -> io::Result<(Stream, Option<Vec<u8>>)> {
    socket.set_nodelay(true)?;
    let socket = MeteredSocket(socket);
    if let Some(tls) = &*TLS {
        let channel = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TlsAcceptor::from(tls.server.clone()).accept(socket),
        )
        .await??;
        let (_, peer) = identity(tls, channel.get_ref().1.peer_certificates())?;
        Ok((Box::new(channel), Some(peer)))
    } else {
        Ok((Box::new(socket), None))
    }
}
pub fn require_peer(author: &[u8]) -> io::Result<()> {
    if !enabled() {
        return Ok(());
    }
    if PEER
        .try_with(|p| p.as_deref() == Some(author))
        .unwrap_or(false)
    {
        Ok(())
    } else {
        Err(invalid(
            "direct message author differs from authenticated channel peer",
        ))
    }
}
