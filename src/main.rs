//! `neutrino-relay`: a blind pairing relay.
//!
//! Peers connect over WebSocket (TLS is terminated by the reverse proxy) and send a
//! 20-byte registration envelope `[16-byte ticket | u32 len = 0]`. The first two
//! connections presenting the same ticket are paired: both receive a pairing notice
//! (the same empty envelope) and every subsequent binary message is forwarded
//! verbatim to the other side. The relay never sees keys or plaintext: tickets are
//! keyed hashes derived by clients and payloads are XChaCha20-Poly1305 ciphertext.
//! Per-client connection and request limits are enforced by the reverse proxy.

mod udp;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

type Ws = WebSocketStream<TcpStream>;
/// A live peer plus the connection-slot guard that travels with its socket.
type Peer = (Ws, ConnGuard);
type Waiting = Arc<Mutex<HashMap<[u8; 16], (u64, oneshot::Sender<Peer>)>>>;

const MAX_CONNECTIONS: usize = 4096;
const MAX_PENDING: usize = 2048;
const MAX_MESSAGE: usize = 4 * 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REGISTER_TIMEOUT: Duration = Duration::from_secs(10);
const PAIR_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const PING_INTERVAL: Duration = Duration::from_secs(25);
/// No traffic (including pong replies to our pings) for this long means a dead peer.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Holds one connection slot until dropped, wherever the socket ends up.
struct ConnGuard(Arc<AtomicUsize>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let udp_bind =
        std::env::var("NEUTRINO_RELAY_UDP_BIND").unwrap_or_else(|_| "0.0.0.0:3479".into());
    let config = udp::Config::from_env()?;
    let socket = tokio::net::UdpSocket::bind(&udp_bind).await?;
    eprintln!("neutrino-relay UDP listening on {}", socket.local_addr()?);
    tokio::select! {
        result = udp::run(socket, config) => result,
        result = websocket() => result,
    }
}

async fn websocket() -> std::io::Result<()> {
    let bind = std::env::var("NEUTRINO_RELAY_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let listener = TcpListener::bind(&bind).await?;
    eprintln!("neutrino-relay listening on {bind}");
    let waiting: Waiting = Arc::new(Mutex::new(HashMap::new()));
    let active = Arc::new(AtomicUsize::new(0));
    let generation = Arc::new(AtomicU64::new(0));
    loop {
        let (tcp, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };
        if active.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::Relaxed);
            drop(tcp);
            continue;
        }
        let guard = ConnGuard(active.clone());
        let waiting = waiting.clone();
        let gen = generation.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            if let Err(e) = handle(tcp, guard, gen, waiting).await {
                eprintln!("relay: {e}");
            }
        });
    }
}

async fn handle(
    tcp: TcpStream,
    guard: ConnGuard,
    gen: u64,
    waiting: Waiting,
) -> Result<(), String> {
    let _ = tcp.set_nodelay(true);
    let mut cfg = WebSocketConfig::default();
    cfg.max_message_size = Some(MAX_MESSAGE);
    cfg.max_frame_size = Some(MAX_MESSAGE);
    let mut ws = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        tokio_tungstenite::accept_async_with_config(tcp, Some(cfg)),
    )
    .await
    .map_err(|_| "handshake timeout".to_string())?
    .map_err(|e| format!("handshake: {e}"))?;

    let first = tokio::time::timeout(REGISTER_TIMEOUT, ws.next())
        .await
        .map_err(|_| "registration timeout".to_string())?
        .ok_or("closed before registration")?
        .map_err(|e| e.to_string())?;
    let Message::Binary(reg) = first else {
        return Err("expected binary registration".into());
    };
    if reg.len() != 20 || reg[16..20] != [0, 0, 0, 0] {
        return Err("malformed registration".into());
    }
    let mut ticket = [0u8; 16];
    ticket.copy_from_slice(&reg[..16]);

    let mut peer: Peer = (ws, guard);
    // Hand ourselves to a waiting peer; if that waiter is already gone, try again
    // (a newer one may have registered) and otherwise become the waiter.
    loop {
        let partner = {
            let mut map = waiting.lock().map_err(|_| "lock poisoned")?;
            map.remove(&ticket)
        };
        match partner {
            Some((_, tx)) => match tx.send(peer) {
                Ok(()) => return Ok(()),
                Err(back) => peer = back,
            },
            None => return wait_for_partner(peer, ticket, gen, waiting).await,
        }
    }
}

async fn wait_for_partner(
    peer: Peer,
    ticket: [u8; 16],
    gen: u64,
    waiting: Waiting,
) -> Result<(), String> {
    let (tx, mut rx) = oneshot::channel();
    {
        let mut map = waiting.lock().map_err(|_| "lock poisoned")?;
        // A newer registration replaces a stale one (e.g. a sender reconnecting);
        // dropping the old sender wakes and retires the old waiter.
        if !map.contains_key(&ticket) && map.len() >= MAX_PENDING {
            return Err("pending registration limit reached".into());
        }
        map.insert(ticket, (gen, tx));
    }
    let (mut ws, guard) = peer;
    let deadline = tokio::time::sleep(PAIR_TIMEOUT);
    tokio::pin!(deadline);
    let mut ping = tokio::time::interval(PING_INTERVAL);
    let outcome = loop {
        tokio::select! {
            other = &mut rx => break other.ok(),
            () = &mut deadline => break None,
            _ = ping.tick() => {
                if ws.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break None;
                }
            }
            msg = ws.next() => match msg {
                Some(Ok(Message::Close(_)) | Err(_)) | None => break None,
                Some(Ok(_)) => {}
            },
        }
    };
    if let Ok(mut map) = waiting.lock() {
        if map.get(&ticket).is_some_and(|(g, _)| *g == gen) {
            map.remove(&ticket);
        }
    }
    match outcome {
        Some((other, other_guard)) => {
            pipe(ws, other, ticket).await;
            drop((guard, other_guard));
            Ok(())
        }
        None => Err("pairing ended without a partner".into()),
    }
}

async fn pipe(a: Ws, b: Ws, ticket: [u8; 16]) {
    let (a_tx, mut a_rx) = a.split();
    let (b_tx, mut b_rx) = b.split();
    let a_tx = tokio::sync::Mutex::new(a_tx);
    let b_tx = tokio::sync::Mutex::new(b_tx);
    // Pairing notice: an empty envelope carrying the ticket.
    let mut notice = ticket.to_vec();
    notice.extend_from_slice(&[0, 0, 0, 0]);
    if a_tx
        .lock()
        .await
        .send(Message::Binary(notice.clone().into()))
        .await
        .is_err()
        || b_tx
            .lock()
            .await
            .send(Message::Binary(notice.into()))
            .await
            .is_err()
    {
        return;
    }
    let ab = async {
        while let Ok(Some(Ok(m))) = tokio::time::timeout(IDLE_TIMEOUT, a_rx.next()).await {
            if matches!(m, Message::Binary(_)) && b_tx.lock().await.send(m).await.is_err() {
                break;
            }
        }
    };
    let ba = async {
        while let Ok(Some(Ok(m))) = tokio::time::timeout(IDLE_TIMEOUT, b_rx.next()).await {
            if matches!(m, Message::Binary(_)) && a_tx.lock().await.send(m).await.is_err() {
                break;
            }
        }
    };
    // Keepalive: peers answer pings, so long quiet phases (receiver verifying a
    // multi-GB file) never trip the idle timeout while the peers are alive.
    let keepalive = async {
        let mut tick = tokio::time::interval(PING_INTERVAL);
        tick.tick().await;
        loop {
            tick.tick().await;
            let _ = a_tx
                .lock()
                .await
                .send(Message::Ping(Vec::new().into()))
                .await;
            let _ = b_tx
                .lock()
                .await
                .send(Message::Ping(Vec::new().into()))
                .await;
        }
    };
    tokio::pin!(ab, ba);
    let drain = async {
        tokio::select! {
            () = &mut ab => { let _ = tokio::time::timeout(IDLE_TIMEOUT, &mut ba).await; }
            () = &mut ba => { let _ = tokio::time::timeout(IDLE_TIMEOUT, &mut ab).await; }
        }
    };
    tokio::select! { () = drain => {}, () = keepalive => {} }
    let _ = a_tx.lock().await.close().await;
    let _ = b_tx.lock().await.close().await;
}
