//! Blind UDP pairing relay, protocol v2.
//!
//! A stateless return-path cookie must be echoed before any allocation, pairing,
//! retry or rebind happens, so a spoofed source can never allocate state or receive
//! forwarded payloads. Rebinding a role to a new address additionally requires the
//! preimage of the commitment registered earlier, and rotates that commitment so a
//! captured rebind cannot be replayed. Admission uses incremental global and per-group
//! counters (no table scans); expiry is a bounded sweep on a one-second timer.
//! The byte-level contract is specified in the crate README.
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::net::UdpSocket;
use zeroize::Zeroizing;

/// Allocations expire after this long without accepted registration or forwarding.
const IDLE: Duration = Duration::from_secs(60);
/// Allocations expire this long after creation, however busy.
const LIFETIME: Duration = Duration::from_secs(6 * 60 * 60);
/// Hard cap on allocations (pending and paired), checked before every other quota.
const MAX_ALLOCATIONS: usize = 4096;
/// Hard cap on tracked rate-limit groups.
const MAX_GROUPS: usize = 16384;
/// Cookie time-bucket width; the current and previous bucket are accepted.
const BUCKET_SECS: u64 = 30;
/// Cookie key rotation period; the previous key is still accepted.
const ROTATE: Duration = Duration::from_secs(300);

const MAGIC: &[u8; 4] = b"NRU2";
const CHALLENGE_MAGIC: &[u8; 4] = b"NRC2";
const NOTICE_MAGIC: &[u8; 4] = b"NRA2";
/// `NRU2 | ticket(16) | role(1)`.
const HEADER: usize = 21;
const COOKIE: usize = 16;
const HASH: usize = 32;
const SECRET: usize = 16;
/// Hello: header plus the commitment `H = SHA-256(s)`.
const HELLO: usize = HEADER + HASH;
/// Registration: Hello plus the cookie it earned.
const REGISTER: usize = HELLO + COOKIE;
/// Rebind: registration (whose Hello carries the new commitment) plus the previous secret.
const REBIND: usize = REGISTER + SECRET;
const CHALLENGE: usize = 4 + COOKIE;
const NOTICE: usize = HEADER;

type Ticket = [u8; 16];
type Commitment = [u8; HASH];
type Key = Zeroizing<[u8; 32]>;

/// Runtime limits, read from the environment.
pub(crate) struct Config {
    pending: usize,
    ip_pending: usize,
    ip_total: usize,
    control: u64,
    packets: u64,
    bytes: u64,
    total: u64,
}

impl Config {
    /// Reads every limit, failing startup on an invalid value.
    pub(crate) fn from_env() -> io::Result<Self> {
        Ok(Self {
            pending: setting("NEUTRINO_RELAY_UDP_MAX_PENDING", 2048)?,
            ip_pending: setting("NEUTRINO_RELAY_UDP_IP_MAX_PENDING", 8)?,
            ip_total: setting("NEUTRINO_RELAY_UDP_IP_MAX_TOTAL", 16)?,
            control: setting("NEUTRINO_RELAY_UDP_IP_CONTROL_PPS", 64)?,
            packets: setting("NEUTRINO_RELAY_UDP_IP_PPS", 20000)?,
            bytes: setting("NEUTRINO_RELAY_UDP_IP_BPS", 32 * 1024 * 1024)?,
            total: setting("NEUTRINO_RELAY_UDP_TOTAL_BPS", 128 * 1024 * 1024)?,
        })
    }
}

fn setting<T: std::str::FromStr>(name: &str, default: T) -> io::Result<T> {
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, name)),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidInput, e)),
    }
}

/// A one-second packet and byte window.
struct Budget {
    start: Instant,
    packets: u64,
    bytes: u64,
}

impl Budget {
    fn new(now: Instant) -> Self {
        Self {
            start: now,
            packets: 0,
            bytes: 0,
        }
    }

    fn admit(&mut self, now: Instant, len: usize, packets: u64, bytes: u64) -> bool {
        if now.duration_since(self.start) >= Duration::from_secs(1) {
            *self = Self::new(now);
        }
        let len = u64::try_from(len).unwrap_or(u64::MAX);
        if self.packets >= packets || len > bytes.saturating_sub(self.bytes) {
            return false;
        }
        self.packets += 1;
        self.bytes += len;
        true
    }
}

/// Per-group ingress windows: all traffic, and the stricter control-plane window.
struct Rate {
    all: Budget,
    control: Budget,
}

/// Quota group: an IPv4 address, or an IPv6 /64 (IPv4-mapped IPv6 normalized to IPv4).
fn group(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let mut bytes = ip.octets();
            bytes[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        v4 @ IpAddr::V4(_) => v4,
    }
}

fn random_key() -> io::Result<Key> {
    let mut key = Zeroizing::new([0; 32]);
    getrandom::getrandom(&mut key[..]).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(key)
}

fn equal(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

/// Stateless return-path cookies under a per-process random key, rotated on a timer.
struct Cookies {
    current: Key,
    previous: Key,
    epoch: Instant,
    rotated: Instant,
}

impl Cookies {
    fn new(now: Instant) -> io::Result<Self> {
        Ok(Self {
            current: random_key()?,
            previous: random_key()?,
            epoch: now,
            rotated: now,
        })
    }

    /// Rotates when due. On RNG failure the current key stays in service.
    fn rotate(&mut self, now: Instant) -> io::Result<()> {
        if now.duration_since(self.rotated) >= ROTATE {
            self.previous = std::mem::replace(&mut self.current, random_key()?);
            self.rotated = now;
        }
        Ok(())
    }

    fn bucket(&self, now: Instant) -> u64 {
        now.duration_since(self.epoch).as_secs() / BUCKET_SECS
    }

    /// `HMAC-SHA256(key, label | family | ip | port | ticket | role | H | bucket)[..16]`.
    fn tag(key: &Key, source: SocketAddr, hello: &[u8], bucket: u64) -> Option<[u8; COOKIE]> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&key[..]).ok()?;
        mac.update(b"neutrino-relay/udp-v2/cookie");
        match source.ip() {
            IpAddr::V4(ip) => {
                mac.update(&[4]);
                mac.update(&ip.octets());
            }
            IpAddr::V6(ip) => {
                mac.update(&[6]);
                mac.update(&ip.octets());
            }
        }
        mac.update(&source.port().to_be_bytes());
        mac.update(&hello[4..HELLO]);
        mac.update(&bucket.to_be_bytes());
        let mut tag = [0; COOKIE];
        tag.copy_from_slice(&mac.finalize().into_bytes()[..COOKIE]);
        Some(tag)
    }

    fn mint(&self, source: SocketAddr, hello: &[u8], now: Instant) -> Option<[u8; COOKIE]> {
        Self::tag(&self.current, source, hello, self.bucket(now))
    }

    fn valid(&self, source: SocketAddr, hello: &[u8], cookie: &[u8], now: Instant) -> bool {
        let bucket = self.bucket(now);
        let mut ok = false;
        for key in [&self.current, &self.previous] {
            for b in [bucket, bucket.wrapping_sub(1)] {
                if let Some(tag) = Self::tag(key, source, hello, b) {
                    ok |= equal(&tag, cookie);
                }
            }
        }
        ok
    }
}

#[derive(Clone, Copy)]
struct Peer {
    address: SocketAddr,
    commitment: Commitment,
}

struct Allocation {
    peers: [Option<Peer>; 2],
    born: Instant,
    last: Instant,
}

impl Allocation {
    fn alive(&self, now: Instant) -> bool {
        now.duration_since(self.last) < IDLE && now.duration_since(self.born) < LIFETIME
    }

    fn pending(&self) -> bool {
        self.peers.iter().any(Option::is_none)
    }
}

/// Registered roles per group. `pending` counts roles in allocations awaiting a partner.
#[derive(Default)]
struct Counts {
    total: usize,
    pending: usize,
}

fn credit(counts: &mut HashMap<IpAddr, Counts>, ip: IpAddr, pending: bool) {
    let c = counts.entry(group(ip)).or_default();
    c.total += 1;
    c.pending += usize::from(pending);
}

fn debit(counts: &mut HashMap<IpAddr, Counts>, ip: IpAddr, pending: bool) {
    let key = group(ip);
    if let Some(c) = counts.get_mut(&key) {
        c.total = c.total.saturating_sub(1);
        c.pending = c.pending.saturating_sub(usize::from(pending));
        if c.total == 0 {
            counts.remove(&key);
        }
    }
}

/// A parsed `NRU2` registration (69 or 85 bytes).
struct Registration<'a> {
    hello: &'a [u8],
    ticket: Ticket,
    role: usize,
    cookie: &'a [u8],
    commitment: Commitment,
    secret: Option<&'a [u8]>,
}

impl<'a> Registration<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        if !matches!(data.len(), REGISTER | REBIND) || data[20] > 1 {
            return None;
        }
        let mut ticket = [0; 16];
        ticket.copy_from_slice(&data[4..20]);
        let mut commitment = [0; HASH];
        commitment.copy_from_slice(&data[HEADER..HELLO]);
        Some(Self {
            hello: &data[..HELLO],
            ticket,
            role: usize::from(data[20]),
            cookie: &data[HELLO..REGISTER],
            commitment,
            secret: (data.len() == REBIND).then(|| &data[REGISTER..]),
        })
    }

    /// True when this message proves knowledge of the preimage of `commitment`.
    fn opens(&self, commitment: &Commitment) -> bool {
        self.secret
            .is_some_and(|s| equal(&Sha256::digest(s), commitment))
    }
}

struct State {
    config: Config,
    cookies: Cookies,
    tickets: HashMap<Ticket, Allocation>,
    sources: HashMap<SocketAddr, (Ticket, usize)>,
    counts: HashMap<IpAddr, Counts>,
    pending: usize,
    rates: HashMap<IpAddr, Rate>,
    egress: Budget,
}

/// At most two small replies or one borrowed payload; no per-packet payload allocation.
enum Action {
    Drop,
    Forward(SocketAddr),
    Challenge([u8; CHALLENGE]),
    Notices([(SocketAddr, [u8; NOTICE]); 2], usize),
}

impl State {
    fn new(config: Config, now: Instant) -> io::Result<Self> {
        Ok(Self {
            config,
            cookies: Cookies::new(now)?,
            tickets: HashMap::new(),
            sources: HashMap::new(),
            counts: HashMap::new(),
            pending: 0,
            rates: HashMap::new(),
            egress: Budget::new(now),
        })
    }

    /// Timer sweep, bounded by `MAX_ALLOCATIONS` and `MAX_GROUPS`; never runs per packet.
    fn expire(&mut self, now: Instant) {
        let Self {
            tickets,
            sources,
            counts,
            pending,
            rates,
            ..
        } = self;
        tickets.retain(|_, a| {
            if a.alive(now) {
                return true;
            }
            let was_pending = a.pending();
            *pending = pending.saturating_sub(usize::from(was_pending));
            for peer in a.peers.iter().flatten() {
                sources.remove(&peer.address);
                debit(counts, peer.address.ip(), was_pending);
            }
            false
        });
        rates.retain(|_, r| now.duration_since(r.all.start) < Duration::from_secs(2));
    }

    fn receive(&mut self, source: SocketAddr, data: &[u8], now: Instant) -> Action {
        let key = group(source.ip());
        if !self.rates.contains_key(&key) && self.rates.len() >= MAX_GROUPS {
            return Action::Drop;
        }
        let rate = self.rates.entry(key).or_insert_with(|| Rate {
            all: Budget::new(now),
            control: Budget::new(now),
        });
        if !rate
            .all
            .admit(now, data.len(), self.config.packets, self.config.bytes)
        {
            return Action::Drop;
        }
        // Every NRU2-prefixed datagram is reserved control traffic, never forwarded.
        if !data.starts_with(MAGIC) {
            return self.forward(source, data.len(), now);
        }
        if !rate.control.admit(now, 0, self.config.control, u64::MAX) {
            return Action::Drop;
        }
        if data.len() == HELLO {
            return self.challenge(source, data, now);
        }
        match Registration::parse(data) {
            Some(r) if self.cookies.valid(source, r.hello, r.cookie, now) => {
                self.register(source, &r, now)
            }
            _ => Action::Drop,
        }
    }

    fn forward(&mut self, source: SocketAddr, len: usize, now: Instant) -> Action {
        let Some((ticket, role)) = self.sources.get(&source) else {
            return Action::Drop;
        };
        let Some(a) = self.tickets.get_mut(ticket) else {
            return Action::Drop;
        };
        let Some(other) = a.peers[1 - role] else {
            return Action::Drop;
        };
        if !a.alive(now) || !self.egress.admit(now, len, u64::MAX, self.config.total) {
            return Action::Drop;
        }
        a.last = now;
        Action::Forward(other.address)
    }

    /// A 53-byte Hello gets a 20-byte challenge: never larger than the request.
    fn challenge(&mut self, source: SocketAddr, data: &[u8], now: Instant) -> Action {
        if data[20] > 1
            || !self
                .egress
                .admit(now, CHALLENGE, u64::MAX, self.config.total)
        {
            return Action::Drop;
        }
        let Some(cookie) = self.cookies.mint(source, data, now) else {
            return Action::Drop;
        };
        let mut reply = [0; CHALLENGE];
        reply[..4].copy_from_slice(CHALLENGE_MAGIC);
        reply[4..].copy_from_slice(&cookie);
        Action::Challenge(reply)
    }

    /// Per-group quota for one more registered role. O(1).
    fn quota(&self, ip: IpAddr, pending: bool) -> bool {
        let (total, held) = self
            .counts
            .get(&group(ip))
            .map_or((0, 0), |c| (c.total, c.pending));
        total < self.config.ip_total && (!pending || held < self.config.ip_pending)
    }

    /// Runs only after a valid cookie round trip from `source`.
    fn register(&mut self, source: SocketAddr, r: &Registration<'_>, now: Instant) -> Action {
        if self
            .sources
            .get(&source)
            .is_some_and(|bound| *bound != (r.ticket, r.role))
        {
            return Action::Drop;
        }
        let Some(a) = self.tickets.get(&r.ticket) else {
            return self.allocate(source, r, now);
        };
        if !a.alive(now) {
            return Action::Drop;
        }
        match a.peers[r.role] {
            None => self.join(source, r, now),
            Some(peer) => self.refresh(source, peer, r, now),
        }
    }

    /// New pending allocation: total capacity first, then global and per-group pending.
    fn allocate(&mut self, source: SocketAddr, r: &Registration<'_>, now: Instant) -> Action {
        if r.secret.is_some()
            || self.tickets.len() >= MAX_ALLOCATIONS
            || self.pending >= self.config.pending
            || !self.quota(source.ip(), true)
        {
            return Action::Drop;
        }
        let mut peers = [None, None];
        peers[r.role] = Some(Peer {
            address: source,
            commitment: r.commitment,
        });
        self.tickets.insert(
            r.ticket,
            Allocation {
                peers,
                born: now,
                last: now,
            },
        );
        self.pending += 1;
        credit(&mut self.counts, source.ip(), true);
        self.sources.insert(source, (r.ticket, r.role));
        Action::Drop
    }

    /// Fills the vacant role of a pending allocation and notifies both peers.
    fn join(&mut self, source: SocketAddr, r: &Registration<'_>, now: Instant) -> Action {
        if r.secret.is_some() || !self.quota(source.ip(), false) {
            return Action::Drop;
        }
        let Some(a) = self.tickets.get_mut(&r.ticket) else {
            return Action::Drop;
        };
        let Some(other) = a.peers[1 - r.role] else {
            return Action::Drop;
        };
        a.peers[r.role] = Some(Peer {
            address: source,
            commitment: r.commitment,
        });
        a.last = now;
        let peers = a.peers;
        self.pending = self.pending.saturating_sub(1);
        if let Some(c) = self.counts.get_mut(&group(other.address.ip())) {
            c.pending = c.pending.saturating_sub(1);
        }
        credit(&mut self.counts, source.ip(), false);
        self.sources.insert(source, (r.ticket, r.role));
        if !self
            .egress
            .admit(now, 2 * NOTICE, u64::MAX, self.config.total)
        {
            return Action::Drop;
        }
        let mut notices = [(source, [0; NOTICE]); 2];
        for (role, slot) in notices.iter_mut().enumerate() {
            if let Some(peer) = peers[role] {
                *slot = (peer.address, notice(r.ticket, role));
            }
        }
        Action::Notices(notices, 2)
    }

    /// Retry, commitment rotation, or rebind of an occupied role.
    fn refresh(
        &mut self,
        source: SocketAddr,
        peer: Peer,
        r: &Registration<'_>,
        now: Instant,
    ) -> Action {
        let moving = peer.address != source;
        let retry = !moving && equal(&r.commitment, &peer.commitment);
        // Anything but an idempotent retry must open the stored commitment and replace
        // it with a different one, so every revealed secret is single-use.
        if !retry && (!r.opens(&peer.commitment) || equal(&r.commitment, &peer.commitment)) {
            return Action::Drop;
        }
        let Some(a) = self.tickets.get(&r.ticket) else {
            return Action::Drop;
        };
        let pending = a.pending();
        let regroup = group(peer.address.ip()) != group(source.ip());
        if moving && regroup && !self.quota(source.ip(), pending) {
            return Action::Drop;
        }
        if moving {
            self.sources.remove(&peer.address);
            self.sources.insert(source, (r.ticket, r.role));
            debit(&mut self.counts, peer.address.ip(), pending);
            credit(&mut self.counts, source.ip(), pending);
        }
        let Some(a) = self.tickets.get_mut(&r.ticket) else {
            return Action::Drop;
        };
        a.peers[r.role] = Some(Peer {
            address: source,
            commitment: r.commitment,
        });
        a.last = now;
        if pending || !self.egress.admit(now, NOTICE, u64::MAX, self.config.total) {
            return Action::Drop;
        }
        Action::Notices([(source, notice(r.ticket, r.role)); 2], 1)
    }
}

/// `NRA2 | ticket | role`: 21 bytes.
fn notice(ticket: Ticket, role: usize) -> [u8; NOTICE] {
    let mut out = [0; NOTICE];
    out[..4].copy_from_slice(NOTICE_MAGIC);
    out[4..20].copy_from_slice(&ticket);
    out[20] = u8::from(role == 1);
    out
}

/// Serves the UDP relay on `socket` until a socket error.
pub(crate) async fn run(socket: UdpSocket, config: Config) -> io::Result<()> {
    let mut state = State::new(config, Instant::now())?;
    let mut buffer = vec![0; 65535];
    let mut sweep = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = sweep.tick() => {
                let now = Instant::now();
                if let Err(e) = state.cookies.rotate(now) {
                    eprintln!("udp cookie key rotation deferred: {e}");
                }
                state.expire(now);
            }
            received = socket.recv_from(&mut buffer) => {
                let (len, source) = received?;
                match state.receive(source, &buffer[..len], Instant::now()) {
                    Action::Drop => {}
                    Action::Forward(target) => {
                        let _ = socket.send_to(&buffer[..len], target).await;
                    }
                    Action::Challenge(reply) => {
                        let _ = socket.send_to(&reply, source).await;
                    }
                    Action::Notices(notices, count) => {
                        for (target, notice) in &notices[..count] {
                            let _ = socket.send_to(notice, target).await;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::many_single_char_names)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            pending: 2048,
            ip_pending: 8,
            ip_total: 16,
            control: 1_000_000,
            packets: 1_000_000,
            bytes: 1 << 40,
            total: 1 << 40,
        }
    }

    fn fixture() -> (State, Instant, SocketAddr, SocketAddr) {
        let now = Instant::now();
        (
            State::new(config(), now).unwrap(),
            now,
            "198.51.100.1:1000".parse().unwrap(),
            "203.0.113.2:2000".parse().unwrap(),
        )
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn ticket(n: u16) -> Ticket {
        let mut t = [0x5a; 16];
        t[..2].copy_from_slice(&n.to_be_bytes());
        t
    }

    fn secret(n: u8) -> [u8; SECRET] {
        [n; SECRET]
    }

    /// `NRU2 | ticket | role | SHA-256(secret(sec))`.
    fn hello(t: Ticket, role: u8, sec: u8) -> Vec<u8> {
        let mut data = MAGIC.to_vec();
        data.extend(t);
        data.push(role);
        data.extend(Sha256::digest(secret(sec)));
        data
    }

    /// Asserts every reply is no larger than the datagram that triggered it.
    fn send(s: &mut State, from: SocketAddr, data: &[u8], now: Instant) -> Action {
        let action = s.receive(from, data, now);
        match &action {
            Action::Challenge(reply) => assert!(reply.len() <= data.len()),
            Action::Notices(_, count) => assert!(count * NOTICE <= data.len()),
            Action::Drop | Action::Forward(_) => {}
        }
        action
    }

    fn cookie(s: &mut State, from: SocketAddr, hello: &[u8], now: Instant) -> Vec<u8> {
        let Action::Challenge(reply) = send(s, from, hello, now) else {
            panic!("no challenge")
        };
        assert_eq!(&reply[..4], CHALLENGE_MAGIC);
        reply[4..].to_vec()
    }

    fn registration(hello: &[u8], cookie: &[u8], old: Option<u8>) -> Vec<u8> {
        let mut data = hello.to_vec();
        data.extend(cookie);
        if let Some(old) = old {
            data.extend(secret(old));
        }
        data
    }

    /// Cookie round trip from `from`, then the registration (or rebind, with `old`).
    fn signed(
        s: &mut State,
        from: SocketAddr,
        t: Ticket,
        (role, sec, old): (u8, u8, Option<u8>),
        now: Instant,
    ) -> Vec<u8> {
        let h = hello(t, role, sec);
        let c = cookie(s, from, &h, now);
        registration(&h, &c, old)
    }

    fn register(s: &mut State, from: SocketAddr, t: Ticket, role: u8, now: Instant) -> Action {
        let data = signed(s, from, t, (role, role + 1, None), now);
        send(s, from, &data, now)
    }

    fn rebind(
        s: &mut State,
        from: SocketAddr,
        t: Ticket,
        new: u8,
        old: u8,
        now: Instant,
    ) -> Action {
        let data = signed(s, from, t, (0, new, Some(old)), now);
        send(s, from, &data, now)
    }

    fn pair(s: &mut State, a: SocketAddr, b: SocketAddr, t: Ticket, now: Instant) {
        assert!(matches!(register(s, a, t, 0, now), Action::Drop));
        let Action::Notices(notices, 2) = register(s, b, t, 1, now) else {
            panic!("not paired")
        };
        assert_eq!(notices, [(a, notice(t, 0)), (b, notice(t, 1))]);
    }

    fn consistent(s: &State) {
        let pending = s.tickets.values().filter(|a| a.pending()).count();
        assert_eq!(s.pending, pending);
        let roles: usize = s
            .tickets
            .values()
            .map(|a| a.peers.iter().flatten().count())
            .sum();
        assert_eq!(s.sources.len(), roles);
        assert_eq!(s.counts.values().map(|c| c.total).sum::<usize>(), roles);
        assert_eq!(s.counts.values().map(|c| c.pending).sum::<usize>(), pending);
    }

    #[test]
    fn pairing_and_bidirectional_forwarding() {
        let (mut s, now, a, b) = fixture();
        let t = ticket(1);
        pair(&mut s, a, b, t, now);
        assert!(matches!(send(&mut s, a, b"ciphertext", now), Action::Forward(x) if x == b));
        assert!(matches!(send(&mut s, b, b"reply", now), Action::Forward(x) if x == a));
        // Lost notice: an identical registration from the same address re-sends one notice.
        let retry = signed(&mut s, a, t, (0, 1, None), now);
        let Action::Notices(n, 1) = send(&mut s, a, &retry, now) else {
            panic!("no retry notice")
        };
        assert_eq!(n[0], (a, notice(t, 0)));
        // A different commitment from the same address is neither a retry nor a rotation.
        let other = signed(&mut s, a, t, (0, 5, None), now);
        assert!(matches!(send(&mut s, a, &other, now), Action::Drop));
        // One source holds exactly one ticket/role.
        let both = signed(&mut s, a, t, (1, 2, None), now);
        assert!(matches!(send(&mut s, a, &both, now), Action::Drop));
        // Control traffic from a paired peer is never forwarded.
        assert!(matches!(send(&mut s, a, b"NRU2junk", now), Action::Drop));
        let mut odd = retry.clone();
        odd.push(0);
        assert!(matches!(send(&mut s, a, &odd, now), Action::Drop));
        consistent(&s);
        assert_eq!(s.pending, 0);
    }

    #[test]
    fn rebind_requires_fresh_cookie_and_secret_and_rotates_commitment() {
        let (mut s, now, a, b) = fixture();
        let t = ticket(2);
        let captured = signed(&mut s, a, t, (0, 1, None), now);
        assert!(matches!(send(&mut s, a, &captured, now), Action::Drop));
        assert!(matches!(
            register(&mut s, b, t, 1, now),
            Action::Notices(_, 2)
        ));
        let moved = addr("192.0.2.9:4000");
        // Replayed initial registration from a new address: cookie bound to the old one.
        assert!(matches!(send(&mut s, moved, &captured, now), Action::Drop));
        // The captured registration plus the right secret: still the wrong cookie.
        let mut guessed = captured.clone();
        guessed.extend(secret(1));
        assert!(matches!(send(&mut s, moved, &guessed, now), Action::Drop));
        // Fresh cookie but no secret, wrong secret, or reused commitment.
        for bad in [(0, 1, None), (0, 7, Some(9)), (0, 1, Some(1))] {
            let data = signed(&mut s, moved, t, bad, now);
            assert!(matches!(send(&mut s, moved, &data, now), Action::Drop));
        }
        assert!(matches!(send(&mut s, b, b"still a", now), Action::Forward(x) if x == a));
        // Valid rebind: fresh cookie, preimage of H(s1), new commitment H(s7).
        let good = signed(&mut s, moved, t, (0, 7, Some(1)), now);
        let Action::Notices(n, 1) = send(&mut s, moved, &good, now) else {
            panic!("rebind refused")
        };
        assert_eq!(n[0], (moved, notice(t, 0)));
        assert!(matches!(send(&mut s, b, b"to moved", now), Action::Forward(x) if x == moved));
        assert!(matches!(send(&mut s, moved, b"from moved", now), Action::Forward(x) if x == b));
        assert!(matches!(send(&mut s, a, b"stale", now), Action::Drop));
        // The identical rebind repeated from the new address is an idempotent retry.
        assert!(matches!(
            send(&mut s, moved, &good, now),
            Action::Notices(_, 1)
        ));
        // Replaying the captured rebind verbatim, or its secret with a fresh cookie, from
        // another address fails: H(s1) is spent.
        let thief = addr("192.0.2.66:5000");
        assert!(matches!(send(&mut s, thief, &good, now), Action::Drop));
        for replay in [(0, 7, Some(1)), (0, 8, Some(1))] {
            let data = signed(&mut s, thief, t, replay, now);
            assert!(matches!(send(&mut s, thief, &data, now), Action::Drop));
        }
        // The old address cannot come back with the spent secret either.
        assert!(matches!(rebind(&mut s, a, t, 9, 1, now), Action::Drop));
        // The legitimate holder can rebind again with the current secret s7.
        assert!(matches!(
            rebind(&mut s, a, t, 10, 7, now),
            Action::Notices(_, 1)
        ));
        assert!(matches!(send(&mut s, b, b"back", now), Action::Forward(x) if x == a));
        consistent(&s);
    }

    #[test]
    fn spoofed_sources_never_allocate_or_receive_payloads() {
        let (mut s, now, victim, attacker) = fixture();
        let t = ticket(3);
        let h = hello(t, 0, 1);
        // A spoofer sees no challenge sent to the victim, so it can only guess or transplant.
        let theirs = cookie(&mut s, attacker, &h, now);
        for forged in [theirs, vec![0; COOKIE], vec![0xff; COOKIE]] {
            let data = registration(&h, &forged, None);
            assert!(matches!(send(&mut s, victim, &data, now), Action::Drop));
        }
        // A spoofed Hello yields one 20-byte challenge to the victim, nothing more.
        for role in 0..2 {
            assert!(matches!(
                send(&mut s, victim, &hello(t, role, 1), now),
                Action::Challenge(_)
            ));
        }
        assert!(s.tickets.is_empty() && s.sources.is_empty() && s.counts.is_empty());
        // Once someone else holds a role, spoofed data from the victim is not forwarded.
        assert!(matches!(
            register(&mut s, attacker, t, 1, now),
            Action::Drop
        ));
        assert!(matches!(
            send(&mut s, victim, b"payload", now),
            Action::Drop
        ));
        assert!(matches!(
            send(&mut s, attacker, b"payload", now),
            Action::Drop
        ));
        consistent(&s);
    }

    #[test]
    fn replies_never_exceed_requests_before_pairing() {
        let (mut s, now, a, b) = fixture();
        let t = ticket(4);
        for len in 0..=REBIND + 8 {
            for role in [0u8, 1, 2, 0xff] {
                let mut data = hello(t, role, 3);
                data.resize(len.max(HELLO), role);
                data.truncate(len);
                let action = send(&mut s, a, &data, now);
                assert!(!matches!(action, Action::Forward(_)));
                let challenged = matches!(action, Action::Challenge(_));
                assert_eq!(challenged, len == HELLO && role <= 1, "len {len}");
            }
        }
        assert!(s.tickets.is_empty());
        // Pairing: 69-byte request, 2 x 21-byte notices (each to a validated address).
        pair(&mut s, a, b, t, now);
    }

    #[test]
    fn cookies_expire_and_keys_rotate() {
        let (mut s, now, a, _) = fixture();
        let t = ticket(5);
        let h = hello(t, 0, 1);
        let c = cookie(&mut s, a, &h, now);
        assert!(s.cookies.valid(a, &h, &c, now + Duration::from_secs(59)));
        assert!(!s.cookies.valid(a, &h, &c, now + Duration::from_secs(60)));
        assert!(!s.cookies.valid(addr("198.51.100.1:1001"), &h, &c, now));
        assert!(!s.cookies.valid(a, &hello(t, 1, 1), &c, now));
        assert!(!s.cookies.valid(a, &hello(t, 0, 2), &c, now));
        assert!(!s.cookies.valid(a, &hello(ticket(6), 0, 1), &c, now));
        let late = registration(&h, &c, None);
        assert!(matches!(
            send(&mut s, a, &late, now + Duration::from_secs(60)),
            Action::Drop
        ));
        assert!(s.tickets.is_empty());
        // Rotation keeps exactly one previous key.
        let at = now + Duration::from_secs(299);
        let c = cookie(&mut s, a, &h, at);
        s.cookies.rotate(now + ROTATE).unwrap();
        assert!(s.cookies.valid(a, &h, &c, now + ROTATE));
        s.cookies.rotated = now;
        s.cookies.rotate(now + ROTATE).unwrap();
        assert!(!s.cookies.valid(a, &h, &c, now + ROTATE));
    }

    #[test]
    fn per_group_quotas_prevent_pool_monopolization() {
        let (mut s, now, a, b) = fixture();
        // One IP, many source ports and random tickets: at most 8 pending.
        for n in 0..40 {
            register(
                &mut s,
                SocketAddr::new(a.ip(), 10_000 + n),
                ticket(n),
                0,
                now,
            );
        }
        assert_eq!((s.tickets.len(), s.pending), (8, 8));
        // Everyone else is unaffected.
        pair(&mut s, b, addr("192.0.2.3:3000"), ticket(500), now);
        consistent(&s);
        // Joining existing tickets is bounded by the total quota (16 roles).
        for n in 0..8 {
            let partner = SocketAddr::new(b.ip(), 20_000 + n);
            assert!(matches!(
                register(&mut s, partner, ticket(n), 1, now),
                Action::Notices(_, 2)
            ));
        }
        for n in 0..40 {
            register(
                &mut s,
                SocketAddr::new(a.ip(), 30_000 + n),
                ticket(1000 + n),
                0,
                now,
            );
        }
        assert_eq!(s.counts[&a.ip()].pending, 8);
        assert_eq!(s.counts[&a.ip()].total, 16);
        // Other groups' pending tickets cannot be joined from the exhausted group either.
        for n in 0..4 {
            register(
                &mut s,
                addr(&format!("192.0.2.50:{}", 100 + n)),
                ticket(600 + n),
                0,
                now,
            );
            let partner = SocketAddr::new(a.ip(), 40_000 + n);
            assert!(matches!(
                register(&mut s, partner, ticket(600 + n), 1, now),
                Action::Drop
            ));
        }
        assert_eq!(s.counts[&a.ip()].total, 16);
        consistent(&s);
        // Expiry releases every counter.
        s.expire(now + IDLE);
        assert!(s.tickets.is_empty() && s.sources.is_empty() && s.counts.is_empty());
        assert_eq!(s.pending, 0);
    }

    #[test]
    fn ipv6_slash_64_is_one_group_and_rebind_checks_destination_quota() {
        let (mut s, now, _, b) = fixture();
        s.config.ip_pending = 1;
        register(&mut s, addr("[2001:db8::1]:1000"), ticket(1), 0, now);
        register(&mut s, addr("[2001:db8::ffff:2]:1000"), ticket(2), 0, now);
        register(&mut s, addr("[::ffff:203.0.113.2]:9"), ticket(3), 0, now);
        assert_eq!(s.tickets.len(), 2);
        register(&mut s, addr("[2001:db8:0:1::1]:1000"), ticket(4), 0, now);
        assert_eq!(s.tickets.len(), 3);
        // b's group is full of pending roles (via the mapped address); a pending rebind
        // into it is refused, leaving the original address in place.
        assert!(matches!(
            rebind(&mut s, b, ticket(1), 5, 1, now),
            Action::Drop
        ));
        assert!(s.sources.contains_key(&addr("[2001:db8::1]:1000")));
        consistent(&s);
    }

    #[test]
    fn total_capacity_is_checked_first_and_pending_is_global() {
        let (mut s, now, _, _) = fixture();
        s.config.pending = 3;
        for n in 0..5u8 {
            let from = SocketAddr::new(IpAddr::from([10, 0, 0, n]), 1);
            let n = u16::from(n);
            register(&mut s, from, ticket(n), 0, now);
        }
        assert_eq!(s.pending, 3);
        s.config.pending = usize::MAX;
        s.config.ip_pending = usize::MAX;
        s.config.ip_total = usize::MAX;
        for n in 0..u16::try_from(MAX_ALLOCATIONS).unwrap() + 10 {
            let [hi, lo] = n.to_be_bytes();
            let from = SocketAddr::new(IpAddr::from([10, 1, hi, lo]), 1);
            register(&mut s, from, ticket(10_000 + n), 0, now);
        }
        assert_eq!(s.tickets.len(), MAX_ALLOCATIONS);
        consistent(&s);
    }

    #[test]
    fn control_rate_bounds_challenges_per_group() {
        let (mut s, now, a, _) = fixture();
        s.config.control = 4;
        let mut challenges = 0;
        for port in 0..20 {
            let from = SocketAddr::new(a.ip(), 5000 + port);
            challenges += usize::from(matches!(
                send(&mut s, from, &hello(ticket(1), 0, 1), now),
                Action::Challenge(_)
            ));
        }
        assert_eq!(challenges, 4);
        let later = now + Duration::from_secs(1);
        assert!(matches!(
            send(&mut s, a, &hello(ticket(1), 0, 1), later),
            Action::Challenge(_)
        ));
    }

    #[test]
    fn idle_and_hard_expiry_and_bandwidth() {
        let (mut s, now, a, b) = fixture();
        let t = ticket(7);
        pair(&mut s, a, b, t, now);
        let mid = now + Duration::from_secs(59);
        assert!(matches!(
            send(&mut s, a, b"keepalive", mid),
            Action::Forward(_)
        ));
        s.expire(now + IDLE);
        assert_eq!(s.tickets.len(), 1);
        assert!(matches!(send(&mut s, a, b"late", mid + IDLE), Action::Drop));
        for a in s.tickets.values_mut() {
            a.last = now + LIFETIME;
        }
        s.expire(now + LIFETIME);
        assert!(s.tickets.is_empty());
        consistent(&s);
        pair(&mut s, a, b, ticket(8), now);
        s.config.total = 0;
        assert!(matches!(send(&mut s, a, b"payload", now), Action::Drop));
        let mut budget = Budget::new(now);
        assert!(budget.admit(now, 10, 2, 15));
        assert!(!budget.admit(now, 6, 2, 15));
        assert!(budget.admit(now, 5, 2, 15));
        assert!(!budget.admit(now, 0, 2, 15));
        assert!(budget.admit(now + Duration::from_secs(1), 10, 2, 15));
    }
}
