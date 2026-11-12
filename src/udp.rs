//! Bounded, blind UDP pairing and raw datagram forwarding.
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const IDLE: Duration = Duration::from_secs(60);
const LIFETIME: Duration = Duration::from_secs(6 * 60 * 60);
const MAX_PAIRS: usize = 4096;
const MAX_IPS: usize = 16384;
const MAGIC: &[u8; 4] = b"NRU1";
type Ticket = [u8; 16];

pub(crate) struct Config {
    pending: usize,
    packets: u64,
    bytes: u64,
    total: u64,
}

impl Config {
    pub(crate) fn from_env() -> io::Result<Self> {
        Ok(Self {
            pending: setting("NEUTRINO_RELAY_UDP_MAX_PENDING", 2048)?,
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

struct Allocation {
    peers: [Option<SocketAddr>; 2],
    born: Instant,
    last: Instant,
}

impl Allocation {
    fn alive(&self, now: Instant) -> bool {
        now.duration_since(self.last) < IDLE && now.duration_since(self.born) < LIFETIME
    }
}

struct State {
    config: Config,
    tickets: HashMap<Ticket, Allocation>,
    sources: HashMap<SocketAddr, (Ticket, usize)>,
    ips: HashMap<IpAddr, Budget>,
    total: Budget,
}

// At most two small notices, or one borrowed raw payload; no per-packet payload allocation.
enum Action {
    Drop,
    Forward(SocketAddr),
    Notices([(SocketAddr, [u8; 21]); 2], usize),
}

impl State {
    fn new(config: Config, now: Instant) -> Self {
        Self {
            config,
            tickets: HashMap::new(),
            sources: HashMap::new(),
            ips: HashMap::new(),
            total: Budget::new(now),
        }
    }

    fn expire(&mut self, now: Instant) {
        self.tickets.retain(|_, a| a.alive(now));
        self.sources
            .retain(|_, (ticket, _)| self.tickets.contains_key(ticket));
        self.ips
            .retain(|_, b| now.duration_since(b.start) < Duration::from_secs(2));
    }

    fn receive(&mut self, source: SocketAddr, data: &[u8], now: Instant) -> Action {
        if !self.ips.contains_key(&source.ip()) && self.ips.len() >= MAX_IPS {
            return Action::Drop;
        }
        if !self
            .ips
            .entry(source.ip())
            .or_insert_with(|| Budget::new(now))
            .admit(now, data.len(), self.config.packets, self.config.bytes)
        {
            return Action::Drop;
        }
        let registration = data.len() == 21 && data.starts_with(MAGIC) && data[20] <= 1;
        if let Some((ticket, role)) = self.sources.get(&source).copied() {
            if let Some(a) = self.tickets.get_mut(&ticket) {
                if a.alive(now) {
                    if let Some(other) = a.peers[1 - role] {
                        // Only an exact repeat registration is control traffic once paired.
                        if !registration || data[4..20] != ticket || usize::from(data[20]) != role {
                            if self
                                .total
                                .admit(now, data.len(), u64::MAX, self.config.total)
                            {
                                a.last = now;
                                return Action::Forward(other);
                            }
                            return Action::Drop;
                        }
                    }
                } else {
                    self.tickets.remove(&ticket);
                    self.sources.retain(|_, (t, _)| *t != ticket);
                }
            }
        }
        if !registration {
            return Action::Drop;
        }
        let mut ticket = [0; 16];
        ticket.copy_from_slice(&data[4..20]);
        let role = usize::from(data[20]);
        // An address cannot claim multiple tickets or switch roles in-place.
        if self
            .sources
            .get(&source)
            .is_some_and(|entry| *entry != (ticket, role))
        {
            return Action::Drop;
        }
        if !self.tickets.contains_key(&ticket) {
            let pending = self
                .tickets
                .values()
                .filter(|a| a.peers.contains(&None))
                .count();
            if pending >= self.config.pending || self.tickets.len() >= MAX_PAIRS {
                return Action::Drop;
            }
        }
        let a = self.tickets.entry(ticket).or_insert(Allocation {
            peers: [None, None],
            born: now,
            last: now,
        });
        if !a.alive(now) {
            return Action::Drop;
        }
        let was_paired = a.peers.iter().all(Option::is_some);
        if let Some(old) = a.peers[role].replace(source) {
            self.sources.remove(&old);
        }
        self.sources.insert(source, (ticket, role));
        a.last = now;
        let (Some(first), Some(second)) = (a.peers[0], a.peers[1]) else {
            return Action::Drop;
        };
        // First pairing sends one notice per registration (21 bytes each). Retries
        // and rebinding send only to the registering source, never unsolicited repeats.
        let mut notice = [0; 21];
        notice[..4].copy_from_slice(MAGIC);
        notice[4..20].copy_from_slice(&ticket);
        let mut second_notice = notice;
        second_notice[20] = 1;
        let notices = if was_paired {
            notice[20] = data[20];
            [(source, notice), (source, notice)]
        } else {
            [(first, notice), (second, second_notice)]
        };
        let count = if was_paired { 1 } else { 2 };
        if !self
            .total
            .admit(now, 21 * count, u64::MAX, self.config.total)
        {
            return Action::Drop;
        }
        Action::Notices(notices, count)
    }
}

pub(crate) async fn run(socket: UdpSocket, config: Config) -> io::Result<()> {
    let mut state = State::new(config, Instant::now());
    let mut buffer = vec![0; 65535];
    let mut cleanup = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = cleanup.tick() => state.expire(Instant::now()),
            received = socket.recv_from(&mut buffer) => {
                let (len, source) = received?;
                match state.receive(source, &buffer[..len], Instant::now()) {
                    Action::Drop => {},
                    Action::Forward(target) => { let _ = socket.send_to(&buffer[..len], target).await; },
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
mod tests {
    use super::*;
    fn state() -> (State, Instant, SocketAddr, SocketAddr) {
        let now = Instant::now();
        (
            State::new(
                Config {
                    pending: 2,
                    packets: 10,
                    bytes: 1000,
                    total: 1000,
                },
                now,
            ),
            now,
            SocketAddr::from(([127, 0, 0, 1], 1000)),
            SocketAddr::from(([127, 0, 0, 1], 1001)),
        )
    }
    fn reg(role: u8) -> [u8; 21] {
        let mut data = [7; 21];
        data[..4].copy_from_slice(MAGIC);
        data[20] = role;
        data
    }
    #[test]
    fn pairing_and_raw_forwarding() {
        let (mut s, now, a, b) = state();
        assert!(matches!(s.receive(a, &reg(0), now), Action::Drop));
        assert!(matches!(s.receive(a, &reg(1), now), Action::Drop));
        assert!(matches!(s.receive(b, &reg(1), now), Action::Notices(_, 2)));
        assert!(matches!(s.receive(a, b"ciphertext", now), Action::Forward(t) if t == b));
        assert!(matches!(s.receive(b, b"reply", now), Action::Forward(t) if t == a));
    }
    #[test]
    fn expiry_idle_and_hard_cap() {
        let (mut s, now, a, b) = state();
        s.receive(a, &reg(0), now);
        s.receive(b, &reg(1), now);
        s.expire(now + IDLE);
        assert!(s.sources.is_empty());
        s.receive(a, &reg(0), now);
        s.receive(b, &reg(1), now);
        for a in s.tickets.values_mut() {
            a.last = now + LIFETIME;
        }
        s.expire(now + LIFETIME);
        assert!(s.tickets.is_empty());
    }
    #[test]
    fn rate_and_bandwidth_limits() {
        let now = Instant::now();
        let mut b = Budget::new(now);
        assert!(b.admit(now, 10, 2, 15));
        assert!(!b.admit(now, 6, 2, 15));
        assert!(b.admit(now, 5, 2, 15));
        assert!(!b.admit(now, 0, 2, 15));
        assert!(b.admit(now + Duration::from_secs(1), 10, 2, 15));
        let (mut s, now, a, peer) = state();
        s.receive(a, &reg(0), now);
        s.receive(peer, &reg(1), now);
        s.config.total = 42;
        assert!(matches!(s.receive(a, b"x", now), Action::Drop));
    }
    #[test]
    fn no_amplification_or_unknown_forwarding() {
        let (mut s, now, a, b) = state();
        assert!(matches!(s.receive(a, b"junk", now), Action::Drop));
        for _ in 0..3 {
            assert!(matches!(s.receive(a, &reg(0), now), Action::Drop));
        }
        let Action::Notices(notices, count) = s.receive(b, &reg(1), now) else {
            panic!("no notices")
        };
        assert_eq!(count, 2);
        for (target, data) in notices {
            assert!(target == a || target == b);
            assert_eq!(data.len(), 21);
        }
        assert!(matches!(s.receive(b, &reg(1), now), Action::Notices(_, 1)));
    }
    #[test]
    fn rebinding_replaces_old_source_and_pending_is_bounded() {
        let (mut s, now, a, b) = state();
        s.receive(a, &reg(0), now);
        s.receive(b, &reg(1), now);
        let new = SocketAddr::from(([127, 0, 0, 2], 2000));
        assert!(matches!(
            s.receive(new, &reg(0), now),
            Action::Notices(_, 1)
        ));
        assert!(matches!(s.receive(a, b"old", now), Action::Drop));
        assert!(matches!(s.receive(b, b"new", now), Action::Forward(t) if t == new));
        s.config.pending = 0;
        let mut other = reg(0);
        other[4] = 8;
        assert!(matches!(s.receive(a, &other, now), Action::Drop));
    }
}
