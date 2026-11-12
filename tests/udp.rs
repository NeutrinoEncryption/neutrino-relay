//! Real process and socket integration coverage for the UDP relay (protocol v2).
use sha2::{Digest, Sha256};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Relay(Child);
impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

const TICKET: [u8; 16] = [9; 16];

fn spawn() -> io::Result<(Relay, SocketAddr)> {
    let reserve = UdpSocket::bind("127.0.0.1:0")?;
    let relay_addr = reserve.local_addr()?;
    let tcp = TcpListener::bind("127.0.0.1:0")?;
    let tcp_addr = tcp.local_addr()?;
    drop((reserve, tcp));
    let mut relay = Relay(
        Command::new(env!("CARGO_BIN_EXE_neutrino-relay"))
            .env("NEUTRINO_RELAY_BIND", tcp_addr.to_string())
            .env("NEUTRINO_RELAY_UDP_BIND", relay_addr.to_string())
            .env("NEUTRINO_RELAY_UDP_IP_PPS", "20000")
            .env("NEUTRINO_RELAY_UDP_IP_BPS", "33554432")
            .env("NEUTRINO_RELAY_UDP_TOTAL_BPS", "134217728")
            .env("NEUTRINO_RELAY_UDP_MAX_PENDING", "2048")
            .env("NEUTRINO_RELAY_UDP_IP_MAX_PENDING", "8")
            .env("NEUTRINO_RELAY_UDP_IP_MAX_TOTAL", "16")
            .env("NEUTRINO_RELAY_UDP_IP_CONTROL_PPS", "1000")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(tcp_addr).is_err() {
        assert!(relay.0.try_wait()?.is_none(), "relay exited");
        assert!(Instant::now() < deadline, "relay startup timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok((relay, relay_addr))
}

fn client(relay: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.connect(relay)?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    Ok(socket)
}

/// 53-byte Hello: `NRU2 | ticket | role | SHA-256(s)` with `s = [secret; 16]`.
fn hello(role: u8, secret: u8) -> Vec<u8> {
    let mut data = b"NRU2".to_vec();
    data.extend(TICKET);
    data.push(role);
    data.extend(Sha256::digest([secret; 16]));
    data
}

fn notice(role: u8) -> Vec<u8> {
    let mut data = b"NRA2".to_vec();
    data.extend(TICKET);
    data.push(role);
    data
}

/// Hello round trip; returns the 16-byte cookie.
fn cookie(socket: &UdpSocket, hello: &[u8]) -> io::Result<Vec<u8>> {
    socket.send(hello)?;
    let mut buffer = [0; 1500];
    let len = socket.recv(&mut buffer)?;
    assert_eq!(len, 20);
    assert!(len <= hello.len());
    assert_eq!(&buffer[..4], b"NRC2");
    Ok(buffer[4..20].to_vec())
}

/// 69-byte registration, or 85-byte rebind carrying the previous secret.
fn registration(hello: &[u8], cookie: &[u8], previous: Option<u8>) -> Vec<u8> {
    let mut data = hello.to_vec();
    data.extend(cookie);
    if let Some(previous) = previous {
        data.extend([previous; 16]);
    }
    data
}

fn signed(socket: &UdpSocket, role: u8, secret: u8, previous: Option<u8>) -> io::Result<Vec<u8>> {
    let hello = hello(role, secret);
    let cookie = cookie(socket, &hello)?;
    Ok(registration(&hello, &cookie, previous))
}

fn silent(socket: &UdpSocket) -> io::Result<()> {
    socket.set_read_timeout(Some(Duration::from_millis(300)))?;
    let mut buffer = vec![0; 65535];
    let result = socket.recv(&mut buffer);
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    match result {
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Ok(())
        }
        Err(e) => Err(e),
        Ok(len) => panic!("unexpected {len}-byte datagram"),
    }
}

fn recv(socket: &UdpSocket) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0; 65535];
    let len = socket.recv(&mut buffer)?;
    buffer.truncate(len);
    Ok(buffer)
}

#[test]
fn v2_pairing_forwarding_spoof_and_rebind() -> io::Result<()> {
    let (_relay, relay_addr) = spawn()?;
    let a = client(relay_addr)?;
    let b = client(relay_addr)?;
    let spoof = client(relay_addr)?;

    // A cookie minted for one source is useless from another (spoofed) source.
    let a_registration = signed(&a, 0, 1, None)?;
    spoof.send(&a_registration)?;
    silent(&spoof)?;
    spoof.send(b"payload from nobody")?;
    silent(&spoof)?;

    a.send(&a_registration)?;
    silent(&a)?;
    b.send(&signed(&b, 1, 2, None)?)?;
    assert_eq!(recv(&a)?, notice(0));
    assert_eq!(recv(&b)?, notice(1));
    silent(&spoof)?;

    for size in [1, 1200, 4096, 60000] {
        let payload = vec![0xc7; size];
        a.send(&payload)?;
        assert_eq!(recv(&b)?, payload);
        b.send(&payload)?;
        assert_eq!(recv(&a)?, payload);
    }

    // NAT rebinding: new socket, fresh cookie, previous secret 1, new commitment H(3).
    let moved = client(relay_addr)?;
    moved.send(&a_registration)?;
    silent(&moved)?;
    moved.send(&signed(&moved, 0, 1, None)?)?;
    silent(&moved)?;
    let rebind = signed(&moved, 0, 3, Some(1))?;
    moved.send(&rebind)?;
    assert_eq!(recv(&moved)?, notice(0));
    b.send(b"to moved")?;
    assert_eq!(recv(&moved)?, b"to moved");
    moved.send(b"from moved")?;
    assert_eq!(recv(&b)?, b"from moved");
    a.send(b"stale")?;
    silent(&b)?;

    // Replaying the observed rebind from yet another address fails: secret 1 is spent.
    spoof.send(&rebind)?;
    spoof.send(&signed(&spoof, 0, 3, Some(1))?)?;
    spoof.send(&signed(&spoof, 0, 4, Some(1))?)?;
    silent(&spoof)?;
    b.send(b"still moved")?;
    assert_eq!(recv(&moved)?, b"still moved");
    silent(&spoof)?;
    Ok(())
}
