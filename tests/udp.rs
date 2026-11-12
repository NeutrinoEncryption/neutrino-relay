//! Real process and socket integration coverage for the UDP relay.
use std::io;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Relay(Child);
impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn two_udp_clients_exchange_verbatim_datagrams() -> io::Result<()> {
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
    let a = UdpSocket::bind("127.0.0.1:0")?;
    let b = UdpSocket::bind("127.0.0.1:0")?;
    for socket in [&a, &b] {
        socket.connect(relay_addr)?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    }
    let mut registration = [9; 21];
    registration[..4].copy_from_slice(b"NRU1");
    registration[20] = 0;
    a.send(&registration)?;
    registration[20] = 1;
    b.send(&registration)?;
    let mut buffer = vec![0; 65535];
    for (socket, role) in [(&a, 0), (&b, 1)] {
        let len = socket.recv(&mut buffer)?;
        registration[20] = role;
        assert_eq!(&buffer[..len], registration);
    }
    for size in [1, 1200, 4096, 60000] {
        let payload = vec![0xc7; size];
        a.send(&payload)?;
        let len = b.recv(&mut buffer)?;
        assert_eq!(&buffer[..len], payload);
        b.send(&payload)?;
        let len = a.recv(&mut buffer)?;
        assert_eq!(&buffer[..len], payload);
    }
    Ok(())
}
