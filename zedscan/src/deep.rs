use crate::event::Found;
use crate::score;
use crate::sweep::{addr_key, Protect};
use crate::targets::Net;
use crate::util::{long_name, mix, percentile, random_label, Rng};
use crate::wire::{self, Edns, Reply};
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::timeout;

pub struct DeepSpec {
    pub domain: String,
    pub tunnel: String,
    pub wait: Duration,
    pub samples: u8,
    pub ladder: Vec<u16>,
    pub types: Vec<u16>,
    pub edns: bool,
    pub nx: bool,
    pub burst: bool,
    pub burst_size: u16,
    pub tcp: bool,
    pub dot: bool,
    pub blocked: Vec<String>,
    pub hijack: Vec<Net>,
    pub seed: u64,
    pub tls: Option<Arc<rustls::ClientConfig>>,
    pub capture: Option<Arc<crate::capture::Capture>>,
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Deep {
    pub ip: String,
    pub port: u16,
    pub score: u8,
    pub alive: bool,
    pub rtt: u32,
    pub rtt_min: u32,
    pub rtt_p90: u32,
    pub jitter: u32,
    pub loss: f32,
    pub hijacked: bool,
    pub via: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answered_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_udp: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_tcp: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hops: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_suspect: Option<bool>,
    pub dup_answers: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_rcode: Option<u16>,
    pub max_qname: u16,
    pub types_ok: Vec<String>,
    pub types_bad: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edns: Option<bool>,
    pub max_reply: u16,
    pub truncates: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nx_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub censored: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_rtt: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dot: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dot_rtt: Option<u32>,
}

#[derive(Debug)]
enum Fail {
    Build,
    Timeout,
    Closed,
    Io,
    Malformed,
}

#[cfg(unix)]
pub(crate) fn protect_fd<T: std::os::fd::AsRawFd>(s: &T, p: &Option<Protect>) {
    if let Some(p) = p {
        p(s.as_raw_fd() as i64);
    }
}

#[cfg(not(unix))]
pub(crate) fn protect_fd<T>(_: &T, _: &Option<Protect>) {}

fn ok_rcode(r: &Reply) -> bool {
    r.rcode == wire::RC_NOERROR || r.rcode == wire::RC_NXDOMAIN
}

struct Conn {
    udp: Option<UdpSocket>,
    tcp: Option<TcpStream>,
    addr: SocketAddr,
    protect: Option<Protect>,
    id: u16,
    buf: Vec<u8>,
    q: Vec<u8>,
    wait: Duration,
}

impl Conn {
    async fn open(addr: SocketAddr, tcp: bool, protect: &Option<Protect>, wait: Duration, seed: u64) -> std::io::Result<Conn> {
        let mut c = Conn {
            udp: None,
            tcp: None,
            addr,
            protect: protect.clone(),
            id: (seed & 0xFFFF) as u16,
            buf: vec![0u8; 65535],
            q: Vec::with_capacity(512),
            wait,
        };
        if tcp {
            c.reconnect().await?;
        } else {
            let bind = if addr.is_ipv6() {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            };
            let sock = UdpSocket::bind(bind).await?;
            protect_fd(&sock, protect);
            sock.connect(addr).await?;
            c.udp = Some(sock);
        }
        Ok(c)
    }

    fn is_tcp(&self) -> bool {
        self.udp.is_none()
    }

    async fn reconnect(&mut self) -> std::io::Result<()> {
        self.tcp = None;
        let s = tcp_connect(self.addr, &self.protect, self.wait)
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect"))?;
        self.tcp = Some(s);
        Ok(())
    }

    fn build(&mut self, id: u16, name: &str, qtype: u16, edns: Option<Edns>) -> bool {
        if !wire::encode_query(&mut self.q, id, name, qtype, true, edns) {
            return false;
        }
        if self.udp.is_none() {
            let len = (self.q.len() as u16).to_be_bytes();
            self.q.splice(0..0, len);
        }
        true
    }

    async fn send(&mut self) -> Result<(), Fail> {
        if let Some(u) = &self.udp {
            return u.send(&self.q).await.map(|_| ()).map_err(|_| Fail::Io);
        }
        if self.tcp.is_none() {
            self.reconnect().await.map_err(|_| Fail::Io)?;
        }
        let Some(t) = self.tcp.as_mut() else { return Err(Fail::Io) };
        if t.write_all(&self.q).await.is_err() {
            self.tcp = None;
            return Err(Fail::Io);
        }
        Ok(())
    }

    async fn recv(&mut self, left: Duration) -> Result<usize, Fail> {
        if let Some(u) = &self.udp {
            return match timeout(left, u.recv(&mut self.buf)).await {
                Err(_) => Err(Fail::Timeout),
                Ok(Err(e)) => Err(if e.kind() == std::io::ErrorKind::ConnectionRefused { Fail::Closed } else { Fail::Io }),
                Ok(Ok(n)) => Ok(n),
            };
        }
        let Some(t) = self.tcp.as_mut() else { return Err(Fail::Io) };
        let buf = &mut self.buf;
        let read = async {
            let mut len = [0u8; 2];
            t.read_exact(&mut len).await?;
            let n = u16::from_be_bytes(len) as usize;
            t.read_exact(&mut buf[..n]).await?;
            Ok::<usize, std::io::Error>(n)
        };
        match timeout(left, read).await {
            Err(_) => {
                self.tcp = None;
                Err(Fail::Timeout)
            }
            Ok(Err(_)) => {
                self.tcp = None;
                Err(Fail::Io)
            }
            Ok(Ok(n)) => Ok(n),
        }
    }

    async fn ask(&mut self, name: &str, qtype: u16, edns: Option<Edns>) -> Result<(Reply, u32), Fail> {
        let mut all = self.ask_window(name, qtype, edns, Duration::ZERO).await?;
        let first = all.remove(0);
        Ok(first)
    }

    async fn ask_window(&mut self, name: &str, qtype: u16, edns: Option<Edns>, extra: Duration) -> Result<Vec<(Reply, u32)>, Fail> {
        self.id = self.id.wrapping_add(1);
        let id = self.id;
        if !self.build(id, name, qtype, edns) {
            return Err(Fail::Build);
        }
        let expect = wire::name_wire(name).ok_or(Fail::Build)?;
        let start = Instant::now();
        if self.send().await.is_err() && self.is_tcp() {
            self.reconnect().await.map_err(|_| Fail::Io)?;
            self.send().await?;
        }
        let mut deadline = start + self.wait;
        let mut out: Vec<(Reply, u32)> = Vec::new();
        let mut resent = false;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let n = match self.recv(left).await {
                Ok(n) => n,
                Err(Fail::Timeout) => break,
                Err(Fail::Io) if self.is_tcp() && out.is_empty() && !resent => {
                    resent = true;
                    if self.reconnect().await.is_err() || self.send().await.is_err() {
                        return Err(Fail::Io);
                    }
                    continue;
                }
                Err(e) => {
                    if out.is_empty() {
                        return Err(e);
                    }
                    break;
                }
            };
            let b = &self.buf[..n];
            if n < 12 || wire::be16(b, 0) != id || !wire::question_is(b, &expect, qtype) {
                continue;
            }
            let Some(r) = wire::parse(b) else { continue };
            if !r.qr {
                continue;
            }
            out.push((r, start.elapsed().as_millis() as u32));
            if out.len() == 1 {
                if extra.is_zero() || self.is_tcp() {
                    break;
                }
                deadline = Instant::now() + extra;
            }
            if out.len() >= 4 {
                break;
            }
        }
        if out.is_empty() {
            Err(Fail::Timeout)
        } else {
            Ok(out)
        }
    }

    async fn ask_twice(&mut self, name: &str, qtype: u16, edns: Option<Edns>) -> Option<Reply> {
        for _ in 0..2 {
            match self.ask(name, qtype, edns).await {
                Ok((r, _)) => return Some(r),
                Err(Fail::Timeout) => continue,
                Err(_) => return None,
            }
        }
        None
    }

    async fn burst(&mut self, names: &[String], qtype: u16) -> (usize, usize) {
        let base = self.id;
        let mut sent = 0;
        for (i, name) in names.iter().enumerate() {
            let id = base.wrapping_add(1 + i as u16);
            if !self.build(id, name, qtype, None) {
                continue;
            }
            if self.send().await.is_ok() {
                sent += 1;
            }
        }
        self.id = base.wrapping_add(names.len() as u16);
        let mut got = vec![false; names.len()];
        let deadline = Instant::now() + self.wait;
        let mut count = 0;
        while count < sent {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match self.recv(left).await {
                Ok(n) if n >= 12 => {
                    let off = wire::be16(&self.buf, 0).wrapping_sub(base).wrapping_sub(1) as usize;
                    if off < got.len() && !got[off] && self.buf[2] & 0x80 != 0 {
                        got[off] = true;
                        count += 1;
                    }
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        (count, names.len())
    }
}

async fn framed<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, id: u16, name: &str, qtype: u16, left: Duration) -> Result<Reply, Fail> {
    let mut q = Vec::with_capacity(300);
    q.extend_from_slice(&[0, 0]);
    let mut body = Vec::with_capacity(300);
    if !wire::encode_query(&mut body, id, name, qtype, true, None) {
        return Err(Fail::Build);
    }
    q[0..2].copy_from_slice(&(body.len() as u16).to_be_bytes());
    q.extend_from_slice(&body);
    let work = async {
        stream.write_all(&q).await.map_err(|_| Fail::Io)?;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.map_err(|_| Fail::Io)?;
        let n = u16::from_be_bytes(len) as usize;
        let mut reply = vec![0u8; n];
        stream.read_exact(&mut reply).await.map_err(|_| Fail::Io)?;
        if n < 12 || wire::be16(&reply, 0) != id {
            return Err(Fail::Malformed);
        }
        wire::parse(&reply).ok_or(Fail::Malformed)
    };
    timeout(left, work).await.map_err(|_| Fail::Timeout)?
}

async fn tcp_connect(addr: SocketAddr, protect: &Option<Protect>, wait: Duration) -> Result<TcpStream, Fail> {
    let sock = if addr.is_ipv6() { TcpSocket::new_v6() } else { TcpSocket::new_v4() }.map_err(|_| Fail::Io)?;
    protect_fd(&sock, protect);
    match timeout(wait, sock.connect(addr)).await {
        Err(_) => Err(Fail::Timeout),
        Ok(Err(e)) => Err(if e.kind() == std::io::ErrorKind::ConnectionRefused { Fail::Closed } else { Fail::Io }),
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            Ok(s)
        }
    }
}

async fn tcp_ask(addr: SocketAddr, protect: &Option<Protect>, name: &str, wait: Duration, id: u16) -> Result<u32, Fail> {
    let start = Instant::now();
    let mut s = tcp_connect(addr, protect, wait).await?;
    let left = wait.saturating_sub(start.elapsed()).max(Duration::from_millis(300));
    let r = framed(&mut s, id, name, wire::T_A, left).await?;
    if !r.qr {
        return Err(Fail::Malformed);
    }
    Ok(start.elapsed().as_millis() as u32)
}

async fn dot_ask(
    addr: SocketAddr,
    protect: &Option<Protect>,
    tls: Arc<rustls::ClientConfig>,
    name: &str,
    wait: Duration,
    id: u16,
) -> Result<u32, Fail> {
    let start = Instant::now();
    let tcp = tcp_connect(addr, protect, wait).await?;
    let server = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
    let connector = tokio_rustls::TlsConnector::from(tls);
    let left = wait.saturating_sub(start.elapsed()).max(Duration::from_millis(300));
    let mut stream = match timeout(left, connector.connect(server, tcp)).await {
        Err(_) => return Err(Fail::Timeout),
        Ok(Err(_)) => return Err(Fail::Io),
        Ok(Ok(s)) => s,
    };
    let left = wait.saturating_sub(start.elapsed()).max(Duration::from_millis(300));
    let r = framed(&mut stream, id, name, wire::T_A, left).await?;
    if !r.qr {
        return Err(Fail::Malformed);
    }
    Ok(start.elapsed().as_millis() as u32)
}

fn hijacked_reply(r: &Reply, nets: &[Net]) -> bool {
    r.ipv4.iter().any(|a| {
        let ip = IpAddr::V4(Ipv4Addr::from(*a));
        nets.iter().any(|n| n.contains(&ip))
    })
}

pub async fn run(found: Found, spec: Arc<DeepSpec>, protect: Option<Protect>, stop: Arc<AtomicBool>) -> Option<Deep> {
    let addr = found.addr;
    let mut tcp_mode = found.via == "tcp";
    if tcp_mode {
        let quick = Duration::from_millis(spec.wait.as_millis().min(1200) as u64);
        if let Ok(mut probe) = Conn::open(addr, false, &protect, quick, mix(spec.seed ^ 0x55)).await {
            let mut r = Rng::new(mix(spec.seed ^ addr_key(&addr) ^ 0x77));
            let name = format!("{}.{}", random_label(&mut r, 10), spec.domain);
            if probe.ask(&name, wire::T_A, None).await.is_ok() {
                tcp_mode = false;
            }
        }
    }
    let mut d = Deep {
        ip: addr.ip().to_string(),
        port: addr.port(),
        hijacked: found.hijacked,
        answered_by: found.answered_by.clone(),
        via: found.via.clone(),
        ..Default::default()
    };
    let has_tunnel = !spec.tunnel.is_empty();
    let mut rng = Rng::new(mix(spec.seed ^ addr_key(&addr)));
    let mut u = match Conn::open(addr, tcp_mode, &protect, spec.wait, rng.next_u64()).await {
        Ok(u) => u,
        Err(_) => {
            d.loss = 1.0;
            return Some(d);
        }
    };
    if tcp_mode {
        d.tcp = Some(true);
    } else if found.via == "tcp" {
        d.tcp = Some(true);
        d.via = "both".into();
    }
    let samples = spec.samples.max(1) as usize;
    let mut rtts: Vec<u32> = Vec::with_capacity(samples);
    for i in 0..samples {
        if stop.load(Ordering::Relaxed) {
            return None;
        }
        let name = format!("{}.{}", random_label(&mut rng, 10), spec.domain);
        if let Ok((r, rtt)) = u.ask(&name, wire::T_A, None).await {
            if ok_rcode(&r) {
                rtts.push(rtt);
            }
        }
        if i + 1 < samples {
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
    }
    d.loss = 1.0 - rtts.len() as f32 / samples as f32;
    if rtts.is_empty() {
        d.score = score::compute(&d, has_tunnel);
        return Some(d);
    }
    d.alive = true;
    rtts.sort_unstable();
    d.rtt = percentile(&rtts, 0.5);
    d.rtt_min = rtts[0];
    d.rtt_p90 = percentile(&rtts, 0.9);
    d.jitter = d.rtt_p90.saturating_sub(d.rtt_min);
    let zone = if has_tunnel { spec.tunnel.clone() } else { spec.domain.clone() };
    let edns = Some(Edns { payload: 1232, dnssec_ok: false });
    if has_tunnel {
        let name = format!("{}.{}", random_label(&mut rng, 10), zone);
        match u.ask_twice(&name, wire::T_TXT, edns).await {
            Some(r) => {
                d.tunnel_rcode = Some(r.rcode);
                d.tunnel = Some(ok_rcode(&r));
            }
            None => d.tunnel = Some(false),
        }
    }
    let path_ok = !has_tunnel || d.tunnel == Some(true);
    if path_ok && !spec.ladder.is_empty() {
        let qt = if has_tunnel { wire::T_TXT } else { wire::T_A };
        let mut ladder = spec.ladder.clone();
        ladder.sort_unstable();
        for len in ladder {
            if stop.load(Ordering::Relaxed) {
                return None;
            }
            let Some(name) = long_name(&mut rng, len as usize, &zone) else { continue };
            match u.ask_twice(&name, qt, edns).await {
                Some(r) if ok_rcode(&r) => d.max_qname = len,
                _ => break,
            }
        }
    }
    if has_tunnel && path_ok {
        for &t in &spec.types {
            if stop.load(Ordering::Relaxed) {
                return None;
            }
            let name = format!("{}.{}", random_label(&mut rng, 10), zone);
            let good = matches!(u.ask_twice(&name, t, edns).await, Some(r) if ok_rcode(&r));
            if good {
                d.types_ok.push(wire::type_name(t));
            } else {
                d.types_bad.push(wire::type_name(t));
            }
        }
    }
    if spec.edns {
        match u.ask_twice(".", wire::T_DNSKEY, Some(Edns { payload: 1232, dnssec_ok: true })).await {
            Some(r) => {
                d.edns = Some(r.edns.is_some());
                d.max_reply = r.size.min(u16::MAX as usize) as u16;
                d.truncates = r.tc;
                if !r.tc {
                    if let Some(r2) = u.ask_twice(".", wire::T_DNSKEY, Some(Edns { payload: 4096, dnssec_ok: true })).await {
                        if !r2.tc {
                            d.max_reply = d.max_reply.max(r2.size.min(u16::MAX as usize) as u16);
                        }
                    }
                }
            }
            None => d.edns = Some(false),
        }
        if !d.truncates && d.max_reply < 900 {
            for probe in ["microsoft.com", "google.com"] {
                if let Some(r) = u.ask_twice(probe, wire::T_TXT, Some(Edns { payload: 1232, dnssec_ok: false })).await {
                    if r.edns.is_some() {
                        d.edns = Some(true);
                    }
                    if r.tc {
                        d.max_reply = d.max_reply.max(1232);
                        break;
                    }
                    d.max_reply = d.max_reply.max(r.size.min(u16::MAX as usize) as u16);
                    if d.max_reply >= 900 {
                        break;
                    }
                }
            }
        }
    }
    if spec.nx {
        let name = format!("{}.iana.org", random_label(&mut rng, 14));
        d.nx_ok = u.ask_twice(&name, wire::T_A, None).await.map(|r| r.ipv4.is_empty() && r.ipv6.is_empty());
    }
    if !spec.blocked.is_empty() {
        let mut any = false;
        let mut censored = false;
        let mut injected = false;
        for b in &spec.blocked {
            let Ok(replies) = u.ask_window(b, wire::T_A, None, Duration::from_millis(350)).await else { continue };
            any = true;
            if replies.iter().any(|(r, _)| hijacked_reply(r, &spec.hijack)) {
                censored = true;
            }
            if replies.len() > 1 {
                let first = &replies[0].0;
                if replies.iter().skip(1).any(|(r, _)| r.ipv4 != first.ipv4 || r.rcode != first.rcode) {
                    injected = true;
                }
            }
        }
        if any {
            d.censored = Some(censored);
            if !u.is_tcp() {
                d.injected = Some(injected);
            }
        }
    }
    if spec.burst && spec.burst_size > 0 {
        let names: Vec<String> = (0..spec.burst_size)
            .map(|_| format!("{}.{}", random_label(&mut rng, 10), spec.domain))
            .collect();
        let (got, total) = u.burst(&names, wire::T_A).await;
        d.burst = Some(got as f32 / total.max(1) as f32);
    }
    if spec.tcp && !tcp_mode {
        let name = format!("{}.{}", random_label(&mut rng, 10), spec.domain);
        match tcp_ask(addr, &protect, &name, spec.wait, rng.next_u64() as u16).await {
            Ok(rtt) => {
                d.tcp = Some(true);
                d.tcp_rtt = Some(rtt);
            }
            Err(_) => d.tcp = Some(false),
        }
    }
    if spec.dot {
        if let Some(tls) = spec.tls.clone() {
            let name = format!("{}.{}", random_label(&mut rng, 10), spec.domain);
            let target = SocketAddr::new(addr.ip(), 853);
            match dot_ask(target, &protect, tls, &name, spec.wait, rng.next_u64() as u16).await {
                Ok(rtt) => {
                    d.dot = Some(true);
                    d.dot_rtt = Some(rtt);
                }
                Err(_) => d.dot = Some(false),
            }
        }
    }
    if let Some(cap) = &spec.capture {
        if let Some(seen) = cap.info(&addr.ip()) {
            d.ttl_udp = seen.udp_ttl();
            d.ttl_tcp = seen.tcp_ttl();
            d.hops = d.ttl_udp.or(d.ttl_tcp).map(crate::capture::hops);
            d.dup_answers = seen.duplicates;
            if let (Some(a), Some(b)) = (d.ttl_udp, d.ttl_tcp) {
                d.proxy_suspect = Some(a.abs_diff(b) > 2);
            }
        }
    }
    d.score = score::compute(&d, has_tunnel);
    Some(d)
}

#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub fn tls_config() -> Option<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    Some(Arc::new(config))
}
