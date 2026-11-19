use crate::deep::protect_fd;
use crate::event::Found;
use crate::sweep::Protect;
use crate::targets::{Net, Order, TargetSet};
use crate::util::{mix, random_label, Rng};
use crate::wire;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::sync::Semaphore;

pub struct TcpSpec {
    pub order: Order,
    pub limit: u64,
    pub skip: u64,
    pub seed: u64,
    pub domain: String,
    pub qtype: u16,
    pub rate: u32,
    pub wait: Duration,
    pub concurrency: usize,
    pub hijack: Vec<Net>,
}

#[derive(Default)]
pub struct TcpCounters {
    pub planned: AtomicU64,
    pub sent: AtomicU64,
    pub done: AtomicU64,
    pub found: AtomicU64,
    pub running: AtomicBool,
}

pub async fn sweep(
    set: Arc<TargetSet>,
    spec: Arc<TcpSpec>,
    protect: Option<Protect>,
    stop: Arc<AtomicBool>,
    counters: Arc<TcpCounters>,
    on_found: Arc<dyn Fn(Found) + Send + Sync>,
) -> &'static str {
    counters.running.store(true, Ordering::SeqCst);
    let mut walker = set.walker(spec.order, spec.limit, spec.seed);
    let skipped = walker.skip(spec.skip, &set);
    counters.planned.store(walker.planned().saturating_sub(skipped), Ordering::Relaxed);
    let sem = Arc::new(Semaphore::new(spec.concurrency.max(1)));
    let gap = Duration::from_secs_f64(1.0 / spec.rate.max(1) as f64);
    let start = Instant::now();
    let mut sent: u64 = 0;
    let mut reason = "complete";
    loop {
        if stop.load(Ordering::Relaxed) {
            reason = "stopped";
            break;
        }
        let Some(idx) = walker.next(&set) else { break };
        let addr = set.addr(idx);
        let due = start + gap.mul_f64(sent as f64);
        let now = Instant::now();
        if due > now {
            tokio::time::sleep(due - now).await;
        }
        sent += 1;
        counters.sent.fetch_add(1, Ordering::Relaxed);
        let Ok(permit) = sem.clone().acquire_owned().await else { break };
        let (spec, protect, counters, on_found) = (spec.clone(), protect.clone(), counters.clone(), on_found.clone());
        tokio::spawn(async move {
            if let Some(f) = probe(addr, &spec, &protect, idx).await {
                counters.found.fetch_add(1, Ordering::Relaxed);
                on_found(f);
            }
            counters.done.fetch_add(1, Ordering::Relaxed);
            drop(permit);
        });
    }
    let _ = sem.acquire_many(spec.concurrency.max(1) as u32).await;
    counters.running.store(false, Ordering::SeqCst);
    reason
}

async fn probe(addr: SocketAddr, spec: &TcpSpec, protect: &Option<Protect>, idx: u64) -> Option<Found> {
    let start = Instant::now();
    let sock = if addr.is_ipv6() { TcpSocket::new_v6() } else { TcpSocket::new_v4() }.ok()?;
    protect_fd(&sock, protect);
    let mut stream = tokio::time::timeout(spec.wait, sock.connect(addr)).await.ok()?.ok()?;
    let mut rng = Rng::new(mix(spec.seed ^ idx.wrapping_mul(0x9E37_79B9_7F4A_7C15)));
    let name = format!("{}.{}", random_label(&mut rng, 12), spec.domain);
    let id = rng.next_u64() as u16;
    let mut q = Vec::with_capacity(300);
    if !wire::encode_query(&mut q, id, &name, spec.qtype, true, None) {
        return None;
    }
    let mut framed = (q.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&q);
    let left = spec.wait.saturating_sub(start.elapsed()).max(Duration::from_millis(200));
    let reply = tokio::time::timeout(left, async {
        stream.write_all(&framed).await?;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await?;
        let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut body).await?;
        Ok::<_, std::io::Error>(body)
    })
    .await
    .ok()?
    .ok()?;
    if reply.len() < 12 || wire::be16(&reply, 0) != id {
        return None;
    }
    let r = wire::parse(&reply)?;
    if !r.qr || !(r.rcode == wire::RC_NOERROR || r.rcode == wire::RC_NXDOMAIN) || !(r.ra || !r.aa) {
        return None;
    }
    let hijacked = r.ipv4.iter().any(|a| {
        let ip = IpAddr::V4(Ipv4Addr::from(*a));
        spec.hijack.iter().any(|n| n.contains(&ip))
    });
    Some(Found {
        ip: addr.ip().to_string(),
        port: addr.port(),
        rtt: start.elapsed().as_millis() as u32,
        rcode: r.rcode,
        ra: r.ra,
        aa: r.aa,
        hijacked,
        answered_by: None,
        late: false,
        via: "tcp".into(),
        addr,
    })
}
