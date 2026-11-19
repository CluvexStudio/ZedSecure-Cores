use crate::capture::{self, Capture};
use crate::config::ScanConfig;
use crate::deep::{self, DeepSpec};
use crate::event::{Event, Found, Progress};
use crate::sweep::{self, addr_key, Protect, Sink, SweepSpec};
use crate::targets::{Net, Order, TargetSet};
use crate::tcp::{self, TcpCounters, TcpSpec};
use crate::util::random_u64;
use crate::wire;
use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

struct Shared {
    queue: Mutex<VecDeque<Event>>,
    cv: Condvar,
    finished: AtomicBool,
    last: Mutex<Progress>,
    reasons: Mutex<Vec<String>>,
    enough: AtomicBool,
    deep_queued: AtomicU64,
    deep_done: AtomicU64,
    good: AtomicU64,
    tcp: Arc<TcpCounters>,
    udp_used: bool,
    udp_running: AtomicBool,
    sweeps_left: AtomicU32,
    capture: Option<Arc<Capture>>,
    root: bool,
    started: Instant,
}

impl Shared {
    fn push(&self, e: Event) {
        if let Ok(mut q) = self.queue.lock() {
            q.push_back(e);
        }
        self.cv.notify_all();
    }

    fn decorate(&self, p: &mut Progress) {
        p.deep_queued = self.deep_queued.load(Ordering::Relaxed);
        p.deep_done = self.deep_done.load(Ordering::Relaxed);
        p.good = self.good.load(Ordering::Relaxed);
        p.tcp_planned = self.tcp.planned.load(Ordering::Relaxed);
        p.tcp_done = self.tcp.done.load(Ordering::Relaxed);
        p.tcp_found = self.tcp.found.load(Ordering::Relaxed);
        p.captured = self.capture.as_ref().map(|c| c.packets()).unwrap_or(0);
        p.root = self.root;
        if !self.udp_used {
            p.planned = p.tcp_planned;
            p.done = p.tcp_done;
            p.found = p.tcp_found;
            p.sent = self.tcp.sent.load(Ordering::Relaxed);
            p.elapsed_ms = self.started.elapsed().as_millis() as u64;
            p.sweep_done = !self.tcp.running.load(Ordering::Relaxed) && self.sweeps_left.load(Ordering::SeqCst) == 0;
        }
    }

    fn snapshot(&self) -> Progress {
        let mut p = self.last.lock().map(|p| p.clone()).unwrap_or_default();
        self.decorate(&mut p);
        p
    }

    fn reason(&self) -> String {
        if self.enough.load(Ordering::SeqCst) {
            return "enough".into();
        }
        let reasons = self.reasons.lock().map(|r| r.clone()).unwrap_or_default();
        if reasons.iter().any(|r| r == "stopped") {
            "stopped".into()
        } else if !reasons.is_empty() && reasons.iter().all(|r| r == "error") {
            "error".into()
        } else {
            "complete".into()
        }
    }

    fn finish(&self) {
        if self.finished.load(Ordering::SeqCst) {
            return;
        }
        let mut p = self.snapshot();
        p.sweep_done = true;
        self.push(Event::Done { reason: self.reason(), progress: p });
        self.finished.store(true, Ordering::SeqCst);
        self.cv.notify_all();
    }
}

struct Router {
    shared: Arc<Shared>,
    deep: Mutex<Option<tokio::sync::mpsc::UnboundedSender<Found>>>,
    has_deep: bool,
    seen: Mutex<HashSet<u64>>,
    max_deep: u64,
    queued: AtomicU64,
}

impl Router {
    fn found(&self, f: Found) {
        let fresh = self.seen.lock().map(|mut s| s.insert(addr_key(&f.addr))).unwrap_or(true);
        if !fresh {
            return;
        }
        if !f.hijacked && self.queued.load(Ordering::Relaxed) < self.max_deep {
            if let Ok(guard) = self.deep.lock() {
                if let Some(tx) = guard.as_ref() {
                    self.queued.fetch_add(1, Ordering::Relaxed);
                    self.shared.deep_queued.fetch_add(1, Ordering::Relaxed);
                    if tx.send(f.clone()).is_err() {
                        self.shared.deep_done.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        self.shared.push(Event::Found(f));
    }

    fn sweep_done(&self, reason: &str) {
        if let Ok(mut r) = self.shared.reasons.lock() {
            r.push(reason.to_string());
        }
        if self.shared.sweeps_left.fetch_sub(1, Ordering::SeqCst) == 1 {
            if let Ok(mut d) = self.deep.lock() {
                d.take();
            }
            if !self.has_deep {
                self.shared.finish();
            }
        }
    }
}

pub struct Scan {
    shared: Arc<Shared>,
    stop: Arc<AtomicBool>,
    sweep: Mutex<Option<JoinHandle<()>>>,
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
}

impl Scan {
    pub fn poll(&self, wait: Duration, max: usize) -> Option<Vec<Event>> {
        let mut q = self.shared.queue.lock().ok()?;
        if q.is_empty() {
            if self.shared.finished.load(Ordering::SeqCst) {
                return None;
            }
            q = self.shared.cv.wait_timeout(q, wait).ok()?.0;
            if q.is_empty() && self.shared.finished.load(Ordering::SeqCst) {
                return None;
            }
        }
        let n = q.len().min(max.max(1));
        Some(q.drain(..n).collect())
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn finished(&self) -> bool {
        self.shared.finished.load(Ordering::SeqCst)
    }
}

impl Drop for Scan {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(mut h) = self.sweep.lock() {
            if let Some(h) = h.take() {
                let _ = h.join();
            }
        }
        if let Ok(mut rt) = self.runtime.lock() {
            if let Some(rt) = rt.take() {
                rt.shutdown_timeout(Duration::from_millis(500));
            }
        }
    }
}

struct EngineSink {
    router: Arc<Router>,
}

impl Sink for EngineSink {
    fn found(&mut self, f: Found) {
        self.router.found(f);
    }

    fn progress(&mut self, p: Progress) {
        let shared = &self.router.shared;
        if let Ok(mut last) = shared.last.lock() {
            *last = p.clone();
        }
        shared.push(Event::Progress(p));
    }

    fn intercept(&mut self, by: IpAddr) {
        self.router.shared.push(Event::Intercept { by: by.to_string() });
    }

    fn warning(&mut self, code: &str, msg: String) {
        self.router.shared.push(Event::Warning { code: code.to_string(), msg });
    }

    fn decorate(&self, p: &mut Progress) {
        self.router.shared.decorate(p);
    }
}

fn normalize_domain(d: &str) -> String {
    d.trim().trim_matches('.').to_ascii_lowercase()
}

fn parse_endpoint(s: &str, port: u16) -> Option<SocketAddr> {
    let s = s.trim();
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Some(a);
    }
    s.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, port))
}

fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

pub fn start_json(json: &str, protect: Option<Protect>) -> Result<Scan, String> {
    let cfg: ScanConfig = serde_json::from_str(json).map_err(|e| format!("config: {e}"))?;
    start(cfg, protect)
}

pub fn country_groups(geoip_path: &str, codes: &[String]) -> Result<String, String> {
    let data = std::fs::read(geoip_path).map_err(|e| format!("geoip: {e}"))?;
    let cidrs = crate::targets::geoip_cidrs(&data, codes);
    let groups: Vec<serde_json::Value> = crate::targets::octet_groups(&cidrs)
        .into_iter()
        .map(|(octet, count, ranges)| serde_json::json!({ "octet": octet, "count": count, "ranges": ranges }))
        .collect();
    serde_json::to_string(&groups).map_err(|e| e.to_string())
}

pub fn start(cfg: ScanConfig, protect: Option<Protect>) -> Result<Scan, String> {
    let seed = if cfg.seed == 0 { random_u64() } else { cfg.seed };
    let port = if cfg.port == 0 { 53 } else { cfg.port };
    let mut specs = cfg.targets.clone();
    if !cfg.countries.is_empty() {
        let data = std::fs::read(&cfg.geoip_path).map_err(|e| format!("geoip: {e}"))?;
        let cidrs = crate::targets::keep_octets(crate::targets::geoip_cidrs(&data, &cfg.countries), &cfg.octets);
        if cidrs.is_empty() {
            return Err(format!("no ranges for {} in the geo file", cfg.countries.join(",")));
        }
        specs.push(cidrs.join("\n"));
    }
    let set = TargetSet::parse(&specs, port, cfg.exclude_special);
    if set.total() == 0 {
        return Err(if set.invalid.is_empty() { "no targets".into() } else { format!("no valid targets: {}", set.invalid.join(" ")) });
    }
    let mut domain = normalize_domain(&cfg.domain);
    if domain.is_empty() {
        domain = "google.com".into();
    }
    let domain_wire = wire::name_wire(&domain).ok_or("invalid test domain")?;
    if 1 + 12 + domain_wire.len() > 255 {
        return Err("test domain is too long".into());
    }
    let tunnel = normalize_domain(&cfg.tunnel_domain);
    if !tunnel.is_empty() && wire::name_wire(&tunnel).is_none() {
        return Err("invalid tunnel domain".into());
    }
    let transport = cfg.transport.trim().to_ascii_lowercase();
    let udp_used = transport != "tcp";
    let tcp_used = transport == "tcp" || transport == "both";
    let qtype = wire::type_code(&cfg.qtype).unwrap_or(wire::T_A);
    let hijack: Vec<Net> = cfg.hijack_nets.iter().filter_map(|s| Net::parse(s)).collect();
    let canaries: Vec<SocketAddr> = cfg.canaries.iter().filter_map(|s| parse_endpoint(s, 53)).collect();
    let rate = cfg.rate.clamp(10, 2_000_000);
    let timeout_ms = cfg.timeout_ms.clamp(200, 30_000);
    let n = if cfg.sockets > 0 { (cfg.sockets as usize).min(16) } else { sweep::sockets_needed(rate, timeout_ms) };
    let n4 = if set.has_v4() || cfg.detect_intercept || canaries.iter().any(|c| c.is_ipv4()) { n } else { 0 };
    let n6 = if set.has_v6() || canaries.iter().any(|c| c.is_ipv6()) { n.min(4) } else { 0 };
    let order = Order::parse(&cfg.order);
    let mut warnings: Vec<Event> = Vec::new();
    if !set.invalid.is_empty() {
        warnings.push(Event::Warning { code: "invalid".into(), msg: set.invalid.join(" ") });
    }
    let capture = if cfg.capture {
        match capture::start(Some(cfg.pcap_path.clone())) {
            Ok(c) => Some(Arc::new(c)),
            Err(e) => {
                warnings.push(Event::Warning { code: "capture".into(), msg: e });
                None
            }
        }
    } else {
        None
    };
    let spec = SweepSpec {
        order,
        limit: cfg.limit,
        skip: cfg.skip,
        seed,
        domain_wire,
        qtype,
        rate,
        timeout_ms,
        retries: cfg.retries.min(5),
        adaptive: cfg.adaptive,
        canaries,
        hijack: hijack.clone(),
        detect_intercept: cfg.detect_intercept,
        neighbors: cfg.neighbors,
        neighbor_blocks: cfg.neighbor_blocks.min(4096),
    };
    let tcp_spec = Arc::new(TcpSpec {
        order,
        limit: cfg.limit,
        skip: cfg.skip,
        seed,
        domain: domain.clone(),
        qtype,
        rate: if udp_used { (rate / 4).max(50) } else { rate },
        wait: Duration::from_millis(timeout_ms as u64),
        concurrency: cfg.tcp_concurrency.clamp(1, 4096) as usize,
        hijack: hijack.clone(),
    });
    let deep_spec = Arc::new(DeepSpec {
        domain,
        tunnel,
        wait: Duration::from_millis(cfg.deep_timeout_ms.clamp(300, 15_000) as u64),
        samples: cfg.latency_samples.clamp(1, 20),
        ladder: cfg.qname_ladder.iter().copied().filter(|l| (16..=253).contains(l)).collect(),
        types: cfg.record_types.iter().filter_map(|t| wire::type_code(t)).collect(),
        edns: cfg.check_edns,
        nx: cfg.check_nx,
        burst: cfg.check_burst,
        burst_size: cfg.burst_size.min(64),
        tcp: cfg.check_tcp,
        dot: cfg.check_dot,
        blocked: cfg.blocked_domains.iter().map(|d| normalize_domain(d)).filter(|d| !d.is_empty()).collect(),
        hijack,
        seed,
        tls: if cfg.check_dot { deep::tls_config() } else { None },
        capture: capture.clone(),
    });
    let shared = Arc::new(Shared {
        queue: Mutex::new(VecDeque::new()),
        cv: Condvar::new(),
        finished: AtomicBool::new(false),
        last: Mutex::new(Progress::default()),
        reasons: Mutex::new(Vec::new()),
        enough: AtomicBool::new(false),
        deep_queued: AtomicU64::new(0),
        deep_done: AtomicU64::new(0),
        good: AtomicU64::new(0),
        tcp: Arc::new(TcpCounters::default()),
        udp_used,
        udp_running: AtomicBool::new(udp_used),
        sweeps_left: AtomicU32::new(udp_used as u32 + tcp_used as u32),
        capture,
        root: is_root(),
        started: Instant::now(),
    });
    for w in warnings {
        shared.push(w);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let runtime = if cfg.deep || tcp_used {
        Some(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("zedscan-async")
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };
    let mut deep_tx = None;
    if let (true, Some(rt)) = (cfg.deep, runtime.as_ref()) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Found>();
        rt.spawn(dispatch(
            rx,
            deep_spec,
            protect.clone(),
            stop.clone(),
            shared.clone(),
            cfg.deep_concurrency.clamp(1, 1024) as usize,
            cfg.stop_after as u64,
            cfg.min_score,
        ));
        deep_tx = Some(tx);
    }
    let router = Arc::new(Router {
        shared: shared.clone(),
        has_deep: deep_tx.is_some(),
        deep: Mutex::new(deep_tx),
        seen: Mutex::new(HashSet::new()),
        max_deep: if cfg.max_results == 0 { u64::MAX } else { cfg.max_results as u64 },
        queued: AtomicU64::new(0),
    });
    if let Some(rt) = runtime.as_ref() {
        rt.spawn(ticker(shared.clone()));
        if tcp_used {
            let set_tcp = Arc::new(TargetSet::parse(&specs, port, cfg.exclude_special));
            let (r, st, pr, counters) = (router.clone(), stop.clone(), protect.clone(), shared.tcp.clone());
            let on_found: Arc<dyn Fn(Found) + Send + Sync> = {
                let r = r.clone();
                Arc::new(move |f: Found| r.found(f))
            };
            rt.spawn(async move {
                let reason = tcp::sweep(set_tcp, tcp_spec, pr, st, counters, on_found).await;
                r.sweep_done(reason);
            });
        }
    }
    let handle = if udp_used {
        let (r, st, pr) = (router.clone(), stop.clone(), protect.clone());
        let source_port = cfg.source_port;
        Some(
            std::thread::Builder::new()
                .name("zedscan-sweep".into())
                .spawn(move || {
                    let mut sink = EngineSink { router: r.clone() };
                    let reason = match sweep::open_io(n4, n6, pr.as_ref(), source_port) {
                        Ok(mut io) => sweep::run(set, &spec, io.as_mut(), &st, &mut sink).to_string(),
                        Err(e) => {
                            sink.warning("socket", e);
                            "error".to_string()
                        }
                    };
                    r.shared.udp_running.store(false, Ordering::SeqCst);
                    r.sweep_done(&reason);
                })
                .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };
    Ok(Scan { shared, stop, sweep: Mutex::new(handle), runtime: Mutex::new(runtime) })
}

async fn ticker(shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    loop {
        tick.tick().await;
        if shared.finished.load(Ordering::SeqCst) {
            break;
        }
        if !shared.udp_running.load(Ordering::SeqCst) {
            let p = shared.snapshot();
            shared.push(Event::Progress(p));
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Found>,
    spec: Arc<DeepSpec>,
    protect: Option<Protect>,
    stop: Arc<AtomicBool>,
    shared: Arc<Shared>,
    concurrency: usize,
    stop_after: u64,
    min_score: u8,
) {
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut open = true;
    loop {
        let queued = shared.deep_queued.load(Ordering::Relaxed);
        let done = shared.deep_done.load(Ordering::Relaxed);
        if !open && done >= queued {
            break;
        }
        if !open {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }
        let Some(f) = rx.recv().await else {
            open = false;
            continue;
        };
        let (spec, protect, stop, shared, sem) = (spec.clone(), protect.clone(), stop.clone(), shared.clone(), sem.clone());
        tokio::spawn(async move {
            let permit = sem.acquire_owned().await;
            if permit.is_ok() && !stop.load(Ordering::Relaxed) {
                if let Some(d) = deep::run(f, spec, protect, stop.clone()).await {
                    if d.score >= min_score {
                        let good = shared.good.fetch_add(1, Ordering::Relaxed) + 1;
                        if stop_after > 0 && good >= stop_after {
                            shared.enough.store(true, Ordering::SeqCst);
                            stop.store(true, Ordering::SeqCst);
                        }
                    }
                    shared.push(Event::Result(d));
                }
            }
            shared.deep_done.fetch_add(1, Ordering::Relaxed);
            drop(permit);
        });
    }
    shared.finish();
}
