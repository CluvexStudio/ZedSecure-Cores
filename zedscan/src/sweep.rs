use crate::event::{Found, Progress};
use crate::targets::{Net, Order, TargetSet, Walker};
use crate::util::{mix, push_label_from};
use crate::wire;
use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub type Protect = Arc<dyn Fn(i64) -> bool + Send + Sync>;

pub struct SweepSpec {
    pub order: Order,
    pub limit: u64,
    pub skip: u64,
    pub seed: u64,
    pub domain_wire: Vec<u8>,
    pub qtype: u16,
    pub rate: u32,
    pub timeout_ms: u32,
    pub retries: u8,
    pub adaptive: bool,
    pub canaries: Vec<SocketAddr>,
    pub hijack: Vec<Net>,
    pub detect_intercept: bool,
    pub neighbors: bool,
    pub neighbor_blocks: u32,
}

pub trait Sink {
    fn found(&mut self, f: Found);
    fn progress(&mut self, p: Progress);
    fn intercept(&mut self, by: IpAddr);
    fn warning(&mut self, code: &str, msg: String);
    fn decorate(&self, _p: &mut Progress) {}
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ErrClass {
    Closed,
    Unreachable,
    Prohibited,
    Other,
}

pub enum IoEvent<'b> {
    Packet(SocketAddr, &'b [u8]),
    Error(Option<SocketAddr>, ErrClass, &'b [u8]),
}

pub struct SendOutcome {
    pub sent: usize,
    pub congested: bool,
    pub failed: Vec<usize>,
}

pub trait Io {
    fn count(&self) -> usize;
    fn is_v6(&self, s: usize) -> bool;
    fn send(&mut self, s: usize, pkts: &[(SocketAddr, usize, usize, u32)], arena: &[u8]) -> SendOutcome;
    fn drain(&mut self, s: usize, on: &mut dyn FnMut(IoEvent));
    fn wait(&mut self, ms: u32);
}

const IDS: usize = 65536;
const ID_STEP: u16 = 40503;
const LABEL_LEN: usize = 12;
const ST_FREE: u8 = 0;
const ST_PENDING: u8 = 1;
const ST_DONE: u8 = 2;
const ST_EXPIRED: u8 = 3;
const K_TARGET: u8 = 0;
const K_CANARY: u8 = 1;
const K_TESTNET: u8 = 2;
const MIN_RATE: f64 = 50.0;

#[derive(Clone, Copy)]
struct Canary {
    target: u64,
    win_ok: u32,
    win_bad: u32,
    ok: u32,
    bad: u32,
    fixed: bool,
}

impl Canary {
    fn new(target: u64, fixed: bool) -> Canary {
        Canary { target, win_ok: 0, win_bad: 0, ok: 0, bad: 0, fixed }
    }
}

#[derive(Clone, Copy, Default)]
struct Slot {
    target: u64,
    sent: u32,
    seq: u16,
    attempt: u8,
    state: u8,
    kind: u8,
}

pub fn sockets_needed(rate: u32, timeout_ms: u32) -> usize {
    let inflight = rate as u64 * timeout_ms.max(1) as u64 / 1000;
    (((inflight * 3 / 2) / 50_000) as usize + 1).clamp(1, 16)
}

pub fn addr_key(a: &SocketAddr) -> u64 {
    let ip = match a.ip() {
        IpAddr::V4(v) => u32::from(v) as u128,
        IpAddr::V6(v) => u128::from(v) ^ (1u128 << 127),
    };
    mix((ip as u64) ^ mix((ip >> 64) as u64) ^ ((a.port() as u64) << 48))
}

fn label_seed(seed: u64, target: u64, attempt: u8) -> u64 {
    mix(seed ^ target.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ ((attempt as u64) << 56))
}

struct Engine<'a> {
    spec: &'a SweepSpec,
    set: TargetSet,
    walker: Walker,
    slots: Vec<Slot>,
    next_id: Vec<u16>,
    socks4: Vec<usize>,
    socks6: Vec<usize>,
    rr4: usize,
    rr6: usize,
    seq: u16,
    fifo: VecDeque<(u32, u16, u32)>,
    retry: VecDeque<(u64, u8)>,
    priority: VecDeque<(u64, u8)>,
    inflight: u64,
    focused: HashSet<u32>,
    seen: HashSet<u64>,
    canaries: Vec<Canary>,
    canary_rr: usize,
    canary_next: u32,
    baseline: Option<f32>,
    windows: u32,
    adaptive: bool,
    reduced: bool,
    start: Instant,
    rate: f64,
    target_rate: f64,
    credit: f64,
    last_ms: u32,
    last_ramp: u32,
    last_adjust: u32,
    last_progress: u32,
    stats: Progress,
    extra_planned: u64,
    exhausted: bool,
    batches: Vec<Vec<(SocketAddr, usize, usize, u32)>>,
    arena: Vec<u8>,
    qbuf: Vec<u8>,
}

pub fn run<S: Sink>(set: TargetSet, spec: &SweepSpec, io: &mut dyn Io, stop: &AtomicBool, sink: &mut S) -> &'static str {
    let mut walker = set.walker(spec.order, spec.limit, spec.seed);
    let skipped = walker.skip(spec.skip, &set);
    let n = io.count();
    let mut socks4 = Vec::new();
    let mut socks6 = Vec::new();
    for s in 0..n {
        if io.is_v6(s) {
            socks6.push(s);
        } else {
            socks4.push(s);
        }
    }
    let target_rate = spec.rate.max(10) as f64;
    let mut e = Engine {
        spec,
        set,
        walker,
        slots: vec![Slot::default(); n * IDS],
        next_id: (0..n).map(|i| (mix(spec.seed ^ i as u64) & 0xFFFF) as u16).collect(),
        socks4,
        socks6,
        rr4: 0,
        rr6: 0,
        seq: 0,
        fifo: VecDeque::with_capacity(4096),
        retry: VecDeque::new(),
        priority: VecDeque::new(),
        inflight: 0,
        focused: HashSet::new(),
        seen: HashSet::new(),
        canaries: Vec::new(),
        canary_rr: 0,
        canary_next: 0,
        baseline: None,
        windows: 0,
        adaptive: spec.adaptive,
        reduced: false,
        start: Instant::now(),
        rate: if spec.adaptive { (target_rate / 8.0).max(200.0).min(target_rate) } else { target_rate },
        target_rate,
        credit: 0.0,
        last_ms: 0,
        last_ramp: 0,
        last_adjust: 0,
        last_progress: 0,
        stats: Progress { target_rate: spec.rate, skipped, walked: skipped, ..Default::default() },
        extra_planned: 0,
        exhausted: false,
        batches: vec![Vec::with_capacity(256); n],
        arena: Vec::with_capacity(256 * 128),
        qbuf: Vec::with_capacity(300),
    };
    if spec.detect_intercept && !e.socks4.is_empty() {
        for ip in [Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 1), Ipv4Addr::new(203, 0, 113, 1)] {
            let idx = e.set.push_extra(SocketAddr::new(IpAddr::V4(ip), 53));
            e.priority.push_back((idx, K_TESTNET));
        }
    }
    for c in &spec.canaries {
        let ok = if c.is_ipv6() { !e.socks6.is_empty() } else { !e.socks4.is_empty() };
        if ok {
            let idx = e.set.push_extra(*c);
            e.canaries.push(Canary::new(idx, true));
        }
    }
    let reason = e.run_loop(io, stop, sink);
    e.emit(sink, true);
    reason
}

impl<'a> Engine<'a> {
    fn now(&self) -> u32 {
        self.start.elapsed().as_millis() as u32
    }

    fn run_loop<S: Sink>(&mut self, io: &mut dyn Io, stop: &AtomicBool, sink: &mut S) -> &'static str {
        loop {
            if stop.load(Ordering::Relaxed) {
                return "stopped";
            }
            let now = self.now();
            let dt = now.saturating_sub(self.last_ms) as f64 / 1000.0;
            self.last_ms = now;
            self.credit = (self.credit + dt * self.rate).min(self.rate * 0.05 + 64.0);
            self.pace(now, sink);
            if self.adaptive && !self.canaries.is_empty() && now >= self.canary_next && !self.finished_sending() {
                self.canary_next = now + 100;
                let c = self.canaries[self.canary_rr % self.canaries.len()].target;
                self.canary_rr += 1;
                self.stage(c, 0, K_CANARY, now);
            }
            let mut budget = (self.credit as usize).min(1024);
            while budget > 0 {
                let next = if let Some(p) = self.priority.pop_front() {
                    Some((p.0, 0u8, p.1))
                } else if let Some(r) = self.retry.pop_front() {
                    Some((r.0, r.1, K_TARGET))
                } else if !self.exhausted {
                    match self.walker.next(&self.set) {
                        Some(t) => {
                            self.stats.walked += 1;
                            Some((t, 0, K_TARGET))
                        }
                        None => {
                            self.exhausted = true;
                            None
                        }
                    }
                } else {
                    None
                };
                let Some((target, attempt, kind)) = next else { break };
                if self.stage(target, attempt, kind, now) {
                    budget -= 1;
                    self.credit -= 1.0;
                } else {
                    if kind == K_TARGET {
                        self.retry.push_front((target, attempt));
                    } else {
                        self.priority.push_front((target, kind));
                    }
                    break;
                }
            }
            self.flush(io, now);
            for s in 0..io.count() {
                io.drain(s, &mut |ev| match ev {
                    IoEvent::Packet(src, data) => self.on_reply(s, src, data, sink),
                    IoEvent::Error(dst, class, data) => self.on_error(s, dst, class, data),
                });
            }
            let now = self.now();
            while let Some(&(idx, seq, deadline)) = self.fifo.front() {
                if deadline > now {
                    break;
                }
                self.fifo.pop_front();
                self.expire(idx as usize, seq);
            }
            if now.saturating_sub(self.last_progress) >= 250 {
                self.last_progress = now;
                self.emit(sink, false);
            }
            if self.finished_sending() && self.inflight == 0 {
                return "complete";
            }
            let wait = if !self.finished_sending() {
                if self.credit >= 1.0 {
                    0
                } else {
                    (((1.0 - self.credit) / self.rate * 1000.0).ceil() as u32).clamp(1, 20)
                }
            } else {
                match self.fifo.front() {
                    Some(&(_, _, d)) => d.saturating_sub(now).clamp(1, 20),
                    None => 5,
                }
            };
            if wait > 0 {
                io.wait(wait);
            }
        }
    }

    fn finished_sending(&self) -> bool {
        self.exhausted && self.retry.is_empty() && self.priority.is_empty()
    }

    fn pace<S: Sink>(&mut self, now: u32, sink: &mut S) {
        if !self.reduced && self.rate < self.target_rate && now.saturating_sub(self.last_ramp) >= 300 {
            self.last_ramp = now;
            self.rate = (self.rate * 1.3).min(self.target_rate);
        }
        if !self.adaptive || now.saturating_sub(self.last_adjust) < 1000 {
            return;
        }
        self.canaries.retain(|c| c.fixed || c.ok + c.bad < 20 || (c.bad as f32) / ((c.ok + c.bad) as f32) <= 0.3);
        let mut best: Option<f32> = None;
        let mut fixed_only = true;
        for c in &self.canaries {
            let life = c.ok + c.bad;
            let trusted = c.fixed || (life >= 10 && c.bad * 5 <= life);
            let resolved = c.win_ok + c.win_bad;
            if trusted && resolved >= 3 {
                let loss = c.win_bad as f32 / resolved as f32;
                best = Some(best.map_or(loss, |b: f32| b.min(loss)));
                fixed_only &= c.fixed;
            }
        }
        let Some(loss) = best else { return };
        self.last_adjust = now;
        for c in &mut self.canaries {
            c.win_ok = 0;
            c.win_bad = 0;
        }
        self.stats.canary_loss = loss;
        self.windows += 1;
        if fixed_only && self.windows <= 2 && loss > 0.9 {
            self.adaptive = false;
            self.rate = self.target_rate.min(self.rate.max(self.target_rate / 2.0));
            sink.warning("canaries", "reference resolvers do not answer; running at a fixed rate".into());
            return;
        }
        let base = match self.baseline {
            Some(b) => b.min(loss),
            None => loss,
        };
        self.baseline = Some(base);
        if loss > (base + 0.15).max(0.2) {
            self.rate = (self.rate * 0.7).max(MIN_RATE);
            self.reduced = true;
        } else if loss <= base + 0.05 && self.rate < self.target_rate {
            self.rate = (self.rate * 1.15 + 20.0).min(self.target_rate);
        }
    }

    fn sock_at(&self, v6: bool, k: usize) -> Option<usize> {
        let list = if v6 { &self.socks6 } else { &self.socks4 };
        if list.is_empty() {
            return None;
        }
        let rr = if v6 { self.rr6 } else { self.rr4 };
        Some(list[(rr + k) % list.len()])
    }

    fn stage(&mut self, target: u64, attempt: u8, kind: u8, now: u32) -> bool {
        let addr = self.set.addr(target);
        let v6 = addr.is_ipv6();
        let n = if v6 { self.socks6.len() } else { self.socks4.len() };
        if n == 0 {
            if kind == K_TARGET {
                self.stats.unreachable += 1;
            }
            return true;
        }
        for k in 0..n {
            let Some(s) = self.sock_at(v6, k) else { return true };
            let id = self.next_id[s];
            let idx = s * IDS + id as usize;
            if self.slots[idx].state == ST_PENDING {
                continue;
            }
            let off = self.arena.len();
            self.arena.extend_from_slice(&id.to_be_bytes());
            self.arena.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
            self.arena.push(LABEL_LEN as u8);
            push_label_from(&mut self.arena, label_seed(self.spec.seed, target, attempt), LABEL_LEN);
            self.arena.extend_from_slice(&self.spec.domain_wire);
            self.arena.extend_from_slice(&self.spec.qtype.to_be_bytes());
            self.arena.extend_from_slice(&[0, 1]);
            let len = self.arena.len() - off;
            self.seq = self.seq.wrapping_add(1);
            self.slots[idx] = Slot { target, sent: now, seq: self.seq, attempt, state: ST_PENDING, kind };
            self.fifo.push_back((idx as u32, self.seq, now + self.spec.timeout_ms));
            self.batches[s].push((addr, off, len, idx as u32));
            self.next_id[s] = id.wrapping_add(ID_STEP);
            if v6 {
                self.rr6 = (self.rr6 + k + 1) % n;
            } else {
                self.rr4 = (self.rr4 + k + 1) % n;
            }
            if kind != K_CANARY {
                self.inflight += 1;
            }
            if kind == K_TARGET {
                self.stats.sent += 1;
            }
            return true;
        }
        false
    }

    fn flush(&mut self, io: &mut dyn Io, now: u32) {
        let mut congested = false;
        for s in 0..self.batches.len() {
            if self.batches[s].is_empty() {
                continue;
            }
            let batch = std::mem::take(&mut self.batches[s]);
            let out = io.send(s, &batch, &self.arena);
            congested |= out.congested;
            for &i in &out.failed {
                if let Some(&(_, _, _, idx)) = batch.get(i) {
                    let slot = self.slots[idx as usize];
                    if slot.state == ST_PENDING {
                        self.slots[idx as usize].state = ST_DONE;
                        self.leave(slot.kind);
                        if slot.kind == K_TARGET && self.seen.insert(addr_key(&self.set.addr(slot.target))) {
                            self.stats.unreachable += 1;
                        }
                    }
                }
            }
            for &(_, _, _, idx) in &batch[out.sent.min(batch.len())..] {
                let slot = self.slots[idx as usize];
                if slot.state != ST_PENDING {
                    continue;
                }
                self.slots[idx as usize].state = ST_FREE;
                self.leave(slot.kind);
                if slot.kind == K_TARGET {
                    self.stats.sent = self.stats.sent.saturating_sub(1);
                    self.retry.push_front((slot.target, slot.attempt));
                } else if slot.kind == K_TESTNET {
                    self.priority.push_front((slot.target, slot.kind));
                }
            }
            let mut batch = batch;
            batch.clear();
            self.batches[s] = batch;
        }
        self.arena.clear();
        if congested {
            self.rate = (self.rate * 0.85).max(MIN_RATE);
            self.credit = self.credit.min(0.0);
            self.reduced = true;
        }
        let _ = now;
    }

    fn canary_result(&mut self, target: u64, ok: bool) {
        if let Some(c) = self.canaries.iter_mut().find(|c| c.target == target) {
            if ok {
                c.win_ok += 1;
                c.ok += 1;
            } else {
                c.win_bad += 1;
                c.bad += 1;
            }
        }
    }

    fn leave(&mut self, kind: u8) {
        if kind != K_CANARY {
            self.inflight = self.inflight.saturating_sub(1);
        }
    }

    fn expected_question(&mut self, target: u64, attempt: u8) {
        self.qbuf.clear();
        self.qbuf.push(LABEL_LEN as u8);
        push_label_from(&mut self.qbuf, label_seed(self.spec.seed, target, attempt), LABEL_LEN);
        self.qbuf.extend_from_slice(&self.spec.domain_wire);
    }

    fn on_reply<S: Sink>(&mut self, s: usize, src: SocketAddr, data: &[u8], sink: &mut S) {
        if data.len() < 12 {
            return;
        }
        self.stats.recv += 1;
        let id = wire::be16(data, 0);
        let idx = s * IDS + id as usize;
        let slot = self.slots[idx];
        if slot.state != ST_PENDING && slot.state != ST_EXPIRED {
            return;
        }
        self.expected_question(slot.target, slot.attempt);
        if !wire::question_is(data, &self.qbuf, self.spec.qtype) {
            return;
        }
        let Some(r) = wire::parse(data) else { return };
        if !r.qr {
            return;
        }
        let was_pending = slot.state == ST_PENDING;
        self.slots[idx].state = ST_DONE;
        if was_pending {
            self.leave(slot.kind);
        }
        let now = self.now();
        let rtt = now.saturating_sub(slot.sent);
        match slot.kind {
            K_CANARY => {
                if was_pending {
                    self.canary_result(slot.target, true);
                }
            }
            K_TESTNET => {
                self.stats.intercepted += 1;
                sink.intercept(src.ip());
            }
            _ => {
                let target = self.set.addr(slot.target);
                if !self.seen.insert(addr_key(&target)) {
                    return;
                }
                let late = !was_pending;
                if late {
                    self.stats.late += 1;
                    if slot.attempt >= self.spec.retries {
                        self.stats.timeouts = self.stats.timeouts.saturating_sub(1);
                    }
                }
                let answered_by = if src.ip() != target.ip() {
                    self.stats.intercepted += 1;
                    Some(src.ip().to_string())
                } else {
                    None
                };
                match r.rcode {
                    wire::RC_REFUSED => self.stats.refused += 1,
                    wire::RC_SERVFAIL => self.stats.servfail += 1,
                    wire::RC_NOERROR | wire::RC_NXDOMAIN if r.ra || !r.aa => {
                        let hijacked = r.ipv4.iter().any(|a| {
                            let ip = IpAddr::V4(Ipv4Addr::from(*a));
                            self.spec.hijack.iter().any(|n| n.contains(&ip))
                        }) || r.ipv6.iter().any(|a| {
                            let ip = IpAddr::V6(std::net::Ipv6Addr::from(*a));
                            self.spec.hijack.iter().any(|n| n.contains(&ip))
                        });
                        self.stats.found += 1;
                        if hijacked {
                            self.stats.hijacked += 1;
                        }
                        if !hijacked && answered_by.is_none() && rtt < 300 && self.adaptive && self.canaries.len() < 4 {
                            self.canaries.push(Canary::new(slot.target, false));
                        }
                        if !hijacked {
                            self.expand(target);
                        }
                        sink.found(Found {
                            ip: target.ip().to_string(),
                            port: target.port(),
                            rtt,
                            rcode: r.rcode,
                            ra: r.ra,
                            aa: r.aa,
                            hijacked,
                            answered_by,
                            late,
                            via: "udp".into(),
                            addr: target,
                        });
                    }
                    _ => self.stats.other += 1,
                }
            }
        }
    }

    fn expand(&mut self, target: SocketAddr) {
        if !self.spec.neighbors || self.focused.len() as u32 >= self.spec.neighbor_blocks {
            return;
        }
        let IpAddr::V4(v4) = target.ip() else { return };
        let ip = u32::from(v4);
        let block = ip >> 8;
        if !self.focused.insert(block) {
            return;
        }
        for h in 1..=254u32 {
            let a = (block << 8) | h;
            if a == ip {
                continue;
            }
            let idx = self.set.push_extra(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(a)), target.port()));
            self.priority.push_back((idx, K_TARGET));
            self.extra_planned += 1;
        }
    }

    fn on_error(&mut self, s: usize, dst: Option<SocketAddr>, class: ErrClass, payload: &[u8]) {
        if payload.len() < 2 {
            return;
        }
        let id = wire::be16(payload, 0);
        let idx = s * IDS + id as usize;
        let slot = self.slots[idx];
        if slot.state != ST_PENDING {
            return;
        }
        let target = self.set.addr(slot.target);
        if let Some(d) = dst {
            if d != target {
                return;
            }
        }
        self.slots[idx].state = ST_DONE;
        self.leave(slot.kind);
        match slot.kind {
            K_CANARY => self.canary_result(slot.target, false),
            K_TESTNET => {}
            _ => {
                if !self.seen.insert(addr_key(&target)) {
                    return;
                }
                match class {
                    ErrClass::Closed => self.stats.closed += 1,
                    _ => self.stats.unreachable += 1,
                }
            }
        }
    }

    fn expire(&mut self, idx: usize, seq: u16) {
        let slot = self.slots[idx];
        if slot.seq != seq || slot.state != ST_PENDING {
            return;
        }
        self.slots[idx].state = ST_EXPIRED;
        self.leave(slot.kind);
        match slot.kind {
            K_CANARY => self.canary_result(slot.target, false),
            K_TESTNET => {}
            _ => {
                if slot.attempt < self.spec.retries {
                    self.retry.push_back((slot.target, slot.attempt + 1));
                } else if !self.seen.contains(&addr_key(&self.set.addr(slot.target))) {
                    self.stats.timeouts += 1;
                }
            }
        }
    }

    fn emit<S: Sink>(&mut self, sink: &mut S, last: bool) {
        let st = &mut self.stats;
        st.planned = self.walker.planned().saturating_sub(st.skipped) + self.extra_planned;
        st.done = st.found + st.refused + st.servfail + st.other + st.timeouts + st.closed + st.unreachable;
        st.rate = self.rate.round() as u32;
        st.target_rate = self.target_rate as u32;
        st.elapsed_ms = self.start.elapsed().as_millis() as u64;
        let left = st.planned.saturating_sub(st.done);
        st.eta_ms = if left == 0 { 0 } else { left * 1000 / (self.rate.max(1.0) as u64) + self.spec.timeout_ms as u64 };
        st.sweep_done = last;
        let mut p = st.clone();
        sink.decorate(&mut p);
        sink.progress(p);
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod mmsg {
    use super::{ErrClass, Io, IoEvent, Protect, SendOutcome};
    use std::mem::{size_of, zeroed};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    const BATCH: usize = 64;
    const RXLEN: usize = 2048;
    const IP_RECVERR: libc::c_int = 11;
    const IPV6_RECVERR: libc::c_int = 25;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ExtErr {
        errno: u32,
        origin: u8,
        typ: u8,
        code: u8,
        pad: u8,
        info: u32,
        data: u32,
    }

    pub struct MmsgIo {
        fds: Vec<(libc::c_int, bool)>,
        rx: Vec<u8>,
        names: Vec<libc::sockaddr_storage>,
        iov: Vec<libc::iovec>,
        hdrs: Vec<libc::mmsghdr>,
        tx_names: Vec<libc::sockaddr_storage>,
        tx_iov: Vec<libc::iovec>,
        tx_hdrs: Vec<libc::mmsghdr>,
        pollfds: Vec<libc::pollfd>,
        err_buf: Vec<u8>,
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn opt(fd: libc::c_int, level: libc::c_int, name: libc::c_int, value: libc::c_int) {
        unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &value as *const _ as *const libc::c_void,
                size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    pub fn to_storage(a: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
        unsafe {
            let mut st: libc::sockaddr_storage = zeroed();
            match a {
                SocketAddr::V4(v) => {
                    let sin = &mut st as *mut _ as *mut libc::sockaddr_in;
                    (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
                    (*sin).sin_port = v.port().to_be();
                    (*sin).sin_addr = libc::in_addr { s_addr: u32::from_ne_bytes(v.ip().octets()) };
                    (st, size_of::<libc::sockaddr_in>() as libc::socklen_t)
                }
                SocketAddr::V6(v) => {
                    let sin6 = &mut st as *mut _ as *mut libc::sockaddr_in6;
                    (*sin6).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    (*sin6).sin6_port = v.port().to_be();
                    (*sin6).sin6_addr = libc::in6_addr { s6_addr: v.ip().octets() };
                    (*sin6).sin6_flowinfo = 0;
                    (*sin6).sin6_scope_id = v.scope_id();
                    (st, size_of::<libc::sockaddr_in6>() as libc::socklen_t)
                }
            }
        }
    }

    pub fn from_storage(st: &libc::sockaddr_storage) -> Option<SocketAddr> {
        unsafe {
            match st.ss_family as libc::c_int {
                libc::AF_INET => {
                    let sin = &*(st as *const _ as *const libc::sockaddr_in);
                    let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
                    Some(SocketAddr::new(IpAddr::V4(ip), u16::from_be(sin.sin_port)))
                }
                libc::AF_INET6 => {
                    let sin6 = &*(st as *const _ as *const libc::sockaddr_in6);
                    let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    let ip = match ip.to_ipv4_mapped() {
                        Some(v4) => IpAddr::V4(v4),
                        None => IpAddr::V6(ip),
                    };
                    Some(SocketAddr::new(ip, u16::from_be(sin6.sin6_port)))
                }
                _ => None,
            }
        }
    }

    impl MmsgIo {
        pub fn open(n4: usize, n6: usize, protect: Option<&Protect>, source_port: u16) -> Result<MmsgIo, String> {
            let mut fds = Vec::new();
            for (count, v6) in [(n4, false), (n6, true)] {
                for _ in 0..count {
                    let family = if v6 { libc::AF_INET6 } else { libc::AF_INET };
                    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
                    if fd < 0 {
                        if v6 {
                            break;
                        }
                        return Err(format!("socket: {}", std::io::Error::last_os_error()));
                    }
                    if let Some(p) = protect {
                        p(fd as i64);
                    }
                    opt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, 4 << 20);
                    opt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, 2 << 20);
                    let (st, len) = if v6 {
                        opt(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1);
                        opt(fd, libc::IPPROTO_IPV6, IPV6_RECVERR, 1);
                        to_storage(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), source_port))
                    } else {
                        opt(fd, libc::IPPROTO_IP, IP_RECVERR, 1);
                        to_storage(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), source_port))
                    };
                    let rc = unsafe { libc::bind(fd, &st as *const _ as *const libc::sockaddr, len) };
                    if rc < 0 {
                        unsafe { libc::close(fd) };
                        if v6 {
                            break;
                        }
                        return Err(format!("bind: {}", std::io::Error::last_os_error()));
                    }
                    fds.push((fd, v6));
                }
            }
            if fds.is_empty() {
                return Err("no sockets".into());
            }
            unsafe {
                Ok(MmsgIo {
                    pollfds: vec![libc::pollfd { fd: -1, events: 0, revents: 0 }; fds.len()],
                    fds,
                    rx: vec![0u8; BATCH * RXLEN],
                    names: vec![zeroed(); BATCH],
                    iov: vec![zeroed(); BATCH],
                    hdrs: vec![zeroed(); BATCH],
                    tx_names: vec![zeroed(); BATCH],
                    tx_iov: vec![zeroed(); BATCH],
                    tx_hdrs: vec![zeroed(); BATCH],
                    err_buf: vec![0u8; 2048],
                })
            }
        }
    }

    impl Drop for MmsgIo {
        fn drop(&mut self) {
            for (fd, _) in &self.fds {
                unsafe { libc::close(*fd) };
            }
        }
    }

    fn classify(e: &ExtErr) -> ErrClass {
        match (e.origin, e.typ, e.code) {
            (2, 3, 3) | (3, 1, 4) => ErrClass::Closed,
            (2, 3, 0) | (2, 3, 1) | (2, 3, 6) | (2, 3, 7) | (3, 1, 0) | (3, 1, 3) => ErrClass::Unreachable,
            (2, 3, 9) | (2, 3, 10) | (2, 3, 13) | (3, 1, 1) | (3, 1, 5) | (3, 1, 6) => ErrClass::Prohibited,
            _ => match e.errno as i32 {
                libc::ECONNREFUSED => ErrClass::Closed,
                libc::EHOSTUNREACH | libc::ENETUNREACH => ErrClass::Unreachable,
                _ => ErrClass::Other,
            },
        }
    }

    impl Io for MmsgIo {
        fn count(&self) -> usize {
            self.fds.len()
        }

        fn is_v6(&self, s: usize) -> bool {
            self.fds[s].1
        }

        fn send(&mut self, s: usize, pkts: &[(SocketAddr, usize, usize, u32)], arena: &[u8]) -> SendOutcome {
            let fd = self.fds[s].0;
            let mut sent = 0;
            let mut congested = false;
            let mut failed = Vec::new();
            while sent < pkts.len() {
                let chunk = &pkts[sent..(sent + BATCH).min(pkts.len())];
                for (i, p) in chunk.iter().enumerate() {
                    let (st, len) = to_storage(&p.0);
                    self.tx_names[i] = st;
                    self.tx_iov[i] = libc::iovec {
                        iov_base: arena[p.1..p.1 + p.2].as_ptr() as *mut libc::c_void,
                        iov_len: p.2,
                    };
                    let h = &mut self.tx_hdrs[i];
                    unsafe { *h = zeroed() };
                    h.msg_hdr.msg_name = &mut self.tx_names[i] as *mut _ as *mut libc::c_void;
                    h.msg_hdr.msg_namelen = len;
                    h.msg_hdr.msg_iov = &mut self.tx_iov[i];
                    h.msg_hdr.msg_iovlen = 1;
                }
                let r = unsafe { libc::sendmmsg(fd, self.tx_hdrs.as_mut_ptr(), chunk.len() as _, 0) };
                if r < 0 {
                    let e = errno();
                    if e == libc::EINTR {
                        continue;
                    }
                    if e == libc::EAGAIN || e == libc::EWOULDBLOCK || e == libc::ENOBUFS || e == libc::ENOMEM {
                        congested = true;
                        break;
                    }
                    failed.push(sent);
                    sent += 1;
                    continue;
                }
                sent += r as usize;
            }
            SendOutcome { sent, congested, failed }
        }

        fn drain(&mut self, s: usize, on: &mut dyn FnMut(IoEvent)) {
            let fd = self.fds[s].0;
            let mut guard = 0;
            loop {
                guard += 1;
                if guard > 64 {
                    break;
                }
                for i in 0..BATCH {
                    self.iov[i] = libc::iovec {
                        iov_base: self.rx[i * RXLEN..].as_mut_ptr() as *mut libc::c_void,
                        iov_len: RXLEN,
                    };
                    let h = &mut self.hdrs[i];
                    unsafe { *h = zeroed() };
                    h.msg_hdr.msg_name = &mut self.names[i] as *mut _ as *mut libc::c_void;
                    h.msg_hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                    h.msg_hdr.msg_iov = &mut self.iov[i];
                    h.msg_hdr.msg_iovlen = 1;
                }
                let r = unsafe {
                    libc::recvmmsg(fd, self.hdrs.as_mut_ptr(), BATCH as _, libc::MSG_DONTWAIT, std::ptr::null_mut())
                };
                if r < 0 {
                    let e = errno();
                    if e == libc::EINTR {
                        continue;
                    }
                    if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                        break;
                    }
                    if matches!(
                        e,
                        libc::ECONNREFUSED
                            | libc::EHOSTUNREACH
                            | libc::ENETUNREACH
                            | libc::EHOSTDOWN
                            | libc::ENETDOWN
                            | libc::EACCES
                            | libc::EPERM
                            | libc::EPROTO
                    ) {
                        continue;
                    }
                    break;
                }
                let n = r as usize;
                for i in 0..n {
                    let len = (self.hdrs[i].msg_len as usize).min(RXLEN);
                    if let Some(src) = from_storage(&self.names[i]) {
                        on(IoEvent::Packet(src, &self.rx[i * RXLEN..i * RXLEN + len]));
                    }
                }
                if n < BATCH {
                    break;
                }
            }
            for _ in 0..4096 {
                unsafe {
                    let mut name: libc::sockaddr_storage = zeroed();
                    let mut iov = libc::iovec {
                        iov_base: self.err_buf.as_mut_ptr() as *mut libc::c_void,
                        iov_len: self.err_buf.len(),
                    };
                    let mut ctrl = [0u64; 64];
                    let mut msg: libc::msghdr = zeroed();
                    msg.msg_name = &mut name as *mut _ as *mut libc::c_void;
                    msg.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                    msg.msg_iov = &mut iov;
                    msg.msg_iovlen = 1;
                    msg.msg_control = ctrl.as_mut_ptr() as *mut libc::c_void;
                    msg.msg_controllen = std::mem::size_of_val(&ctrl) as _;
                    let n = libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT);
                    if n < 0 {
                        if errno() == libc::EINTR {
                            continue;
                        }
                        break;
                    }
                    let mut class = ErrClass::Other;
                    let mut cm = libc::CMSG_FIRSTHDR(&msg);
                    while !cm.is_null() {
                        let h = &*cm;
                        if (h.cmsg_level == libc::IPPROTO_IP && h.cmsg_type == IP_RECVERR)
                            || (h.cmsg_level == libc::IPPROTO_IPV6 && h.cmsg_type == IPV6_RECVERR)
                        {
                            let ee = std::ptr::read_unaligned(libc::CMSG_DATA(cm) as *const ExtErr);
                            class = classify(&ee);
                        }
                        cm = libc::CMSG_NXTHDR(&msg, cm);
                    }
                    let dst = from_storage(&name);
                    let len = (n as usize).min(self.err_buf.len());
                    on(IoEvent::Error(dst, class, &self.err_buf[..len]));
                }
            }
        }

        fn wait(&mut self, ms: u32) {
            for (i, (fd, _)) in self.fds.iter().enumerate() {
                self.pollfds[i] = libc::pollfd { fd: *fd, events: libc::POLLIN, revents: 0 };
            }
            unsafe {
                libc::poll(self.pollfds.as_mut_ptr(), self.pollfds.len() as _, ms as libc::c_int);
            }
        }
    }
}

pub mod portable {
    use super::{Io, IoEvent, Protect, SendOutcome};
    use std::net::{SocketAddr, UdpSocket};

    pub struct StdIo {
        socks: Vec<(UdpSocket, bool)>,
        buf: Vec<u8>,
    }

    impl StdIo {
        pub fn open(n4: usize, n6: usize, protect: Option<&Protect>, source_port: u16) -> Result<StdIo, String> {
            let mut socks = Vec::new();
            for (count, v6) in [(n4, false), (n6, true)] {
                for _ in 0..count {
                    let bind = if v6 { format!("[::]:{source_port}") } else { format!("0.0.0.0:{source_port}") };
                    let s = match UdpSocket::bind(bind.as_str()) {
                        Ok(s) => s,
                        Err(e) => {
                            if v6 {
                                break;
                            }
                            return Err(e.to_string());
                        }
                    };
                    #[cfg(unix)]
                    if let Some(p) = protect {
                        use std::os::fd::AsRawFd;
                        p(s.as_raw_fd() as i64);
                    }
                    #[cfg(not(unix))]
                    let _ = protect;
                    s.set_nonblocking(true).map_err(|e| e.to_string())?;
                    socks.push((s, v6));
                }
            }
            if socks.is_empty() {
                return Err("no sockets".into());
            }
            Ok(StdIo { socks, buf: vec![0u8; 4096] })
        }
    }

    impl Io for StdIo {
        fn count(&self) -> usize {
            self.socks.len()
        }

        fn is_v6(&self, s: usize) -> bool {
            self.socks[s].1
        }

        fn send(&mut self, s: usize, pkts: &[(SocketAddr, usize, usize, u32)], arena: &[u8]) -> SendOutcome {
            let sock = &self.socks[s].0;
            let mut sent = 0;
            let mut congested = false;
            let mut failed = Vec::new();
            for (i, p) in pkts.iter().enumerate() {
                match sock.send_to(&arena[p.1..p.1 + p.2], p.0) {
                    Ok(_) => sent += 1,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        congested = true;
                        break;
                    }
                    Err(_) => {
                        failed.push(i);
                        sent += 1;
                    }
                }
            }
            SendOutcome { sent, congested, failed }
        }

        fn drain(&mut self, s: usize, on: &mut dyn FnMut(IoEvent)) {
            for _ in 0..8192 {
                match self.socks[s].0.recv_from(&mut self.buf) {
                    Ok((n, src)) => on(IoEvent::Packet(src, &self.buf[..n])),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
                    Err(_) => break,
                }
            }
        }

        fn wait(&mut self, ms: u32) {
            std::thread::sleep(std::time::Duration::from_millis(ms.clamp(1, 10) as u64));
        }
    }
}

pub fn open_io(n4: usize, n6: usize, protect: Option<&Protect>, source_port: u16) -> Result<Box<dyn Io>, String> {
    let (n4, n6) = if source_port != 0 { (n4.min(1), n6.min(1)) } else { (n4, n6) };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return mmsg::MmsgIo::open(n4, n6, protect, source_port).map(|io| Box::new(io) as Box<dyn Io>);
    }
    #[allow(unreachable_code)]
    portable::StdIo::open(n4, n6, protect, source_port).map(|io| Box::new(io) as Box<dyn Io>)
}
