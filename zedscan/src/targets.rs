use crate::util::{mix, Rng};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Span {
    v6: bool,
    port: u16,
    start: u128,
    end: u128,
}

#[derive(Clone, Copy, Debug)]
pub struct Net {
    v6: bool,
    start: u128,
    end: u128,
}

impl Net {
    pub fn parse(s: &str) -> Option<Net> {
        let s = s.trim();
        let (ip, bits) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b.parse::<u32>().ok()?)),
            None => (s, None),
        };
        match ip.parse::<IpAddr>().ok()? {
            IpAddr::V4(a) => {
                let bits = bits.unwrap_or(32).min(32);
                let (start, end) = cidr_bounds(u32::from(a) as u128, bits, 32);
                Some(Net { v6: false, start, end })
            }
            IpAddr::V6(a) => {
                let bits = bits.unwrap_or(128).min(128);
                let (start, end) = cidr_bounds(u128::from(a), bits, 128);
                Some(Net { v6: true, start, end })
            }
        }
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => !self.v6 && (self.start..=self.end).contains(&(u32::from(*a) as u128)),
            IpAddr::V6(a) => self.v6 && (self.start..=self.end).contains(&u128::from(*a)),
        }
    }
}

fn cidr_bounds(addr: u128, bits: u32, width: u32) -> (u128, u128) {
    let host = width - bits;
    if host >= 128 {
        return (0, u128::MAX);
    }
    let mask: u128 = if host == 0 { 0 } else { (1u128 << host) - 1 };
    let start = addr & !mask;
    (start, start | mask)
}

const SPECIAL_V4: &[(u32, u32)] = &[
    (0x0000_0000, 0x00FF_FFFF),
    (0x7F00_0000, 0x7FFF_FFFF),
    (0xE000_0000, 0xFFFF_FFFF),
];

pub struct TargetSet {
    spans: Vec<Span>,
    cum: Vec<u64>,
    total: u64,
    extra: Vec<SocketAddr>,
    pub invalid: Vec<String>,
}

const MAX_TOTAL: u64 = 1 << 40;
const MAX_V6_SPAN: u128 = 1 << 20;

impl TargetSet {
    pub fn parse(specs: &[String], default_port: u16, exclude_special: bool) -> TargetSet {
        let mut spans: Vec<Span> = Vec::new();
        let mut invalid = Vec::new();
        for spec in specs {
            for raw in spec.split(|c: char| c == '\n' || c == ',' || c == ';' || c.is_whitespace()) {
                let token = raw.split('#').next().unwrap_or("").trim();
                if token.is_empty() {
                    continue;
                }
                match parse_token(token, default_port) {
                    Some(s) => spans.push(s),
                    None => {
                        if invalid.len() < 50 {
                            invalid.push(token.to_string());
                        }
                    }
                }
            }
        }
        let mut set = TargetSet { spans: merge(spans), cum: Vec::new(), total: 0, extra: Vec::new(), invalid };
        if exclude_special {
            set.spans = subtract_special(&set.spans);
        }
        set.reindex();
        set
    }

    fn reindex(&mut self) {
        self.cum.clear();
        let mut acc: u64 = 0;
        let mut kept = Vec::with_capacity(self.spans.len());
        for s in &self.spans {
            let n = (s.end - s.start + 1).min(MAX_TOTAL as u128) as u64;
            if acc + n > MAX_TOTAL {
                break;
            }
            self.cum.push(acc);
            kept.push(*s);
            acc += n;
        }
        self.spans = kept;
        self.total = acc;
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn all_v4(&self) -> bool {
        self.spans.iter().all(|s| !s.v6)
    }

    pub fn has_v6(&self) -> bool {
        self.spans.iter().any(|s| s.v6) || self.extra.iter().any(|a| a.is_ipv6())
    }

    pub fn has_v4(&self) -> bool {
        self.spans.iter().any(|s| !s.v6) || self.extra.iter().any(|a| a.is_ipv4())
    }

    pub fn push_extra(&mut self, addr: SocketAddr) -> u64 {
        self.extra.push(addr);
        self.total + self.extra.len() as u64 - 1
    }

    pub fn addr(&self, idx: u64) -> SocketAddr {
        if idx >= self.total {
            return self.extra[(idx - self.total) as usize];
        }
        let i = match self.cum.binary_search(&idx) {
            Ok(i) => i,
            Err(i) => i - 1,
        };
        let s = self.spans[i];
        let v = s.start + (idx - self.cum[i]) as u128;
        to_addr(s.v6, v, s.port)
    }

    fn index_of_v4(&self, span: usize, ip: u32) -> u64 {
        self.cum[span] + (ip as u128 - self.spans[span].start) as u64
    }

    pub fn walker(&self, order: Order, limit: u64, seed: u64) -> Walker {
        let n = if limit > 0 { limit.min(self.total) } else { self.total };
        match order {
            Order::Smart if self.all_v4() && self.total > 0 && self.total <= (1 << 28) => {
                Walker::Smart(Smart::new(self, n, seed))
            }
            Order::Given => Walker::Seq { i: 0, n },
            _ => Walker::Perm { perm: Feistel::new(self.total, seed), i: 0, n },
        }
    }
}

fn to_addr(v6: bool, v: u128, port: u16) -> SocketAddr {
    if v6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(v)), port)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(v as u32)), port)
    }
}

fn parse_token(token: &str, default_port: u16) -> Option<Span> {
    if let Ok(sa) = token.parse::<SocketAddr>() {
        return Some(single(sa.ip(), if sa.port() == 0 { default_port } else { sa.port() }));
    }
    if let Some((a, b)) = token.split_once('/') {
        let bits: u32 = b.parse().ok()?;
        return match a.parse::<IpAddr>().ok()? {
            IpAddr::V4(ip) if bits <= 32 => {
                let (start, end) = cidr_bounds(u32::from(ip) as u128, bits, 32);
                Some(Span { v6: false, port: default_port, start, end })
            }
            IpAddr::V6(ip) if bits <= 128 => {
                let (start, end) = cidr_bounds(u128::from(ip), bits, 128);
                if end - start >= MAX_V6_SPAN {
                    return None;
                }
                Some(Span { v6: true, port: default_port, start, end })
            }
            _ => None,
        };
    }
    if token.contains('*') && !token.contains(':') {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        let mut lo = 0u32;
        let mut hi = 0u32;
        for p in parts {
            let (a, b) = if p == "*" {
                (0u32, 255u32)
            } else {
                let v: u32 = p.parse().ok()?;
                if v > 255 {
                    return None;
                }
                (v, v)
            };
            lo = (lo << 8) | a;
            hi = (hi << 8) | b;
        }
        return Some(Span { v6: false, port: default_port, start: lo as u128, end: hi as u128 });
    }
    if let Some((a, b)) = token.split_once('-') {
        let start: IpAddr = a.trim().parse().ok()?;
        let end: IpAddr = match b.trim().parse::<IpAddr>() {
            Ok(e) => e,
            Err(_) => match start {
                IpAddr::V4(s) => {
                    let last: u8 = b.trim().parse().ok()?;
                    let o = s.octets();
                    IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], last))
                }
                IpAddr::V6(_) => return None,
            },
        };
        return match (start, end) {
            (IpAddr::V4(s), IpAddr::V4(e)) => {
                let (s, e) = (u32::from(s) as u128, u32::from(e) as u128);
                (s <= e).then_some(Span { v6: false, port: default_port, start: s, end: e })
            }
            (IpAddr::V6(s), IpAddr::V6(e)) => {
                let (s, e) = (u128::from(s), u128::from(e));
                (s <= e && e - s < MAX_V6_SPAN).then_some(Span { v6: true, port: default_port, start: s, end: e })
            }
            _ => None,
        };
    }
    let ip: IpAddr = token.trim_matches(|c| c == '[' || c == ']').parse().ok()?;
    Some(single(ip, default_port))
}

fn single(ip: IpAddr, port: u16) -> Span {
    match ip {
        IpAddr::V4(a) => {
            let v = u32::from(a) as u128;
            Span { v6: false, port, start: v, end: v }
        }
        IpAddr::V6(a) => {
            let v = u128::from(a);
            Span { v6: true, port, start: v, end: v }
        }
    }
}

fn merge(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort();
    let mut out: Vec<Span> = Vec::with_capacity(spans.len());
    for s in spans {
        if let Some(last) = out.last_mut() {
            if last.v6 == s.v6 && last.port == s.port && s.start <= last.end.saturating_add(1) {
                if s.end > last.end {
                    last.end = s.end;
                }
                continue;
            }
        }
        out.push(s);
    }
    out
}

fn subtract_special(spans: &[Span]) -> Vec<Span> {
    let mut out = Vec::with_capacity(spans.len());
    for s in spans {
        if s.v6 {
            out.push(*s);
            continue;
        }
        let mut pieces = vec![(s.start, s.end)];
        for &(a, b) in SPECIAL_V4 {
            let (a, b) = (a as u128, b as u128);
            let mut next = Vec::with_capacity(pieces.len() + 1);
            for (x, y) in pieces {
                if y < a || x > b {
                    next.push((x, y));
                    continue;
                }
                if x < a {
                    next.push((x, a - 1));
                }
                if y > b {
                    next.push((b + 1, y));
                }
            }
            pieces = next;
        }
        for (x, y) in pieces {
            out.push(Span { v6: false, port: s.port, start: x, end: y });
        }
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    Given,
    Shuffle,
    Smart,
}

impl Order {
    pub fn parse(s: &str) -> Order {
        match s.trim().to_ascii_lowercase().as_str() {
            "given" | "sequential" | "seq" => Order::Given,
            "shuffle" | "random" => Order::Shuffle,
            _ => Order::Smart,
        }
    }
}

pub struct Feistel {
    n: u64,
    half: u32,
    mask: u64,
    keys: [u64; 4],
}

impl Feistel {
    pub fn new(n: u64, seed: u64) -> Feistel {
        let mut bits = 2u32;
        while bits < 64 && (1u128 << bits) < n as u128 {
            bits += 2;
        }
        let half = bits / 2;
        let mut rng = Rng::new(seed ^ 0xA076_1D64_78BD_642F);
        Feistel {
            n,
            half,
            mask: (1u64 << half) - 1,
            keys: [rng.next_u64(), rng.next_u64(), rng.next_u64(), rng.next_u64()],
        }
    }

    fn round(&self, mut x: u64) -> u64 {
        let mut l = x >> self.half;
        let mut r = x & self.mask;
        for k in self.keys {
            let f = mix(r ^ k) & self.mask;
            let nl = r;
            r = l ^ f;
            l = nl;
        }
        x = (l << self.half) | r;
        x
    }

    pub fn get(&self, i: u64) -> u64 {
        let mut x = i;
        loop {
            x = self.round(x);
            if x < self.n {
                return x;
            }
        }
    }
}

pub struct Smart {
    blocks: Vec<(u32, u32, u8, u8)>,
    order: Feistel,
    hosts: [u8; 256],
    round: usize,
    cursor: u64,
    emitted: u64,
    n: u64,
}

const PRIORITY_HOSTS: &[u8] = &[
    1, 2, 53, 10, 100, 254, 250, 3, 4, 5, 11, 20, 22, 30, 33, 44, 50, 55, 66, 77, 88, 99, 101, 110, 111, 150, 200,
    201, 202, 222, 251, 252, 253, 6, 7, 8, 9, 12, 13, 14, 15, 16, 21, 25, 40, 60, 70, 80, 90, 120, 130, 140, 160,
    170, 180, 190, 210, 220, 230, 240, 245, 248, 249,
];

impl Smart {
    fn new(set: &TargetSet, n: u64, seed: u64) -> Smart {
        let mut blocks = Vec::new();
        for (si, s) in set.spans.iter().enumerate() {
            let (start, end) = (s.start as u32, s.end as u32);
            let mut base = start & 0xFFFF_FF00;
            loop {
                let lo = if base < start { (start - base) as u8 } else { 0 };
                let block_end = base | 0xFF;
                let hi = if block_end > end { (end - base) as u8 } else { 255 };
                blocks.push((si as u32, base, lo, hi));
                if block_end >= end {
                    break;
                }
                base = block_end + 1;
            }
        }
        let mut hosts = [0u8; 256];
        let mut used = [false; 256];
        let mut k = 0;
        for &h in PRIORITY_HOSTS {
            if !used[h as usize] {
                used[h as usize] = true;
                hosts[k] = h;
                k += 1;
            }
        }
        let mut rest: Vec<u8> = (0u16..=255).map(|v| v as u8).filter(|v| !used[*v as usize]).collect();
        let mut rng = Rng::new(seed ^ 0x2545_F491_4F6C_DD1D);
        for i in (1..rest.len()).rev() {
            let j = rng.below(i as u64 + 1) as usize;
            rest.swap(i, j);
        }
        for h in rest {
            hosts[k] = h;
            k += 1;
        }
        let order = Feistel::new(blocks.len() as u64, seed);
        Smart { blocks, order, hosts, round: 0, cursor: 0, emitted: 0, n }
    }

    fn next_index(&mut self, set: &TargetSet) -> Option<u64> {
        let b = self.blocks.len() as u64;
        while self.emitted < self.n && self.round < 256 {
            let (si, base, lo, hi) = self.blocks[self.order.get(self.cursor) as usize];
            let h = self.hosts[self.round];
            self.cursor += 1;
            if self.cursor == b {
                self.cursor = 0;
                self.round += 1;
            }
            if h >= lo && h <= hi {
                self.emitted += 1;
                return Some(set.index_of_v4(si as usize, base | h as u32));
            }
        }
        None
    }
}

pub enum Walker {
    Seq { i: u64, n: u64 },
    Perm { perm: Feistel, i: u64, n: u64 },
    Smart(Smart),
}

impl Walker {
    pub fn skip(&mut self, count: u64, set: &TargetSet) -> u64 {
        match self {
            Walker::Seq { i, n } | Walker::Perm { i, n, .. } => {
                let k = count.min(*n - *i);
                *i += k;
                k
            }
            Walker::Smart(s) => {
                let mut k = 0;
                while k < count && s.next_index(set).is_some() {
                    k += 1;
                }
                k
            }
        }
    }

    pub fn planned(&self) -> u64 {
        match self {
            Walker::Seq { n, .. } | Walker::Perm { n, .. } => *n,
            Walker::Smart(s) => s.n,
        }
    }

    pub fn next(&mut self, set: &TargetSet) -> Option<u64> {
        match self {
            Walker::Seq { i, n } => {
                if *i < *n {
                    *i += 1;
                    Some(*i - 1)
                } else {
                    None
                }
            }
            Walker::Perm { perm, i, n } => {
                if *i < *n {
                    *i += 1;
                    Some(perm.get(*i - 1))
                } else {
                    None
                }
            }
            Walker::Smart(s) => s.next_index(set),
        }
    }
}

pub fn geoip_cidrs(data: &[u8], codes: &[String]) -> Vec<String> {
    let wanted: Vec<String> = codes.iter().map(|c| c.trim().to_ascii_uppercase()).filter(|c| !c.is_empty()).collect();
    let mut out = Vec::new();
    let mut p = 0usize;
    while p < data.len() {
        let Some((key, n)) = varint(&data[p..]) else { break };
        p += n;
        if key & 7 != 2 {
            break;
        }
        let Some((len, n)) = varint(&data[p..]) else { break };
        p += n;
        let end = p.saturating_add(len as usize);
        if end > data.len() {
            break;
        }
        if (key >> 3) == 1 {
            geoip_entry(&data[p..end], &wanted, &mut out);
        }
        p = end;
    }
    out
}

fn geoip_entry(e: &[u8], wanted: &[String], out: &mut Vec<String>) {
    let mut p = 0usize;
    let mut code: Option<String> = None;
    let mut cidrs: Vec<(usize, usize)> = Vec::new();
    while p < e.len() {
        let Some((key, n)) = varint(&e[p..]) else { return };
        p += n;
        match key & 7 {
            0 => {
                let Some((_, n)) = varint(&e[p..]) else { return };
                p += n;
            }
            2 => {
                let Some((len, n)) = varint(&e[p..]) else { return };
                p += n;
                let end = p.saturating_add(len as usize);
                if end > e.len() {
                    return;
                }
                match key >> 3 {
                    1 => {
                        let c = String::from_utf8_lossy(&e[p..end]).to_ascii_uppercase();
                        if !wanted.iter().any(|w| *w == c) {
                            return;
                        }
                        code = Some(c);
                    }
                    2 => cidrs.push((p, end)),
                    _ => {}
                }
                p = end;
            }
            1 => p += 8,
            5 => p += 4,
            _ => return,
        }
    }
    if code.is_none() {
        return;
    }
    for (a, b) in cidrs {
        let c = &e[a..b];
        let mut q = 0usize;
        let mut ip: &[u8] = &[];
        let mut prefix: u64 = 0;
        while q < c.len() {
            let Some((key, n)) = varint(&c[q..]) else { break };
            q += n;
            match (key >> 3, key & 7) {
                (1, 2) => {
                    let Some((len, n)) = varint(&c[q..]) else { break };
                    q += n;
                    let end = (q + len as usize).min(c.len());
                    ip = &c[q..end];
                    q = end;
                }
                (2, 0) => {
                    let Some((v, n)) = varint(&c[q..]) else { break };
                    q += n;
                    prefix = v;
                }
                (_, 0) => {
                    let Some((_, n)) = varint(&c[q..]) else { break };
                    q += n;
                }
                (_, 2) => {
                    let Some((len, n)) = varint(&c[q..]) else { break };
                    q += n + len as usize;
                }
                _ => break,
            }
        }
        if ip.len() == 4 && prefix <= 32 {
            out.push(format!("{}.{}.{}.{}/{}", ip[0], ip[1], ip[2], ip[3], prefix));
        }
    }
}

fn varint(b: &[u8]) -> Option<(u64, usize)> {
    let mut v: u64 = 0;
    for (i, byte) in b.iter().enumerate().take(10) {
        v |= ((byte & 0x7F) as u64) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

pub fn keep_octets(cidrs: Vec<String>, octets: &[u8]) -> Vec<String> {
    if octets.is_empty() {
        return cidrs;
    }
    cidrs
        .into_iter()
        .filter(|c| c.split('.').next().and_then(|o| o.parse::<u8>().ok()).is_some_and(|o| octets.contains(&o)))
        .collect()
}

pub fn octet_groups(cidrs: &[String]) -> Vec<(u8, u64, u32)> {
    let mut groups: std::collections::BTreeMap<u8, (u64, u32)> = std::collections::BTreeMap::new();
    for c in cidrs {
        let Some((ip, bits)) = c.split_once('/') else { continue };
        let Some(first) = ip.split('.').next().and_then(|o| o.parse::<u8>().ok()) else { continue };
        let Ok(bits) = bits.parse::<u32>() else { continue };
        let size = 1u64 << (32 - bits.min(32));
        let e = groups.entry(first).or_insert((0, 0));
        e.0 += size;
        e.1 += 1;
    }
    groups.into_iter().map(|(o, (n, r))| (o, n, r)).collect()
}
