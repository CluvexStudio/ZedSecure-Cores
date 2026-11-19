pub const T_A: u16 = 1;
pub const T_NS: u16 = 2;
pub const T_CNAME: u16 = 5;
pub const T_NULL: u16 = 10;
pub const T_MX: u16 = 15;
pub const T_TXT: u16 = 16;
pub const T_AAAA: u16 = 28;
pub const T_SRV: u16 = 33;
pub const T_OPT: u16 = 41;
pub const T_DNSKEY: u16 = 48;
pub const T_CAA: u16 = 257;

pub const RC_NOERROR: u16 = 0;
pub const RC_SERVFAIL: u16 = 2;
pub const RC_NXDOMAIN: u16 = 3;
pub const RC_REFUSED: u16 = 5;

#[derive(Clone, Copy, Debug)]
pub struct Edns {
    pub payload: u16,
    pub dnssec_ok: bool,
}

pub fn type_code(name: &str) -> Option<u16> {
    let t = name.trim().to_ascii_lowercase();
    Some(match t.as_str() {
        "a" => T_A,
        "ns" => T_NS,
        "cname" => T_CNAME,
        "null" => T_NULL,
        "mx" => T_MX,
        "txt" => T_TXT,
        "aaaa" => T_AAAA,
        "srv" => T_SRV,
        "dnskey" => T_DNSKEY,
        "caa" => T_CAA,
        other => other.strip_prefix("type").unwrap_or(other).parse::<u16>().ok()?,
    })
}

pub fn type_name(code: u16) -> String {
    match code {
        T_A => "A".into(),
        T_NS => "NS".into(),
        T_CNAME => "CNAME".into(),
        T_NULL => "NULL".into(),
        T_MX => "MX".into(),
        T_TXT => "TXT".into(),
        T_AAAA => "AAAA".into(),
        T_SRV => "SRV".into(),
        T_DNSKEY => "DNSKEY".into(),
        T_CAA => "CAA".into(),
        other => format!("TYPE{other}"),
    }
}

#[inline]
pub fn be16(b: &[u8], p: usize) -> u16 {
    u16::from_be_bytes([b[p], b[p + 1]])
}

#[inline]
fn be32(b: &[u8], p: usize) -> u32 {
    u32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]])
}

pub fn push_name(out: &mut Vec<u8>, name: &str) -> bool {
    let start = out.len();
    let trimmed = name.trim_end_matches('.');
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            let b = label.as_bytes();
            if b.is_empty() || b.len() > 63 {
                out.truncate(start);
                return false;
            }
            out.push(b.len() as u8);
            out.extend(b.iter().map(|c| c.to_ascii_lowercase()));
        }
    }
    out.push(0);
    if out.len() - start > 255 {
        out.truncate(start);
        return false;
    }
    true
}

pub fn name_wire(name: &str) -> Option<Vec<u8>> {
    let mut v = Vec::with_capacity(name.len() + 2);
    if push_name(&mut v, name) {
        Some(v)
    } else {
        None
    }
}

pub fn header_into(out: &mut Vec<u8>, id: u16, rd: bool, edns: bool) {
    out.clear();
    out.extend_from_slice(&id.to_be_bytes());
    out.push(if rd { 0x01 } else { 0x00 });
    out.push(0x00);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&(if edns { 1u16 } else { 0 }).to_be_bytes());
}

pub fn tail_into(out: &mut Vec<u8>, qtype: u16, edns: Option<Edns>) {
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    if let Some(e) = edns {
        out.push(0);
        out.extend_from_slice(&T_OPT.to_be_bytes());
        out.extend_from_slice(&e.payload.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&(if e.dnssec_ok { 0x8000u16 } else { 0 }).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
    }
}

pub fn encode_query(out: &mut Vec<u8>, id: u16, name: &str, qtype: u16, rd: bool, edns: Option<Edns>) -> bool {
    header_into(out, id, rd, edns.is_some());
    if !push_name(out, name) {
        return false;
    }
    tail_into(out, qtype, edns);
    true
}

pub fn question_is(buf: &[u8], wire_lower: &[u8], qtype: u16) -> bool {
    let n = wire_lower.len();
    if buf.len() < 12 + n + 4 || be16(buf, 4) != 1 {
        return false;
    }
    let q = &buf[12..12 + n];
    if q.iter().zip(wire_lower).any(|(a, b)| a.to_ascii_lowercase() != *b) {
        return false;
    }
    be16(buf, 12 + n) == qtype && be16(buf, 12 + n + 2) == 1
}

pub fn skip_name(buf: &[u8], mut p: usize) -> Option<usize> {
    for _ in 0..128 {
        let l = *buf.get(p)? as usize;
        if l == 0 {
            return Some(p + 1);
        }
        if l & 0xC0 == 0xC0 {
            buf.get(p + 1)?;
            return Some(p + 2);
        }
        if l & 0xC0 != 0 {
            return None;
        }
        p += 1 + l;
    }
    None
}

#[derive(Clone, Debug, Default)]
pub struct Reply {
    pub id: u16,
    pub qr: bool,
    pub aa: bool,
    pub tc: bool,
    pub ra: bool,
    pub rcode: u16,
    pub an: u16,
    pub size: usize,
    pub edns: Option<u16>,
    pub ipv4: Vec<[u8; 4]>,
    pub ipv6: Vec<[u8; 16]>,
    pub txt_bytes: usize,
    pub answer_types: Vec<u16>,
    pub complete: bool,
}

pub fn parse(buf: &[u8]) -> Option<Reply> {
    if buf.len() < 12 {
        return None;
    }
    let f1 = buf[2];
    let f2 = buf[3];
    let mut r = Reply {
        id: be16(buf, 0),
        qr: f1 & 0x80 != 0,
        aa: f1 & 0x04 != 0,
        tc: f1 & 0x02 != 0,
        ra: f2 & 0x80 != 0,
        rcode: (f2 & 0x0F) as u16,
        an: be16(buf, 6),
        size: buf.len(),
        ..Default::default()
    };
    let qd = be16(buf, 4) as usize;
    let total = r.an as usize + be16(buf, 8) as usize + be16(buf, 10) as usize;
    let mut p = 12;
    for _ in 0..qd {
        p = skip_name(buf, p)? + 4;
        if p > buf.len() {
            return Some(r);
        }
    }
    for i in 0..total {
        p = match skip_name(buf, p) {
            Some(v) => v,
            None => return Some(r),
        };
        if p + 10 > buf.len() {
            return Some(r);
        }
        let t = be16(buf, p);
        let class = be16(buf, p + 2);
        let ttl = be32(buf, p + 4);
        let rdlen = be16(buf, p + 8) as usize;
        p += 10;
        if p + rdlen > buf.len() {
            return Some(r);
        }
        let rd = &buf[p..p + rdlen];
        if i < r.an as usize {
            match t {
                T_A if rdlen == 4 => r.ipv4.push([rd[0], rd[1], rd[2], rd[3]]),
                T_AAAA if rdlen == 16 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(rd);
                    r.ipv6.push(a);
                }
                T_TXT => r.txt_bytes += rdlen,
                _ => {}
            }
            if !r.answer_types.contains(&t) {
                r.answer_types.push(t);
            }
        } else if t == T_OPT {
            r.edns = Some(class);
            r.rcode |= ((ttl >> 24) as u16 & 0xFF) << 4;
        }
        p += rdlen;
    }
    r.complete = true;
    Some(r)
}
