use crate::deep::Deep;

fn latency_factor(ms: u32) -> f32 {
    if ms <= 40 {
        return 1.0;
    }
    if ms >= 1500 {
        return 0.05;
    }
    let x = (ms as f32 / 40.0).ln() / (1500.0f32 / 40.0).ln();
    (1.0 - x * 0.95).clamp(0.05, 1.0)
}

fn qname_factor(len: u16) -> f32 {
    match len {
        0 => 0.0,
        1..=79 => 0.3,
        80..=120 => 0.6,
        121..=170 => 0.8,
        171..=220 => 0.9,
        _ => 1.0,
    }
}

pub fn compute(d: &Deep, has_tunnel: bool) -> u8 {
    if !d.alive {
        return 0;
    }
    let mut got = 0f32;
    let mut max = 0f32;
    max += 25.0;
    got += 25.0 * latency_factor(d.rtt);
    max += 15.0;
    got += 15.0 * (1.0 - d.loss).clamp(0.0, 1.0);
    max += 5.0;
    got += 5.0 * latency_factor(d.jitter.saturating_add(40));
    if has_tunnel {
        max += 25.0;
        if d.tunnel == Some(true) {
            got += 25.0;
        }
    }
    max += 10.0;
    got += 10.0 * qname_factor(d.max_qname);
    if let Some(e) = d.edns {
        max += 8.0;
        if e {
            got += match d.max_reply {
                1200.. => 8.0,
                900..=1199 => 6.0,
                512..=899 => 3.0,
                _ => 1.0,
            };
        }
    }
    if let Some(b) = d.burst {
        max += 8.0;
        got += 8.0 * b.clamp(0.0, 1.0);
    }
    if let Some(nx) = d.nx_ok {
        max += 2.0;
        if nx {
            got += 2.0;
        }
    }
    if let Some(c) = d.censored {
        max += 2.0;
        if !c {
            got += 2.0;
        }
    }
    if !d.types_ok.is_empty() || !d.types_bad.is_empty() {
        let total = (d.types_ok.len() + d.types_bad.len()) as f32;
        max += 4.0;
        got += 4.0 * d.types_ok.len() as f32 / total;
    }
    if d.tcp == Some(true) {
        got += 2.0;
    }
    if d.dot == Some(true) {
        got += 1.0;
    }
    let mut s = (got / max.max(1.0) * 100.0).round().clamp(0.0, 100.0);
    if let Some(b) = d.burst {
        if b < 0.5 {
            s = s.min(70.0);
        } else if b < 0.8 {
            s = s.min(85.0);
        }
    }
    if d.truncates {
        s = s.min(if d.tcp == Some(true) { 88.0 } else { 80.0 });
    }
    if d.loss >= 0.4 {
        s = s.min(60.0);
    }
    if has_tunnel && d.tunnel != Some(true) {
        s = s.min(30.0);
    }
    if d.hijacked {
        s = s.min(15.0);
    }
    if d.answered_by.is_some() || d.proxy_suspect == Some(true) {
        s = s.min(60.0);
    }
    s as u8
}
