use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Default, Clone, Debug)]
pub struct Seen {
    pub udp_ttls: Vec<u8>,
    pub tcp_ttls: Vec<u8>,
    pub replies: HashMap<u16, u8>,
    pub duplicates: u32,
}

impl Seen {
    pub fn udp_ttl(&self) -> Option<u8> {
        mode(&self.udp_ttls)
    }

    pub fn tcp_ttl(&self) -> Option<u8> {
        mode(&self.tcp_ttls)
    }
}

fn mode(v: &[u8]) -> Option<u8> {
    let mut counts = [0u16; 256];
    for &t in v {
        counts[t as usize] += 1;
    }
    let (best, n) = counts.iter().enumerate().max_by_key(|(_, n)| **n)?;
    (*n > 0).then_some(best as u8)
}

pub fn hops(ttl: u8) -> u8 {
    let start = if ttl <= 64 {
        64
    } else if ttl <= 128 {
        128
    } else {
        255
    };
    start - ttl
}

pub struct Capture {
    table: Arc<Mutex<HashMap<u32, Seen>>>,
    packets: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Capture {
    pub fn info(&self, ip: &IpAddr) -> Option<Seen> {
        let IpAddr::V4(v4) = ip else { return None };
        self.table.lock().ok()?.get(&u32::from(*v4)).cloned()
    }

    pub fn packets(&self) -> u64 {
        self.packets.load(Ordering::Relaxed)
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn start(pcap: Option<String>) -> Result<Capture, String> {
    use std::io::Write;
    let proto = (libc::ETH_P_IP as u16).to_be() as libc::c_int;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM, proto) };
    if fd < 0 {
        return Err(format!("raw capture needs root: {}", std::io::Error::last_os_error()));
    }
    let tv = libc::timeval { tv_sec: 0, tv_usec: 200_000 };
    let big: libc::c_int = 8 << 20;
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as libc::socklen_t);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &big as *const _ as *const libc::c_void, 4);
    }
    let mut writer = match pcap.filter(|p| !p.is_empty()) {
        Some(path) => {
            let mut f = std::io::BufWriter::new(std::fs::File::create(&path).map_err(|e| format!("pcap: {e}"))?);
            let mut h = Vec::with_capacity(24);
            h.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
            h.extend_from_slice(&2u16.to_le_bytes());
            h.extend_from_slice(&4u16.to_le_bytes());
            h.extend_from_slice(&0i32.to_le_bytes());
            h.extend_from_slice(&0u32.to_le_bytes());
            h.extend_from_slice(&65535u32.to_le_bytes());
            h.extend_from_slice(&101u32.to_le_bytes());
            f.write_all(&h).map_err(|e| format!("pcap: {e}"))?;
            Some(f)
        }
        None => None,
    };
    let table: Arc<Mutex<HashMap<u32, Seen>>> = Arc::new(Mutex::new(HashMap::new()));
    let packets = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (t, p, s) = (table.clone(), packets.clone(), stop.clone());
    let handle = std::thread::Builder::new()
        .name("zedscan-capture".into())
        .spawn(move || {
            let mut buf = vec![0u8; 65536];
            while !s.load(Ordering::Relaxed) {
                let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
                if n <= 0 {
                    continue;
                }
                let pkt = &buf[..n as usize];
                if let Some(dns) = observe(pkt, &t) {
                    p.fetch_add(1, Ordering::Relaxed);
                    if dns {
                        if let Some(w) = writer.as_mut() {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default();
                            let mut rec = Vec::with_capacity(16 + pkt.len());
                            rec.extend_from_slice(&(now.as_secs() as u32).to_le_bytes());
                            rec.extend_from_slice(&now.subsec_micros().to_le_bytes());
                            rec.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
                            rec.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
                            rec.extend_from_slice(pkt);
                            let _ = w.write_all(&rec);
                        }
                    }
                }
            }
            if let Some(mut w) = writer {
                let _ = w.flush();
            }
            unsafe { libc::close(fd) };
        })
        .map_err(|e| e.to_string())?;
    Ok(Capture { table, packets, stop, handle: Some(handle) })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn start(_pcap: Option<String>) -> Result<Capture, String> {
    Err("raw capture is only available on Linux and Android".into())
}

fn observe(pkt: &[u8], table: &Mutex<HashMap<u32, Seen>>) -> Option<bool> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    if pkt.len() < ihl + 8 {
        return None;
    }
    let ttl = pkt[8];
    let proto = pkt[9];
    let src = u32::from(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
    let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    let dns_port = |p: u16| p == 53 || p == 853;
    match proto {
        17 => {
            if sport != 53 {
                return Some(dns_port(dport));
            }
            let payload = &pkt[ihl + 8..];
            let mut t = table.lock().ok()?;
            let seen = t.entry(src).or_default();
            if seen.udp_ttls.len() < 32 {
                seen.udp_ttls.push(ttl);
            }
            if payload.len() >= 12 {
                let id = u16::from_be_bytes([payload[0], payload[1]]);
                let c = seen.replies.entry(id).or_insert(0);
                *c = c.saturating_add(1);
                if *c > 1 {
                    seen.duplicates += 1;
                }
                if seen.replies.len() > 4096 {
                    seen.replies.clear();
                }
            }
            Some(true)
        }
        6 => {
            if pkt.len() < ihl + 14 {
                return None;
            }
            let flags = pkt[ihl + 13];
            if dns_port(sport) && flags & 0x12 == 0x12 {
                let mut t = table.lock().ok()?;
                let seen = t.entry(src).or_default();
                if seen.tcp_ttls.len() < 32 {
                    seen.tcp_ttls.push(ttl);
                }
            }
            Some(dns_port(sport) || dns_port(dport))
        }
        _ => None,
    }
}
