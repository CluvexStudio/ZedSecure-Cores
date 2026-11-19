use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

pub fn random_u64() -> u64 {
    let mut h = RandomState::new().build_hasher();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    h.write_u64(nanos);
    h.write_usize(&nanos as *const u64 as usize);
    h.finish()
}

#[inline]
pub fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        mix(self.0)
    }

    #[inline]
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            ((self.next_u64() as u128 * n as u128) >> 64) as u64
        }
    }
}

pub const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

pub fn push_label_from(out: &mut Vec<u8>, mut seed: u64, len: usize) {
    let mut bits = 64u32;
    let mut v = mix(seed);
    for _ in 0..len {
        if bits < 5 {
            seed = seed.wrapping_add(0x632B_E59B_D9B4_E019);
            v = mix(seed);
            bits = 64;
        }
        out.push(BASE32[(v & 31) as usize]);
        v >>= 5;
        bits -= 5;
    }
}

pub fn random_label(rng: &mut Rng, len: usize) -> String {
    let mut out = Vec::with_capacity(len);
    push_label_from(&mut out, rng.next_u64(), len);
    String::from_utf8(out).unwrap_or_default()
}

pub fn long_name(rng: &mut Rng, total: usize, suffix: &str) -> Option<String> {
    let suffix = suffix.trim_matches('.');
    let total = total.min(253);
    let room = total.checked_sub(suffix.len() + 1)?;
    if room < 1 {
        return None;
    }
    let k = (room + 64) / 64;
    let chars = room + 1 - k;
    let mut lens = vec![63usize; k];
    let last = chars as isize - 63 * (k as isize - 1);
    if last >= 1 {
        lens[k - 1] = last as usize;
    } else if k >= 2 {
        lens[k - 2] = 62;
        lens[k - 1] = 1;
    } else {
        return None;
    }
    let mut name = lens
        .iter()
        .map(|&len| random_label(rng, len))
        .collect::<Vec<_>>()
        .join(".");
    name.push('.');
    name.push_str(suffix);
    Some(name)
}

pub fn median(sorted: &[u32]) -> u32 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[sorted.len() / 2]
}

pub fn percentile(sorted: &[u32], p: f32) -> u32 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f32 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}
