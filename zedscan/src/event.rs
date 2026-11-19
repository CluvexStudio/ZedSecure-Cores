use serde::Serialize;
use std::net::SocketAddr;

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub planned: u64,
    pub walked: u64,
    pub skipped: u64,
    pub sent: u64,
    pub done: u64,
    pub recv: u64,
    pub found: u64,
    pub refused: u64,
    pub servfail: u64,
    pub other: u64,
    pub timeouts: u64,
    pub closed: u64,
    pub unreachable: u64,
    pub hijacked: u64,
    pub intercepted: u64,
    pub late: u64,
    pub rate: u32,
    pub target_rate: u32,
    pub canary_loss: f32,
    pub elapsed_ms: u64,
    pub eta_ms: u64,
    pub sweep_done: bool,
    pub deep_queued: u64,
    pub deep_done: u64,
    pub good: u64,
    pub tcp_planned: u64,
    pub tcp_done: u64,
    pub tcp_found: u64,
    pub captured: u64,
    pub root: bool,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Found {
    pub ip: String,
    pub port: u16,
    pub rtt: u32,
    pub rcode: u16,
    pub ra: bool,
    pub aa: bool,
    pub hijacked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answered_by: Option<String>,
    pub late: bool,
    pub via: String,
    #[serde(skip)]
    pub addr: SocketAddr,
}

#[derive(Serialize, Clone, Debug)]
#[serde(tag = "t", rename_all = "camelCase")]
pub enum Event {
    Progress(Progress),
    Found(Found),
    Result(crate::deep::Deep),
    Intercept { by: String },
    Warning { code: String, msg: String },
    Done { reason: String, progress: Progress },
}
