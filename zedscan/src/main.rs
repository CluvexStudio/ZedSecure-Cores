use std::io::{Read, Write};
use std::time::Duration;
use zedscan::config::ScanConfig;
use zedscan::deep::Deep;
use zedscan::event::{Event, Progress};

const USAGE: &str = "zedscan [options] <targets...>

targets: IPs, IP:port, CIDRs, ranges (a.b.c.d-e.f.g.h, a.b.c.d-200) and wildcards (5.160.*.*)

  -f, --file PATH        read targets from a file ('-' for stdin)
  -c, --config PATH      read a JSON config (same fields as the app)
      --country IR,..    add every range of these countries from --geoip PATH (v2ray geoip.dat)
      --domain NAME      domain whose random subdomains prove recursion (google.com)
      --tunnel NAME      DNS tunnel domain to test reachability, long names and record types
      --rate N           packets per second ceiling (2000)
      --timeout MS       sweep timeout per probe (2500)
      --retries N        sweep retries (1)
      --order KIND       smart, shuffle or given (smart)
      --limit N          scan at most N addresses
      --port N           default port (53)
      --sockets N        sweep sockets (auto)
      --no-adaptive      fixed rate, no reference resolvers
      --canary IP        reference resolver for rate control (repeatable)
      --neighbors        also scan the /24 around every resolver found
      --no-deep          sweep only
      --deep-concurrency N, --deep-timeout MS, --samples N
      --types A,TXT,...  record types to test on the tunnel domain
      --ladder 64,101,.. query name lengths to test
      --blocked a,b      domains used to detect filtering
      --no-tcp --dot --no-edns --no-burst --no-nx --no-intercept --allow-special
      --stop-after N     stop once N resolvers reach --min-score (50)
      --transport KIND   udp, tcp or both (udp)
      --skip N           resume: skip the first N addresses of the same --seed order
      --octets 5,31,..   keep only these first octets of --country ranges
      --country-groups   print the first-octet groups of --country and exit
      --capture          root: record reply TTLs and duplicate answers from raw packets
      --pcap PATH        root: also save the DNS packets to a pcap file
      --source-port N    send from this source port (53 needs root)
      --stdin            read one JSON config line from stdin, print events as JSON lines, stop at EOF
      --seed N           repeatable order
      --quiet            do not print found/progress events
      --summary          print only the summary
      --top N            rows in the summary (20)
";

fn value(args: &[String], i: &mut usize) -> String {
    *i += 1;
    args.get(*i).cloned().unwrap_or_default()
}

fn num<T: std::str::FromStr>(args: &[String], i: &mut usize, name: &str) -> T {
    let v = value(args, i);
    match v.parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("zedscan: {name} needs a number, got '{v}'");
            std::process::exit(2);
        }
    }
}

fn list(args: &[String], i: &mut usize) -> Vec<String> {
    value(args, i).split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

fn mark_protect(line: &str) -> Option<zedscan::sweep::Protect> {
    let mark = serde_json::from_str::<serde_json::Value>(line).ok()?.get("fwmark")?.as_u64()? as u32;
    if mark == 0 {
        return None;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let protect: zedscan::sweep::Protect = std::sync::Arc::new(move |fd: i64| {
            let v = mark as libc::c_int;
            unsafe {
                libc::setsockopt(
                    fd as libc::c_int,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &v as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                ) == 0
            }
        });
        return Some(protect);
    }
    #[allow(unreachable_code)]
    None
}

fn run_stdin() {
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() || line.trim().is_empty() {
        println!("{}", serde_json::json!({"t": "warning", "code": "config", "msg": "no config on stdin"}));
        std::process::exit(2);
    }
    let scan = match zedscan::start_json(line.trim(), mark_protect(line.trim())) {
        Ok(s) => std::sync::Arc::new(s),
        Err(e) => {
            println!("{}", serde_json::json!({"t": "done", "reason": "error", "error": e}));
            std::process::exit(2);
        }
    };
    let watcher = scan.clone();
    std::thread::spawn(move || {
        let mut sink = String::new();
        let _ = std::io::stdin().read_to_string(&mut sink);
        watcher.stop();
    });
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    while let Some(events) = scan.poll(Duration::from_millis(400), 4096) {
        for ev in events {
            let _ = serde_json::to_writer(&mut out, &ev);
            let _ = writeln!(out);
        }
        if out.flush().is_err() {
            scan.stop();
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cfg = ScanConfig::default();
    let mut quiet = false;
    let mut summary_only = false;
    let mut top = 20usize;
    let mut dry: Option<usize> = None;
    let mut stdin_mode = false;
    let mut groups = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return;
            }
            "-c" | "--config" => {
                let path = value(&args, &mut i);
                let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                    eprintln!("zedscan: {path}: {e}");
                    std::process::exit(2)
                });
                let targets = std::mem::take(&mut cfg.targets);
                cfg = serde_json::from_str(&text).unwrap_or_else(|e| {
                    eprintln!("zedscan: {path}: {e}");
                    std::process::exit(2)
                });
                cfg.targets.extend(targets);
            }
            "-f" | "--file" => {
                let path = value(&args, &mut i);
                let mut text = String::new();
                if path == "-" {
                    let _ = std::io::stdin().read_to_string(&mut text);
                } else {
                    text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                        eprintln!("zedscan: {path}: {e}");
                        std::process::exit(2)
                    });
                }
                cfg.targets.push(text);
            }
            "--country" => cfg.countries = list(&args, &mut i),
            "--geoip" => cfg.geoip_path = value(&args, &mut i),
            "--domain" => cfg.domain = value(&args, &mut i),
            "--tunnel" => cfg.tunnel_domain = value(&args, &mut i),
            "--rate" => cfg.rate = num(&args, &mut i, "--rate"),
            "--timeout" => cfg.timeout_ms = num(&args, &mut i, "--timeout"),
            "--retries" => cfg.retries = num(&args, &mut i, "--retries"),
            "--order" => cfg.order = value(&args, &mut i),
            "--limit" => cfg.limit = num(&args, &mut i, "--limit"),
            "--port" => cfg.port = num(&args, &mut i, "--port"),
            "--sockets" => cfg.sockets = num(&args, &mut i, "--sockets"),
            "--no-adaptive" => cfg.adaptive = false,
            "--canary" => cfg.canaries.push(value(&args, &mut i)),
            "--neighbors" => cfg.neighbors = true,
            "--no-deep" => cfg.deep = false,
            "--deep-concurrency" => cfg.deep_concurrency = num(&args, &mut i, "--deep-concurrency"),
            "--deep-timeout" => cfg.deep_timeout_ms = num(&args, &mut i, "--deep-timeout"),
            "--samples" => cfg.latency_samples = num(&args, &mut i, "--samples"),
            "--types" => cfg.record_types = list(&args, &mut i),
            "--ladder" => cfg.qname_ladder = list(&args, &mut i).iter().filter_map(|s| s.parse().ok()).collect(),
            "--blocked" => cfg.blocked_domains = list(&args, &mut i),
            "--no-tcp" => cfg.check_tcp = false,
            "--dot" => cfg.check_dot = true,
            "--no-edns" => cfg.check_edns = false,
            "--no-burst" => cfg.check_burst = false,
            "--no-nx" => cfg.check_nx = false,
            "--no-intercept" => cfg.detect_intercept = false,
            "--allow-special" => cfg.exclude_special = false,
            "--stop-after" => cfg.stop_after = num(&args, &mut i, "--stop-after"),
            "--min-score" => cfg.min_score = num(&args, &mut i, "--min-score"),
            "--seed" => cfg.seed = num(&args, &mut i, "--seed"),
            "--quiet" => quiet = true,
            "--summary" => summary_only = true,
            "--top" => top = num(&args, &mut i, "--top"),
            "--dry-run" => dry = Some(num(&args, &mut i, "--dry-run")),
            "--stdin" => stdin_mode = true,
            "--country-groups" => groups = true,
            "--transport" => cfg.transport = value(&args, &mut i),
            "--skip" => cfg.skip = num(&args, &mut i, "--skip"),
            "--octets" => cfg.octets = list(&args, &mut i).iter().filter_map(|s| s.parse().ok()).collect(),
            "--tcp-concurrency" => cfg.tcp_concurrency = num(&args, &mut i, "--tcp-concurrency"),
            "--capture" => cfg.capture = true,
            "--pcap" => {
                cfg.capture = true;
                cfg.pcap_path = value(&args, &mut i);
            }
            "--source-port" => cfg.source_port = num(&args, &mut i, "--source-port"),
            other => cfg.targets.push(other.to_string()),
        }
        i += 1;
    }
    if stdin_mode {
        run_stdin();
        return;
    }
    if groups {
        match zedscan::engine::country_groups(&cfg.geoip_path, &cfg.countries) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("zedscan: {e}");
                std::process::exit(2);
            }
        }
        return;
    }
    if cfg.targets.is_empty() && cfg.countries.is_empty() {
        eprint!("{USAGE}");
        std::process::exit(2);
    }
    if let Some(n) = dry {
        let mut specs = cfg.targets.clone();
        if !cfg.countries.is_empty() {
            let data = std::fs::read(&cfg.geoip_path).unwrap_or_default();
            let cidrs = zedscan::targets::geoip_cidrs(&data, &cfg.countries);
            eprintln!("{} ranges for {}", cidrs.len(), cfg.countries.join(","));
            specs.push(cidrs.join("\n"));
        }
        let set = zedscan::targets::TargetSet::parse(&specs, cfg.port, cfg.exclude_special);
        let order = zedscan::targets::Order::parse(&cfg.order);
        let mut w = set.walker(order, cfg.limit, if cfg.seed == 0 { 1 } else { cfg.seed });
        println!("addresses {} planned {}", set.total(), w.planned());
        for _ in 0..n {
            match w.next(&set) {
                Some(idx) => println!("{}", set.addr(idx)),
                None => break,
            }
        }
        return;
    }
    let scan = match zedscan::start(cfg, None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zedscan: {e}");
            std::process::exit(2);
        }
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut results: Vec<Deep> = Vec::new();
    let mut last: Option<Progress> = None;
    let mut reason = String::new();
    let mut intercepted: Vec<String> = Vec::new();
    while let Some(events) = scan.poll(Duration::from_millis(500), 8192) {
        for ev in events {
            match &ev {
                Event::Result(d) => results.push(d.clone()),
                Event::Progress(p) => last = Some(p.clone()),
                Event::Done { reason: r, progress } => {
                    reason = r.clone();
                    last = Some(progress.clone());
                }
                Event::Intercept { by } => intercepted.push(by.clone()),
                _ => {}
            }
            let hide = summary_only || (quiet && matches!(ev, Event::Found(_) | Event::Progress(_)));
            if !hide {
                let _ = serde_json::to_writer(&mut out, &ev);
                let _ = writeln!(out);
            }
        }
        let _ = out.flush();
    }
    if let Some(p) = last {
        let secs = (p.elapsed_ms as f64 / 1000.0).max(0.001);
        eprintln!(
            "\n{} | planned {} sent {} done {} | recursive {} refused {} servfail {} other {} timeout {} closed {} unreachable {} hijacked {} intercepted {} late {}",
            reason, p.planned, p.sent, p.done, p.found, p.refused, p.servfail, p.other, p.timeouts, p.closed, p.unreachable,
            p.hijacked, p.intercepted, p.late
        );
        eprintln!(
            "{:.1}s, {:.0} probes/s average, final rate {}/{}, reference loss {:.0}% | deep {}/{} good {}",
            secs,
            p.sent as f64 / secs,
            p.rate,
            p.target_rate,
            p.canary_loss * 100.0,
            p.deep_done,
            p.deep_queued,
            p.good
        );
    }
    if !intercepted.is_empty() {
        eprintln!("DNS interception detected on this network (answers from {})", intercepted.join(", "));
    }
    results.sort_by(|a, b| b.score.cmp(&a.score).then(a.rtt.cmp(&b.rtt)));
    if !results.is_empty() {
        eprintln!("\nscore  rtt   p90  loss  qname  reply  burst tunnel tcp  address");
        for d in results.iter().take(top) {
            eprintln!(
                "{:>5} {:>4} {:>5} {:>4.0}% {:>6} {:>6} {:>5} {:>6} {:>4}  {}:{}{}",
                d.score,
                d.rtt,
                d.rtt_p90,
                d.loss * 100.0,
                d.max_qname,
                d.max_reply,
                d.burst.map(|b| format!("{:.0}%", b * 100.0)).unwrap_or_else(|| "-".into()),
                d.tunnel.map(|t| if t { "yes" } else { "no" }).unwrap_or("-"),
                d.tcp.map(|t| if t { "yes" } else { "no" }).unwrap_or("-"),
                d.ip,
                d.port,
                d.answered_by.as_ref().map(|a| format!(" (answered by {a})")).unwrap_or_default()
            );
        }
    }
}
