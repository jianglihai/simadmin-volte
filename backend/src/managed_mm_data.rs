//! Cellular data via a directly-managed ModemManager bearer.
//!
//! ============================================================================
//! REVERSE-ENGINEERED from simadmin 1.1.6-beta9 (aarch64-unknown-linux-musl)
//!   binary md5 : de53b623259c8190eb70aa6a82c6f2da
//!   commit     : 1f96018
//!
//! Evidence
//!   - .rodata cluster @ 0x90bdb5..0x90c305 (contiguous, complete)
//!   - mmcli argv fragments @ 0x8ec3a4..0x8ec4ec (contiguous)
//!   - panic anchor: src/managed_mm_data.rs:74  -> file is ~377 lines
//!   - functions: 0x533674 (16680B), 0x527d18 (12092B), 0x54bc90 (9556B),
//!                0x549314 (6588B), 0x54af00 (2324B), 0x58ff90 (716B)
//!
//! Confidence: A = literal from binary, B = control flow, C = inferred.
//! ============================================================================
//!
//! # Position in the data-path design
//!
//! SimAdmin has three ways to get user data up:
//!
//! | path | owner | module |
//! |---|---|---|
//! | NetworkManager GSM profile | NM | `modem_manager` |
//! | direct ModemManager bearer | us, via `mmcli` | **this module** |
//! | DATA6 secondary QMI WDS | us, via `qmicli` | `secondary_qmi_data` |
//!
//! This one exists because NetworkManager insists on owning the whole
//! connection lifecycle, which conflicts with VoLTE needing a second context on
//! the same modem. Driving `mmcli` directly keeps the bearer under our control
//! while leaving ModemManager as the QMI multiplexer.
//!
//! Route metric is **730**, one higher than [`crate::secondary_qmi_data`]'s
//! 729, so when both are somehow up the DATA6 path wins.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// mmcli argv + property keys — all literals from .rodata (confidence A)
// ---------------------------------------------------------------------------

const ARG_CREATE_BEARER_PREFIX: &str = "--create-bearer=apn=";
const ARG_CREATE_IP_TYPE: &str = ",ip-type=";
const ARG_CREATE_ALLOW_ROAMING: &str = ",allow-roaming=";
const ARG_DELETE_BEARER_PREFIX: &str = "--delete-bearer=";
const ARG_CONNECT: &str = "--connect";
const ARG_DISCONNECT: &str = "--disconnect";

/// `-K` selects machine-readable `key: value` output; `-b` addresses a bearer.
const ARG_KEYVALUE: &str = "-K";
const ARG_BEARER: &str = "-b";

const BEARER_PATH_PREFIX: &str = "/org/freedesktop/ModemManager1/Bearer/";

const P_CONNECTED: &str = "bearer.status.connected";
const P_INTERFACE: &str = "bearer.status.interface";
const P_APN: &str = "bearer.properties.apn";
const P_V4_ADDRESS: &str = "bearer.ipv4-config.address";
const P_V4_PREFIX: &str = "bearer.ipv4-config.prefix";
const P_V4_GATEWAY: &str = "bearer.ipv4-config.gateway";
const P_V4_DNS: &str = "bearer.ipv4-config.dns";
const P_V6_ADDRESS: &str = "bearer.ipv6-config.address";
const P_V6_PREFIX: &str = "bearer.ipv6-config.prefix";
const P_V6_GATEWAY: &str = "bearer.ipv6-config.gateway";
const P_V6_DNS: &str = "bearer.ipv6-config.dns";

// Error codes, forwarded verbatim to the HTTP layer.
const E_LOCK_POISONED: &str = "managed_mm_data_operation_lock_poisoned";
const E_APN_MISSING: &str = "managed_mm_data_apn_missing";
const E_BEARER_PATH_MISSING: &str = "managed_mm_data_bearer_path_missing";
const E_BEARER_NOT_CONNECTED: &str = "managed_mm_data_bearer_not_connected";
const E_SETTINGS_NOT_READY: &str = "managed_mm_data_settings_not_ready";
const E_IPV4_INVALID: &str = "managed_mm_data_ipv4_invalid";
const E_PREFIX_INVALID: &str = "managed_mm_data_prefix_invalid";
const E_GATEWAY_INVALID: &str = "managed_mm_data_gateway_invalid";
const E_IPV6_INVALID: &str = "managed_mm_data_ipv6_invalid";
const E_IPV6_GATEWAY_INVALID: &str = "managed_mm_data_ipv6_gateway_invalid";
/// Prefixed forms: `<code>:<detail>`.
const E_UNEXPECTED_INTERFACE: &str = "managed_mm_data_unexpected_interface";
const E_DUAL_STACK_FAILED: &str = "managed_mm_data_dual_stack_failed";
const E_IPV4_FAILED: &str = "ipv4_failed";
/// Emitted by the data coordinator, not by this module; kept for completeness.
#[allow(dead_code)]
const E_MISSING: &str = "managed_mm_data_missing";

/// Route metric for this path (literal `730`).
const ROUTE_METRIC: u32 = 730;

/// `--wait` style polling for bearer settings to populate after `--connect`.
const SETTINGS_POLL_ATTEMPTS: u32 = 25;

static OPERATION_LOCK: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Which address families to request from the modem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpType {
    Ipv4,
    Ipv6,
    Ipv4v6,
}

impl IpType {
    /// mmcli spelling.
    fn as_str(self) -> &'static str {
        match self {
            IpType::Ipv4 => "ipv4",
            IpType::Ipv6 => "ipv6",
            IpType::Ipv4v6 => "ipv4v6",
        }
    }
}

/// SIM auth method; mapped onto mmcli's `allowed-auth`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    None,
    Pap,
    Chap,
}

impl AuthMethod {
    fn as_str(self) -> &'static str {
        match self {
            AuthMethod::None => "none",
            AuthMethod::Pap => "pap",
            AuthMethod::Chap => "chap",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManagedDataRequest {
    pub apn: String,
    pub ip_type: IpType,
    pub roaming_allowed: bool,
    pub auth: AuthMethod,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone)]
struct Ipv4Config {
    address: Ipv4Addr,
    prefix: u8,
    gateway: Ipv4Addr,
    dns: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone)]
struct Ipv6Config {
    address: Ipv6Addr,
    prefix: u8,
    gateway: Ipv6Addr,
    dns: Vec<Ipv6Addr>,
}

#[derive(Debug, Clone, Default)]
pub struct ManagedDataState {
    pub active: bool,
    pub bearer_path: Option<String>,
    pub interface: String,
    pub apn: String,
    pub ipv4: Option<String>,
    pub ipv4_gateway: Option<String>,
    pub ipv6: Option<String>,
    started_at: Option<Instant>,
}

impl ManagedDataState {
    fn age_secs(&self) -> u64 {
        self.started_at.map(|t| t.elapsed().as_secs()).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Activation — VA 0x533674 / 0x527d18
// ---------------------------------------------------------------------------

/// Create, connect, and configure a ModemManager bearer.
///
/// Dual-stack is attempted first. On failure the whole attempt is retried as
/// IPv4-only, logging `Dual-stack ModemManager data activation failed; falling
/// back to IPv4` — note this differs from [`crate::secondary_qmi_data`], which
/// keeps a working IPv4 session and only drops IPv6.
pub fn activate(req: &ManagedDataRequest, state: &mut ManagedDataState) -> Result<()> {
    let _guard = OPERATION_LOCK.lock().map_err(|_| anyhow!(E_LOCK_POISONED))?;

    if req.apn.trim().is_empty() {
        bail!(E_APN_MISSING);
    }

    if state.active {
        info!(
            target: "simadmin::managed_mm_data",
            "Managed MM data already active interface={} ip={} gw={} age_secs={}",
            state.interface,
            state.ipv4.as_deref().unwrap_or("-"),
            state.ipv4_gateway.as_deref().unwrap_or("-"),
            state.age_secs(),
        );
        return Ok(());
    }

    // First attempt: whatever the caller asked for.
    match try_activate(req, state) {
        Ok(()) => Ok(()),
        Err(dual_err) if req.ip_type == IpType::Ipv4v6 => {
            warn!(
                target: "simadmin::managed_mm_data",
                error = %dual_err,
                "Dual-stack ModemManager data activation failed; falling back to IPv4"
            );
            let mut v4_only = req.clone();
            v4_only.ip_type = IpType::Ipv4;
            try_activate(&v4_only, state).map_err(|v4_err| {
                anyhow!("{E_DUAL_STACK_FAILED}:{dual_err};{E_IPV4_FAILED}:{v4_err}")
            })
        }
        Err(e) => Err(e),
    }
}

fn try_activate(req: &ManagedDataRequest, state: &mut ManagedDataState) -> Result<()> {
    let bearer_path = create_bearer(req)?;
    // From here on any failure must delete the bearer, else the modem
    // accumulates orphans and eventually returns ClientIdsExhausted.
    let result = (|| -> Result<()> {
        connect_bearer(&bearer_path)?;
        let props = wait_for_settings(&bearer_path)?;

        let interface = props
            .get(P_INTERFACE)
            .cloned()
            .ok_or_else(|| anyhow!(E_SETTINGS_NOT_READY))?;
        if interface.is_empty() || interface == "--" {
            bail!("{E_UNEXPECTED_INTERFACE}:{interface}");
        }

        let v4 = parse_ipv4(&props)?;
        configure_ipv4(&interface, &v4)?;
        state.ipv4 = Some(v4.address.to_string());
        state.ipv4_gateway = Some(v4.gateway.to_string());

        let mut v6cfg = None;
        if matches!(req.ip_type, IpType::Ipv6 | IpType::Ipv4v6) {
            match parse_ipv6(&props) {
                Ok(v6) => match configure_ipv6(&interface, &v6) {
                    Ok(()) => {
                        state.ipv6 = Some(v6.address.to_string());
                        v6cfg = Some(v6);
                    }
                    Err(e) => warn!(
                        target: "simadmin::managed_mm_data",
                        error = %e,
                        "IPv6 data configuration failed; retaining IPv4 data"
                    ),
                },
                Err(e) => warn!(
                    target: "simadmin::managed_mm_data",
                    error = %e,
                    "IPv6 data configuration failed; retaining IPv4 data"
                ),
            }
        }

        if configure_dns(&interface, &v4, v6cfg.as_ref()).is_ok() {
            info!(target: "simadmin::managed_mm_data", "Cellular DNS configured");
        }

        state.active = true;
        state.bearer_path = Some(bearer_path.clone());
        state.interface = interface;
        state.apn = props.get(P_APN).cloned().unwrap_or_else(|| req.apn.clone());
        state.started_at = Some(Instant::now());

        info!(
            target: "simadmin::managed_mm_data",
            "Managed MM data activated interface={} ipv4={} gw={} ipv6={} apn={}",
            state.interface,
            state.ipv4.as_deref().unwrap_or("-"),
            state.ipv4_gateway.as_deref().unwrap_or("-"),
            state.ipv6.as_deref().unwrap_or("-"),
            state.apn,
        );
        info!(
            target: "simadmin::managed_mm_data",
            "Managed ModemManager data bearer activated"
        );
        Ok(())
    })();

    if result.is_err() {
        let _ = delete_bearer(&bearer_path);
    }
    result
}

/// `mmcli -m any --create-bearer=apn=...,ip-type=...,allow-roaming=...`
///
/// Returns the D-Bus object path of the new bearer.
fn create_bearer(req: &ManagedDataRequest) -> Result<String> {
    let mut spec = String::new();
    spec.push_str(ARG_CREATE_BEARER_PREFIX);
    spec.push_str(&req.apn);
    spec.push_str(ARG_CREATE_IP_TYPE);
    spec.push_str(req.ip_type.as_str());
    spec.push_str(ARG_CREATE_ALLOW_ROAMING);
    spec.push_str(if req.roaming_allowed { "yes" } else { "no" });
    if req.auth != AuthMethod::None {
        spec.push_str(",allowed-auth=");
        spec.push_str(req.auth.as_str());
    }
    if let Some(u) = &req.username {
        if !u.is_empty() {
            spec.push_str(",user=");
            spec.push_str(u);
        }
    }
    if let Some(p) = &req.password {
        if !p.is_empty() {
            spec.push_str(",password=");
            spec.push_str(p);
        }
    }

    let out = mmcli(&["-m", "any", &spec])?;
    parse_bearer_path(&out).ok_or_else(|| anyhow!(E_BEARER_PATH_MISSING))
}

fn connect_bearer(path: &str) -> Result<()> {
    mmcli(&[ARG_BEARER, path, ARG_CONNECT])?;
    Ok(())
}

fn delete_bearer(path: &str) -> Result<()> {
    let spec = format!("{ARG_DELETE_BEARER_PREFIX}{path}");
    mmcli(&["-m", "any", &spec])?;
    Ok(())
}

/// Poll `mmcli -b <path> -K` until the IP config is populated. ModemManager
/// reports `connected: yes` slightly before the addresses land.
fn wait_for_settings(path: &str) -> Result<std::collections::BTreeMap<String, String>> {
    for _ in 0..SETTINGS_POLL_ATTEMPTS {
        let out = mmcli(&[ARG_BEARER, path, ARG_KEYVALUE])?;
        let props = parse_keyvalue(&out);
        let connected = props
            .get(P_CONNECTED)
            .map(|v| v == "yes")
            .unwrap_or(false);
        if connected && props.contains_key(P_V4_ADDRESS) {
            return Ok(props);
        }
        if !connected {
            // Still transitioning; keep waiting rather than failing fast.
            std::thread::sleep(std::time::Duration::from_millis(200));
            continue;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    // One last read so the caller sees a real reason.
    let out = mmcli(&[ARG_BEARER, path, ARG_KEYVALUE])?;
    let props = parse_keyvalue(&out);
    if props.get(P_CONNECTED).map(|v| v != "yes").unwrap_or(true) {
        bail!(E_BEARER_NOT_CONNECTED);
    }
    bail!(E_SETTINGS_NOT_READY)
}

// ---------------------------------------------------------------------------
// Deactivation — VA 0x54bc90
// ---------------------------------------------------------------------------

pub fn deactivate(state: &mut ManagedDataState) -> Result<()> {
    let _guard = OPERATION_LOCK.lock().map_err(|_| anyhow!(E_LOCK_POISONED))?;

    if !state.active {
        return Ok(());
    }
    let path = state
        .bearer_path
        .clone()
        .ok_or_else(|| anyhow!(E_BEARER_PATH_MISSING))?;

    if let Err(e) = mmcli(&[ARG_BEARER, &path, ARG_DISCONNECT]) {
        warn!(target: "simadmin::managed_mm_data", error = %e, "bearer disconnect failed");
    }
    if let Err(e) = delete_bearer(&path) {
        warn!(target: "simadmin::managed_mm_data", error = %e, "bearer delete failed");
    }

    if !state.interface.is_empty() {
        let ip = ip_bin();
        let _ = run(ip, &["addr", "flush", "dev", &state.interface]);
        let _ = run(ip, &["-6", "addr", "flush", "dev", &state.interface]);
    }

    *state = ManagedDataState::default();
    info!(target: "simadmin::managed_mm_data", "Managed MM data deactivated");
    info!(
        target: "simadmin::managed_mm_data",
        "Managed ModemManager data bearer deactivated"
    );
    Ok(())
}

/// Drop any bearer we own before handing the modem back to NetworkManager.
/// Called by the data coordinator; the log line
/// `Managed data cleanup before NM activation failed` lives at the call site.
pub fn cleanup_before_nm(state: &mut ManagedDataState) -> Result<()> {
    if state.active {
        deactivate(state)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// mmcli plumbing
// ---------------------------------------------------------------------------

fn mmcli(args: &[&str]) -> Result<String> {
    let out = Command::new("mmcli")
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute mmcli: {args:?}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("mmcli exited with {}: {}", out.status, stderr.trim());
    }
    Ok(stdout)
}

/// `mmcli -K` emits `key : value`; also tolerate the human format.
fn parse_keyvalue(out: &str) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    for line in out.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if !k.is_empty() && !v.is_empty() && v != "--" {
                map.insert(k.to_string(), v.to_string());
            }
        }
    }
    map
}

fn parse_bearer_path(out: &str) -> Option<String> {
    out.lines()
        .flat_map(|l| l.split_whitespace())
        .find(|t| t.starts_with(BEARER_PATH_PREFIX))
        .map(|s| s.trim_matches(|c: char| !c.is_ascii_graphic()).to_string())
}

fn parse_ipv4(p: &std::collections::BTreeMap<String, String>) -> Result<Ipv4Config> {
    let address: Ipv4Addr = p
        .get(P_V4_ADDRESS)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!(E_IPV4_INVALID))?;
    let prefix: u8 = p
        .get(P_V4_PREFIX)
        .and_then(|s| s.parse().ok())
        .filter(|n| *n <= 32)
        .ok_or_else(|| anyhow!(E_PREFIX_INVALID))?;
    let gateway: Ipv4Addr = p
        .get(P_V4_GATEWAY)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!(E_GATEWAY_INVALID))?;
    let dns = p
        .get(P_V4_DNS)
        .map(|s| {
            s.split(',')
                .filter_map(|x| x.trim().parse::<Ipv4Addr>().ok())
                .collect()
        })
        .unwrap_or_default();
    Ok(Ipv4Config {
        address,
        prefix,
        gateway,
        dns,
    })
}

fn parse_ipv6(p: &std::collections::BTreeMap<String, String>) -> Result<Ipv6Config> {
    let address: Ipv6Addr = p
        .get(P_V6_ADDRESS)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!(E_IPV6_INVALID))?;
    let prefix: u8 = p
        .get(P_V6_PREFIX)
        .and_then(|s| s.parse().ok())
        .filter(|n| *n <= 128)
        .unwrap_or(64);
    let gateway: Ipv6Addr = p
        .get(P_V6_GATEWAY)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!(E_IPV6_GATEWAY_INVALID))?;
    let dns = p
        .get(P_V6_DNS)
        .map(|s| {
            s.split(',')
                .filter_map(|x| x.trim().parse::<Ipv6Addr>().ok())
                .collect()
        })
        .unwrap_or_default();
    Ok(Ipv6Config {
        address,
        prefix,
        gateway,
        dns,
    })
}

// ---------------------------------------------------------------------------
// Interface configuration (shared shape with secondary_qmi_data)
// ---------------------------------------------------------------------------

fn ip_bin() -> &'static str {
    if std::path::Path::new("/bin/ip").exists() {
        "/bin/ip"
    } else {
        "/usr/bin/ip"
    }
}

fn configure_ipv4(iface: &str, cfg: &Ipv4Config) -> Result<()> {
    let ip = ip_bin();
    run(ip, &["link", "set", iface, "up"])?;
    let cidr = format!("{}/{}", cfg.address, cfg.prefix);
    run(ip, &["addr", "replace", &cidr, "dev", iface])?;
    run(
        ip,
        &[
            "route",
            "replace",
            "default",
            "via",
            &cfg.gateway.to_string(),
            "dev",
            iface,
            "metric",
            &ROUTE_METRIC.to_string(),
        ],
    )?;
    Ok(())
}

fn configure_ipv6(iface: &str, cfg: &Ipv6Config) -> Result<()> {
    let ip = ip_bin();
    let cidr = format!("{}/{}", cfg.address, cfg.prefix);
    run(
        ip,
        &[
            "-6", "addr", "replace", &cidr, "dev", iface, "nodad", "noprefixroute",
        ],
    )?;
    run(
        ip,
        &[
            "-6",
            "route",
            "replace",
            "default",
            "via",
            &cfg.gateway.to_string(),
            "dev",
            iface,
            "metric",
            &ROUTE_METRIC.to_string(),
            "onlink",
        ],
    )?;
    Ok(())
}

fn configure_dns(iface: &str, v4: &Ipv4Config, v6: Option<&Ipv6Config>) -> Result<()> {
    let mut servers: Vec<String> = v4.dns.iter().map(|a| a.to_string()).collect();
    if let Some(c) = v6 {
        servers.extend(c.dns.iter().map(|a| a.to_string()));
    }
    if servers.is_empty() {
        bail!("cellular_dns_servers_missing");
    }
    if nm_active() {
        let body = format!("[global-dns-domain-*]\nservers={}\n", servers.join(","));
        std::fs::create_dir_all("/run/NetworkManager/conf.d").ok();
        std::fs::write(
            "/run/NetworkManager/conf.d/90-simadmin-cellular-dns.conf",
            body,
        )?;
        let _ = run("nmcli", &["general", "reload", "conf,dns-rc"]);
        return Ok(());
    }
    let mut args: Vec<&str> = vec!["dns", iface];
    for s in &servers {
        args.push(s.as_str());
    }
    run("resolvectl", &args)?;
    run("resolvectl", &["domain", iface, "~."])?;
    Ok(())
}

fn nm_active() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "NetworkManager.service"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run(bin: &str, args: &[&str]) -> Result<()> {
    let st = Command::new(bin)
        .args(args)
        .status()
        .with_context(|| format!("failed to execute command: {bin} {args:?}"))?;
    if !st.success() {
        bail!("{bin} {args:?} failed: {st}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_bearer_path() {
        let out = "Successfully created new bearer in modem:\n\t/org/freedesktop/ModemManager1/Bearer/4\n";
        assert_eq!(
            parse_bearer_path(out).as_deref(),
            Some("/org/freedesktop/ModemManager1/Bearer/4")
        );
    }

    #[test]
    fn parses_keyvalue_output() {
        let out = "\
bearer.status.connected      : yes
bearer.status.interface      : wwan0
bearer.ipv4-config.address   : 10.1.2.3
bearer.ipv4-config.prefix    : 30
bearer.ipv4-config.gateway   : 10.1.2.4
bearer.ipv4-config.dns       : 8.8.8.8, 8.8.4.4
bearer.ipv6-config.address   : --
";
        let p = parse_keyvalue(out);
        assert_eq!(p.get(P_CONNECTED).unwrap(), "yes");
        assert_eq!(p.get(P_INTERFACE).unwrap(), "wwan0");
        // `--` placeholders are dropped so parse_ipv6 fails cleanly.
        assert!(!p.contains_key(P_V6_ADDRESS));

        let v4 = parse_ipv4(&p).unwrap();
        assert_eq!(v4.prefix, 30);
        assert_eq!(v4.dns.len(), 2);
    }

    #[test]
    fn ip_type_and_auth_spellings_match_mmcli() {
        assert_eq!(IpType::Ipv4v6.as_str(), "ipv4v6");
        assert_eq!(AuthMethod::Chap.as_str(), "chap");
    }

    /// This module must sort *after* the DATA6 path when both are up.
    #[test]
    fn route_metric_is_higher_than_secondary_path() {
        assert_eq!(ROUTE_METRIC, 730);
        assert!(ROUTE_METRIC > 729);
    }

    #[test]
    fn create_bearer_spec_shape() {
        let req = ManagedDataRequest {
            apn: "ctlte".into(),
            ip_type: IpType::Ipv4v6,
            roaming_allowed: false,
            auth: AuthMethod::None,
            username: None,
            password: None,
        };
        let mut spec = String::new();
        spec.push_str(ARG_CREATE_BEARER_PREFIX);
        spec.push_str(&req.apn);
        spec.push_str(ARG_CREATE_IP_TYPE);
        spec.push_str(req.ip_type.as_str());
        spec.push_str(ARG_CREATE_ALLOW_ROAMING);
        spec.push_str("no");
        assert_eq!(
            spec,
            "--create-bearer=apn=ctlte,ip-type=ipv4v6,allow-roaming=no"
        );
    }
}
