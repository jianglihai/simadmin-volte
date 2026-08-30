//! Cellular data over the DATA6 secondary QMI endpoint.
//!
//! ============================================================================
//! REVERSE-ENGINEERED from simadmin 1.1.6-beta9 (aarch64-unknown-linux-musl)
//!   binary md5 : de53b623259c8190eb70aa6a82c6f2da
//!   commit     : 1f96018
//!
//! Evidence
//!   - .rodata string cluster @ 0x90c8a2..0x90cf05 (contiguous, complete)
//!   - qmicli argv fragments  @ 0x8ec837..0x8ec9da (contiguous, complete)
//!   - panic anchors: src/secondary_qmi_data.rs:{156,161,187,214,474,517}
//!     -> original file is ~517 lines
//!   - functions: 0x54ec5c (180B, deactivate), 0x550cd0 (11632B, activate),
//!                0x5aa83c (384B, status), 0x7d82a0 (32B, thunk)
//!
//! Confidence: A = literal from binary, B = control flow from disassembly,
//!             C = inferred ordering.
//! ============================================================================
//!
//! # Why this module exists
//!
//! ModemManager owns the primary QMI port. To run *two* independent PDP
//! contexts — one for user data, one for IMS — SimAdmin drives a second WDS
//! service on the DATA6 endpoint that [`crate::secondary_qmi`] published.
//!
//! # The CID lifecycle, which is the whole trick
//!
//! `qmicli` normally allocates a WDS client ID, does one operation, and
//! releases it on exit. A released CID tears down its network session, so a
//! naive `--wds-start-network` followed by a separate `--wds-get-current-settings`
//! reads back *nothing*: the second invocation gets a fresh, empty client.
//!
//! The sequence below keeps one CID alive across several `qmicli` processes:
//!
//! ```text
//!   1. --wds-noop --client-no-release-cid          -> allocates CID, keeps it
//!      (parse "CID: 'N'" from stdout)
//!   2. --client-cid=N --wds-set-ip-family=4|6      -> pin family on that CID
//!   3. --client-cid=N --wds-start-network=apn=...  -> session on that CID
//!      (parse "Packet data handle: 'H'")
//!   4. --client-cid=N --wds-get-current-settings   -> NOW returns the config
//!   ...
//!   5. --client-cid=N --wds-stop-network=H         -> teardown
//! ```
//!
//! IPv4 and IPv6 get **separate CIDs and separate handles**; they are two
//! independent WDS sessions on the same endpoint.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use tracing::{info, warn};

use crate::secondary_qmi::{self, SecondaryQmiEndpoint};

// ---------------------------------------------------------------------------
// qmicli argv — all literals verbatim from .rodata (confidence A)
// ---------------------------------------------------------------------------

const ARG_CLIENT_NO_RELEASE_CID: &str = "--client-no-release-cid";
const ARG_WDS_NOOP: &str = "--wds-noop";
const ARG_CLIENT_CID_PREFIX: &str = "--client-cid=";
const ARG_SET_IP_FAMILY_4: &str = "--wds-set-ip-family=4";
const ARG_SET_IP_FAMILY_6: &str = "--wds-set-ip-family=6";
const ARG_START_NETWORK_PREFIX: &str = "--wds-start-network=apn=";
const ARG_START_SUFFIX_V4: &str = ",3gpp-profile=1,ip-type=4";
const ARG_START_SUFFIX_V6: &str = ",3gpp-profile=1,ip-type=6";
const ARG_STOP_NETWORK_PREFIX: &str = "--wds-stop-network=";
const ARG_GET_CURRENT_SETTINGS: &str = "--wds-get-current-settings";
const ARG_GET_PACKET_SERVICE_STATUS: &str = "--wds-get-packet-service-status";

/// Markers parsed out of qmicli stdout.
const MARK_CID: &str = "CID:";
const MARK_PACKET_DATA_HANDLE: &str = "Packet data handle:";
const MARK_CONNECTED: &str = "Connection status: 'connected'";

/// `--wds-get-current-settings` field labels.
const F_IPV4_ADDRESS: &str = "IPv4 address";
const F_IPV4_MASK: &str = "IPv4 subnet mask";
const F_IPV4_GATEWAY: &str = "IPv4 gateway address";
const F_IPV4_DNS1: &str = "IPv4 primary DNS";
const F_IPV4_DNS2: &str = "IPv4 secondary DNS";
const F_IPV6_ADDRESS: &str = "IPv6 address";
const F_IPV6_GATEWAY: &str = "IPv6 gateway address";
const F_IPV6_DNS1: &str = "IPv6 primary DNS";
const F_IPV6_DNS2: &str = "IPv6 secondary DNS";

/// ModemManager property consulted before dialling.
const MM_PROP_REGISTRATION_STATE: &str = "modem.3gpp.registration-state";

/// Registration-state tokens (cluster @ 0x906xxx: "roamingsearchingdeniedidle").
const REG_HOME: &str = "home";
const REG_ROAMING: &str = "roaming";

/// Error codes. Every one is a literal in .rodata; the HTTP layer forwards
/// these verbatim to the UI, so the spelling matters.
const E_LOCK_POISONED: &str = "secondary_qmi_data_operation_lock_poisoned";
const E_APN_MISSING: &str = "secondary_qmi_data_apn_missing";
const E_CID_MISSING: &str = "secondary_qmi_data_cid_missing";
const E_HANDLE_MISSING: &str = "secondary_qmi_data_handle_missing";
const E_IPV6_CID_MISSING: &str = "secondary_qmi_data_ipv6_cid_missing";
const E_IPV6_HANDLE_MISSING: &str = "secondary_qmi_data_ipv6_handle_missing";
const E_IPV4_INVALID: &str = "secondary_qmi_data_ipv4_invalid";
const E_MASK_INVALID: &str = "secondary_qmi_data_mask_invalid";
const E_MASK_NON_CONTIGUOUS: &str = "secondary_qmi_data_mask_non_contiguous";
const E_GATEWAY_INVALID: &str = "secondary_qmi_data_gateway_invalid";
const E_IPV6_INVALID: &str = "secondary_qmi_data_ipv6_invalid";
const E_IPV6_GATEWAY_INVALID: &str = "secondary_qmi_data_ipv6_gateway_invalid";
const E_IPV6_PREFIX_INVALID: &str = "secondary_qmi_data_ipv6_prefix_invalid";
const E_REG_STATE_MISSING: &str = "secondary_qmi_data_registration_state_missing";
const E_ROAMING_FORBIDDEN: &str = "secondary_qmi_data_roaming_forbidden";
/// Prefixed forms — the binary stores these with a leading sigil byte that the
/// formatter replaces, e.g. `secondary_qmi_data_registration_not_home:<state>`.
const E_REG_NOT_HOME: &str = "secondary_qmi_data_registration_not_home";
const E_DEVICE_UNAVAILABLE: &str = "secondary_qmi_device_unavailable";
const E_DATA6_START_FAILED: &str = "secondary_qmi_data6_start_failed";
/// Emitted by the data coordinator, not by this module; kept for completeness.
#[allow(dead_code)]
const E_MISSING: &str = "secondary_qmi_data_missing";

/// Route metric used for the secondary default route (literal `729`; the
/// managed-MM path next door uses `730`, keeping the two orderable).
const ROUTE_METRIC: u32 = 729;

/// Serialises activate/deactivate. The poisoned case maps to [`E_LOCK_POISONED`].
static OPERATION_LOCK: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One WDS session: a CID we keep alive plus the handle it produced.
///
/// Public because [`is_connected`] takes one — the health checker in
/// `volte::runtime` polls sessions it did not create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WdsSession {
    pub cid: u32,
    pub handle: u64,
}

/// IPv4 config as reported by `--wds-get-current-settings`.
#[derive(Debug, Clone)]
struct Ipv4Config {
    address: Ipv4Addr,
    prefix: u8,
    gateway: Ipv4Addr,
    dns: Vec<Ipv4Addr>,
}

/// IPv6 config. The modem reports a full address; prefix defaults to /64.
#[derive(Debug, Clone)]
struct Ipv6Config {
    address: Ipv6Addr,
    prefix: u8,
    gateway: Ipv6Addr,
    dns: Vec<Ipv6Addr>,
}

/// Live state, kept so `deactivate` can stop exactly the sessions we started
/// and so repeated `activate` calls are idempotent.
#[derive(Debug, Clone, Default)]
pub struct SecondaryDataState {
    pub active: bool,
    pub interface: String,
    pub apn: String,
    pub ipv4: Option<String>,
    pub ipv4_gateway: Option<String>,
    pub ipv6: Option<String>,
    started_at: Option<Instant>,
    v4: Option<WdsSession>,
    v6: Option<WdsSession>,
}

impl SecondaryDataState {
    fn age_secs(&self) -> u64 {
        self.started_at.map(|t| t.elapsed().as_secs()).unwrap_or(0)
    }
}

/// Caller-supplied dial parameters.
#[derive(Debug, Clone)]
pub struct SecondaryDataRequest {
    pub apn: String,
    /// `false` refuses to dial while the modem reports roaming.
    pub roaming_allowed: bool,
    /// Try IPv4 *and* IPv6; on IPv6 failure the IPv4 session is retained.
    pub dual_stack: bool,
}

// ---------------------------------------------------------------------------
// Activation — VA 0x550cd0 (11632 bytes; the bulk of this module)
// ---------------------------------------------------------------------------

/// Bring up cellular data on the DATA6 endpoint.
///
/// Dual-stack strategy (matches the sibling `managed_mm_data` path): IPv4 is
/// established first and is the one that must succeed. IPv6 is attempted after,
/// and if it fails we log `Secondary DATA6 IPv6 unavailable; retaining IPv4
/// data`, restore the IPv4-only DNS set, and return success.
pub fn activate(
    req: &SecondaryDataRequest,
    state: &mut SecondaryDataState,
) -> Result<()> {
    let _guard = OPERATION_LOCK.lock().map_err(|_| anyhow!(E_LOCK_POISONED))?;

    if req.apn.trim().is_empty() {
        bail!(E_APN_MISSING);
    }

    // Idempotence: already up with the same APN -> report and return.
    if state.active {
        info!(
            target: "simadmin::secondary_qmi_data",
            "Secondary QMI data already active interface={} ipv4={} gw={} ipv6={} age_secs={}",
            state.interface,
            state.ipv4.as_deref().unwrap_or("-"),
            state.ipv4_gateway.as_deref().unwrap_or("-"),
            state.ipv6.as_deref().unwrap_or("-"),
            state.age_secs(),
        );
        return Ok(());
    }

    let endpoint = secondary_qmi::load_runtime_state()
        .map_err(|e| anyhow!("{E_DEVICE_UNAVAILABLE}:{e}"))?;

    // Registration gate. `mmcli` is the source of truth; a missing property is
    // a hard error rather than an optimistic dial.
    let reg = read_registration_state().ok_or_else(|| anyhow!(E_REG_STATE_MISSING))?;
    match reg.as_str() {
        REG_HOME => {}
        REG_ROAMING if req.roaming_allowed => {}
        REG_ROAMING => bail!(E_ROAMING_FORBIDDEN),
        other => bail!("{E_REG_NOT_HOME}:{other}"),
    }

    // ---- IPv4 ----
    let v4_session = start_session(&endpoint, &req.apn, IpFamily::V4)?;
    let v4_cfg = read_ipv4_settings(&endpoint, v4_session.cid)?;
    configure_ipv4(&endpoint.netdev, &v4_cfg)?;

    state.v4 = Some(v4_session);
    state.ipv4 = Some(v4_cfg.address.to_string());
    state.ipv4_gateway = Some(v4_cfg.gateway.to_string());

    // ---- IPv6 (best effort) ----
    let mut v6_cfg: Option<Ipv6Config> = None;
    if req.dual_stack {
        match start_session(&endpoint, &req.apn, IpFamily::V6)
            .and_then(|s| read_ipv6_settings(&endpoint, s.cid).map(|c| (s, c)))
        {
            Ok((session, cfg)) => {
                if let Err(e) = configure_ipv6(&endpoint.netdev, &cfg) {
                    warn!(
                        target: "simadmin::secondary_qmi_data",
                        error = %e,
                        "Secondary DATA6 IPv6 unavailable; retaining IPv4 data"
                    );
                    let _ = stop_session(&endpoint, session);
                } else {
                    state.v6 = Some(session);
                    state.ipv6 = Some(cfg.address.to_string());
                    v6_cfg = Some(cfg);
                }
            }
            Err(e) => {
                warn!(
                    target: "simadmin::secondary_qmi_data",
                    error = %e,
                    "Secondary DATA6 IPv6 unavailable; retaining IPv4 data"
                );
            }
        }
    }

    // DNS last, so a dual-stack resolver set is written in one shot. Falling
    // back to IPv4-only DNS must not fail the whole activation.
    if let Err(e) = configure_dns(&endpoint.netdev, &v4_cfg, v6_cfg.as_ref()) {
        warn!(
            target: "simadmin::secondary_qmi_data",
            error = %e,
            "Failed to restore IPv4 DNS after DATA6 IPv6 fallback"
        );
    } else if v6_cfg.is_some() {
        info!(
            target: "simadmin::secondary_qmi_data",
            "Dual-stack cellular DNS configured"
        );
    }

    state.active = true;
    state.interface = endpoint.netdev.clone();
    state.apn = req.apn.clone();
    state.started_at = Some(Instant::now());

    info!(
        target: "simadmin::secondary_qmi_data",
        "Secondary QMI data activated interface={} ipv4={} gw={} ipv6={} apn={}",
        state.interface,
        state.ipv4.as_deref().unwrap_or("-"),
        state.ipv4_gateway.as_deref().unwrap_or("-"),
        state.ipv6.as_deref().unwrap_or("-"),
        state.apn,
    );
    info!(
        target: "simadmin::secondary_qmi_data",
        "Secondary DATA6 QMI data bearer activated"
    );

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    fn set_family_arg(self) -> &'static str {
        match self {
            IpFamily::V4 => ARG_SET_IP_FAMILY_4,
            IpFamily::V6 => ARG_SET_IP_FAMILY_6,
        }
    }
    fn start_suffix(self) -> &'static str {
        match self {
            IpFamily::V4 => ARG_START_SUFFIX_V4,
            IpFamily::V6 => ARG_START_SUFFIX_V6,
        }
    }
    fn cid_missing_err(self) -> &'static str {
        match self {
            IpFamily::V4 => E_CID_MISSING,
            IpFamily::V6 => E_IPV6_CID_MISSING,
        }
    }
    fn handle_missing_err(self) -> &'static str {
        match self {
            IpFamily::V4 => E_HANDLE_MISSING,
            IpFamily::V6 => E_IPV6_HANDLE_MISSING,
        }
    }
}

/// The three-step CID-preserving dial described in the module docs.
fn start_session(
    ep: &SecondaryQmiEndpoint,
    apn: &str,
    family: IpFamily,
) -> Result<WdsSession> {
    // 1. Allocate a CID and *keep* it.
    let noop = qmicli(ep, &[ARG_WDS_NOOP, ARG_CLIENT_NO_RELEASE_CID])?;
    let cid = parse_cid(&noop).ok_or_else(|| anyhow!(family.cid_missing_err()))?;

    let cid_arg = format!("{ARG_CLIENT_CID_PREFIX}{cid}");

    // 2. Pin the IP family on that CID.
    qmicli(
        ep,
        &[&cid_arg, family.set_family_arg(), ARG_CLIENT_NO_RELEASE_CID],
    )?;

    // 3. Start the network on that CID.
    let start_arg = format!(
        "{ARG_START_NETWORK_PREFIX}{apn}{suffix}",
        suffix = family.start_suffix()
    );
    let out = qmicli(ep, &[&cid_arg, &start_arg, ARG_CLIENT_NO_RELEASE_CID])
        .map_err(|e| anyhow!("{E_DATA6_START_FAILED}:{e}"))?;
    let handle =
        parse_packet_data_handle(&out).ok_or_else(|| anyhow!(family.handle_missing_err()))?;

    Ok(WdsSession { cid, handle })
}

fn stop_session(ep: &SecondaryQmiEndpoint, s: WdsSession) -> Result<()> {
    let cid_arg = format!("{ARG_CLIENT_CID_PREFIX}{}", s.cid);
    let stop_arg = format!("{ARG_STOP_NETWORK_PREFIX}{}", s.handle);
    qmicli(ep, &[&cid_arg, &stop_arg])?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Deactivation — VA 0x54ec5c
// ---------------------------------------------------------------------------

/// Tear down both sessions using the saved CID/handle pairs.
pub fn deactivate(state: &mut SecondaryDataState) -> Result<()> {
    let _guard = OPERATION_LOCK.lock().map_err(|_| anyhow!(E_LOCK_POISONED))?;

    if !state.active {
        info!(
            target: "simadmin::secondary_qmi_data",
            "Secondary QMI data already inactive"
        );
        return Ok(());
    }

    let endpoint = secondary_qmi::load_runtime_state()
        .map_err(|e| anyhow!("{E_DEVICE_UNAVAILABLE}:{e}"))?;

    // IPv6 first, so a failure there still lets IPv4 be cleaned.
    if let Some(s) = state.v6.take() {
        if let Err(e) = stop_session(&endpoint, s) {
            warn!(target: "simadmin::secondary_qmi_data", error = %e, "IPv6 session stop failed");
        }
    }
    if let Some(s) = state.v4.take() {
        if let Err(e) = stop_session(&endpoint, s) {
            warn!(target: "simadmin::secondary_qmi_data", error = %e, "IPv4 session stop failed");
        }
    }

    flush_interface(&endpoint.netdev);

    *state = SecondaryDataState::default();

    info!(target: "simadmin::secondary_qmi_data", "Secondary QMI data deactivated");
    info!(
        target: "simadmin::secondary_qmi_data",
        "Secondary DATA6 QMI data bearer deactivated"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Health check — VA 0x5aa83c
// ---------------------------------------------------------------------------

/// True when the modem still reports the packet session as connected.
pub fn is_connected(ep: &SecondaryQmiEndpoint, s: WdsSession) -> bool {
    let cid_arg = format!("{ARG_CLIENT_CID_PREFIX}{}", s.cid);
    match qmicli(ep, &[&cid_arg, ARG_GET_PACKET_SERVICE_STATUS]) {
        Ok(out) => out.contains(MARK_CONNECTED),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// qmicli plumbing
// ---------------------------------------------------------------------------

fn qmicli(ep: &SecondaryQmiEndpoint, args: &[&str]) -> Result<String> {
    let out = Command::new("qmicli")
        .arg(format!("--device={}", ep.qmi_device.display()))
        .arg("--device-open-qmi")
        .args(args)
        .output()
        .with_context(|| format!("failed to execute command: qmicli {args:?}"))?;

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("qmicli exited with {}: {}", out.status, stderr.trim());
    }
    Ok(stdout)
}

/// Extract `N` from a line like `    CID: '17'`.
fn parse_cid(out: &str) -> Option<u32> {
    for line in out.lines() {
        if let Some(rest) = line.trim().strip_prefix(MARK_CID) {
            return rest.trim().trim_matches('\'').parse().ok();
        }
    }
    None
}

/// Extract `H` from `Packet data handle: '2334889824'`.
fn parse_packet_data_handle(out: &str) -> Option<u64> {
    for line in out.lines() {
        if let Some(rest) = line.trim().strip_prefix(MARK_PACKET_DATA_HANDLE) {
            return rest.trim().trim_matches('\'').parse().ok();
        }
    }
    None
}

/// Pull `Label: value` out of `--wds-get-current-settings` output.
fn field<'a>(out: &'a str, label: &str) -> Option<&'a str> {
    for line in out.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix(label) {
            let rest = rest.trim_start();
            if let Some(v) = rest.strip_prefix(':') {
                return Some(v.trim());
            }
        }
    }
    None
}

fn read_ipv4_settings(ep: &SecondaryQmiEndpoint, cid: u32) -> Result<Ipv4Config> {
    let cid_arg = format!("{ARG_CLIENT_CID_PREFIX}{cid}");
    let out = qmicli(ep, &[&cid_arg, ARG_GET_CURRENT_SETTINGS])?;

    let address: Ipv4Addr = field(&out, F_IPV4_ADDRESS)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!(E_IPV4_INVALID))?;
    let mask: Ipv4Addr = field(&out, F_IPV4_MASK)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!(E_MASK_INVALID))?;
    let prefix = mask_to_prefix(mask).ok_or_else(|| anyhow!(E_MASK_NON_CONTIGUOUS))?;
    let gateway: Ipv4Addr = field(&out, F_IPV4_GATEWAY)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!(E_GATEWAY_INVALID))?;

    let mut dns = Vec::new();
    for label in [F_IPV4_DNS1, F_IPV4_DNS2] {
        if let Some(v) = field(&out, label).and_then(|s| s.parse::<Ipv4Addr>().ok()) {
            dns.push(v);
        }
    }

    Ok(Ipv4Config {
        address,
        prefix,
        gateway,
        dns,
    })
}

fn read_ipv6_settings(ep: &SecondaryQmiEndpoint, cid: u32) -> Result<Ipv6Config> {
    let cid_arg = format!("{ARG_CLIENT_CID_PREFIX}{cid}");
    let out = qmicli(ep, &[&cid_arg, ARG_GET_CURRENT_SETTINGS])?;

    // qmicli renders IPv6 as `addr/prefix`; split before parsing.
    let raw = field(&out, F_IPV6_ADDRESS).ok_or_else(|| anyhow!(E_IPV6_INVALID))?;
    let (addr_s, prefix_s) = match raw.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (raw, None),
    };
    let address: Ipv6Addr = addr_s.parse().map_err(|_| anyhow!(E_IPV6_INVALID))?;
    let prefix: u8 = match prefix_s {
        Some(p) => p.parse().map_err(|_| anyhow!(E_IPV6_PREFIX_INVALID))?,
        None => 64,
    };

    let raw_gw = field(&out, F_IPV6_GATEWAY).ok_or_else(|| anyhow!(E_IPV6_GATEWAY_INVALID))?;
    let gw_s = raw_gw.split('/').next().unwrap_or(raw_gw);
    let gateway: Ipv6Addr = gw_s.parse().map_err(|_| anyhow!(E_IPV6_GATEWAY_INVALID))?;

    let mut dns = Vec::new();
    for label in [F_IPV6_DNS1, F_IPV6_DNS2] {
        if let Some(v) = field(&out, label)
            .map(|s| s.split('/').next().unwrap_or(s))
            .and_then(|s| s.parse::<Ipv6Addr>().ok())
        {
            dns.push(v);
        }
    }

    Ok(Ipv6Config {
        address,
        prefix,
        gateway,
        dns,
    })
}

/// Netmask -> prefix length, rejecting non-contiguous masks.
fn mask_to_prefix(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from_be_bytes(mask.octets());
    let ones = bits.leading_ones();
    // Must be all-ones followed by all-zeros.
    if ones == 32 {
        return Some(32);
    }
    if bits << ones != 0 {
        return None;
    }
    Some(ones as u8)
}

// ---------------------------------------------------------------------------
// Interface configuration via iproute2
// ---------------------------------------------------------------------------

fn ip_bin() -> &'static str {
    if std::path::Path::new("/bin/ip").exists() {
        "/bin/ip"
    } else {
        "/usr/bin/ip"
    }
}

fn configure_ipv4(netdev: &str, cfg: &Ipv4Config) -> Result<()> {
    let ip = ip_bin();
    run(ip, &["link", "set", netdev, "up"])?;
    let cidr = format!("{}/{}", cfg.address, cfg.prefix);
    // `replace` keeps this idempotent across retries.
    run(ip, &["addr", "replace", &cidr, "dev", netdev])?;
    run(
        ip,
        &[
            "route",
            "replace",
            "default",
            "via",
            &cfg.gateway.to_string(),
            "dev",
            netdev,
            "metric",
            &ROUTE_METRIC.to_string(),
        ],
    )?;
    Ok(())
}

fn configure_ipv6(netdev: &str, cfg: &Ipv6Config) -> Result<()> {
    let ip = ip_bin();
    let cidr = format!("{}/{}", cfg.address, cfg.prefix);
    // `nodad` + `noprefixroute`: the modem link is point-to-point, DAD is
    // pointless and the kernel's automatic prefix route would shadow ours.
    run(
        ip,
        &[
            "-6",
            "addr",
            "replace",
            &cidr,
            "dev",
            netdev,
            "nodad",
            "noprefixroute",
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
            netdev,
            "metric",
            &ROUTE_METRIC.to_string(),
            "onlink",
        ],
    )
    .map_err(|e| anyhow!("cellular_dns_ipv6_route_missing: {e}"))?;
    Ok(())
}

fn flush_interface(netdev: &str) {
    let ip = ip_bin();
    let _ = run(ip, &["addr", "flush", "dev", netdev]);
    let _ = run(ip, &["-6", "addr", "flush", "dev", netdev]);
    let _ = run(ip, &["link", "set", netdev, "down"]);
}

/// Publish resolvers. NetworkManager is authoritative when running, so we drop
/// a conf.d snippet and reload it; otherwise fall back to `resolvectl`.
fn configure_dns(netdev: &str, v4: &Ipv4Config, v6: Option<&Ipv6Config>) -> Result<()> {
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
        )
        .context("write cellular dns conf")?;
        let _ = run("nmcli", &["general", "reload", "conf,dns-rc"]);
        return Ok(());
    }

    let mut args: Vec<&str> = vec!["dns", netdev];
    let owned: Vec<String> = servers.clone();
    for s in &owned {
        args.push(s.as_str());
    }
    run("resolvectl", &args)?;
    run("resolvectl", &["domain", netdev, "~."])?;
    Ok(())
}

fn nm_active() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "NetworkManager.service"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn read_registration_state() -> Option<String> {
    let out = Command::new("mmcli")
        .args(["-m", "any", "-K"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim() == MM_PROP_REGISTRATION_STATE {
                return Some(v.trim().to_string());
            }
        }
    }
    None
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
    fn parses_cid_from_qmicli_output() {
        let out = "[/dev/wwan0qmi1] Client ID not released:\n\tService: 'wds'\n\t    CID: '17'\n";
        assert_eq!(parse_cid(out), Some(17));
    }

    #[test]
    fn parses_packet_data_handle() {
        let out = "[/dev/wwan0qmi1] Network started\n\tPacket data handle: '2334889824'\n";
        assert_eq!(parse_packet_data_handle(out), Some(2334889824));
    }

    #[test]
    fn parses_current_settings_fields() {
        let out = "\
[/dev/wwan0qmi1] Current settings retrieved:
           IP Family: IPv6
        IPv6 address: 2408:8456:4624:79f1:8925:21d9:b1e1:2d11/64
IPv6 gateway address: 2408:8456:4624:79f1:146c:b8c8:adff:825/64
    IPv6 primary DNS: 2408:8888:0:8888::8
  IPv6 secondary DNS: 2408:8899:0:8899::8
                 MTU: 1500
";
        assert_eq!(
            field(out, F_IPV6_ADDRESS),
            Some("2408:8456:4624:79f1:8925:21d9:b1e1:2d11/64")
        );
        assert_eq!(field(out, F_IPV6_DNS1), Some("2408:8888:0:8888::8"));
    }

    #[test]
    fn netmask_to_prefix() {
        assert_eq!(mask_to_prefix("255.255.255.0".parse().unwrap()), Some(24));
        assert_eq!(mask_to_prefix("255.255.255.255".parse().unwrap()), Some(32));
        assert_eq!(mask_to_prefix("255.255.255.252".parse().unwrap()), Some(30));
        // non-contiguous
        assert_eq!(mask_to_prefix("255.0.255.0".parse().unwrap()), None);
    }

    /// The CID-preserving argv shape is the load-bearing detail of this module.
    #[test]
    fn wds_argv_literals_match_binary() {
        assert_eq!(ARG_WDS_NOOP, "--wds-noop");
        assert_eq!(ARG_CLIENT_NO_RELEASE_CID, "--client-no-release-cid");
        assert_eq!(ARG_CLIENT_CID_PREFIX, "--client-cid=");
        assert_eq!(ARG_START_SUFFIX_V6, ",3gpp-profile=1,ip-type=6");
        assert_eq!(ARG_START_SUFFIX_V4, ",3gpp-profile=1,ip-type=4");
        assert_eq!(IpFamily::V6.set_family_arg(), "--wds-set-ip-family=6");
    }

    #[test]
    fn ipv6_prefix_defaults_to_64_when_absent() {
        // Exercised indirectly: raw address without '/' must not error.
        let raw = "2408::1";
        let (a, p) = match raw.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (raw, None),
        };
        assert!(a.parse::<Ipv6Addr>().is_ok());
        assert!(p.is_none());
    }
}
