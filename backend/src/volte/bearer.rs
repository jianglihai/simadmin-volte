//! IMS PDP profile leasing and bearer activation.
//!
//! Recovered from `src/volte.rs` lines ~1598-1666, 1768-1878, 1991-2044.
//!
//! Evidence (confidence A for literals):
//!   - `AT+CGDCONT=<cid>,"IPV4V6|IP|IPV6","ims"`, `AT+CGACT=0,<cid>`, `AT+CGPADDR=<cid>`
//!   - `--create-bearer=apn=ims,ip-type=ipv6,allow-roaming=`
//!   - `--wds-start-network=apn=ims,3gpp-profile=<cid>,ip-type=6`
//!   - `Native VoLTE secondary QMI IMS WDS bearer started`
//!   - `Native VoLTE secondary QMI WDS settings not ready`
//!   - `Native VoLTE runtime MM IMS bearer connected` / `... connect failed`
//!   - `Native VoLTE runtime IMS bearer is up`
//!   - `Native VoLTE runtime recreating IMS bearer to match roaming policy`
//!   - `Deleted stale disconnected IMS bearer` (+ `... before P-CSCF discovery`)
//!   - `ModemManager modem is ready for VoLTE IMS bearer`
//!   - `ModemManager modem is present for VoLTE startup`
//!   - `Waiting for initial QMI UIM provisioning to settle`
//!   - `QMI auto-activate ready marker did not appear; continuing with modem readiness checks`
//!   - `/run/qmi_auto_activate.ready`, `marker_age_secs`, `wait_secs`
//!   - `wrong state: modem in enabling state`, `registered in roaming network`,
//!     `roaming not allowed`, `pdp authentication failure`

use std::net::IpAddr;
use std::time::Duration;

use super::{err, ApnProtocol, ImsFamily, QMI_READY_MARKER};
use super::slot::ImsSlot;

/// IMS APN label used in the PDP context. The full EPC form
/// (`ims.epc.mnc..mcc..gprs`) is used for the WDS/mmcli APN; `AT+CGDCONT` takes
/// the short label.
pub const IMS_APN_LABEL: &str = "ims";

/// How long to wait for the vendor QMI marker before proceeding anyway.
pub const QMI_MARKER_WAIT: Duration = Duration::from_secs(30);
/// How long to wait for ModemManager to expose a usable modem.
pub const MODEM_PRESENT_TIMEOUT: Duration = Duration::from_secs(60);
/// How long to wait for the modem to leave `enabling`.
pub const MODEM_READY_TIMEOUT: Duration = Duration::from_secs(45);

/// Define the IMS PDP context.
pub fn at_define_context(cid: u32, proto: ApnProtocol) -> String {
    format!(
        "AT+CGDCONT={cid},\"{}\",\"{IMS_APN_LABEL}\"",
        proto.as_cgdcont()
    )
}

/// Deactivate a context (used when reclaiming a stale lease).
pub fn at_deactivate_context(cid: u32) -> String {
    format!("AT+CGACT=0,{cid}")
}

/// Query the address assigned to a context.
pub fn at_context_address(cid: u32) -> String {
    format!("AT+CGPADDR={cid}")
}

/// Query defined contexts, to find a free CID.
///
/// **beta8-only as a whole string (confidence C for beta9).** beta9 has the
/// `CGDCONT` / `CGACT` tokens and the `CGACT=1,` write form, but not these
/// read-form queries as literals — they are likely composed at runtime.
pub const AT_LIST_CONTEXTS: &str = "AT+CGDCONT?";
/// Query active contexts. Same provenance caveat as [`AT_LIST_CONTEXTS`].
pub const AT_LIST_ACTIVE: &str = "AT+CGACT?";
/// Activate a context — this *write* form is present in beta9 at VA 0x8ee400.
pub const AT_ACTIVATE_PREFIX: &str = "AT+CGACT=1,";

/// A leased IMS PDP profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImsProfileLease {
    pub cid: u32,
    pub protocol: ApnProtocol,
}

/// Find a context id we can safely use for IMS.
///
/// Strategy: prefer a context already defined with the `ims` APN (re-lease it),
/// otherwise take the lowest CID in 2..=7 that is neither defined nor active.
/// CID 1 is left alone — it is the default internet context on every device
/// observed.
pub fn pick_profile(
    defined: &[(u32, String)],
    active: &[u32],
) -> Result<u32, String> {
    // Re-lease an existing ims context.
    for (cid, apn) in defined {
        if apn.eq_ignore_ascii_case(IMS_APN_LABEL) || apn.starts_with("ims.") {
            return Ok(*cid);
        }
    }
    for cid in 2u32..=7 {
        let is_defined = defined.iter().any(|(c, _)| *c == cid);
        let is_active = active.contains(&cid);
        if !is_defined && !is_active {
            return Ok(cid);
        }
    }
    Err(err::DATA_PATH_APN_MISSING.to_string())
}

/// Parse `AT+CGDCONT?` into (cid, apn) pairs.
pub fn parse_defined_contexts(response: &str) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    for line in response.lines() {
        let rest = match line.trim().strip_prefix("+CGDCONT:") {
            Some(r) => r.trim(),
            None => continue,
        };
        let f: Vec<&str> = rest.split(',').collect();
        if f.len() < 3 {
            continue;
        }
        if let Ok(cid) = f[0].trim().parse::<u32>() {
            let apn = f[2].trim().trim_matches('"').to_string();
            out.push((cid, apn));
        }
    }
    out
}

/// Parse `AT+CGACT?` into the list of active cids.
pub fn parse_active_contexts(response: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for line in response.lines() {
        let rest = match line.trim().strip_prefix("+CGACT:") {
            Some(r) => r.trim(),
            None => continue,
        };
        let f: Vec<&str> = rest.split(',').collect();
        if f.len() >= 2 {
            if let (Ok(cid), Ok(state)) =
                (f[0].trim().parse::<u32>(), f[1].trim().parse::<u32>())
            {
                if state == 1 {
                    out.push(cid);
                }
            }
        }
    }
    out
}

/// mmcli spec for the IMS bearer on the primary port.
pub fn mmcli_create_ims_bearer(
    apn: &str,
    family: ImsFamily,
    roaming_allowed: bool,
) -> String {
    let ip_type = match family {
        ImsFamily::V4 => "ipv4",
        ImsFamily::V6 => "ipv6",
    };
    format!(
        "--create-bearer=apn={apn},ip-type={ip_type},allow-roaming={}",
        if roaming_allowed { "yes" } else { "no" }
    )
}

/// qmicli spec for the IMS bearer on the DATA6 secondary port.
///
/// Note this pins `3gpp-profile` to the leased CID so the modem uses the context
/// we configured with `AT$QCPDPIMSCFGE` (which is what turns on P-CSCF
/// reporting).
pub fn qmicli_start_ims_network(apn: &str, cid: u32, family: ImsFamily) -> String {
    let t = match family {
        ImsFamily::V4 => '4',
        ImsFamily::V6 => '6',
    };
    format!("--wds-start-network=apn={apn},3gpp-profile={cid},ip-type={t}")
}

/// Which backend created the bearer, and the handles needed to tear it down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImsBearer {
    /// ModemManager on the primary port.
    ModemManager {
        path: String,
        interface: String,
        local: IpAddr,
        prefix: u8,
        gateway: Option<IpAddr>,
        pcscf: Vec<IpAddr>,
    },
    /// QMI WDS on the DATA6 secondary port.
    SecondaryQmi {
        cid: u32,
        handle: u64,
        interface: String,
        local: IpAddr,
        prefix: u8,
        gateway: Option<IpAddr>,
        pcscf: Vec<IpAddr>,
    },
}

impl ImsBearer {
    pub fn interface(&self) -> &str {
        match self {
            ImsBearer::ModemManager { interface, .. } => interface,
            ImsBearer::SecondaryQmi { interface, .. } => interface,
        }
    }
    pub fn local(&self) -> IpAddr {
        match self {
            ImsBearer::ModemManager { local, .. } => *local,
            ImsBearer::SecondaryQmi { local, .. } => *local,
        }
    }
    pub fn gateway(&self) -> Option<IpAddr> {
        match self {
            ImsBearer::ModemManager { gateway, .. } => *gateway,
            ImsBearer::SecondaryQmi { gateway, .. } => *gateway,
        }
    }
    pub fn prefix(&self) -> u8 {
        match self {
            ImsBearer::ModemManager { prefix, .. } => *prefix,
            ImsBearer::SecondaryQmi { prefix, .. } => *prefix,
        }
    }
    pub fn pcscf(&self) -> &[IpAddr] {
        match self {
            ImsBearer::ModemManager { pcscf, .. } => pcscf,
            ImsBearer::SecondaryQmi { pcscf, .. } => pcscf,
        }
    }
    /// Human-readable slot, for the `data_path` log field.
    pub fn slot(&self) -> ImsSlot {
        match self {
            ImsBearer::ModemManager { .. } => ImsSlot::PrimaryQmi0,
            ImsBearer::SecondaryQmi { .. } => ImsSlot::Data6,
        }
    }
}

/// Modem readiness gate.
///
/// The vendor's `qmi_auto_activate` script writes a marker once UIM
/// provisioning settles. Waiting on it avoids racing the SIM; a missing marker
/// is *not* fatal — we log and fall through to ModemManager's own state checks
/// (`QMI auto-activate ready marker did not appear; continuing with modem
/// readiness checks`).
pub fn qmi_marker_present() -> bool {
    std::path::Path::new(QMI_READY_MARKER).exists()
}

/// Age of the readiness marker in seconds, reported as `marker_age_secs`.
pub fn qmi_marker_age_secs() -> Option<u64> {
    let md = std::fs::metadata(QMI_READY_MARKER).ok()?;
    let mtime = md.modified().ok()?;
    mtime.elapsed().ok().map(|d| d.as_secs())
}

/// Classify a ModemManager state string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModemReadiness {
    /// Usable now.
    Ready,
    /// Still coming up — keep waiting.
    Transitioning,
    /// Will not become ready without intervention.
    NotReady,
}

/// Interpret `modem.generic.state`.
///
/// `enabling` is explicitly called out in the binary (`wrong state: modem in
/// enabling state`) because issuing a bearer create during that window fails in
/// a way that looks permanent but is not.
pub fn classify_modem_state(state: &str) -> ModemReadiness {
    match state.trim().to_ascii_lowercase().as_str() {
        "registered" | "connected" | "enabled" => ModemReadiness::Ready,
        "enabling" | "searching" | "connecting" | "activating" | "reloading" => {
            ModemReadiness::Transitioning
        }
        _ => ModemReadiness::NotReady,
    }
}

/// Does the current registration satisfy the roaming policy?
///
/// Returns the error the binary emits so the caller can surface it directly.
pub fn check_roaming(state: &str, roaming_allowed: bool) -> Result<(), String> {
    let s = state.trim().to_ascii_lowercase();
    if s == "home" {
        return Ok(());
    }
    if s == "roaming" {
        if roaming_allowed {
            return Ok(());
        }
        return Err(err::RUNTIME_MM_BEARER_ROAMING_FORBIDDEN.to_string());
    }
    Err(err::RUNTIME_MM_MODEM_NOT_READY.to_string())
}

/// Should a stale bearer be dropped before reuse?
///
/// Two triggers, both present in the binary:
/// - the bearer exists but is disconnected (`Deleted stale disconnected IMS bearer`)
/// - the bearer's roaming flag disagrees with current policy
///   (`Native VoLTE runtime recreating IMS bearer to match roaming policy`)
pub fn should_recreate_bearer(
    connected: bool,
    bearer_allows_roaming: bool,
    policy_allows_roaming: bool,
) -> bool {
    !connected || bearer_allows_roaming != policy_allows_roaming
}

/// Single-stack fallback order derived from what the network actually granted.
///
/// Logged as `Native VoLTE selected single-stack fallback families from granted
/// IMS addresses`; exhausting the list gives
/// `volte_runtime_all_ip_families_failed`.
pub fn fallback_families(granted_v4: bool, granted_v6: bool) -> Vec<ImsFamily> {
    let mut v = Vec::new();
    // IPv6 first: IPsec requires it, so it is the more capable path.
    if granted_v6 {
        v.push(ImsFamily::V6);
    }
    if granted_v4 {
        v.push(ImsFamily::V4);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_command_shapes() {
        assert_eq!(
            at_define_context(3, ApnProtocol::Ipv4v6),
            "AT+CGDCONT=3,\"IPV4V6\",\"ims\""
        );
        assert_eq!(at_deactivate_context(3), "AT+CGACT=0,3");
        assert_eq!(at_context_address(3), "AT+CGPADDR=3");
    }

    #[test]
    fn parses_defined_and_active_contexts() {
        let defined = "\
+CGDCONT: 1,\"IPV4V6\",\"3gnet\",\"\",0,0
+CGDCONT: 3,\"IPV6\",\"ims\",\"\",0,0
OK";
        let d = parse_defined_contexts(defined);
        assert_eq!(d.len(), 2);
        assert_eq!(d[1], (3, "ims".to_string()));

        let active = "+CGACT: 1,1\r\n+CGACT: 3,0\r\nOK";
        assert_eq!(parse_active_contexts(active), vec![1]);
    }

    #[test]
    fn releases_existing_ims_context() {
        let defined = vec![(1, "3gnet".into()), (4, "ims".into())];
        assert_eq!(pick_profile(&defined, &[1]).unwrap(), 4);
    }

    #[test]
    fn picks_lowest_free_cid_above_one() {
        let defined = vec![(1, "3gnet".into()), (2, "cmnet".into())];
        assert_eq!(pick_profile(&defined, &[1]).unwrap(), 3);
    }

    #[test]
    fn exhausted_profiles_error() {
        let defined: Vec<(u32, String)> =
            (1..=7).map(|c| (c, format!("apn{c}"))).collect();
        assert!(pick_profile(&defined, &[]).is_err());
    }

    #[test]
    fn bearer_specs_match_binary() {
        assert_eq!(
            mmcli_create_ims_bearer("ims.epc.mnc001.mcc460.gprs", ImsFamily::V6, false),
            "--create-bearer=apn=ims.epc.mnc001.mcc460.gprs,ip-type=ipv6,allow-roaming=no"
        );
        assert_eq!(
            qmicli_start_ims_network("ims.epc.mnc001.mcc460.gprs", 3, ImsFamily::V6),
            "--wds-start-network=apn=ims.epc.mnc001.mcc460.gprs,3gpp-profile=3,ip-type=6"
        );
    }

    #[test]
    fn enabling_state_is_transitional_not_fatal() {
        assert_eq!(
            classify_modem_state("enabling"),
            ModemReadiness::Transitioning
        );
        assert_eq!(classify_modem_state("registered"), ModemReadiness::Ready);
        assert_eq!(classify_modem_state("failed"), ModemReadiness::NotReady);
    }

    #[test]
    fn roaming_policy_enforced() {
        assert!(check_roaming("home", false).is_ok());
        assert!(check_roaming("roaming", true).is_ok());
        assert_eq!(
            check_roaming("roaming", false).unwrap_err(),
            err::RUNTIME_MM_BEARER_ROAMING_FORBIDDEN
        );
        assert_eq!(
            check_roaming("denied", true).unwrap_err(),
            err::RUNTIME_MM_MODEM_NOT_READY
        );
    }

    #[test]
    fn recreate_on_disconnect_or_policy_change() {
        assert!(should_recreate_bearer(false, false, false));
        assert!(should_recreate_bearer(true, true, false));
        assert!(!should_recreate_bearer(true, false, false));
    }

    #[test]
    fn ipv6_is_preferred_in_fallback_order() {
        assert_eq!(
            fallback_families(true, true),
            vec![ImsFamily::V6, ImsFamily::V4]
        );
        assert_eq!(fallback_families(true, false), vec![ImsFamily::V4]);
        assert!(fallback_families(false, false).is_empty());
    }

    #[test]
    fn bearer_accessors_report_slot() {
        let b = ImsBearer::SecondaryQmi {
            cid: 4,
            handle: 123,
            interface: "wwan1".into(),
            local: "2408::1".parse().unwrap(),
            prefix: 64,
            gateway: None,
            pcscf: vec![],
        };
        assert_eq!(b.interface(), "wwan1");
        assert_eq!(b.slot(), ImsSlot::Data6);
    }
}
