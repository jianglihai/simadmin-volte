//! P-CSCF discovery and host-route installation.
//!
//! Recovered from `src/volte.rs` lines ~1666, 1710, 1738-1787, 3105-3112.
//!
//! Evidence (confidence A for literals):
//!   - `AT+CGCONTRDP`, `+CGCONTRDP:`
//!   - `AT$QCPDPIMSCFGE=<cid>,1,1,1` (enables P-CSCF reporting)
//!   - `Native VoLTE P-CSCF candidates prefetched from IMS profile`
//!   - `Native VoLTE P-CSCF candidates discovered from active IMS bearer`
//!   - `Native VoLTE profile P-CSCF prefetch failed; falling back to active bearer discovery`
//!   - `Native VoLTE using P-CSCF candidates prefetched from IMS profile`
//!   - `Native VoLTE active bearer CGCONTRDP query failed`
//!   - `Native VoLTE P-CSCF reporting setup failed`
//!   - `VoLTE runtime P-CSCF candidate failed`, `VoLTE runtime IMS route configuration failed`
//!   - `volte_runtime_all_pcscf_failed`, `volte_runtime_mm_pcscf_missing`,
//!     `volte_runtime_profile_pcscf_missing`, `volte_pcscf_family_mismatch`
//!   - `volte_cgcontrdp_ipv6_missing`, `volte_cgcontrdp_gateway_missing`
//!   - `nodad`, `noprefixroute`
//!
//! # Four sources, tried in order
//!
//! 1. P-CSCF prefetched from the IMS PDP profile (cheapest — no bearer needed)
//! 2. QMI `--wds-get-current-settings` on the saved CID
//! 3. `AT+CGCONTRDP` on the active context
//! 4. Whatever the active ModemManager bearer reported
//!
//! Each candidate is tried in turn; the family must match the IMS bearer's own
//! family or it is skipped with `volte_pcscf_family_mismatch`. Exhausting the
//! list yields `volte_runtime_all_pcscf_failed`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{err, ip_bin, ImsFamily};

/// Enable P-CSCF address reporting on a PDP context (Qualcomm-specific).
pub fn at_enable_pcscf_reporting(cid: u32) -> String {
    format!("AT$QCPDPIMSCFGE={cid},1,1,1")
}

/// Disable it again on teardown.
pub fn at_disable_pcscf_reporting(cid: u32) -> String {
    format!("AT$QCPDPIMSCFGE={cid},0,0,0")
}

/// Read dynamic context parameters, including P-CSCF.
pub fn at_read_dynamic_params(cid: u32) -> String {
    format!("AT+CGCONTRDP={cid}")
}

/// Where a candidate came from, for logging and for choosing the next fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcscfSource {
    /// Prefetched from the configured IMS PDP profile.
    Profile,
    /// QMI WDS current settings on the saved CID.
    QmiSettings,
    /// `AT+CGCONTRDP` on the active context.
    Cgcontrdp,
    /// The active ModemManager bearer's reported config.
    ActiveBearer,
}

impl PcscfSource {
    pub fn log_message(self) -> &'static str {
        match self {
            PcscfSource::Profile => "Native VoLTE P-CSCF candidates prefetched from IMS profile",
            PcscfSource::QmiSettings | PcscfSource::ActiveBearer => {
                "Native VoLTE P-CSCF candidates discovered from active IMS bearer"
            }
            PcscfSource::Cgcontrdp => "Native VoLTE active bearer CGCONTRDP query failed",
        }
    }
}

/// One discovered P-CSCF plus provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcscfCandidate {
    pub addr: IpAddr,
    pub source: PcscfSource,
}

/// The IMS bearer's own addressing, needed to install routes toward the P-CSCF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImsBearerAddressing {
    pub interface: String,
    pub local: IpAddr,
    pub prefix: u8,
    pub gateway: Option<IpAddr>,
}

impl ImsBearerAddressing {
    pub fn family(&self) -> ImsFamily {
        match self.local {
            IpAddr::V4(_) => ImsFamily::V4,
            IpAddr::V6(_) => ImsFamily::V6,
        }
    }
}

/// Parse `+CGCONTRDP:` lines for the local address and P-CSCF list.
///
/// Format (3GPP TS 27.007 §10.1.23):
/// ```text
/// +CGCONTRDP: <cid>,<bearer_id>,<apn>,<local_addr_and_subnet>,<gw>,<dns1>,<dns2>,<p-cscf1>,<p-cscf2>
/// ```
/// IPv6 fields arrive as **dot-separated decimal octets** (32 groups), not
/// colon-hex — that quirk is the usual reason a naive parser returns nothing.
pub fn parse_cgcontrdp(response: &str) -> Result<(IpAddr, Option<IpAddr>, Vec<IpAddr>), String> {
    for line in response.lines() {
        let line = line.trim();
        let rest = match line.strip_prefix("+CGCONTRDP:") {
            Some(r) => r.trim(),
            None => continue,
        };
        let fields: Vec<String> = rest
            .split(',')
            .map(|f| f.trim().trim_matches('"').to_string())
            .collect();
        if fields.len() < 5 {
            continue;
        }

        let local = parse_at_addr(&fields[3]).ok_or_else(|| {
            err::CGCONTRDP_IPV6_MISSING.to_string()
        })?;
        let gw = fields.get(4).and_then(|f| parse_at_addr(f));
        let mut pcscf = Vec::new();
        for f in fields.iter().skip(7) {
            if let Some(a) = parse_at_addr(f) {
                pcscf.push(a);
            }
        }
        return Ok((local, gw, pcscf));
    }
    Err(err::CGCONTRDP_IPV6_MISSING.to_string())
}

/// Decode an AT-style address.
///
/// Handles three shapes:
/// - plain dotted IPv4: `10.1.2.3`
/// - IPv4 + mask packed as 8 groups: `10.1.2.3.255.255.255.0`
/// - IPv6 as 16 or 32 decimal groups (the second half of a 32-group value is
///   the prefix/mask and is discarded)
pub fn parse_at_addr(s: &str) -> Option<IpAddr> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    // Already a normal textual form?
    if let Ok(a) = t.parse::<IpAddr>() {
        return Some(a);
    }
    let groups: Vec<u16> = t
        .split('.')
        .filter_map(|g| g.trim().parse::<u16>().ok())
        .collect();
    match groups.len() {
        4 => {
            let o: Vec<u8> = groups.iter().map(|g| *g as u8).collect();
            Some(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])))
        }
        8 => {
            // addr + mask; take the first four.
            let o: Vec<u8> = groups[..4].iter().map(|g| *g as u8).collect();
            Some(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])))
        }
        16 | 32 => {
            let o: Vec<u8> = groups[..16].iter().map(|g| *g as u8).collect();
            let mut b = [0u8; 16];
            b.copy_from_slice(&o);
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

/// Filter candidates to those matching the bearer's family.
pub fn filter_by_family(
    candidates: &[PcscfCandidate],
    family: ImsFamily,
) -> Vec<PcscfCandidate> {
    candidates
        .iter()
        .filter(|c| match (c.addr, family) {
            (IpAddr::V4(_), ImsFamily::V4) => true,
            (IpAddr::V6(_), ImsFamily::V6) => true,
            _ => false,
        })
        .cloned()
        .collect()
}

/// Assemble the ordered candidate list from every available source.
///
/// Deduplicates while preserving first-seen order, so a P-CSCF discovered from
/// the profile is preferred over the same address found later via CGCONTRDP.
pub fn collect_candidates(
    profile: &[IpAddr],
    qmi_settings: &[IpAddr],
    cgcontrdp: &[IpAddr],
    active_bearer: &[IpAddr],
) -> Result<Vec<PcscfCandidate>, String> {
    let mut out: Vec<PcscfCandidate> = Vec::new();
    let mut seen: Vec<IpAddr> = Vec::new();

    let sources: [(&[IpAddr], PcscfSource); 4] = [
        (profile, PcscfSource::Profile),
        (qmi_settings, PcscfSource::QmiSettings),
        (cgcontrdp, PcscfSource::Cgcontrdp),
        (active_bearer, PcscfSource::ActiveBearer),
    ];

    for (list, src) in sources {
        for a in list {
            if !seen.contains(a) {
                seen.push(*a);
                out.push(PcscfCandidate {
                    addr: *a,
                    source: src,
                });
            }
        }
    }

    if out.is_empty() {
        return Err(err::RUNTIME_ALL_PCSCF_FAILED.to_string());
    }
    Ok(out)
}

/// Commands to bring up the IMS interface and route toward one P-CSCF.
///
/// `nodad` and `noprefixroute` are both required on the modem's
/// point-to-point link: DAD has no peer to answer it, and the kernel's implicit
/// prefix route would otherwise shadow the explicit host route.
pub fn route_commands(
    bearer: &ImsBearerAddressing,
    pcscf: IpAddr,
) -> Result<Vec<Vec<String>>, String> {
    // Family agreement is checked here rather than at the call site so the
    // specific error code is preserved.
    let matches = matches!(
        (bearer.local, pcscf),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    );
    if !matches {
        return Err(err::PCSCF_FAMILY_MISMATCH.to_string());
    }

    let ip = ip_bin()?;
    let v6 = matches!(bearer.local, IpAddr::V6(_));
    let mut cmds: Vec<Vec<String>> = Vec::new();

    cmds.push(vec![
        ip.into(), "link".into(), "set".into(), bearer.interface.clone(), "up".into(),
    ]);

    let cidr = format!("{}/{}", bearer.local, bearer.prefix);
    let mut addr = vec![ip.to_string()];
    if v6 {
        addr.push("-6".into());
    }
    addr.extend([
        "addr".into(), "replace".into(), cidr, "dev".into(), bearer.interface.clone(),
    ]);
    if v6 {
        addr.push("nodad".into());
        addr.push("noprefixroute".into());
    }
    cmds.push(addr);

    // Host route to the P-CSCF. Prefer via-gateway; fall back to on-link.
    let mut route = vec![ip.to_string()];
    if v6 {
        route.push("-6".into());
    }
    route.extend(["route".into(), "replace".into(), pcscf.to_string()]);
    match bearer.gateway {
        Some(gw) => {
            route.push("via".into());
            route.push(gw.to_string());
            route.push("dev".into());
            route.push(bearer.interface.clone());
        }
        None => {
            route.push("dev".into());
            route.push(bearer.interface.clone());
            route.push("onlink".into());
        }
    }
    cmds.push(route);

    Ok(cmds)
}

/// IPv6 IMS without a gateway is unusable for the host route.
pub fn require_gateway(bearer: &ImsBearerAddressing) -> Result<IpAddr, String> {
    match bearer.gateway {
        Some(g) => Ok(g),
        None => Err(if matches!(bearer.local, IpAddr::V6(_)) {
            err::IPV6_GATEWAY_MISSING.to_string()
        } else {
            err::CGCONTRDP_GATEWAY_MISSING.to_string()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_commands_shape() {
        assert_eq!(at_enable_pcscf_reporting(3), "AT$QCPDPIMSCFGE=3,1,1,1");
        assert_eq!(at_disable_pcscf_reporting(3), "AT$QCPDPIMSCFGE=3,0,0,0");
        assert_eq!(at_read_dynamic_params(3), "AT+CGCONTRDP=3");
    }

    #[test]
    fn decodes_ipv4_forms() {
        assert_eq!(
            parse_at_addr("10.1.2.3"),
            Some("10.1.2.3".parse().unwrap())
        );
        // address + netmask packed together
        assert_eq!(
            parse_at_addr("10.1.2.3.255.255.255.0"),
            Some("10.1.2.3".parse().unwrap())
        );
    }

    #[test]
    fn decodes_ipv6_decimal_group_form() {
        // 2408:8142:6001:1:: as 16 decimal groups
        let s = "36.8.129.66.96.1.0.1.0.0.0.0.0.0.0.0";
        let a = parse_at_addr(s).unwrap();
        assert_eq!(a, "2408:8142:6001:1::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ipv6_32_group_form_drops_the_mask_half() {
        let addr = "36.8.129.66.96.1.0.1.0.0.0.0.0.0.0.0";
        let mask = "255.255.255.255.255.255.255.255.0.0.0.0.0.0.0.0";
        let a = parse_at_addr(&format!("{addr}.{mask}")).unwrap();
        assert_eq!(a, "2408:8142:6001:1::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parses_cgcontrdp_with_pcscf() {
        let resp = "\
+CGCONTRDP: 3,6,\"ims.epc.mnc001.mcc460.gprs\",\"36.8.133.86.162.49.16.78.0.0.0.0.0.0.0.1\",\"36.8.133.86.162.49.16.78.217.240.204.160.55.10.58.159\",\"36.8.136.136.0.0.136.136.0.0.0.0.0.0.0.8\",\"\",\"36.8.129.66.96.1.0.1.0.0.0.0.0.0.0.0\"\r\nOK";
        let (local, gw, pcscf) = parse_cgcontrdp(resp).unwrap();
        assert!(matches!(local, IpAddr::V6(_)));
        assert!(gw.is_some());
        assert_eq!(pcscf.len(), 1);
        assert_eq!(pcscf[0], "2408:8142:6001:1::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn candidate_dedup_keeps_first_source() {
        let a: IpAddr = "2408:8142:6001:1::".parse().unwrap();
        let list = collect_candidates(&[a], &[a], &[a], &[a]).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].source, PcscfSource::Profile);
    }

    #[test]
    fn empty_candidate_set_is_an_error() {
        assert_eq!(
            collect_candidates(&[], &[], &[], &[]).unwrap_err(),
            err::RUNTIME_ALL_PCSCF_FAILED
        );
    }

    #[test]
    fn family_filter_excludes_mismatches() {
        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        let v6: IpAddr = "2408::1".parse().unwrap();
        let cands = collect_candidates(&[v4, v6], &[], &[], &[]).unwrap();
        assert_eq!(filter_by_family(&cands, ImsFamily::V6).len(), 1);
        assert_eq!(filter_by_family(&cands, ImsFamily::V4).len(), 1);
    }

    #[test]
    fn route_commands_include_nodad_for_ipv6() {
        let bearer = ImsBearerAddressing {
            interface: "wwan1".into(),
            local: "2408:8556:a231:104e::1".parse().unwrap(),
            prefix: 64,
            gateway: Some("2408:8556:a231:104e::2".parse().unwrap()),
        };
        let cmds = route_commands(&bearer, "2408:8142:6001:1::".parse().unwrap()).unwrap();
        let flat: Vec<String> = cmds.iter().flatten().cloned().collect();
        assert!(flat.contains(&"nodad".to_string()));
        assert!(flat.contains(&"noprefixroute".to_string()));
        assert!(flat.contains(&"wwan1".to_string()));
    }

    #[test]
    fn family_mismatch_is_reported() {
        let bearer = ImsBearerAddressing {
            interface: "wwan1".into(),
            local: "2408::1".parse().unwrap(),
            prefix: 64,
            gateway: None,
        };
        assert_eq!(
            route_commands(&bearer, "1.2.3.4".parse().unwrap()).unwrap_err(),
            err::PCSCF_FAMILY_MISMATCH
        );
    }

    #[test]
    fn missing_ipv6_gateway_has_its_own_code() {
        let bearer = ImsBearerAddressing {
            interface: "wwan1".into(),
            local: "2408::1".parse().unwrap(),
            prefix: 64,
            gateway: None,
        };
        assert_eq!(
            require_gateway(&bearer).unwrap_err(),
            err::IPV6_GATEWAY_MISSING
        );
    }
}
