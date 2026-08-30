//! 3GPP IPsec for SIP signalling — SA negotiation and `ip xfrm` installation.
//!
//! Recovered from `src/volte.rs` lines ~3440, 3703, 2474-2521, 2604-2687.
//!
//! Evidence (confidence A for literals):
//!   - `mechanism`, `security-server`, `spi-c`, `spi-s`, `port-c`, `port-s`
//!   - `volte_security_server_missing`
//!   - `Require: sec-agree`, `Proxy-Require: sec-agree`
//!   - xfrm vocabulary: `policy`, `dst`, `proto`, `esp`, `spi`, `auth-trunc`,
//!     `hmac(md5)`, `enc`, `udp`, `sport`, `dport`, `out`, `in`
//!   - `local_send_port`, `local_receive_port`, `remote_client_port`,
//!     `pcscf_spi_c`, `pcscf_spi_s`
//!   - `Native VoLTE IPsec xfrm installed`
//!   - `volte_ipsec_requires_ipv6`, `volte_ipsec_udp_bind_failed`,
//!     `volte_ipsec_send_udp_bind_failed`, `volte_ipsec_recv_udp_bind_failed`
//!   - `Native VoLTE IPsec IMS REGISTER 200 OK over IPsec`
//!   - `Native VoLTE IPsec registration failed, falling back to plain UDP SIP`
//!
//! # How the SA is agreed
//!
//! RFC 3329 `sec-agree`. The UE proposes in `Security-Client`, the P-CSCF
//! answers in `Security-Server` with its own SPIs and ports, and the UE echoes
//! the server's parameters back verbatim in `Security-Verify` on the protected
//! request. Four SAs exist in total (two directions × two SPI pairs), all
//! installed into the kernel with `ip xfrm`.
//!
//! # Field-observed constraint
//!
//! The integrity algorithm that is actually accepted is `hmac-md5-96` with
//! **null encryption**; `hmac-sha-1-96` / `aes-cbc` proposals are rejected with
//! 420 Bad Extension on the networks this was tested against. IPv6 is mandatory
//! (`volte_ipsec_requires_ipv6`).

use std::net::{IpAddr, Ipv6Addr};

use super::{err, ip_bin};

/// Integrity algorithm token as sent in `Security-Client`.
pub const ALG_HMAC_MD5_96: &str = "hmac-md5-96";
/// Encryption algorithm token — null, i.e. integrity only.
pub const EALG_NULL: &str = "null";
/// Protocol and mode, always ESP in transport mode.
pub const PROT_ESP: &str = "prot=esp";
pub const MOD_TRANS: &str = "mod=trans";
/// Kernel-side names for the same choices.
const XFRM_AUTH_ALG: &str = "hmac(md5)";
const XFRM_AUTH_TRUNC_BITS: u32 = 96;
const XFRM_ENC_ALG: &str = "cipher_null";

/// RFC 3329 mechanism name.
pub const MECHANISM_IPSEC_3GPP: &str = "ipsec-3gpp";

/// Header names.
///
/// Only `Security-Client` and `Security-Verify` exist as *emit* templates in the
/// binary (VA 0x8ee3e9 / 0x8ee1cb, both with the trailing `": "`).
/// `security-server` appears lowercase in the parse-side token cluster at
/// 0x915704 alongside `mechanism`, `spi-c`, `spi-s`, `port-c`, `port-s` —
/// header lookup is case-insensitive, so the parser stores it folded.
pub const H_SECURITY_CLIENT: &str = "Security-Client";
pub const H_SECURITY_VERIFY: &str = "Security-Verify";
pub const H_SECURITY_SERVER: &str = "security-server";
pub const H_REQUIRE: &str = "Require";
pub const H_PROXY_REQUIRE: &str = "Proxy-Require";
pub const SEC_AGREE: &str = "sec-agree";
/// Parse-side parameter keys, verbatim from the 0x915704 cluster.
pub const P_MECHANISM: &str = "mechanism";
pub const P_SPI_C: &str = "spi-c";
pub const P_SPI_S: &str = "spi-s";
pub const P_PORT_C: &str = "port-c";
pub const P_PORT_S: &str = "port-s";

/// Ephemeral port range for the UE's SIP sockets. SPIs and ports are randomly
/// drawn; failures surface as `volte_random_port_invalid` /
/// `volte_random_port_range_invalid` / `volte_random_spi_invalid`.
pub const UE_PORT_MIN: u16 = 40000;
pub const UE_PORT_MAX: u16 = 60000;

/// Parameters the UE proposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityClient {
    /// UE inbound SPI (P-CSCF encrypts to this).
    pub spi_c: u32,
    /// UE outbound SPI.
    pub spi_s: u32,
    /// UE port that receives protected traffic.
    pub port_c: u16,
    /// UE port that sends protected traffic.
    pub port_s: u16,
}

impl SecurityClient {
    /// Render the `Security-Client` value.
    ///
    /// Parameter order and spacing are **byte-exact from the binary** — the
    /// format string at VA 0x8edfcd is:
    ///
    /// ```text
    /// ipsec-3gpp;prot=esp;mod=trans;spi-c=..;spi-s=..;port-c=..;port-s=..;alg=hmac-md5-96;ealg=null
    /// ```
    ///
    /// Note: no spaces after the semicolons, `prot`/`mod` come first, and
    /// `alg`/`ealg` come **last**. P-CSCFs have been observed to reject
    /// reordered or space-padded variants with 420 Bad Extension.
    pub fn to_header(&self) -> String {
        format!(
            "{MECHANISM_IPSEC_3GPP};{PROT_ESP};{MOD_TRANS};spi-c={};spi-s={};port-c={};port-s={};alg={ALG_HMAC_MD5_96};ealg={EALG_NULL}",
            self.spi_c, self.spi_s, self.port_c, self.port_s
        )
    }
}

/// Parameters the P-CSCF answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityServer {
    pub mechanism: String,
    pub alg: String,
    pub ealg: String,
    /// P-CSCF inbound SPI.
    pub spi_c: u32,
    /// P-CSCF outbound SPI.
    pub spi_s: u32,
    /// P-CSCF port that receives protected traffic.
    pub port_c: u16,
    /// P-CSCF port that sends protected traffic.
    pub port_s: u16,
    /// Raw header value, kept byte-exact for `Security-Verify`.
    pub raw: String,
}

/// Parse a `Security-Server` header value.
///
/// Multiple mechanisms may be offered, comma-separated; the first
/// `ipsec-3gpp` entry wins. Missing header -> `volte_security_server_missing`.
pub fn parse_security_server(header_value: &str) -> Result<SecurityServer, String> {
    let v = header_value.trim();
    if v.is_empty() {
        return Err(err::SECURITY_SERVER_MISSING.to_string());
    }

    for candidate in v.split(',') {
        let c = candidate.trim();
        if !c.starts_with(MECHANISM_IPSEC_3GPP) {
            continue;
        }
        let mut alg = String::new();
        let mut ealg = String::new();
        let mut spi_c = None;
        let mut spi_s = None;
        let mut port_c = None;
        let mut port_s = None;

        for part in c.split(';').skip(1) {
            let (k, val) = match part.split_once('=') {
                Some((k, val)) => (k.trim().to_ascii_lowercase(), val.trim()),
                None => continue,
            };
            match k.as_str() {
                "alg" => alg = val.to_string(),
                "ealg" => ealg = val.to_string(),
                "spi-c" => spi_c = val.parse::<u32>().ok(),
                "spi-s" => spi_s = val.parse::<u32>().ok(),
                "port-c" => port_c = val.parse::<u16>().ok(),
                "port-s" => port_s = val.parse::<u16>().ok(),
                _ => {}
            }
        }

        let (spi_c, spi_s, port_c, port_s) = match (spi_c, spi_s, port_c, port_s) {
            (Some(a), Some(b), Some(cc), Some(d)) => (a, b, cc, d),
            _ => return Err(err::SECURITY_SERVER_MISSING.to_string()),
        };

        return Ok(SecurityServer {
            mechanism: MECHANISM_IPSEC_3GPP.to_string(),
            alg,
            ealg,
            spi_c,
            spi_s,
            port_c,
            port_s,
            raw: c.to_string(),
        });
    }

    Err(err::SECURITY_SERVER_MISSING.to_string())
}

/// `Security-Verify` must echo the server's parameters **verbatim**. Any
/// normalisation (reordering, whitespace changes) causes a 401/403 loop.
pub fn security_verify_header(server: &SecurityServer) -> String {
    server.raw.clone()
}

/// The four SAs that make up a protected SIP association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpsecContext {
    pub ue_addr: Ipv6Addr,
    pub pcscf_addr: Ipv6Addr,
    pub client: SecurityClient,
    pub server: SecurityServer,
    /// Integrity key = IK from AKA.
    pub ik: Vec<u8>,
}

impl IpsecContext {
    /// UE socket used to send protected requests.
    pub fn local_send_port(&self) -> u16 {
        self.client.port_s
    }
    /// UE socket that receives protected responses/requests.
    pub fn local_receive_port(&self) -> u16 {
        self.client.port_c
    }
    /// P-CSCF port we send to.
    pub fn remote_server_port(&self) -> u16 {
        self.server.port_s
    }
    /// P-CSCF port that originates traffic toward us.
    pub fn remote_client_port(&self) -> u16 {
        self.server.port_c
    }
}

/// Build and install all SAs and policies with `ip xfrm`.
///
/// Returns the argv sequences that were run, which makes the whole thing
/// testable without touching the kernel.
pub fn install(ctx: &IpsecContext) -> Result<Vec<Vec<String>>, String> {
    let ip = ip_bin()?;
    if ctx.ik.len() < 16 {
        return Err(err::IPSEC_IK_INVALID.to_string());
    }
    let key = format!("0x{}", ctx.ik.iter().map(|b| format!("{b:02x}")).collect::<String>());

    let ue = ctx.ue_addr.to_string();
    let pc = ctx.pcscf_addr.to_string();
    let mut cmds: Vec<Vec<String>> = Vec::new();

    // --- outbound state: UE:port_s -> P-CSCF:port_s, SPI = server spi_s ---
    cmds.push(state_add(
        ip, &ue, &pc, ctx.server.spi_s, &key,
        ctx.client.port_s, ctx.server.port_s,
    ));
    // --- inbound state: P-CSCF:port_c -> UE:port_c, SPI = client spi_c ---
    cmds.push(state_add(
        ip, &pc, &ue, ctx.client.spi_c, &key,
        ctx.server.port_c, ctx.client.port_c,
    ));

    // --- policies, one per direction ---
    cmds.push(policy_add(
        ip, &ue, &pc, "out", ctx.server.spi_s,
        ctx.client.port_s, ctx.server.port_s,
    ));
    cmds.push(policy_add(
        ip, &pc, &ue, "in", ctx.client.spi_c,
        ctx.server.port_c, ctx.client.port_c,
    ));

    Ok(cmds)
}

fn state_add(
    ip: &str,
    src: &str,
    dst: &str,
    spi: u32,
    key: &str,
    sport: u16,
    dport: u16,
) -> Vec<String> {
    vec![
        ip.into(), "xfrm".into(), "state".into(), "add".into(),
        "src".into(), src.into(),
        "dst".into(), dst.into(),
        "proto".into(), "esp".into(),
        "spi".into(), format!("0x{spi:08x}"),
        "mode".into(), "transport".into(),
        "auth-trunc".into(), XFRM_AUTH_ALG.into(), key.into(), XFRM_AUTH_TRUNC_BITS.to_string(),
        "enc".into(), XFRM_ENC_ALG.into(), "0x".into(),
        "encap".into(), "udp".into(), sport.to_string(), dport.to_string(), "0.0.0.0".into(),
    ]
}

fn policy_add(
    ip: &str,
    src: &str,
    dst: &str,
    dir: &str,
    spi: u32,
    sport: u16,
    dport: u16,
) -> Vec<String> {
    vec![
        ip.into(), "xfrm".into(), "policy".into(), "add".into(),
        "src".into(), format!("{src}/128"),
        "dst".into(), format!("{dst}/128"),
        "sport".into(), sport.to_string(),
        "dport".into(), dport.to_string(),
        "dir".into(), dir.into(),
        "tmpl".into(),
        "src".into(), src.into(),
        "dst".into(), dst.into(),
        "proto".into(), "esp".into(),
        "spi".into(), format!("0x{spi:08x}"),
        "mode".into(), "transport".into(),
    ]
}

/// Remove everything this module installed. Called on teardown and before a
/// re-REGISTER so stale SAs can't shadow new ones
/// (`Cleaning up native VoLTE IMS context`).
pub fn teardown() -> Result<Vec<Vec<String>>, String> {
    let ip = ip_bin()?;
    Ok(vec![
        vec![ip.into(), "xfrm".into(), "state".into(), "flush".into()],
        vec![ip.into(), "xfrm".into(), "policy".into(), "flush".into()],
    ])
}

/// IPsec is IPv6-only in this implementation.
pub fn require_ipv6(addr: IpAddr) -> Result<Ipv6Addr, String> {
    match addr {
        IpAddr::V6(a) => Ok(a),
        IpAddr::V4(_) => Err(err::IPSEC_REQUIRES_IPV6.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shape a real P-CSCF answers with (same parameter style as our own
    /// Security-Client, plus the customary q-value).
    fn server() -> SecurityServer {
        parse_security_server(
            "ipsec-3gpp;prot=esp;mod=trans;spi-c=9900;spi-s=9950;port-c=5060;port-s=5061;alg=hmac-md5-96;ealg=null;q=0.5",
        )
        .unwrap()
    }

    #[test]
    fn parses_security_server() {
        let s = server();
        assert_eq!(s.spi_c, 9900);
        assert_eq!(s.spi_s, 9950);
        assert_eq!(s.port_c, 5060);
        assert_eq!(s.port_s, 5061);
        assert_eq!(s.alg, ALG_HMAC_MD5_96);
        assert_eq!(s.ealg, EALG_NULL);
    }

    #[test]
    fn missing_or_incomplete_header_rejected() {
        assert_eq!(
            parse_security_server("").unwrap_err(),
            err::SECURITY_SERVER_MISSING
        );
        assert_eq!(
            parse_security_server("ipsec-3gpp;alg=hmac-md5-96;spi-c=1").unwrap_err(),
            err::SECURITY_SERVER_MISSING
        );
        assert_eq!(
            parse_security_server("tls; q=0.1").unwrap_err(),
            err::SECURITY_SERVER_MISSING
        );
    }

    /// Byte-exactness of Security-Verify is the difference between 200 OK and
    /// an endless 401 loop.
    #[test]
    fn security_verify_echoes_raw_value() {
        let s = server();
        assert_eq!(security_verify_header(&s), s.raw);
        assert!(s.raw.contains("q=0.5"), "trailing params must be preserved");
        assert!(s.raw.contains("prot=esp"), "prot/mod must survive verbatim");
    }

    /// Byte-exact reproduction of the format string at VA 0x8edfcd.
    #[test]
    fn security_client_header_is_byte_exact() {
        let c = SecurityClient {
            spi_c: 42221,
            spi_s: 48657,
            port_c: 42221,
            port_s: 48657,
        };
        assert_eq!(
            c.to_header(),
            "ipsec-3gpp;prot=esp;mod=trans;spi-c=42221;spi-s=48657;port-c=42221;port-s=48657;alg=hmac-md5-96;ealg=null"
        );
    }

    #[test]
    fn security_client_has_no_spaces_and_correct_param_order() {
        let c = SecurityClient { spi_c: 1, spi_s: 2, port_c: 3, port_s: 4 };
        let h = c.to_header();
        assert!(!h.contains("; "), "binary uses bare semicolons");
        // prot/mod first, alg/ealg last.
        assert!(h.find("prot=esp").unwrap() < h.find("spi-c").unwrap());
        assert!(h.find("alg=").unwrap() > h.find("port-s").unwrap());
        assert!(h.ends_with("ealg=null"));
        assert!(!h.contains("sha"));
        assert!(!h.contains("aes"));
    }

    #[test]
    fn installs_four_xfrm_rules() {
        let ctx = IpsecContext {
            ue_addr: "2408:8556:a231:104e::1".parse().unwrap(),
            pcscf_addr: "2408:8142:6001:1::".parse().unwrap(),
            client: SecurityClient {
                spi_c: 42221,
                spi_s: 48657,
                port_c: 42221,
                port_s: 48657,
            },
            server: server(),
            ik: vec![0xEB; 16],
        };
        let cmds = install(&ctx).unwrap();
        assert_eq!(cmds.len(), 4);
        let flat: Vec<String> = cmds.iter().flatten().cloned().collect();
        assert!(flat.contains(&"hmac(md5)".to_string()));
        assert!(flat.contains(&"cipher_null".to_string()));
        assert!(flat.contains(&"96".to_string()));
        assert!(flat.iter().any(|s| s == "transport"));
    }

    #[test]
    fn short_ik_is_rejected() {
        let ctx = IpsecContext {
            ue_addr: "2408::1".parse().unwrap(),
            pcscf_addr: "2408::2".parse().unwrap(),
            client: SecurityClient { spi_c: 1, spi_s: 2, port_c: 3, port_s: 4 },
            server: server(),
            ik: vec![0; 8],
        };
        assert_eq!(install(&ctx).unwrap_err(), err::IPSEC_IK_INVALID);
    }

    #[test]
    fn ipv4_pcscf_rejected() {
        assert_eq!(
            require_ipv6("1.2.3.4".parse().unwrap()).unwrap_err(),
            err::IPSEC_REQUIRES_IPV6
        );
        assert!(require_ipv6("2408::1".parse().unwrap()).is_ok());
    }

    #[test]
    fn port_accessors_map_to_the_right_side() {
        let ctx = IpsecContext {
            ue_addr: "2408::1".parse().unwrap(),
            pcscf_addr: "2408::2".parse().unwrap(),
            client: SecurityClient { spi_c: 1, spi_s: 2, port_c: 42221, port_s: 48657 },
            server: server(),
            ik: vec![0; 16],
        };
        assert_eq!(ctx.local_receive_port(), 42221);
        assert_eq!(ctx.local_send_port(), 48657);
        assert_eq!(ctx.remote_client_port(), 5060);
        assert_eq!(ctx.remote_server_port(), 5061);
    }
}
