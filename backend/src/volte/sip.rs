//! SIP message construction and parsing for IMS REGISTER / MESSAGE.
//!
//! Recovered from `src/volte.rs` lines ~804, 3150-3272, 4563, 3939.
//!
//! Evidence (confidence A for literals):
//!   - `SIP/2.0`, `Via`, `Call-ID`, `Content-Length: 0`, `To;tag=`
//!   - `Expires: 3600`
//!   - `Supported: path, gruu`
//!   - `Allow: INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,MESSAGE,REFER,NOTIFY,INFO,OPTIONS`
//!   - `Require: sec-agree`, `Proxy-Require: sec-agree`
//!   - `P-Access-Network-Info: 3GPP-E-UTRAN-FDD`
//!   - `Accept-Contact: *;+g.3gpp.smsip`
//!   - `P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.sms`
//!   - `User-Agent: SimAdmin VoLTE`
//!   - `Content-Type: application/vnd.3gpp.sms`
//!   - `NOTIFY `, `INVITE `, `CANCEL `, `Proxy-Authorization`
//!   - acceptance headers: `associated_uri`, `service_route`, `feature_caps`,
//!     `security_verify`, `contact_smsip`, `contact`
//!   - `Native VoLTE IMS REGISTER acceptance headers`
//!   - `volte_sip_status_invalid`, `volte_sip_status_missing`,
//!     `volte_sip_header_missing`, `volte_sip_header_not_utf8`,
//!     `volte_sip_not_utf8`

use super::{err, SIP_VERSION, REGISTER_EXPIRES_SECS};

// ---------------------------------------------------------------------------
// Fixed header values (verbatim)
// ---------------------------------------------------------------------------

pub const H_ALLOW: &str =
    "Allow: INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,MESSAGE,REFER,NOTIFY,INFO,OPTIONS";
pub const H_SUPPORTED: &str = "Supported: path, gruu";
pub const H_REQUIRE_SEC_AGREE: &str = "Require: sec-agree";
pub const H_PROXY_REQUIRE_SEC_AGREE: &str = "Proxy-Require: sec-agree";
pub const H_PANI_EUTRAN: &str = "P-Access-Network-Info: 3GPP-E-UTRAN-FDD";
pub const H_ACCEPT_CONTACT_SMSIP: &str = "Accept-Contact: *;+g.3gpp.smsip";
pub const H_PREFERRED_SERVICE_SMS: &str =
    "P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.sms";
pub const H_USER_AGENT: &str = "User-Agent: SimAdmin VoLTE";
pub const H_CONTENT_TYPE_3GPP_SMS: &str = "Content-Type: application/vnd.3gpp.sms";
pub const H_CONTENT_LENGTH_ZERO: &str = "Content-Length: 0";
pub const H_MAX_FORWARDS: &str = "Max-Forwards: 70";
/// Branch-parameter magic cookie (RFC 3261 §8.1.1.7).
pub const BRANCH_MAGIC: &str = "z9hG4bK";

/// SIP methods this client emits or answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Register,
    Message,
    Notify,
    Invite,
    Cancel,
    Ack,
    Options,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Register => "REGISTER",
            Method::Message => "MESSAGE",
            Method::Notify => "NOTIFY",
            Method::Invite => "INVITE",
            Method::Cancel => "CANCEL",
            Method::Ack => "ACK",
            Method::Options => "OPTIONS",
        }
    }
}

/// A parsed SIP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// First header matching `name`, case-insensitive.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// All headers matching `name` — `P-Associated-URI` and `Service-Route` can
    /// legitimately repeat.
    pub fn headers_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Required header or `volte_sip_header_missing`.
    pub fn require_header(&self, name: &str) -> Result<&str, String> {
        self.header(name)
            .ok_or_else(|| err::SIP_HEADER_MISSING.to_string())
    }
}

/// Parse a SIP response from the wire.
///
/// Bodies are kept as bytes: 3GPP SMS payloads are binary and must not go
/// through UTF-8 validation (`volte_sip_not_utf8` is only for the header block).
pub fn parse_response(raw: &[u8]) -> Result<Response, String> {
    // Split header block from body at the first CRLFCRLF (tolerate bare LF).
    let (head, body) = split_head_body(raw);
    let head = std::str::from_utf8(head).map_err(|_| err::SIP_HEADER_NOT_UTF8.to_string())?;

    let mut lines = head.split(|c| c == '\n').map(|l| l.trim_end_matches('\r'));
    let start = lines.next().ok_or_else(|| err::SIP_STATUS_MISSING.to_string())?;

    // `SIP/2.0 401 Unauthorized`
    let mut it = start.splitn(3, ' ');
    let version = it.next().unwrap_or("");
    if version != SIP_VERSION {
        return Err(err::SIP_STATUS_INVALID.to_string());
    }
    let status: u16 = it
        .next()
        .ok_or_else(|| err::SIP_STATUS_MISSING.to_string())?
        .parse()
        .map_err(|_| err::SIP_STATUS_INVALID.to_string())?;
    if !(100..=699).contains(&status) {
        return Err(err::SIP_STATUS_INVALID.to_string());
    }
    let reason = it.next().unwrap_or("").to_string();

    // Header lines, with RFC 3261 line folding.
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = headers.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    Ok(Response {
        status,
        reason,
        headers,
        body: body.to_vec(),
    })
}

fn split_head_body(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(i) = find(raw, b"\r\n\r\n") {
        return (&raw[..i], &raw[i + 4..]);
    }
    if let Some(i) = find(raw, b"\n\n") {
        return (&raw[..i], &raw[i + 2..]);
    }
    (raw, &[])
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Everything needed to build a REGISTER.
#[derive(Debug, Clone)]
pub struct RegisterParams<'a> {
    pub home_domain: &'a str,
    /// IMPU, e.g. `sip:460010...@ims.mnc001.mcc460.3gppnetwork.org`
    pub public_identity: &'a str,
    /// UE contact address, IPv6 must be bracketed.
    pub contact_host: &'a str,
    pub contact_port: u16,
    pub call_id: &'a str,
    pub cseq: u32,
    pub from_tag: &'a str,
    pub branch: &'a str,
    /// `Authorization` value, or `None` on a bare probe.
    pub authorization: Option<&'a str>,
    /// `Security-Client` value for the first (unprotected) REGISTER.
    pub security_client: Option<&'a str>,
    /// `Security-Verify` value for the protected REGISTER.
    pub security_verify: Option<&'a str>,
    /// Advertise `+g.3gpp.smsip` in Contact so the network routes SMS to us.
    pub smsip: bool,
    /// Transport token for Via: `TCP` or `UDP`.
    pub transport: &'a str,
}

/// Build a REGISTER request.
///
/// # Header set is fixed, not staged
///
/// The binary carries a single contiguous REGISTER header block (VA 0x9172f0):
///
/// ```text
/// Expires: 3600
/// Supported: path, gruu
/// Allow: INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,MESSAGE,REFER,NOTIFY,INFO,OPTIONS
/// Require: sec-agree
/// Proxy-Require: sec-agree
/// Content-Length: 0
/// ```
///
/// There is **no `Supported: sec-agree`** anywhere in the binary — beta9 always
/// sends the strict `Require`/`Proxy-Require` pair, on the first REGISTER as
/// well as the protected one. (Field experience against some P-CSCFs suggests a
/// staged approach works better, but that is *not* what this build does, and
/// this reconstruction follows the binary.)
///
/// `Security-Client` is present on the unprotected REGISTER and
/// `Security-Verify` on the protected one; that is the only difference between
/// the two rounds.
pub fn build_register(p: &RegisterParams) -> String {
    let req_uri = format!("sip:{}", p.home_domain);
    let mut s = String::new();

    s.push_str(&format!("REGISTER {req_uri} {SIP_VERSION}\r\n"));
    s.push_str(&format!(
        "Via: {SIP_VERSION}/{} {}:{};branch={};rport\r\n",
        p.transport, p.contact_host, p.contact_port, p.branch
    ));
    s.push_str(H_MAX_FORWARDS);
    s.push_str("\r\n");
    s.push_str(&format!(
        "From: <{}>;tag={}\r\n",
        p.public_identity, p.from_tag
    ));
    // To has no tag on a REGISTER (the `To;tag=` literal in the binary belongs
    // to the response-side dialog handling).
    s.push_str(&format!("To: <{}>\r\n", p.public_identity));
    s.push_str(&format!("Call-ID: {}\r\n", p.call_id));
    s.push_str(&format!("CSeq: {} REGISTER\r\n", p.cseq));

    let mut contact = format!(
        "Contact: <sip:{}:{};transport={}>",
        p.contact_host,
        p.contact_port,
        p.transport.to_ascii_lowercase()
    );
    if p.smsip {
        contact.push_str(";+g.3gpp.smsip");
    }
    contact.push_str(&format!(";expires={REGISTER_EXPIRES_SECS}"));
    s.push_str(&contact);
    s.push_str("\r\n");

    s.push_str(&format!("Expires: {REGISTER_EXPIRES_SECS}\r\n"));
    s.push_str(H_SUPPORTED);
    s.push_str("\r\n");

    if let Some(a) = p.authorization {
        s.push_str(&format!("Authorization: {a}\r\n"));
    }

    // Round 1 proposes, round 2 echoes. Both carry the strict sec-agree pair.
    if let Some(client) = p.security_client {
        s.push_str(&format!("Security-Client: {client}\r\n"));
    }
    if let Some(verify) = p.security_verify {
        s.push_str(&format!("Security-Verify: {verify}\r\n"));
    }
    s.push_str(H_REQUIRE_SEC_AGREE);
    s.push_str("\r\n");
    s.push_str(H_PROXY_REQUIRE_SEC_AGREE);
    s.push_str("\r\n");
    s.push_str(H_PANI_EUTRAN);
    s.push_str("\r\n");

    s.push_str(H_ALLOW);
    s.push_str("\r\n");
    s.push_str(H_USER_AGENT);
    s.push_str("\r\n");
    s.push_str(H_CONTENT_LENGTH_ZERO);
    s.push_str("\r\n\r\n");
    s
}

/// Headers pulled out of a 200 OK, logged as
/// `Native VoLTE IMS REGISTER acceptance headers`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcceptanceHeaders {
    pub associated_uri: Vec<String>,
    pub service_route: Vec<String>,
    pub feature_caps: Vec<String>,
    pub security_verify: Option<String>,
    /// Whether our Contact came back with `+g.3gpp.smsip` intact.
    pub contact_smsip: bool,
    pub contact: Vec<String>,
}

/// Collect the interesting bits from a successful REGISTER response.
pub fn acceptance_headers(r: &Response) -> AcceptanceHeaders {
    let contact: Vec<String> = r.headers_all("Contact").iter().map(|s| s.to_string()).collect();
    AcceptanceHeaders {
        associated_uri: r
            .headers_all("P-Associated-URI")
            .iter()
            .map(|s| s.to_string())
            .collect(),
        service_route: r
            .headers_all("Service-Route")
            .iter()
            .map(|s| s.to_string())
            .collect(),
        feature_caps: r
            .headers_all("Feature-Caps")
            .iter()
            .map(|s| s.to_string())
            .collect(),
        security_verify: r.header("Security-Verify").map(|s| s.to_string()),
        contact_smsip: contact.iter().any(|c| c.contains("+g.3gpp.smsip")),
        contact,
    }
}

/// Build a MESSAGE carrying a 3GPP SMS RPDU.
pub struct MessageParams<'a> {
    pub home_domain: &'a str,
    pub public_identity: &'a str,
    /// Service centre URI (`sip:` with `user=phone`, or `tel:`).
    pub request_uri: &'a str,
    pub contact_host: &'a str,
    pub contact_port: u16,
    pub call_id: &'a str,
    pub cseq: u32,
    pub from_tag: &'a str,
    pub branch: &'a str,
    pub transport: &'a str,
    pub body: &'a [u8],
}

/// Build the MESSAGE request. Returns head + body separately so the caller can
/// send a single datagram without re-encoding the binary payload.
pub fn build_message(p: &MessageParams) -> (String, Vec<u8>) {
    let mut s = String::new();
    s.push_str(&format!("MESSAGE {} {SIP_VERSION}\r\n", p.request_uri));
    s.push_str(&format!(
        "Via: {SIP_VERSION}/{} {}:{};branch={};rport\r\n",
        p.transport, p.contact_host, p.contact_port, p.branch
    ));
    s.push_str("Max-Forwards: 70\r\n");
    s.push_str(&format!(
        "From: <{}>;tag={}\r\n",
        p.public_identity, p.from_tag
    ));
    s.push_str(&format!("To: <{}>\r\n", p.request_uri));
    s.push_str(&format!("Call-ID: {}\r\n", p.call_id));
    s.push_str(&format!("CSeq: {} MESSAGE\r\n", p.cseq));
    s.push_str(H_ACCEPT_CONTACT_SMSIP);
    s.push_str("\r\n");
    s.push_str(H_PREFERRED_SERVICE_SMS);
    s.push_str("\r\n");
    s.push_str(H_PANI_EUTRAN);
    s.push_str("\r\n");
    s.push_str(H_USER_AGENT);
    s.push_str("\r\n");
    s.push_str(H_CONTENT_TYPE_3GPP_SMS);
    s.push_str("\r\n");
    s.push_str(&format!("Content-Length: {}\r\n\r\n", p.body.len()));
    (s, p.body.to_vec())
}

/// Recipient URI variants tried in order — the binary keeps three spellings and
/// retries the MESSAGE with each (`volte_sms_message_all_variants_failed` when
/// all fail). Token names in .rodata: `service_center_sip_user_phone`,
/// `service_center_tel`, `recipient_sip_user_phone`.
pub fn recipient_variants(number: &str, home_domain: &str) -> Vec<String> {
    let n = number.trim();
    vec![
        format!("sip:{n}@{home_domain};user=phone"),
        format!("tel:{n}"),
        format!("sip:{n}@{home_domain}"),
    ]
}

/// Minimal 200 OK used to acknowledge an inbound request (MT SMS delivery,
/// NOTIFY, or any non-MESSAGE request we simply ack).
pub fn build_ok(req: &Response, contact_host: &str, contact_port: u16) -> String {
    let mut s = format!("{SIP_VERSION} 200 OK\r\n");
    for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
        if let Some(v) = req.header(name) {
            s.push_str(&format!("{name}: {v}\r\n"));
        }
    }
    s.push_str(&format!(
        "Contact: <sip:{contact_host}:{contact_port}>\r\n"
    ));
    s.push_str(H_CONTENT_LENGTH_ZERO);
    s.push_str("\r\n\r\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_401_with_challenge() {
        let raw = b"SIP/2.0 401 Unauthorized\r\n\
WWW-Authenticate: Digest realm=\"ims.mnc001.mcc460.3gppnetwork.org\", nonce=\"AAAA\", algorithm=AKAv1-MD5\r\n\
Security-Server: ipsec-3gpp; alg=hmac-md5-96; ealg=null; spi-c=9900; spi-s=9950; port-c=5060; port-s=5061\r\n\
Content-Length: 0\r\n\r\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 401);
        assert_eq!(r.reason, "Unauthorized");
        assert!(r.header("www-authenticate").unwrap().contains("AKAv1-MD5"));
        assert!(r.header("Security-Server").unwrap().contains("spi-c=9900"));
    }

    #[test]
    fn rejects_malformed_status_line() {
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\n\r\n").unwrap_err(),
            err::SIP_STATUS_INVALID
        );
        assert_eq!(
            parse_response(b"SIP/2.0 abc Bad\r\n\r\n").unwrap_err(),
            err::SIP_STATUS_INVALID
        );
        assert_eq!(
            parse_response(b"SIP/2.0\r\n\r\n").unwrap_err(),
            err::SIP_STATUS_MISSING
        );
    }

    #[test]
    fn handles_folded_headers() {
        let raw = b"SIP/2.0 200 OK\r\nP-Associated-URI: <sip:a@b>,\r\n <tel:+123>\r\n\r\n";
        let r = parse_response(raw).unwrap();
        let v = r.header("P-Associated-URI").unwrap();
        assert!(v.contains("<sip:a@b>"));
        assert!(v.contains("<tel:+123>"));
    }

    #[test]
    fn binary_body_survives_parsing() {
        let mut raw = b"SIP/2.0 200 OK\r\nContent-Length: 4\r\n\r\n".to_vec();
        raw.extend_from_slice(&[0x00, 0xFF, 0x80, 0x7F]);
        let r = parse_response(&raw).unwrap();
        assert_eq!(r.body, vec![0x00, 0xFF, 0x80, 0x7F]);
    }

    /// beta9 sends the strict sec-agree pair on **both** rounds; there is no
    /// `Supported: sec-agree` in the binary at all.
    #[test]
    fn both_register_rounds_carry_strict_sec_agree() {
        let base = RegisterParams {
            home_domain: "ims.mnc001.mcc460.3gppnetwork.org",
            public_identity: "sip:460010123456789@ims.mnc001.mcc460.3gppnetwork.org",
            contact_host: "[2408:8556:a231:104e::1]",
            contact_port: 5060,
            call_id: "abc123",
            cseq: 1,
            from_tag: "tag1",
            branch: "z9hG4bKbranch1",
            authorization: Some("Digest username=\"u\",realm=\"r\",nonce=\"\",uri=\"sip:r\",response=\"\",algorithm=AKAv1-MD5"),
            security_client: Some("ipsec-3gpp;prot=esp;mod=trans;spi-c=1;spi-s=2;port-c=3;port-s=4;alg=hmac-md5-96;ealg=null"),
            security_verify: None,
            smsip: true,
            transport: "TCP",
        };

        let round1 = build_register(&base);
        assert!(round1.contains("Require: sec-agree"));
        assert!(round1.contains("Proxy-Require: sec-agree"));
        assert!(round1.contains("Security-Client:"));
        assert!(!round1.contains("Security-Verify:"));
        assert!(
            !round1.contains("Supported: sec-agree"),
            "not present in the binary"
        );
        assert!(round1.contains("Supported: path, gruu"));
        assert!(round1.contains("+g.3gpp.smsip"));
        assert!(round1.starts_with("REGISTER sip:ims.mnc001.mcc460.3gppnetwork.org SIP/2.0\r\n"));

        let mut p2 = base.clone();
        p2.security_client = None;
        p2.security_verify = Some("ipsec-3gpp;prot=esp;mod=trans;spi-c=9900;spi-s=9950;port-c=5060;port-s=5061;alg=hmac-md5-96;ealg=null");
        let round2 = build_register(&p2);
        assert!(round2.contains("Security-Verify:"));
        assert!(!round2.contains("Security-Client:"));
        assert!(round2.contains("Require: sec-agree"));
        assert!(round2.contains("Proxy-Require: sec-agree"));
        assert!(round2.contains("P-Access-Network-Info: 3GPP-E-UTRAN-FDD"));
    }

    #[test]
    fn register_header_block_matches_binary_literals() {
        let p = RegisterParams {
            home_domain: "ims.mnc001.mcc460.3gppnetwork.org",
            public_identity: "sip:u@ims",
            contact_host: "[2408::1]",
            contact_port: 5060,
            call_id: "c",
            cseq: 1,
            from_tag: "t",
            branch: "z9hG4bKb",
            authorization: None,
            security_client: None,
            security_verify: None,
            smsip: false,
            transport: "TCP",
        };
        let m = build_register(&p);
        for want in [
            "Expires: 3600",
            "Supported: path, gruu",
            "Allow: INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,MESSAGE,REFER,NOTIFY,INFO,OPTIONS",
            "Require: sec-agree",
            "Proxy-Require: sec-agree",
            "Content-Length: 0",
            "Max-Forwards: 70",
            "User-Agent: SimAdmin VoLTE",
        ] {
            assert!(m.contains(want), "missing: {want}");
        }
        assert!(p.branch.starts_with(BRANCH_MAGIC));
    }

    #[test]
    fn extracts_acceptance_headers() {
        let raw = b"SIP/2.0 200 OK\r\n\
P-Associated-URI: <sip:460010123456789@ims.mnc001.mcc460.3gppnetwork.org>\r\n\
P-Associated-URI: <tel:+8613074325965>\r\n\
Service-Route: <sip:orig@scscf.ims:5060;lr>\r\n\
Contact: <sip:[2408::1]:42221>;+g.3gpp.smsip;expires=3600\r\n\
\r\n";
        let r = parse_response(raw).unwrap();
        let a = acceptance_headers(&r);
        assert_eq!(a.associated_uri.len(), 2);
        assert_eq!(a.service_route.len(), 1);
        assert!(a.contact_smsip);
    }

    #[test]
    fn recipient_variant_order() {
        let v = recipient_variants("+8613800100500", "ims.mnc001.mcc460.3gppnetwork.org");
        assert_eq!(v.len(), 3);
        assert!(v[0].ends_with(";user=phone"));
        assert!(v[1].starts_with("tel:"));
        assert!(!v[2].contains("user=phone"));
    }

    #[test]
    fn message_body_length_matches_header() {
        let body = vec![0x01, 0x02, 0x03];
        let p = MessageParams {
            home_domain: "ims.mnc001.mcc460.3gppnetwork.org",
            public_identity: "sip:u@ims",
            request_uri: "sip:+8613800100500@ims;user=phone",
            contact_host: "[2408::1]",
            contact_port: 42221,
            call_id: "cid",
            cseq: 3,
            from_tag: "t",
            branch: "b",
            transport: "TCP",
            body: &body,
        };
        let (head, b) = build_message(&p);
        assert!(head.contains("Content-Length: 3"));
        assert!(head.contains("Content-Type: application/vnd.3gpp.sms"));
        assert_eq!(b, body);
    }

    #[test]
    fn ok_response_mirrors_dialog_headers() {
        let raw = b"MESSAGE sip:me SIP/2.0\r\nVia: SIP/2.0/TCP p;branch=x\r\nFrom: <sip:sc>;tag=a\r\nTo: <sip:me>\r\nCall-ID: c1\r\nCSeq: 9 MESSAGE\r\n\r\n";
        // parse_response only handles responses; craft the fields directly.
        let req = Response {
            status: 0,
            reason: String::new(),
            headers: vec![
                ("Via".into(), "SIP/2.0/TCP p;branch=x".into()),
                ("From".into(), "<sip:sc>;tag=a".into()),
                ("To".into(), "<sip:me>".into()),
                ("Call-ID".into(), "c1".into()),
                ("CSeq".into(), "9 MESSAGE".into()),
            ],
            body: vec![],
        };
        let _ = raw;
        let ok = build_ok(&req, "[2408::1]", 42221);
        assert!(ok.starts_with("SIP/2.0 200 OK\r\n"));
        assert!(ok.contains("Call-ID: c1"));
        assert!(ok.contains("CSeq: 9 MESSAGE"));
    }
}
