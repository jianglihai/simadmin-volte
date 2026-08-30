//! 3GPP AKA over USIM, and the SIP digest that wraps it.
//!
//! Recovered from `src/volte.rs` lines ~3370-3440, 2604-2687.
//!
//! Evidence (confidence A for literals):
//!   - `AKAv1-MD5`, `AKAv2-MD5`, `MD5`
//!   - `http-digest-akav2-password`
//!   - `volte_digest_algorithm_unsupported`, `volte_digest_challenge_missing`,
//!     `volte_digest_nonce_missing`, `volte_digest_realm_missing`,
//!     `volte_digest_qop_unsupported`, `volte_digest_nonce_decode_failed`
//!   - `volte_register_nonce_not_aka`, `volte_aka_material_invalid`,
//!     `volte_aka_res_empty`, `volte_ipsec_aka_res_empty_without_auts`
//!   - `Native VoLTE IPsec AKA returned AUTS, requesting resync`
//!   - `Digest `, `realm`, `nonce`, `qop`, `opaque`
//!   - `sim_auth_*` error family (APDU proxy) in the shared error blob
//!
//! # Key point: the host never sees K
//!
//! AKA is executed *inside the USIM* via an AUTHENTICATE APDU. The host supplies
//! RAND and AUTN, and the card returns RES, CK, IK — or AUTS if its sequence
//! number is out of range. There is no long-term key on the host, which is why
//! this module has no crypto beyond MD5 for the digest itself.

use super::err;

/// Digest algorithm advertised in the 401 challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// 3GPP AKA v1: password = RES.
    Akav1Md5,
    /// 3GPP AKA v2: password = derived from RES/CK/IK via a KDF.
    Akav2Md5,
    /// Plain HTTP digest (non-AKA); accepted for lab/IMS-lite setups.
    Md5,
}

impl DigestAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            DigestAlgorithm::Akav1Md5 => "AKAv1-MD5",
            DigestAlgorithm::Akav2Md5 => "AKAv2-MD5",
            DigestAlgorithm::Md5 => "MD5",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_uppercase().as_str() {
            "AKAV1-MD5" => Ok(DigestAlgorithm::Akav1Md5),
            "AKAV2-MD5" => Ok(DigestAlgorithm::Akav2Md5),
            "MD5" => Ok(DigestAlgorithm::Md5),
            _ => Err(err::DIGEST_ALGORITHM_UNSUPPORTED.to_string()),
        }
    }

    /// AKA variants carry RAND||AUTN in the nonce; plain MD5 does not.
    pub fn is_aka(self) -> bool {
        matches!(self, DigestAlgorithm::Akav1Md5 | DigestAlgorithm::Akav2Md5)
    }
}

/// Label used by the AKAv2 password KDF (RFC 4169).
pub const AKAV2_PASSWORD_LABEL: &str = "http-digest-akav2-password";

/// Parsed `WWW-Authenticate` / `Proxy-Authenticate` challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestChallenge {
    pub realm: String,
    /// Base64 as received.
    pub nonce_b64: String,
    /// Decoded nonce: RAND(16) || AUTN(16) for AKA.
    pub nonce: Vec<u8>,
    pub algorithm: DigestAlgorithm,
    pub qop: Option<String>,
    pub opaque: Option<String>,
}

/// RAND and AUTN as handed to the card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkaChallenge {
    pub rand: [u8; 16],
    pub autn: [u8; 16],
}

/// What the card returns from AUTHENTICATE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AkaResult {
    /// Success: RES plus session keys.
    Success {
        res: Vec<u8>,
        ck: Vec<u8>,
        ik: Vec<u8>,
    },
    /// Sequence number out of sync; AUTS must be sent back so the network can
    /// resynchronise. Logged as `Native VoLTE IPsec AKA returned AUTS,
    /// requesting resync`.
    Resync { auts: Vec<u8> },
}

/// Parse a `Digest ...` challenge value.
///
/// Accepts the header value with or without the leading `Digest ` token.
pub fn parse_challenge(header_value: &str) -> Result<DigestChallenge, String> {
    let v = header_value.trim();
    let v = v
        .strip_prefix("Digest ")
        .or_else(|| v.strip_prefix("digest "))
        .unwrap_or(v);
    if v.is_empty() {
        return Err(err::DIGEST_CHALLENGE_MISSING.to_string());
    }

    let mut realm = None;
    let mut nonce_b64 = None;
    let mut algorithm = DigestAlgorithm::Md5;
    let mut qop = None;
    let mut opaque = None;

    for part in split_params(v) {
        let (k, val) = match part.split_once('=') {
            Some((k, val)) => (k.trim().to_ascii_lowercase(), unquote(val.trim())),
            None => continue,
        };
        match k.as_str() {
            "realm" => realm = Some(val),
            "nonce" => nonce_b64 = Some(val),
            "algorithm" => algorithm = DigestAlgorithm::parse(&val)?,
            "qop" => qop = Some(val),
            "opaque" => opaque = Some(val),
            _ => {}
        }
    }

    let realm = realm.ok_or_else(|| err::DIGEST_REALM_MISSING.to_string())?;
    let nonce_b64 = nonce_b64.ok_or_else(|| err::DIGEST_NONCE_MISSING.to_string())?;

    // qop, when present, must include "auth"; "auth-int" alone is unsupported.
    if let Some(q) = &qop {
        if !q.split(',').any(|x| x.trim().eq_ignore_ascii_case("auth")) {
            return Err(err::DIGEST_QOP_UNSUPPORTED.to_string());
        }
    }

    let nonce = base64_decode(&nonce_b64)
        .map_err(|_| err::DIGEST_NONCE_DECODE_FAILED.to_string())?;

    Ok(DigestChallenge {
        realm,
        nonce_b64,
        nonce,
        algorithm,
        qop,
        opaque,
    })
}

/// Split RAND||AUTN out of an AKA nonce.
///
/// The nonce must be at least 32 bytes; anything shorter means the registrar
/// sent a non-AKA nonce while advertising an AKA algorithm
/// (`volte_register_nonce_not_aka`).
pub fn aka_challenge_from_nonce(nonce: &[u8]) -> Result<AkaChallenge, String> {
    if nonce.len() < 32 {
        return Err(err::REGISTER_NONCE_NOT_AKA.to_string());
    }
    let mut rand = [0u8; 16];
    let mut autn = [0u8; 16];
    rand.copy_from_slice(&nonce[0..16]);
    autn.copy_from_slice(&nonce[16..32]);
    Ok(AkaChallenge { rand, autn })
}

/// Validate what the card gave back before using it.
///
/// An empty RES with no AUTS is a hard failure and gets its own code so the
/// resync path can be told apart from a dead card.
pub fn validate_aka_result(r: &AkaResult, ipsec: bool) -> Result<(), String> {
    match r {
        AkaResult::Success { res, ck, ik } => {
            if res.is_empty() {
                return Err(if ipsec {
                    err::IPSEC_AKA_RES_EMPTY.to_string()
                } else {
                    err::AKA_RES_EMPTY.to_string()
                });
            }
            // IPsec needs IK for the integrity SA; CK is unused with null
            // encryption but a zero-length CK signals a malformed response.
            if ipsec && ik.len() < 16 {
                return Err(err::IPSEC_IK_INVALID.to_string());
            }
            if ck.is_empty() || ik.is_empty() {
                return Err(err::AKA_MATERIAL_INVALID.to_string());
            }
            Ok(())
        }
        AkaResult::Resync { auts } => {
            if auts.is_empty() {
                Err(err::IPSEC_AKA_RES_EMPTY_WITHOUT_AUTS.to_string())
            } else {
                Ok(())
            }
        }
    }
}

/// Digest password for the chosen algorithm.
///
/// - AKAv1: the password *is* RES.
/// - AKAv2: password = base64(KDF), per RFC 4169 — keyed by CK||IK over the
///   label [`AKAV2_PASSWORD_LABEL`].
/// - MD5: caller-supplied secret (not used in production against a real IMS).
pub fn digest_password(alg: DigestAlgorithm, res: &[u8], ck: &[u8], ik: &[u8]) -> Vec<u8> {
    match alg {
        DigestAlgorithm::Akav1Md5 => res.to_vec(),
        DigestAlgorithm::Akav2Md5 => {
            // RFC 4169: password = base64(H(RES||CK||IK, label))
            let mut input = Vec::with_capacity(res.len() + ck.len() + ik.len());
            input.extend_from_slice(res);
            input.extend_from_slice(ck);
            input.extend_from_slice(ik);
            let mac = hmac_md5(&input, AKAV2_PASSWORD_LABEL.as_bytes());
            base64_encode(&mac).into_bytes()
        }
        DigestAlgorithm::Md5 => Vec::new(),
    }
}

/// Compute the RFC 2617 / RFC 3310 digest response.
///
/// `HA1 = MD5(user:realm:password)`
/// `HA2 = MD5(method:uri)`
/// with qop=auth: `MD5(HA1:nonce:nc:cnonce:qop:HA2)`
/// without qop:   `MD5(HA1:nonce:HA2)`
pub fn digest_response(
    username: &str,
    realm: &str,
    password: &[u8],
    method: &str,
    uri: &str,
    nonce: &str,
    qop: Option<&str>,
    nc: &str,
    cnonce: &str,
) -> String {
    let mut a1 = Vec::new();
    a1.extend_from_slice(username.as_bytes());
    a1.push(b':');
    a1.extend_from_slice(realm.as_bytes());
    a1.push(b':');
    a1.extend_from_slice(password);
    let ha1 = hex(&md5(&a1));

    let a2 = format!("{method}:{uri}");
    let ha2 = hex(&md5(a2.as_bytes()));

    let payload = match qop {
        Some(q) => format!("{ha1}:{nonce}:{nc}:{cnonce}:{q}:{ha2}"),
        None => format!("{ha1}:{nonce}:{ha2}"),
    };
    hex(&md5(payload.as_bytes()))
}

/// Render the `Authorization: Digest ...` value.
///
/// Format string is **byte-exact from the binary** (VA 0x8ee4a2 region):
///
/// ```text
/// Digest username="..",realm="..",nonce="..",uri="..",response="..",algorithm=..
///        [,qop=..,nc=00000001,cnonce=".."]  [,opaque=".."]  [,auts=".."]
/// ```
///
/// Two details that matter on the wire:
/// - **No space after the commas.** The binary's template has none.
/// - **`nc` is hard-coded to `00000001`.** Each REGISTER opens a fresh nonce
///   context, so the counter never advances.
///
/// The optional `auts` parameter carries the USIM's resynchronisation token back
/// to the network after an AKA sequence-number failure — see
/// [`AkaResult::Resync`].
pub fn authorization_header(
    username: &str,
    realm: &str,
    uri: &str,
    nonce: &str,
    response: &str,
    algorithm: DigestAlgorithm,
    qop: Option<&str>,
    cnonce: Option<&str>,
    opaque: Option<&str>,
    auts: Option<&str>,
) -> String {
    let mut s = format!(
        "Digest username=\"{username}\",realm=\"{realm}\",nonce=\"{nonce}\",uri=\"{uri}\",response=\"{response}\",algorithm={}",
        algorithm.as_str()
    );
    if let Some(q) = qop {
        s.push_str(&format!(",qop={q},nc={NONCE_COUNT}"));
        if let Some(cn) = cnonce {
            s.push_str(&format!(",cnonce=\"{cn}\""));
        }
    }
    if let Some(o) = opaque {
        s.push_str(&format!(",opaque=\"{o}\""));
    }
    if let Some(a) = auts {
        s.push_str(&format!(",auts=\"{a}\""));
    }
    s
}

/// Nonce count, fixed at `00000001` in the binary's template.
pub const NONCE_COUNT: &str = "00000001";

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Split comma-separated auth params, respecting quoted strings.
fn split_params(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_q = !in_q;
                cur.push(c);
            }
            ',' if !in_q => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// The real binary links `ring` / `md-5` / `hmac`. Signatures are kept here so
// the module is self-describing; wire these to the crate of your choice.
fn md5(data: &[u8]) -> [u8; 16] {
    md5_impl::compute(data)
}

fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC-MD5, RFC 2104.
    const BLOCK: usize = 64;
    let mut k = if key.len() > BLOCK {
        md5(key).to_vec()
    } else {
        key.to_vec()
    };
    k.resize(BLOCK, 0);
    let mut ipad = vec![0x36u8; BLOCK];
    let mut opad = vec![0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = ipad;
    inner.extend_from_slice(data);
    let ih = md5(&inner);
    let mut outer = opad;
    outer.extend_from_slice(&ih);
    md5(&outer).to_vec()
}

fn base64_encode(b: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let b0 = c[0] as u32;
        let b1 = *c.get(1).unwrap_or(&0) as u32;
        let b2 = *c.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if c.len() > 1 { T[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if c.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    fn val(c: u8) -> Result<u32, ()> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(()),
        }
    }
    let t: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let t: Vec<u8> = t.into_iter().take_while(|c| *c != b'=').collect();
    let mut out = Vec::new();
    for chunk in t.chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            n |= val(*c)? << (18 - 6 * i);
        }
        let bytes = match chunk.len() {
            4 => 3,
            3 => 2,
            2 => 1,
            _ => return Err(()),
        };
        for i in 0..bytes {
            out.push((n >> (16 - 8 * i) & 0xFF) as u8);
        }
    }
    Ok(out)
}

/// Minimal MD5 so this module is testable standalone. The shipped binary uses
/// the `md-5` crate; behaviour is identical.
mod md5_impl {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    pub fn compute(input: &[u8]) -> [u8; 16] {
        let mut k = [0u32; 64];
        for i in 0..64 {
            k[i] = ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32;
        }
        let mut a0: u32 = 0x67452301;
        let mut b0: u32 = 0xefcdab89;
        let mut c0: u32 = 0x98badcfe;
        let mut d0: u32 = 0x10325476;

        let mut msg = input.to_vec();
        let bitlen = (input.len() as u64).wrapping_mul(8);
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bitlen.to_le_bytes());

        for chunk in msg.chunks(64) {
            let mut m = [0u32; 16];
            for i in 0..16 {
                m[i] = u32::from_le_bytes([
                    chunk[4 * i],
                    chunk[4 * i + 1],
                    chunk[4 * i + 2],
                    chunk[4 * i + 3],
                ]);
            }
            let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
            for i in 0..64 {
                let (f, g) = match i / 16 {
                    0 => ((b & c) | (!b & d), i),
                    1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                    2 => (b ^ c ^ d, (3 * i + 5) % 16),
                    _ => (c ^ (b | !d), (7 * i) % 16),
                };
                let f2 = f
                    .wrapping_add(a)
                    .wrapping_add(k[i])
                    .wrapping_add(m[g]);
                a = d;
                d = c;
                c = b;
                b = b.wrapping_add(f2.rotate_left(S[i]));
            }
            a0 = a0.wrapping_add(a);
            b0 = b0.wrapping_add(b);
            c0 = c0.wrapping_add(c);
            d0 = d0.wrapping_add(d);
        }

        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&a0.to_le_bytes());
        out[4..8].copy_from_slice(&b0.to_le_bytes());
        out[8..12].copy_from_slice(&c0.to_le_bytes());
        out[12..16].copy_from_slice(&d0.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_known_vectors() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn parses_aka_challenge() {
        // 32-byte nonce -> RAND||AUTN
        let nonce = vec![0xAAu8; 16]
            .into_iter()
            .chain(vec![0xBBu8; 16])
            .collect::<Vec<u8>>();
        let b64 = base64_encode(&nonce);
        let hv = format!(
            "Digest realm=\"ims.mnc001.mcc460.3gppnetwork.org\", nonce=\"{b64}\", algorithm=AKAv1-MD5, qop=\"auth\""
        );
        let c = parse_challenge(&hv).unwrap();
        assert_eq!(c.algorithm, DigestAlgorithm::Akav1Md5);
        assert!(c.algorithm.is_aka());
        assert_eq!(c.nonce.len(), 32);

        let aka = aka_challenge_from_nonce(&c.nonce).unwrap();
        assert_eq!(aka.rand, [0xAA; 16]);
        assert_eq!(aka.autn, [0xBB; 16]);
    }

    #[test]
    fn short_nonce_with_aka_algorithm_is_rejected() {
        let b64 = base64_encode(&[1, 2, 3, 4]);
        let hv = format!("Digest realm=\"r\", nonce=\"{b64}\", algorithm=AKAv1-MD5");
        let c = parse_challenge(&hv).unwrap();
        assert_eq!(
            aka_challenge_from_nonce(&c.nonce).unwrap_err(),
            err::REGISTER_NONCE_NOT_AKA
        );
    }

    #[test]
    fn missing_realm_and_nonce_are_distinct_errors() {
        assert_eq!(
            parse_challenge("Digest nonce=\"AAAA\"").unwrap_err(),
            err::DIGEST_REALM_MISSING
        );
        assert_eq!(
            parse_challenge("Digest realm=\"r\"").unwrap_err(),
            err::DIGEST_NONCE_MISSING
        );
        assert_eq!(
            parse_challenge("").unwrap_err(),
            err::DIGEST_CHALLENGE_MISSING
        );
    }

    #[test]
    fn auth_int_only_qop_is_unsupported() {
        let b64 = base64_encode(&[0u8; 32]);
        let hv = format!("Digest realm=\"r\", nonce=\"{b64}\", qop=\"auth-int\"");
        assert_eq!(parse_challenge(&hv).unwrap_err(), err::DIGEST_QOP_UNSUPPORTED);
    }

    #[test]
    fn akav1_password_is_res() {
        let res = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let p = digest_password(DigestAlgorithm::Akav1Md5, &res, &[9; 16], &[8; 16]);
        assert_eq!(p, res);
    }

    #[test]
    fn empty_res_rejected_and_resync_accepted() {
        let bad = AkaResult::Success {
            res: vec![],
            ck: vec![1; 16],
            ik: vec![2; 16],
        };
        assert_eq!(
            validate_aka_result(&bad, true).unwrap_err(),
            err::IPSEC_AKA_RES_EMPTY
        );

        let resync = AkaResult::Resync { auts: vec![7; 14] };
        assert!(validate_aka_result(&resync, true).is_ok());

        let empty_resync = AkaResult::Resync { auts: vec![] };
        assert_eq!(
            validate_aka_result(&empty_resync, true).unwrap_err(),
            err::IPSEC_AKA_RES_EMPTY_WITHOUT_AUTS
        );
    }

    #[test]
    fn ipsec_requires_full_length_ik() {
        let short_ik = AkaResult::Success {
            res: vec![1; 8],
            ck: vec![1; 16],
            ik: vec![2; 8],
        };
        assert_eq!(
            validate_aka_result(&short_ik, true).unwrap_err(),
            err::IPSEC_IK_INVALID
        );
        // Non-IPsec registration tolerates it.
        assert!(validate_aka_result(&short_ik, false).is_ok());
    }

    #[test]
    fn base64_roundtrip() {
        for n in 0..40usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 % 251) as u8).collect();
            let e = base64_encode(&data);
            assert_eq!(base64_decode(&e).unwrap(), data, "n={n}");
        }
    }

    #[test]
    fn initial_register_carries_empty_response() {
        let h = authorization_header(
            "460010123456789@ims.mnc001.mcc460.3gppnetwork.org",
            "ims.mnc001.mcc460.3gppnetwork.org",
            "sip:ims.mnc001.mcc460.3gppnetwork.org",
            "",
            "",
            DigestAlgorithm::Akav1Md5,
            None,
            None,
            None,
            None,
        );
        assert!(h.contains("response=\"\""));
        assert!(h.contains("algorithm=AKAv1-MD5"));
    }

    /// Byte-exact reproduction of the binary's template: no spaces after commas.
    #[test]
    fn authorization_has_no_spaces_after_commas() {
        let h = authorization_header(
            "u", "r", "sip:r", "n", "resp",
            DigestAlgorithm::Akav1Md5,
            None, None, None, None,
        );
        assert_eq!(
            h,
            "Digest username=\"u\",realm=\"r\",nonce=\"n\",uri=\"sip:r\",response=\"resp\",algorithm=AKAv1-MD5"
        );
        assert!(!h.contains(", "));
    }

    #[test]
    fn nonce_count_is_fixed_at_one() {
        let h = authorization_header(
            "u", "r", "sip:r", "n", "resp",
            DigestAlgorithm::Akav1Md5,
            Some("auth"), Some("abc123"), None, None,
        );
        assert!(h.contains(",qop=auth,nc=00000001,cnonce=\"abc123\""));
        assert_eq!(NONCE_COUNT, "00000001");
    }

    /// AUTS is appended after a resync so the network can catch up its SQN.
    #[test]
    fn auts_is_appended_for_resync() {
        let h = authorization_header(
            "u", "r", "sip:r", "n", "",
            DigestAlgorithm::Akav1Md5,
            None, None, None, Some("aabbccdd"),
        );
        assert!(h.ends_with(",auts=\"aabbccdd\""));
    }

    #[test]
    fn opaque_precedes_auts() {
        let h = authorization_header(
            "u", "r", "sip:r", "n", "",
            DigestAlgorithm::Akav1Md5,
            None, None, Some("op"), Some("au"),
        );
        assert!(h.find("opaque").unwrap() < h.find("auts").unwrap());
    }
}
