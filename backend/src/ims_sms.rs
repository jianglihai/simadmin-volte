//! 3GPP SMS over IMS: RPDU/TPDU encode and decode, concatenation, RP-ACK.
//!
//! ============================================================================
//! REVERSE-ENGINEERED from simadmin 1.1.6-beta9
//!   binary md5 : de53b623259c8190eb70aa6a82c6f2da
//!
//! Evidence
//!   - source path literal `src/ims_sms.rs` @ 0x8ee5c6
//!   - trace prefixes `volte-sms-`, `volte-sms-trace-`, `volte-mo:`
//!   - `segment_reference`, `segment_total`, `segment_sequence`
//!   - `rp_ack`, `rp_ack_send_failed`, `rp_ack_timeout`, `rp_ack_unconfirmed`,
//!     `no_rp_ack_timeout`
//!   - `Native VoLTE MT multipart SMS assembled`
//!   - `Native VoLTE MT multipart segment buffered`
//!   - `Native VoLTE MT multipart cache lock poisoned`
//!   - `Skipped duplicate native VoLTE MT SMS already in database`
//!   - `Stored native VoLTE MT SMS`, `volte_ims` (source marker in DB)
//!   - `Content-Type: application/vnd.3gpp.sms`
//!   - `volte_sms_encode_failed`
//!
//! Confidence: A for literals and field names; B for bit-level layout (from
//! 3GPP TS 23.040 / TS 24.011, consistent with the recovered error set).
//! ============================================================================
//!
//! # Layering
//!
//! ```text
//!   SIP MESSAGE body = RPDU  (TS 24.011, relay protocol)
//!                       └── TPDU (TS 23.040, transfer protocol)
//!                             └── user data, optional UDH for concatenation
//! ```
//! MO direction sends `RP-DATA` wrapping `SMS-SUBMIT`; the network answers
//! `RP-ACK`. MT direction receives `RP-DATA` wrapping `SMS-DELIVER`, and we must
//! answer with `RP-ACK` or the network retransmits.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Database source marker for messages that arrived over IMS.
pub const SMS_SOURCE_IMS: &str = "volte_ims";

/// Trace-file prefixes used when diagnostics capture is on.
pub const TRACE_PREFIX: &str = "volte-sms-";
pub const TRACE_FILE_PREFIX: &str = "volte-sms-trace-";
/// Log tag for outbound messages.
pub const MO_TAG: &str = "volte-mo:";

/// How long to wait for RP-ACK before declaring the MT delivery unconfirmed.
pub const RP_ACK_TIMEOUT: Duration = Duration::from_secs(15);

/// Multipart reassembly window. Segments older than this are dropped.
pub const MULTIPART_TTL: Duration = Duration::from_secs(600);

pub mod err {
    pub const ENCODE_FAILED: &str = "volte_sms_encode_failed";
    pub const RP_ACK_SEND_FAILED: &str = "rp_ack_send_failed";
    pub const RP_ACK_TIMEOUT: &str = "rp_ack_timeout";
    pub const RP_ACK_UNCONFIRMED: &str = "rp_ack_unconfirmed";
    pub const NO_RP_ACK_TIMEOUT: &str = "no_rp_ack_timeout";
    pub const CACHE_LOCK_POISONED: &str = "Native VoLTE MT multipart cache lock poisoned";
}

// ---------------------------------------------------------------------------
// RP layer (TS 24.011)
// ---------------------------------------------------------------------------

/// RP message type, low 3 bits of the first octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpType {
    /// MS -> network
    DataMs = 0x00,
    /// Network -> MS
    DataNetwork = 0x01,
    AckMs = 0x02,
    AckNetwork = 0x03,
    ErrorMs = 0x04,
    ErrorNetwork = 0x05,
    SmmaMs = 0x06,
}

impl RpType {
    pub fn from_octet(o: u8) -> Option<Self> {
        Some(match o & 0x07 {
            0x00 => RpType::DataMs,
            0x01 => RpType::DataNetwork,
            0x02 => RpType::AckMs,
            0x03 => RpType::AckNetwork,
            0x04 => RpType::ErrorMs,
            0x05 => RpType::ErrorNetwork,
            0x06 => RpType::SmmaMs,
            _ => return None,
        })
    }
}

/// Wrap a TPDU in RP-DATA for the MO direction.
///
/// Layout: `MTI | ref | orig_addr_len(0) | dest_addr(SMSC) | user_data_len | TPDU`
/// The originating address is empty on the MS side; the destination address is
/// the service centre.
pub fn encode_rp_data_mo(reference: u8, smsc: &str, tpdu: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(tpdu.len() + 16);
    out.push(RpType::DataMs as u8);
    out.push(reference);
    // RP-Originator-Address: length 0
    out.push(0x00);
    // RP-Destination-Address: the SMSC
    let addr = encode_address(smsc)?;
    out.push(addr.len() as u8);
    out.extend_from_slice(&addr);
    // RP-User-Data
    if tpdu.len() > 255 {
        return Err(err::ENCODE_FAILED.to_string());
    }
    out.push(tpdu.len() as u8);
    out.extend_from_slice(tpdu);
    Ok(out)
}

/// Build RP-ACK for a received RP-DATA, echoing its reference.
pub fn encode_rp_ack(reference: u8) -> Vec<u8> {
    vec![RpType::AckMs as u8, reference]
}

/// Parsed RP-DATA from the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpData {
    pub reference: u8,
    /// TPDU payload.
    pub tpdu: Vec<u8>,
}

/// Decode an inbound RPDU, returning the TPDU and the reference we must ack.
pub fn decode_rp_data(rpdu: &[u8]) -> Result<RpData, String> {
    if rpdu.len() < 3 {
        return Err(err::ENCODE_FAILED.to_string());
    }
    let ty = RpType::from_octet(rpdu[0]).ok_or_else(|| err::ENCODE_FAILED.to_string())?;
    if ty != RpType::DataNetwork {
        return Err(err::ENCODE_FAILED.to_string());
    }
    let reference = rpdu[1];
    let mut i = 2usize;

    // RP-Originating-Address (SMSC).
    let oa_len = *rpdu.get(i).ok_or_else(|| err::ENCODE_FAILED.to_string())? as usize;
    i += 1 + oa_len;
    // RP-Destination-Address (empty toward MS).
    let da_len = *rpdu.get(i).ok_or_else(|| err::ENCODE_FAILED.to_string())? as usize;
    i += 1 + da_len;
    // RP-User-Data.
    let ud_len = *rpdu.get(i).ok_or_else(|| err::ENCODE_FAILED.to_string())? as usize;
    i += 1;
    if i + ud_len > rpdu.len() {
        return Err(err::ENCODE_FAILED.to_string());
    }

    Ok(RpData {
        reference,
        tpdu: rpdu[i..i + ud_len].to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Address encoding (TS 23.040 §9.1.2.5)
// ---------------------------------------------------------------------------

/// Encode a phone number as TP-Address: `len | TOA | semi-octet digits`.
///
/// `len` counts digits, not bytes — a detail that silently corrupts the PDU if
/// you write the byte count instead.
pub fn encode_address(number: &str) -> Result<Vec<u8>, String> {
    let intl = number.trim().starts_with('+');
    let digits: Vec<u8> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c as u8 - b'0')
        .collect();
    if digits.is_empty() {
        return Err(err::ENCODE_FAILED.to_string());
    }
    // TOA: international = 0x91, national = 0x81
    let toa = if intl { 0x91u8 } else { 0x81u8 };
    let mut out = vec![digits.len() as u8, toa];
    for pair in digits.chunks(2) {
        let lo = pair[0];
        let hi = *pair.get(1).unwrap_or(&0x0F);
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Decode a TP-Address back to a string.
pub fn decode_address(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() < 2 {
        return Err(err::ENCODE_FAILED.to_string());
    }
    let ndigits = bytes[0] as usize;
    let toa = bytes[1];
    let mut s = String::new();
    if toa & 0x70 == 0x10 {
        s.push('+');
    }
    for b in &bytes[2..] {
        let lo = b & 0x0F;
        let hi = b >> 4;
        if s.chars().filter(char::is_ascii_digit).count() < ndigits {
            s.push((b'0' + lo) as char);
        }
        if hi != 0x0F && s.chars().filter(char::is_ascii_digit).count() < ndigits {
            s.push((b'0' + hi) as char);
        }
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// TPDU: SMS-SUBMIT (MO) and SMS-DELIVER (MT)
// ---------------------------------------------------------------------------

/// Data coding scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dcs {
    /// GSM 7-bit default alphabet, packed.
    Gsm7 = 0x00,
    /// UCS-2 big endian.
    Ucs2 = 0x08,
}

/// Concatenation info from the user-data header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Concat {
    /// Shared reference identifying the group.
    pub reference: u16,
    pub total: u8,
    pub sequence: u8,
}

/// Build SMS-SUBMIT.
///
/// TP-MTI = 01 (SUBMIT). TP-UDHI is set when `concat` is present. Status reports
/// are not requested — the runtime tracks delivery via RP-ACK instead.
pub fn encode_sms_submit(
    reference: u8,
    dest: &str,
    text: &str,
    dcs: Dcs,
    concat: Option<Concat>,
) -> Result<Vec<u8>, String> {
    let mut first = 0x01u8; // MTI = SUBMIT
    if concat.is_some() {
        first |= 0x40; // TP-UDHI
    }

    let mut out = vec![first, reference];
    out.extend_from_slice(&encode_address(dest)?);
    out.push(0x00); // TP-PID
    out.push(dcs as u8);
    out.push(0xAA); // TP-VP relative, ~4 days

    let (ud, udl) = encode_user_data(text, dcs, concat)?;
    out.push(udl);
    out.extend_from_slice(&ud);
    Ok(out)
}

/// Encode the user data field, prepending a UDH when concatenating.
///
/// Returns `(bytes, udl)`. For GSM-7 the UDL is in **septets**, and when a UDH
/// is present the septet count must include the UDH's padding — getting this
/// wrong shifts the whole message by a few bits and produces mojibake.
fn encode_user_data(
    text: &str,
    dcs: Dcs,
    concat: Option<Concat>,
) -> Result<(Vec<u8>, u8), String> {
    let udh: Vec<u8> = match concat {
        None => Vec::new(),
        Some(c) => {
            // IEI 0x08 = 16-bit reference concatenation.
            // UDHL counts everything after itself: IEI + IEDL + 4 value bytes = 6.
            // (The 8-bit-reference variant, IEI 0x00, is the one that uses 5.)
            let mut h = vec![0x06u8, 0x08, 0x04];
            h.extend_from_slice(&c.reference.to_be_bytes());
            h.push(c.total);
            h.push(c.sequence);
            h
        }
    };

    match dcs {
        Dcs::Ucs2 => {
            let mut body = Vec::new();
            for u in text.encode_utf16() {
                body.extend_from_slice(&u.to_be_bytes());
            }
            let total = udh.len() + body.len();
            if total > 255 {
                return Err(err::ENCODE_FAILED.to_string());
            }
            let mut out = udh;
            out.extend_from_slice(&body);
            Ok((out, total as u8))
        }
        Dcs::Gsm7 => {
            let septets = gsm7_encode(text).ok_or_else(|| err::ENCODE_FAILED.to_string())?;
            // UDH occupies whole octets; pad bits so the text starts on a septet
            // boundary.
            let udh_septets = if udh.is_empty() {
                0
            } else {
                (udh.len() * 8 + 6) / 7
            };
            let packed = gsm7_pack(&septets, udh_septets * 7 - udh.len() * 8);
            let total_septets = udh_septets + septets.len();
            if total_septets > 255 {
                return Err(err::ENCODE_FAILED.to_string());
            }
            let mut out = udh;
            out.extend_from_slice(&packed);
            Ok((out, total_septets as u8))
        }
    }
}

/// A decoded inbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsDeliver {
    pub sender: String,
    pub text: String,
    /// Service-centre timestamp, raw semi-octets (7 bytes).
    pub scts: [u8; 7],
    pub concat: Option<Concat>,
}

/// Decode SMS-DELIVER.
pub fn decode_sms_deliver(tpdu: &[u8]) -> Result<SmsDeliver, String> {
    if tpdu.len() < 3 {
        return Err(err::ENCODE_FAILED.to_string());
    }
    let first = tpdu[0];
    if first & 0x03 != 0x00 {
        return Err(err::ENCODE_FAILED.to_string()); // not DELIVER
    }
    let udhi = first & 0x40 != 0;

    let mut i = 1usize;
    // TP-OA
    let oa_digits = tpdu[i] as usize;
    let oa_bytes = 2 + (oa_digits + 1) / 2;
    if i + oa_bytes > tpdu.len() {
        return Err(err::ENCODE_FAILED.to_string());
    }
    let sender = decode_address(&tpdu[i..i + oa_bytes])?;
    i += oa_bytes;

    // TP-PID, TP-DCS
    if i + 2 > tpdu.len() {
        return Err(err::ENCODE_FAILED.to_string());
    }
    let dcs_raw = tpdu[i + 1];
    i += 2;

    // TP-SCTS
    if i + 7 > tpdu.len() {
        return Err(err::ENCODE_FAILED.to_string());
    }
    let mut scts = [0u8; 7];
    scts.copy_from_slice(&tpdu[i..i + 7]);
    i += 7;

    // TP-UDL + TP-UD
    if i >= tpdu.len() {
        return Err(err::ENCODE_FAILED.to_string());
    }
    let udl = tpdu[i] as usize;
    i += 1;
    let ud = &tpdu[i..];

    let is_ucs2 = dcs_raw & 0x0C == 0x08;
    let (concat, text) = decode_user_data(ud, udl, udhi, is_ucs2)?;

    Ok(SmsDeliver {
        sender,
        text,
        scts,
        concat,
    })
}

fn decode_user_data(
    ud: &[u8],
    udl: usize,
    udhi: bool,
    is_ucs2: bool,
) -> Result<(Option<Concat>, String), String> {
    let mut concat = None;
    let mut offset = 0usize;

    if udhi {
        if ud.is_empty() {
            return Err(err::ENCODE_FAILED.to_string());
        }
        let udhl = ud[0] as usize;
        if 1 + udhl > ud.len() {
            return Err(err::ENCODE_FAILED.to_string());
        }
        let mut p = 1usize;
        while p + 1 < 1 + udhl {
            let iei = ud[p];
            let ielen = ud[p + 1] as usize;
            let val = &ud[p + 2..(p + 2 + ielen).min(ud.len())];
            match (iei, val.len()) {
                // 8-bit reference
                (0x00, 3) => {
                    concat = Some(Concat {
                        reference: val[0] as u16,
                        total: val[1],
                        sequence: val[2],
                    })
                }
                // 16-bit reference
                (0x08, 4) => {
                    concat = Some(Concat {
                        reference: u16::from_be_bytes([val[0], val[1]]),
                        total: val[2],
                        sequence: val[3],
                    })
                }
                _ => {}
            }
            p += 2 + ielen;
        }
        offset = 1 + udhl;
    }

    let text = if is_ucs2 {
        let body = &ud[offset.min(ud.len())..];
        let mut units = Vec::new();
        for c in body.chunks(2) {
            if c.len() == 2 {
                units.push(u16::from_be_bytes([c[0], c[1]]));
            }
        }
        String::from_utf16_lossy(&units)
    } else {
        // GSM-7: skip the UDH's septet space, then unpack.
        let udh_octets = offset;
        let udh_septets = if udh_octets == 0 {
            0
        } else {
            (udh_octets * 8 + 6) / 7
        };
        let pad = udh_septets * 7 - udh_octets * 8;
        let septets = gsm7_unpack(&ud[udh_octets.min(ud.len())..], udl.saturating_sub(udh_septets), pad);
        gsm7_decode(&septets)
    };

    Ok((concat, text))
}

// ---------------------------------------------------------------------------
// GSM 7-bit alphabet
// ---------------------------------------------------------------------------

/// Basic GSM 03.38 alphabet. Positions matter; `\u{1b}` marks the escape to the
/// extension table.
///
/// **Not a binary literal.** The table does not appear as a contiguous string in
/// either binary — Rust encodes such lookups as jump tables or `match` arms, and
/// the recovered code needs an explicit table to be readable. Contents are from
/// 3GPP TS 23.038 §6.2.1 (confidence: spec, not binary).
const GSM7_BASIC: &str = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\u{1b}ÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà";

fn gsm7_encode(text: &str) -> Option<Vec<u8>> {
    let table: Vec<char> = GSM7_BASIC.chars().collect();
    let mut out = Vec::new();
    for c in text.chars() {
        match table.iter().position(|t| *t == c) {
            Some(i) => out.push(i as u8),
            // Anything outside the basic table forces UCS-2 at a higher level.
            None => return None,
        }
    }
    Some(out)
}

fn gsm7_decode(septets: &[u8]) -> String {
    let table: Vec<char> = GSM7_BASIC.chars().collect();
    septets
        .iter()
        .map(|s| *table.get(*s as usize).unwrap_or(&'?'))
        .collect()
}

/// Pack septets into octets, with `pad` leading bits of padding.
fn gsm7_pack(septets: &[u8], pad: usize) -> Vec<u8> {
    let mut bits: Vec<u8> = Vec::with_capacity(septets.len() * 7 + pad);
    for _ in 0..pad {
        bits.push(0);
    }
    for s in septets {
        for b in 0..7 {
            bits.push((s >> b) & 1);
        }
    }
    let mut out = Vec::with_capacity((bits.len() + 7) / 8);
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, bit) in chunk.iter().enumerate() {
            byte |= bit << i;
        }
        out.push(byte);
    }
    out
}

/// Unpack `count` septets out of octets, skipping `pad` leading bits.
fn gsm7_unpack(octets: &[u8], count: usize, pad: usize) -> Vec<u8> {
    let mut bits: Vec<u8> = Vec::with_capacity(octets.len() * 8);
    for o in octets {
        for b in 0..8 {
            bits.push((o >> b) & 1);
        }
    }
    let mut out = Vec::with_capacity(count);
    let mut i = pad;
    while out.len() < count && i + 7 <= bits.len() {
        let mut s = 0u8;
        for b in 0..7 {
            s |= bits[i + b] << b;
        }
        out.push(s);
        i += 7;
    }
    out
}

// ---------------------------------------------------------------------------
// Multipart reassembly
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct PartialMessage {
    total: u8,
    parts: HashMap<u8, String>,
    sender: String,
    first_seen: Instant,
}

/// Reassembly cache keyed by (sender, concat reference).
#[derive(Debug, Default)]
pub struct MultipartCache {
    inner: Mutex<HashMap<(String, u16), PartialMessage>>,
}

/// What happened when a segment was offered to the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipartOutcome {
    /// Stored, still waiting for more
    /// (`Native VoLTE MT multipart segment buffered`).
    Buffered { have: usize, total: u8 },
    /// All segments present (`Native VoLTE MT multipart SMS assembled`).
    Complete { sender: String, text: String },
}

impl MultipartCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Offer one segment. Single-part messages should bypass this entirely.
    pub fn offer(&self, msg: &SmsDeliver) -> Result<MultipartOutcome, String> {
        let c = match msg.concat {
            Some(c) => c,
            None => {
                return Ok(MultipartOutcome::Complete {
                    sender: msg.sender.clone(),
                    text: msg.text.clone(),
                })
            }
        };

        let mut map = self
            .inner
            .lock()
            .map_err(|_| err::CACHE_LOCK_POISONED.to_string())?;

        // Drop anything stale before inserting, so a lost segment can't pin
        // memory forever.
        map.retain(|_, v| v.first_seen.elapsed() < MULTIPART_TTL);

        let key = (msg.sender.clone(), c.reference);
        let entry = map.entry(key.clone()).or_insert_with(|| PartialMessage {
            total: c.total,
            parts: HashMap::new(),
            sender: msg.sender.clone(),
            first_seen: Instant::now(),
        });
        entry.parts.insert(c.sequence, msg.text.clone());

        if entry.parts.len() as u8 >= entry.total {
            let mut seqs: Vec<u8> = entry.parts.keys().copied().collect();
            seqs.sort_unstable();
            let text: String = seqs
                .iter()
                .filter_map(|s| entry.parts.get(s))
                .cloned()
                .collect();
            let sender = entry.sender.clone();
            map.remove(&key);
            return Ok(MultipartOutcome::Complete { sender, text });
        }

        Ok(MultipartOutcome::Buffered {
            have: entry.parts.len(),
            total: entry.total,
        })
    }
}

/// Split text into concatenated segments.
///
/// Segment capacity shrinks when a UDH is present: 153 septets (GSM-7) or 67
/// UCS-2 characters instead of 160 / 70.
pub fn segment_text(text: &str, dcs: Dcs) -> Vec<String> {
    let (single, multi) = match dcs {
        Dcs::Gsm7 => (160usize, 153usize),
        Dcs::Ucs2 => (70usize, 67usize),
    };
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= single {
        return vec![text.to_string()];
    }
    chars
        .chunks(multi)
        .map(|c| c.iter().collect::<String>())
        .collect()
}

/// Pick the coding scheme: GSM-7 when every character is representable.
pub fn choose_dcs(text: &str) -> Dcs {
    if gsm7_encode(text).is_some() {
        Dcs::Gsm7
    } else {
        Dcs::Ucs2
    }
}

/// Duplicate detection key for MT messages, so retransmissions after a lost
/// RP-ACK don't create a second row
/// (`Skipped duplicate native VoLTE MT SMS already in database`).
pub fn duplicate_key(sender: &str, scts: &[u8; 7], text: &str) -> String {
    let ts: String = scts.iter().map(|b| format!("{b:02x}")).collect();
    format!("{sender}|{ts}|{}", text.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_roundtrip_international() {
        let enc = encode_address("+8613074325965").unwrap();
        // 13 digits; the '+' is conveyed by the TOA nibble, not counted.
        assert_eq!(enc[0], 13);
        assert_eq!(enc[1], 0x91); // international
        assert_eq!(decode_address(&enc).unwrap(), "+8613074325965");
    }

    #[test]
    fn address_roundtrip_national_odd_length() {
        let enc = encode_address("10086").unwrap();
        assert_eq!(enc[0], 5);
        assert_eq!(enc[1], 0x81);
        assert_eq!(decode_address(&enc).unwrap(), "10086");
    }

    #[test]
    fn gsm7_pack_unpack_roundtrip() {
        let text = "Hello SimAdmin";
        let septets = gsm7_encode(text).unwrap();
        let packed = gsm7_pack(&septets, 0);
        let back = gsm7_unpack(&packed, septets.len(), 0);
        assert_eq!(gsm7_decode(&back), text);
    }

    #[test]
    fn chinese_text_selects_ucs2() {
        assert_eq!(choose_dcs("hello"), Dcs::Gsm7);
        assert_eq!(choose_dcs("测试短信"), Dcs::Ucs2);
    }

    #[test]
    fn submit_sets_udhi_only_when_concatenating() {
        let plain = encode_sms_submit(1, "10086", "hi", Dcs::Gsm7, None).unwrap();
        assert_eq!(plain[0] & 0x40, 0, "UDHI must be clear");

        let part = encode_sms_submit(
            1,
            "10086",
            "hi",
            Dcs::Gsm7,
            Some(Concat {
                reference: 0x1234,
                total: 2,
                sequence: 1,
            }),
        )
        .unwrap();
        assert_ne!(part[0] & 0x40, 0, "UDHI must be set");
    }

    #[test]
    fn rp_data_wraps_and_unwraps() {
        let tpdu = vec![0x01, 0x02, 0x03];
        let rpdu = encode_rp_data_mo(0x42, "+8613800100500", &tpdu).unwrap();
        assert_eq!(rpdu[0], RpType::DataMs as u8);
        assert_eq!(rpdu[1], 0x42);
        assert_eq!(rpdu[2], 0x00, "MO originator address is empty");
    }

    #[test]
    fn decodes_network_rp_data() {
        // RP-DATA (network) | ref | OA(smsc) | DA(empty) | UDL | TPDU
        let smsc = encode_address("+8613800100500").unwrap();
        let tpdu = vec![0xAA, 0xBB];
        let mut rpdu = vec![RpType::DataNetwork as u8, 0x07];
        rpdu.push(smsc.len() as u8);
        rpdu.extend_from_slice(&smsc);
        rpdu.push(0x00);
        rpdu.push(tpdu.len() as u8);
        rpdu.extend_from_slice(&tpdu);

        let d = decode_rp_data(&rpdu).unwrap();
        assert_eq!(d.reference, 0x07);
        assert_eq!(d.tpdu, tpdu);
        assert_eq!(encode_rp_ack(d.reference), vec![RpType::AckMs as u8, 0x07]);
    }

    #[test]
    fn rejects_wrong_rp_direction() {
        assert!(decode_rp_data(&[RpType::DataMs as u8, 1, 0, 0, 0]).is_err());
    }

    #[test]
    fn segments_respect_udh_overhead() {
        let long = "a".repeat(200);
        let segs = segment_text(&long, Dcs::Gsm7);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].chars().count(), 153);

        let exact = "a".repeat(160);
        assert_eq!(segment_text(&exact, Dcs::Gsm7).len(), 1);

        let ucs2 = "测".repeat(100);
        let segs = segment_text(&ucs2, Dcs::Ucs2);
        assert_eq!(segs[0].chars().count(), 67);
    }

    #[test]
    fn multipart_reassembly_in_order() {
        let cache = MultipartCache::new();
        let mk = |seq: u8, text: &str| SmsDeliver {
            sender: "+8613800100500".into(),
            text: text.into(),
            scts: [0; 7],
            concat: Some(Concat {
                reference: 0xABCD,
                total: 3,
                sequence: seq,
            }),
        };

        assert!(matches!(
            cache.offer(&mk(1, "one ")).unwrap(),
            MultipartOutcome::Buffered { have: 1, total: 3 }
        ));
        assert!(matches!(
            cache.offer(&mk(2, "two ")).unwrap(),
            MultipartOutcome::Buffered { have: 2, total: 3 }
        ));
        match cache.offer(&mk(3, "three")).unwrap() {
            MultipartOutcome::Complete { text, .. } => assert_eq!(text, "one two three"),
            _ => panic!("expected complete"),
        }
    }

    #[test]
    fn out_of_order_segments_still_assemble_sorted() {
        let cache = MultipartCache::new();
        let mk = |seq: u8, text: &str| SmsDeliver {
            sender: "s".into(),
            text: text.into(),
            scts: [0; 7],
            concat: Some(Concat {
                reference: 1,
                total: 2,
                sequence: seq,
            }),
        };
        let _ = cache.offer(&mk(2, "second")).unwrap();
        match cache.offer(&mk(1, "first ")).unwrap() {
            MultipartOutcome::Complete { text, .. } => assert_eq!(text, "first second"),
            _ => panic!("expected complete"),
        }
    }

    #[test]
    fn single_part_bypasses_cache() {
        let cache = MultipartCache::new();
        let msg = SmsDeliver {
            sender: "s".into(),
            text: "solo".into(),
            scts: [0; 7],
            concat: None,
        };
        match cache.offer(&msg).unwrap() {
            MultipartOutcome::Complete { text, .. } => assert_eq!(text, "solo"),
            _ => panic!("expected complete"),
        }
    }

    #[test]
    fn duplicate_key_is_stable_and_discriminating() {
        let a = duplicate_key("s", &[1, 2, 3, 4, 5, 6, 7], "hello");
        let b = duplicate_key("s", &[1, 2, 3, 4, 5, 6, 7], "hello");
        let c = duplicate_key("s", &[1, 2, 3, 4, 5, 6, 8], "hello");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn deliver_roundtrip_ucs2_with_concat() {
        // Build a DELIVER by hand: MTI=0, UDHI set, UCS-2.
        let oa = encode_address("+8613800100500").unwrap();
        let mut tpdu = vec![0x40];
        tpdu.extend_from_slice(&oa);
        tpdu.push(0x00); // PID
        tpdu.push(Dcs::Ucs2 as u8);
        tpdu.extend_from_slice(&[0x52, 0x80, 0x11, 0x22, 0x33, 0x44, 0x00]); // SCTS

        let udh = vec![0x06u8, 0x08, 0x04, 0x12, 0x34, 0x02, 0x01];
        let body: Vec<u8> = "测试".encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
        tpdu.push((udh.len() + body.len()) as u8);
        tpdu.extend_from_slice(&udh);
        tpdu.extend_from_slice(&body);

        let d = decode_sms_deliver(&tpdu).unwrap();
        assert_eq!(d.sender, "+8613800100500");
        assert_eq!(d.text, "测试");
        assert_eq!(
            d.concat,
            Some(Concat {
                reference: 0x1234,
                total: 2,
                sequence: 1
            })
        );
    }
}
