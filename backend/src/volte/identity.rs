//! IMS identity: IMSI, EF_AD/MNC length, USIM AID, SMSC, SIP URIs.
//!
//! Recovered from `src/volte.rs` lines ~1251-1255, 3486-3493, 5151, 5745-5764.
//!
//! Evidence (confidence A for literals):
//!   - `AT+CIMI`, `AT+CRSM=176,28589,0,0,4`
//!   - `--uim-get-card-status`, `--uim-read-transparent=0x3F00,0x7FFF,0x6FAD`
//!   - `application type:`, `application id:`, `'usim`
//!   - `Native VoLTE resolved USIM AID from card status`
//!   - `Native VoLTE USIM AID discovery failed, using built-in fallback`
//!   - `Native VoLTE ModemManager AT+CIMI failed, using SIM IMSI fallback`
//!   - `Native VoLTE runtime SMSC lookup failed, using empty SMSC`
//!   - `ims_p_associated_uri`, `Cached own phone number from IMS P-Associated-URI`
//!   - `Skipped IMS phone number cache because the active SIM changed`
//!   - MNC-length provenance tokens: `modemmanager_home_operator`, `sim_ef_ad`,
//!     `three_digit_fallback`, `china_compatibility_fallback`

use super::{err, ims_apn, ims_domain, parse_hex};

/// Where the MNC length came from.
///
/// **Provenance warning:** these four token strings (`modemmanager_home_operator`,
/// `sim_ef_ad`, `three_digit_fallback`, `china_compatibility_fallback`) are
/// present in **1.1.7-beta8** but do **not** appear anywhere in the beta9
/// binary. beta9 keeps `imsi_prefix` and the `ims.mnc`/`.mcc` fragments but
/// emits no provenance token, so it likely derives the MNC length without
/// recording which rule fired.
///
/// The enum is retained because the *logic* is still needed to build the domain,
/// but treat the token strings as beta8 evidence, not beta9 (confidence C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MncLengthSource {
    /// ModemManager already knew the home operator code.
    ModemManagerHomeOperator,
    /// Read from EF_AD (administrative data) on the card.
    SimEfAd,
    /// Nothing readable; assumed 3 digits.
    ThreeDigitFallback,
    /// Chinese MCCs are 2-digit MNC in practice; special-cased.
    ChinaCompatibilityFallback,
}

impl MncLengthSource {
    /// beta8 token spellings. Not emitted by beta9.
    pub fn as_str(self) -> &'static str {
        match self {
            MncLengthSource::ModemManagerHomeOperator => "modemmanager_home_operator",
            MncLengthSource::SimEfAd => "sim_ef_ad",
            MncLengthSource::ThreeDigitFallback => "three_digit_fallback",
            MncLengthSource::ChinaCompatibilityFallback => "china_compatibility_fallback",
        }
    }
}

/// Everything the SIP layer needs to identify this subscriber.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImsIdentity {
    pub imsi: String,
    pub mcc: String,
    pub mnc: String,
    pub mnc_len_source: MncLengthSource,
    /// `ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org`
    pub home_domain: String,
    /// `ims.epc.mnc<MNC>.mcc<MCC>.gprs`
    pub apn: String,
    /// IMPI: `<IMSI>@<home_domain>`
    pub private_identity: String,
    /// IMPU: `sip:<IMSI>@<home_domain>`
    pub public_identity: String,
    /// USIM application id, hex. Needed for APDU channel selection.
    pub usim_aid: Vec<u8>,
    /// Service centre address, may be empty — SMSC lookup failure is
    /// non-fatal (`Native VoLTE runtime SMSC lookup failed, using empty SMSC`).
    pub smsc: String,
    /// MSISDN learned from the registrar's `P-Associated-URI`, if any.
    pub own_number: Option<String>,
}

/// Built-in AID used when card-status discovery fails. 3GPP USIM ADF AID
/// prefix `A0000000871002` (`Native VoLTE USIM AID discovery failed, using
/// built-in fallback`).
pub const FALLBACK_USIM_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

/// AT command to read IMSI.
pub const AT_CIMI: &str = "AT+CIMI";
/// EF_AD via restricted SIM access: 176 = READ BINARY, 28589 = 0x6FAD, 4 bytes.
pub const AT_CRSM_EF_AD: &str = "AT+CRSM=176,28589,0,0,4";
/// QMI equivalents.
pub const QMI_CARD_STATUS: &str = "--uim-get-card-status";
pub const QMI_READ_EF_AD: &str = "--uim-read-transparent=0x3F00,0x7FFF,0x6FAD";

/// Card-status output labels.
const L_APPLICATION_TYPE: &str = "application type:";
const L_APPLICATION_ID: &str = "application id:";
/// The type value we require; quoted in the binary as `'usim`.
const V_USIM: &str = "usim";

/// Split an IMSI into MCC (always 3 digits) and MNC (2 or 3, per EF_AD).
///
/// Returns `volte_imsi_missing` when the IMSI is too short to split.
pub fn split_imsi(imsi: &str, mnc_len: usize) -> Result<(String, String), String> {
    let digits: String = imsi.chars().filter(char::is_ascii_digit).collect();
    if digits.len() < 3 + mnc_len {
        return Err(err::IMSI_MISSING.to_string());
    }
    let mcc = digits[0..3].to_string();
    let mnc = digits[3..3 + mnc_len].to_string();
    Ok((mcc, mnc))
}

/// Decide the MNC length.
///
/// EF_AD byte 4 low nibble carries the MNC length when present. Chinese
/// networks (MCC 460) report 2 even when the domain needs 3 digits, hence the
/// dedicated compatibility branch — the domain builder pads separately.
pub fn mnc_length(ef_ad: Option<&[u8]>, mcc: &str, mm_operator_code: Option<&str>) -> (usize, MncLengthSource) {
    if let Some(code) = mm_operator_code {
        let d: String = code.chars().filter(char::is_ascii_digit).collect();
        if d.len() == 5 {
            return (2, MncLengthSource::ModemManagerHomeOperator);
        }
        if d.len() == 6 {
            return (3, MncLengthSource::ModemManagerHomeOperator);
        }
    }
    if let Some(b) = ef_ad {
        if b.len() >= 4 {
            let n = (b[3] & 0x0F) as usize;
            if n == 2 || n == 3 {
                return (n, MncLengthSource::SimEfAd);
            }
        }
    }
    if mcc == "460" {
        return (2, MncLengthSource::ChinaCompatibilityFallback);
    }
    (3, MncLengthSource::ThreeDigitFallback)
}

/// Assemble the full identity from raw inputs.
pub fn build(
    imsi: &str,
    ef_ad: Option<&[u8]>,
    mm_operator_code: Option<&str>,
    usim_aid: Option<Vec<u8>>,
    smsc: Option<String>,
) -> Result<ImsIdentity, String> {
    let digits: String = imsi.chars().filter(char::is_ascii_digit).collect();
    if digits.len() < 6 {
        return Err(err::IMSI_MISSING.to_string());
    }
    let mcc = digits[0..3].to_string();
    let (mnc_len, src) = mnc_length(ef_ad, &mcc, mm_operator_code);
    let (mcc, mnc) = split_imsi(&digits, mnc_len)?;

    let home_domain = ims_domain(&mcc, &mnc);
    let apn = ims_apn(&mcc, &mnc);
    let private_identity = format!("{digits}@{home_domain}");
    let public_identity = format!("sip:{private_identity}");

    Ok(ImsIdentity {
        imsi: digits,
        mcc,
        mnc,
        mnc_len_source: src,
        home_domain,
        apn,
        private_identity,
        public_identity,
        usim_aid: usim_aid.unwrap_or_else(|| FALLBACK_USIM_AID.to_vec()),
        smsc: smsc.unwrap_or_default(),
        own_number: None,
    })
}

/// Pull the USIM AID out of `qmicli --uim-get-card-status` output.
///
/// The card lists several applications; we want the one whose
/// `application type:` is `usim`. A non-USIM-only card yields
/// `volte_usim_aid_not_usim`; no AID at all yields `volte_usim_aid_missing`.
pub fn parse_usim_aid(card_status: &str) -> Result<Vec<u8>, String> {
    let mut current_is_usim = false;
    let mut saw_any_app = false;

    for line in card_status.lines() {
        let t = line.trim();
        if let Some(v) = t.strip_prefix(L_APPLICATION_TYPE) {
            saw_any_app = true;
            let v = v.trim().trim_matches('\'').to_ascii_lowercase();
            current_is_usim = v.contains(V_USIM);
            continue;
        }
        if current_is_usim {
            if let Some(v) = t.strip_prefix(L_APPLICATION_ID) {
                let hex = v.trim().trim_matches('\'').replace(':', "");
                if let Ok(bytes) = parse_hex(&hex) {
                    if !bytes.is_empty() {
                        return Ok(bytes);
                    }
                }
            }
        }
    }

    if saw_any_app {
        Err(err::USIM_AID_NOT_USIM.to_string())
    } else {
        Err(err::USIM_AID_MISSING.to_string())
    }
}

/// Extract the subscriber number from a `P-Associated-URI` header value.
///
/// The registrar returns one or more URIs; a `tel:` URI (or a `sip:` user that
/// looks like a phone number) is the MSISDN. Cached so the UI can show the own
/// number without an extra SIM read.
pub fn own_number_from_p_associated_uri(header: &str) -> Option<String> {
    // Two passes on purpose. The registrar lists the IMPU first, and an
    // IMSI-derived IMPU is *also* all digits — a single pass that accepts the
    // first digits-only user returns the IMSI instead of the MSISDN. `tel:` is
    // unambiguous, so it wins outright.
    let parts: Vec<&str> = header.split(',').collect();

    for part in &parts {
        let p = normalise_uri(part);
        if let Some(rest) = p.strip_prefix("tel:") {
            let n: String = rest
                .chars()
                .filter(|c| c.is_ascii_digit() || *c == '+')
                .collect();
            if n.chars().filter(|c| c.is_ascii_digit()).count() >= 5 {
                return Some(n);
            }
        }
    }

    for part in &parts {
        let p = normalise_uri(part);
        if let Some(rest) = p.strip_prefix("sip:") {
            let user = rest.split('@').next().unwrap_or("");
            let is_phone_uri = p.contains("user=phone");
            let digits: String = user.chars().filter(|c| c.is_ascii_digit()).collect();
            let all_digits =
                !digits.is_empty() && digits.len() == user.trim_start_matches('+').len();
            if !all_digits {
                continue;
            }
            // A 15-digit IMPU is the IMSI, not a dialable number. Only accept it
            // when the URI explicitly says it is a telephone subscriber.
            if !is_phone_uri && digits.len() >= 14 {
                continue;
            }
            if digits.len() >= 5 {
                let plus = if user.starts_with('+') { "+" } else { "" };
                return Some(format!("{plus}{digits}"));
            }
        }
    }
    None
}

/// Strip angle brackets and trailing header parameters from a URI list entry.
fn normalise_uri(part: &str) -> &str {
    let p = part.trim().trim_start_matches('<');
    match p.find('>') {
        Some(i) => p[..i].trim(),
        None => p.trim(),
    }
}

/// Guard against caching a number against the wrong SIM after a hot-swap.
/// Compares IMSI prefixes (`registered_imsi_prefix` vs `current_imsi_prefix`,
/// volte.rs:5745-5749). Mismatch logs `Skipped IMS phone number cache because
/// the active SIM changed`.
pub fn same_sim(registered_imsi: &str, current_imsi: &str) -> bool {
    let n = 8usize.min(registered_imsi.len()).min(current_imsi.len());
    n > 0 && registered_imsi[..n] == current_imsi[..n]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn china_unicom_identity() {
        let id = build("460010123456789", None, None, None, None).unwrap();
        assert_eq!(id.mcc, "460");
        assert_eq!(id.mnc, "01");
        assert_eq!(id.home_domain, "ims.mnc001.mcc460.3gppnetwork.org");
        assert_eq!(id.apn, "ims.epc.mnc001.mcc460.gprs");
        assert_eq!(
            id.public_identity,
            "sip:460010123456789@ims.mnc001.mcc460.3gppnetwork.org"
        );
        assert_eq!(id.mnc_len_source, MncLengthSource::ChinaCompatibilityFallback);
        assert_eq!(id.usim_aid, FALLBACK_USIM_AID.to_vec());
    }

    #[test]
    fn ef_ad_overrides_heuristics() {
        // EF_AD byte 4 = 0x03 -> 3-digit MNC
        let ef = [0x00u8, 0x00, 0x00, 0x03];
        let (n, src) = mnc_length(Some(&ef), "310", None);
        assert_eq!(n, 3);
        assert_eq!(src, MncLengthSource::SimEfAd);
    }

    #[test]
    fn parses_usim_aid_from_card_status() {
        let out = "\
Card [0]:
  Application [0]:
    application type: 'usim'
    application state: 'ready'
    application id: 'A0:00:00:00:87:10:02:FF:49:FF:05:89:00:00:11:00'
";
        let aid = parse_usim_aid(out).unwrap();
        assert_eq!(&aid[..7], &FALLBACK_USIM_AID[..]);
    }

    #[test]
    fn non_usim_card_is_rejected_distinctly() {
        let out = "    application type: 'sim'\n    application id: 'A000'\n";
        assert_eq!(parse_usim_aid(out).unwrap_err(), err::USIM_AID_NOT_USIM);
        assert_eq!(parse_usim_aid("").unwrap_err(), err::USIM_AID_MISSING);
    }

    #[test]
    fn msisdn_from_tel_uri() {
        let h = "<sip:460010123456789@ims.mnc001.mcc460.3gppnetwork.org>, <tel:+8613074325965>";
        assert_eq!(
            own_number_from_p_associated_uri(h).as_deref(),
            Some("+8613074325965")
        );
    }

    /// Regression: the IMSI-derived IMPU appears first and is all digits, so a
    /// naive single-pass scan returns the IMSI instead of the MSISDN.
    #[test]
    fn impu_is_not_mistaken_for_the_msisdn() {
        let only_impu = "<sip:460010123456789@ims.mnc001.mcc460.3gppnetwork.org>";
        assert_eq!(own_number_from_p_associated_uri(only_impu), None);
    }

    #[test]
    fn sip_phone_uri_is_accepted() {
        let h = "<sip:+8613074325965@ims.mnc001.mcc460.3gppnetwork.org;user=phone>";
        assert_eq!(
            own_number_from_p_associated_uri(h).as_deref(),
            Some("+8613074325965")
        );
    }

    #[test]
    fn sim_swap_detection() {
        assert!(same_sim("460010123456789", "460010123456789"));
        assert!(!same_sim("460010123456789", "460019999999999"));
    }
}
