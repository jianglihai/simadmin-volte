//! VoLTE runtime supervisor: phase/stage machine, health checks, retry policy.
//!
//! Recovered from `src/volte.rs` lines ~1251, 2255-2521, 3105-3193, 4563,
//! 5649-5764.
//!
//! Evidence (confidence A for literals):
//!   - phase tokens: `disabled`, `starting`, `registered`, `degraded`, `stopping`
//!   - stage tokens: `starting`, `identity`, `identity_aka`, `radio`, `pcscf`,
//!     `modem`, `bearer`, `register_ipsec`, `register_udp`, `registered`,
//!     `stopping`
//!   - `VolteRuntimeStatus` field list (0x914e78): `phase`, `stage`,
//!     `registration_mode`, `session_started_at`, `registered_at`, `last_rx_at`,
//!     `last_tx_at`, `last_error`, `last_failure_at`, `next_retry_at`,
//!     `sent_count`, `received_count`, `duplicate_count`, `reconnect_count`,
//!     `data_path_mode`
//!   - `Native VoLTE runtime registered with 3GPP IPsec and listening`
//!   - `Native VoLTE runtime registered with plain UDP SIP and listening`
//!   - `Native VoLTE IPsec registration failed, falling back to plain UDP SIP`
//!   - `Native VoLTE runtime IPsec REGISTER refreshed`
//!   - `Native VoLTE runtime plain UDP REGISTER refreshed`
//!   - `Native VoLTE plain UDP refresh failed; supervisor will restart auto registration`
//!   - `Native VoLTE runtime stopped by config`, `Native VoLTE runtime stop requested`
//!   - `Native VoLTE SMS runtime supervisor enabled`, `... stopped cleanly`,
//!     `... failed`, `... worker join failed`
//!   - `Cleaning up native VoLTE IMS context`
//!   - health codes: `volte_runtime_health_bearer*`, `volte_runtime_health_qmi*`
//!   - `Secondary QMI packet status was inconclusive; retaining live host IMS state`

use std::time::{Duration, Instant};

use super::err;
use super::slot::DataPathMode;

/// Top-level lifecycle phase, as surfaced by `/api/volte/control`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Disabled,
    Starting,
    Registered,
    /// Registration lost; supervisor is retrying with backoff.
    Degraded,
    Stopping,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Disabled => "disabled",
            Phase::Starting => "starting",
            Phase::Registered => "registered",
            Phase::Degraded => "degraded",
            Phase::Stopping => "stopping",
        }
    }
}

/// Fine-grained progress within [`Phase::Starting`]. Order here is the order the
/// supervisor walks through, which is what makes it useful for diagnosis: the
/// stage you are stuck in names the subsystem to look at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Starting,
    /// Reading IMSI / EF_AD / SMSC.
    Identity,
    /// USIM AID resolution + AKA capability probe.
    IdentityAka,
    /// Waiting for radio attach.
    Radio,
    /// Waiting for ModemManager to expose a usable modem.
    Modem,
    /// Creating the IMS PDP context and bearer.
    Bearer,
    /// Discovering P-CSCF and installing routes.
    Pcscf,
    /// SIP REGISTER over 3GPP IPsec.
    RegisterIpsec,
    /// SIP REGISTER over plain UDP (fallback).
    RegisterUdp,
    Registered,
    Stopping,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Starting => "starting",
            Stage::Identity => "identity",
            Stage::IdentityAka => "identity_aka",
            Stage::Radio => "radio",
            Stage::Modem => "modem",
            Stage::Bearer => "bearer",
            Stage::Pcscf => "pcscf",
            Stage::RegisterIpsec => "register_ipsec",
            Stage::RegisterUdp => "register_udp",
            Stage::Registered => "registered",
            Stage::Stopping => "stopping",
        }
    }
}

/// Which transport carried the successful registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationMode {
    /// SIP over ESP, preferred.
    Ipsec,
    /// Plain UDP SIP, used only after IPsec failed.
    PlainUdp,
}

impl RegistrationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            RegistrationMode::Ipsec => "register_ipsec",
            RegistrationMode::PlainUdp => "register_udp",
        }
    }

    /// Log line emitted on success.
    pub fn success_message(self) -> &'static str {
        match self {
            RegistrationMode::Ipsec => "Native VoLTE runtime registered with 3GPP IPsec and listening",
            RegistrationMode::PlainUdp => "Native VoLTE runtime registered with plain UDP SIP and listening",
        }
    }

    /// Log line emitted on periodic refresh.
    pub fn refresh_message(self) -> &'static str {
        match self {
            RegistrationMode::Ipsec => "Native VoLTE runtime IPsec REGISTER refreshed",
            RegistrationMode::PlainUdp => "Native VoLTE runtime plain UDP REGISTER refreshed",
        }
    }
}

/// Runtime status exposed over HTTP. Field names match the serde struct in the
/// binary exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolteRuntimeStatus {
    pub phase: Phase,
    pub stage: Stage,
    pub registration_mode: Option<RegistrationMode>,
    /// Unix seconds; `None` until the session starts.
    pub session_started_at: Option<u64>,
    pub registered_at: Option<u64>,
    pub last_rx_at: Option<u64>,
    pub last_tx_at: Option<u64>,
    pub last_error: Option<String>,
    pub last_failure_at: Option<u64>,
    pub next_retry_at: Option<u64>,
    pub sent_count: u64,
    pub received_count: u64,
    /// MT messages discarded as retransmissions.
    pub duplicate_count: u64,
    pub reconnect_count: u64,
    pub data_path_mode: Option<DataPathMode>,
}

impl Default for VolteRuntimeStatus {
    fn default() -> Self {
        Self {
            phase: Phase::Disabled,
            stage: Stage::Starting,
            registration_mode: None,
            session_started_at: None,
            registered_at: None,
            last_rx_at: None,
            last_tx_at: None,
            last_error: None,
            last_failure_at: None,
            next_retry_at: None,
            sent_count: 0,
            received_count: 0,
            duplicate_count: 0,
            reconnect_count: 0,
            data_path_mode: None,
        }
    }
}

/// Commands the HTTP layer sends to the worker. Channel failures map onto the
/// `volte_runtime_*` error family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeCommand {
    /// Send an SMS through the IMS runtime.
    SendSms { to: String, body: String },
    /// Force a re-REGISTER.
    Refresh,
    /// Graceful shutdown (`Native VoLTE runtime stop requested`).
    Stop,
    /// Report current status.
    Status,
}

/// Registration refresh cadence. REGISTER advertises `Expires: 3600`, and the
/// runtime refreshes at half that so a lost refresh still leaves a full margin.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(1800);

/// Retry backoff after a failure. Doubles up to a cap so a hard outage doesn't
/// hammer the network.
pub const RETRY_BASE: Duration = Duration::from_secs(15);
pub const RETRY_MAX: Duration = Duration::from_secs(300);

/// Reply timeout for the command channel.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Compute the next retry delay for a given consecutive-failure count.
pub fn retry_delay(consecutive_failures: u32) -> Duration {
    let shift = consecutive_failures.saturating_sub(1).min(16);
    let d = RETRY_BASE.saturating_mul(1u32 << shift);
    if d > RETRY_MAX {
        RETRY_MAX
    } else {
        d
    }
}

/// Outcome of the periodic health probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthVerdict {
    /// Everything still up.
    Healthy,
    /// Probe was inconclusive — keep the current state rather than tearing down.
    ///
    /// This exists because a transient QMI query failure used to cause a
    /// needless full re-registration (`Secondary QMI packet status was
    /// inconclusive; retaining live host IMS state`).
    Inconclusive(&'static str),
    /// Definitely broken; re-register.
    Unhealthy(String),
}

/// Health inputs for the ModemManager-backed bearer.
#[derive(Debug, Clone)]
pub struct MmHealthInputs {
    /// `None` when the bearer query itself failed.
    pub connected: Option<bool>,
    /// Bearer object path now, versus the one we registered with.
    pub current_path: Option<String>,
    pub expected_path: String,
}

/// Health inputs for the DATA6 secondary QMI bearer.
#[derive(Debug, Clone)]
pub struct QmiHealthInputs {
    /// Device node still present.
    pub device_present: bool,
    /// `None` when `--wds-get-packet-service-status` failed or was ambiguous.
    pub connected: Option<bool>,
    /// Interface still carries the IMS address.
    pub address_present: bool,
}

/// Evaluate the ModemManager bearer.
pub fn check_mm_health(i: &MmHealthInputs) -> HealthVerdict {
    match i.connected {
        None => HealthVerdict::Inconclusive(err::RUNTIME_HEALTH_BEARER_QUERY_FAILED),
        Some(false) => {
            HealthVerdict::Unhealthy(err::RUNTIME_HEALTH_BEARER_DISCONNECTED.to_string())
        }
        Some(true) => {
            // A different bearer path means ModemManager recreated it under us;
            // our routes and SAs point at the old interface state.
            match &i.current_path {
                Some(p) if *p != i.expected_path => {
                    HealthVerdict::Unhealthy(err::RUNTIME_HEALTH_BEARER_CHANGED.to_string())
                }
                _ => HealthVerdict::Healthy,
            }
        }
    }
}

/// Evaluate the DATA6 bearer.
pub fn check_qmi_health(i: &QmiHealthInputs) -> HealthVerdict {
    if !i.device_present {
        return HealthVerdict::Unhealthy(err::RUNTIME_HEALTH_QMI_DEVICE_MISSING.to_string());
    }
    if !i.address_present {
        return HealthVerdict::Unhealthy(err::RUNTIME_HEALTH_QMI_ADDRESS_MISSING.to_string());
    }
    match i.connected {
        // Query failure is explicitly *not* fatal.
        None => HealthVerdict::Inconclusive(err::RUNTIME_HEALTH_QMI_DISCONNECTED),
        Some(false) => {
            HealthVerdict::Unhealthy(err::RUNTIME_HEALTH_QMI_DISCONNECTED.to_string())
        }
        Some(true) => HealthVerdict::Healthy,
    }
}

/// Supervisor state machine.
///
/// Owns the phase/stage transitions and the retry schedule. The actual I/O
/// (bearer, SIP, IPsec) lives in the sibling modules; this type only sequences
/// them and records what happened.
#[derive(Debug)]
pub struct VolteSupervisor {
    status: VolteRuntimeStatus,
    consecutive_failures: u32,
    session_start: Option<Instant>,
    /// Mirrors `config.volte.feature_enabled`; a false value stops the worker
    /// (`Native VoLTE runtime stopped by config`).
    enabled: bool,
    /// Mirrors `config.volte.sms_enabled`.
    sms_enabled: bool,
}

impl VolteSupervisor {
    pub fn new(enabled: bool, sms_enabled: bool) -> Self {
        Self {
            status: VolteRuntimeStatus::default(),
            consecutive_failures: 0,
            session_start: None,
            enabled,
            sms_enabled,
        }
    }

    pub fn status(&self) -> &VolteRuntimeStatus {
        &self.status
    }

    /// Reflect a config change. Disabling takes effect at the next supervisor
    /// tick rather than mid-transaction.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.status.phase = Phase::Stopping;
            self.status.stage = Stage::Stopping;
        }
    }

    pub fn sms_enabled(&self) -> bool {
        self.sms_enabled
    }

    /// Gate for the SMS runtime — refuses when either the feature or SMS is off.
    pub fn sms_gate(&self) -> Result<(), String> {
        if !self.enabled {
            return Err(err::DISABLED.to_string());
        }
        if !self.sms_enabled {
            return Err(err::SMS_DISABLED.to_string());
        }
        if self.status.phase != Phase::Registered {
            return Err(err::RUNTIME_NOT_RUNNING.to_string());
        }
        Ok(())
    }

    /// Begin a session.
    pub fn begin(&mut self, now_unix: u64) {
        self.status = VolteRuntimeStatus {
            phase: Phase::Starting,
            stage: Stage::Starting,
            session_started_at: Some(now_unix),
            ..VolteRuntimeStatus::default()
        };
        self.session_start = Some(Instant::now());
    }

    pub fn advance(&mut self, stage: Stage) {
        self.status.stage = stage;
    }

    /// Record a successful registration.
    pub fn registered(&mut self, mode: RegistrationMode, now_unix: u64, path: DataPathMode) {
        self.status.phase = Phase::Registered;
        self.status.stage = Stage::Registered;
        self.status.registration_mode = Some(mode);
        self.status.registered_at = Some(now_unix);
        self.status.data_path_mode = Some(path);
        self.status.last_error = None;
        self.status.next_retry_at = None;
        self.consecutive_failures = 0;
    }

    /// Record a failure and schedule the retry.
    pub fn failed(&mut self, error: impl Into<String>, now_unix: u64) -> Duration {
        self.consecutive_failures += 1;
        let delay = retry_delay(self.consecutive_failures);
        self.status.phase = Phase::Degraded;
        self.status.last_error = Some(error.into());
        self.status.last_failure_at = Some(now_unix);
        self.status.next_retry_at = Some(now_unix + delay.as_secs());
        delay
    }

    /// Count a reconnect (bearer or registration rebuilt while enabled).
    pub fn reconnected(&mut self) {
        self.status.reconnect_count += 1;
    }

    pub fn sent(&mut self, now_unix: u64) {
        self.status.sent_count += 1;
        self.status.last_tx_at = Some(now_unix);
    }

    pub fn received(&mut self, now_unix: u64) {
        self.status.received_count += 1;
        self.status.last_rx_at = Some(now_unix);
    }

    /// A retransmitted MT message we already stored
    /// (`Native VoLTE runtime duplicate MT SMS ignored`).
    pub fn duplicate(&mut self) {
        self.status.duplicate_count += 1;
    }

    /// Apply a health verdict; returns true when a re-registration is needed.
    pub fn apply_health(&mut self, v: &HealthVerdict, now_unix: u64) -> bool {
        match v {
            HealthVerdict::Healthy => false,
            // Deliberately sticky: keep serving with the current state.
            HealthVerdict::Inconclusive(_) => false,
            HealthVerdict::Unhealthy(code) => {
                self.failed(code.clone(), now_unix);
                true
            }
        }
    }

    pub fn stopped(&mut self) {
        self.status.phase = Phase::Disabled;
        self.status.stage = Stage::Stopping;
        self.status.registration_mode = None;
        self.session_start = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_and_stage_tokens_match_binary() {
        assert_eq!(Phase::Degraded.as_str(), "degraded");
        assert_eq!(Stage::IdentityAka.as_str(), "identity_aka");
        assert_eq!(Stage::RegisterIpsec.as_str(), "register_ipsec");
        assert_eq!(Stage::RegisterUdp.as_str(), "register_udp");
    }

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(retry_delay(1), Duration::from_secs(15));
        assert_eq!(retry_delay(2), Duration::from_secs(30));
        assert_eq!(retry_delay(3), Duration::from_secs(60));
        assert_eq!(retry_delay(10), RETRY_MAX);
    }

    #[test]
    fn refresh_is_half_the_registration_lifetime() {
        assert_eq!(REFRESH_INTERVAL.as_secs() * 2, 3600);
    }

    /// The whole point of Inconclusive: a flaky query must not tear down a
    /// working registration.
    #[test]
    fn inconclusive_health_does_not_trigger_reregistration() {
        let mut s = VolteSupervisor::new(true, true);
        s.begin(1000);
        s.registered(RegistrationMode::Ipsec, 1010, DataPathMode::IndependentWwan1);

        let v = check_qmi_health(&QmiHealthInputs {
            device_present: true,
            connected: None,
            address_present: true,
        });
        assert!(matches!(v, HealthVerdict::Inconclusive(_)));
        assert!(!s.apply_health(&v, 1100));
        assert_eq!(s.status().phase, Phase::Registered);
        assert!(s.status().last_error.is_none());
    }

    #[test]
    fn disconnected_bearer_forces_reregistration() {
        let mut s = VolteSupervisor::new(true, true);
        s.begin(1000);
        s.registered(RegistrationMode::Ipsec, 1010, DataPathMode::IndependentWwan1);

        let v = check_mm_health(&MmHealthInputs {
            connected: Some(false),
            current_path: None,
            expected_path: "/org/freedesktop/ModemManager1/Bearer/1".into(),
        });
        assert!(s.apply_health(&v, 1100));
        assert_eq!(s.status().phase, Phase::Degraded);
        assert_eq!(
            s.status().last_error.as_deref(),
            Some(err::RUNTIME_HEALTH_BEARER_DISCONNECTED)
        );
        assert_eq!(s.status().next_retry_at, Some(1100 + 15));
    }

    #[test]
    fn bearer_path_change_is_detected() {
        let v = check_mm_health(&MmHealthInputs {
            connected: Some(true),
            current_path: Some("/org/freedesktop/ModemManager1/Bearer/9".into()),
            expected_path: "/org/freedesktop/ModemManager1/Bearer/1".into(),
        });
        match v {
            HealthVerdict::Unhealthy(c) => {
                assert_eq!(c, err::RUNTIME_HEALTH_BEARER_CHANGED)
            }
            _ => panic!("expected unhealthy"),
        }
    }

    #[test]
    fn missing_qmi_device_is_fatal_for_the_session() {
        let v = check_qmi_health(&QmiHealthInputs {
            device_present: false,
            connected: Some(true),
            address_present: true,
        });
        match v {
            HealthVerdict::Unhealthy(c) => {
                assert_eq!(c, err::RUNTIME_HEALTH_QMI_DEVICE_MISSING)
            }
            _ => panic!("expected unhealthy"),
        }
    }

    #[test]
    fn sms_gate_requires_feature_sms_and_registration() {
        let mut s = VolteSupervisor::new(false, true);
        assert_eq!(s.sms_gate().unwrap_err(), err::DISABLED);

        s = VolteSupervisor::new(true, false);
        assert_eq!(s.sms_gate().unwrap_err(), err::SMS_DISABLED);

        s = VolteSupervisor::new(true, true);
        assert_eq!(s.sms_gate().unwrap_err(), err::RUNTIME_NOT_RUNNING);

        s.begin(1);
        s.registered(RegistrationMode::PlainUdp, 2, DataPathMode::SecondaryQmiData);
        assert!(s.sms_gate().is_ok());
    }

    #[test]
    fn success_clears_error_and_resets_backoff() {
        let mut s = VolteSupervisor::new(true, true);
        s.begin(1000);
        s.failed("boom", 1010);
        s.failed("boom", 1020);
        assert_eq!(s.status().phase, Phase::Degraded);

        s.registered(RegistrationMode::Ipsec, 1030, DataPathMode::IndependentWwan1);
        assert!(s.status().last_error.is_none());
        assert!(s.status().next_retry_at.is_none());
        // Backoff restarts from base after success.
        assert_eq!(s.failed("again", 1040), Duration::from_secs(15));
    }

    #[test]
    fn counters_track_traffic() {
        let mut s = VolteSupervisor::new(true, true);
        s.begin(1);
        s.sent(10);
        s.received(11);
        s.duplicate();
        s.reconnected();
        let st = s.status();
        assert_eq!((st.sent_count, st.received_count), (1, 1));
        assert_eq!(st.duplicate_count, 1);
        assert_eq!(st.reconnect_count, 1);
        assert_eq!(st.last_tx_at, Some(10));
        assert_eq!(st.last_rx_at, Some(11));
    }

    #[test]
    fn registration_mode_log_lines() {
        assert_eq!(
            RegistrationMode::Ipsec.success_message(),
            "Native VoLTE runtime registered with 3GPP IPsec and listening"
        );
        assert_eq!(
            RegistrationMode::PlainUdp.refresh_message(),
            "Native VoLTE runtime plain UDP REGISTER refreshed"
        );
    }
}
