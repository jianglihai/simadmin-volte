//! IMS/data slot allocation — which endpoint carries IMS, which carries user data.
//!
//! Recovered from `src/volte.rs` lines ~1289-1441 (anchors 1289, 1307, 1344,
//! 1358, 1371, 1395, 1430, 1441).
//!
//! Evidence (confidence A for all string literals):
//!   - `data_requested` / `primary_data_active` / `secondary_data_active`
//!     (runtime inputs, at volte.rs:1430)
//!   - `independent_wwan1` / `secondary_qmi_data` / `both_data_slots_active`
//!     (mode tokens, declaration order preserved)
//!   - `IMS allocated to primary qmi0; DATA6 is reserved for data`
//!   - `IMS allocated to DATA6; primary qmi0 is reserved for data`
//!   - `volte_data_slot_mode_missing`, `volte_data_slot_conflict`
//!   - `VoLTE and data path allocation selected`
//!
//! # The constraint
//!
//! There are exactly two usable data endpoints on this hardware:
//!
//! - **primary qmi0** — the port ModemManager owns
//! - **DATA6 / secondary qmi1** — the port [`crate::secondary_qmi`] creates
//!
//! IMS needs one of them for its own PDP context. So does user data, when
//! enabled. If user data has taken *both*, there is no slot left for IMS and the
//! allocation is refused rather than silently stealing one.

use super::err;

/// Where user data lives, which implicitly says where IMS goes.
///
/// Token strings are the persisted/serialised form and match .rodata exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataPathMode {
    /// User data on primary qmi0; IMS gets DATA6 with its own netdev (wwan1).
    IndependentWwan1,
    /// User data on DATA6 secondary QMI; IMS gets primary qmi0.
    SecondaryQmiData,
    /// Both endpoints already carry user data — no slot for IMS.
    BothDataSlotsActive,
}

impl DataPathMode {
    pub fn as_str(self) -> &'static str {
        match self {
            DataPathMode::IndependentWwan1 => "independent_wwan1",
            DataPathMode::SecondaryQmiData => "secondary_qmi_data",
            DataPathMode::BothDataSlotsActive => "both_data_slots_active",
        }
    }

    /// Parse the persisted token. Unknown values collapse to
    /// [`DataPathMode::BothDataSlotsActive`], mirroring the binary's
    /// `w20 = 2` default in the selector at 0x58e0c4 (beta2 analysis) — i.e.
    /// an unrecognised config is treated as "no slot available" rather than
    /// optimistically picking one.
    pub fn parse(s: &str) -> Self {
        match s {
            "independent_wwan1" => DataPathMode::IndependentWwan1,
            "secondary_qmi_data" => DataPathMode::SecondaryQmiData,
            _ => DataPathMode::BothDataSlotsActive,
        }
    }
}

/// Which endpoint IMS ends up on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImsSlot {
    /// ModemManager-owned primary port; IMS bearer created via `mmcli`.
    PrimaryQmi0,
    /// DATA6 secondary port; IMS bearer created via `qmicli --wds-start-network`.
    Data6,
}

impl ImsSlot {
    /// Human-readable log line, verbatim from .rodata.
    pub fn log_message(self) -> &'static str {
        match self {
            ImsSlot::PrimaryQmi0 => "IMS allocated to primary qmi0; DATA6 is reserved for data",
            ImsSlot::Data6 => "IMS allocated to DATA6; primary qmi0 is reserved for data",
        }
    }
}

/// Result of [`allocate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotAllocation {
    pub ims: ImsSlot,
    pub data_path_mode: DataPathMode,
}

/// Runtime signals feeding the decision (volte.rs:1430).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotInputs {
    /// User has data switched on.
    pub data_requested: bool,
    /// A bearer is currently up on primary qmi0.
    pub primary_data_active: bool,
    /// A WDS session is currently up on DATA6.
    pub secondary_data_active: bool,
    /// DATA6 endpoint exists at all (secondary-qmi-init succeeded).
    pub secondary_endpoint_available: bool,
    /// Configured preference, used only when nothing is active yet.
    pub intent: DataPathMode,
}

/// Decide who gets which endpoint.
///
/// Order of checks is load-bearing and taken from the branch structure:
/// conflict first, then "respect whatever data already holds", then fall back
/// to the configured intent.
pub fn allocate(inp: SlotInputs) -> Result<SlotAllocation, String> {
    // Both endpoints busy with user data -> nothing left for IMS.
    if inp.primary_data_active && inp.secondary_data_active {
        return Err(err::DATA_SLOT_CONFLICT.to_string());
    }

    // Data already on primary -> IMS must take DATA6.
    if inp.primary_data_active {
        if !inp.secondary_endpoint_available {
            return Err(err::DATA_SLOT_CONFLICT.to_string());
        }
        return Ok(SlotAllocation {
            ims: ImsSlot::Data6,
            data_path_mode: DataPathMode::IndependentWwan1,
        });
    }

    // Data already on DATA6 -> IMS takes primary.
    if inp.secondary_data_active {
        return Ok(SlotAllocation {
            ims: ImsSlot::PrimaryQmi0,
            data_path_mode: DataPathMode::SecondaryQmiData,
        });
    }

    // Nothing active. If data isn't even requested, IMS may take the primary
    // port outright — the simplest and most compatible layout.
    if !inp.data_requested {
        return Ok(SlotAllocation {
            ims: ImsSlot::PrimaryQmi0,
            data_path_mode: DataPathMode::SecondaryQmiData,
        });
    }

    // Data requested but not up yet: honour the configured intent.
    match inp.intent {
        DataPathMode::IndependentWwan1 => {
            if !inp.secondary_endpoint_available {
                // Cannot give IMS DATA6; fall back to sharing the primary and
                // let the caller surface the degraded arrangement.
                return Ok(SlotAllocation {
                    ims: ImsSlot::PrimaryQmi0,
                    data_path_mode: DataPathMode::SecondaryQmiData,
                });
            }
            Ok(SlotAllocation {
                ims: ImsSlot::Data6,
                data_path_mode: DataPathMode::IndependentWwan1,
            })
        }
        DataPathMode::SecondaryQmiData => {
            if !inp.secondary_endpoint_available {
                return Err(err::DATA_SLOT_CONFLICT.to_string());
            }
            Ok(SlotAllocation {
                ims: ImsSlot::PrimaryQmi0,
                data_path_mode: DataPathMode::SecondaryQmiData,
            })
        }
        DataPathMode::BothDataSlotsActive => Err(err::DATA_SLOT_MODE_MISSING.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> SlotInputs {
        SlotInputs {
            data_requested: false,
            primary_data_active: false,
            secondary_data_active: false,
            secondary_endpoint_available: true,
            intent: DataPathMode::IndependentWwan1,
        }
    }

    #[test]
    fn both_slots_busy_is_a_conflict() {
        let mut i = base();
        i.primary_data_active = true;
        i.secondary_data_active = true;
        assert_eq!(allocate(i).unwrap_err(), err::DATA_SLOT_CONFLICT);
    }

    #[test]
    fn data_on_primary_pushes_ims_to_data6() {
        let mut i = base();
        i.primary_data_active = true;
        let a = allocate(i).unwrap();
        assert_eq!(a.ims, ImsSlot::Data6);
        assert_eq!(a.data_path_mode, DataPathMode::IndependentWwan1);
    }

    #[test]
    fn data_on_data6_pushes_ims_to_primary() {
        let mut i = base();
        i.secondary_data_active = true;
        let a = allocate(i).unwrap();
        assert_eq!(a.ims, ImsSlot::PrimaryQmi0);
        assert_eq!(a.data_path_mode, DataPathMode::SecondaryQmiData);
    }

    #[test]
    fn no_data_requested_gives_ims_the_primary_port() {
        let a = allocate(base()).unwrap();
        assert_eq!(a.ims, ImsSlot::PrimaryQmi0);
    }

    #[test]
    fn missing_data6_endpoint_blocks_independent_layout() {
        let mut i = base();
        i.primary_data_active = true;
        i.secondary_endpoint_available = false;
        assert_eq!(allocate(i).unwrap_err(), err::DATA_SLOT_CONFLICT);
    }

    #[test]
    fn mode_tokens_match_binary() {
        assert_eq!(DataPathMode::IndependentWwan1.as_str(), "independent_wwan1");
        assert_eq!(DataPathMode::SecondaryQmiData.as_str(), "secondary_qmi_data");
        assert_eq!(
            DataPathMode::BothDataSlotsActive.as_str(),
            "both_data_slots_active"
        );
    }

    #[test]
    fn unknown_mode_token_is_treated_as_unavailable() {
        assert_eq!(
            DataPathMode::parse("nonsense"),
            DataPathMode::BothDataSlotsActive
        );
    }
}
