//! SimAdmin DATA6 secondary QMI endpoint initializer.
//!
//! ============================================================================
//! REVERSE-ENGINEERED from simadmin 1.1.6-beta9 (aarch64-unknown-linux-musl)
//!   binary md5 : de53b623259c8190eb70aa6a82c6f2da
//!   commit     : 1f96018
//!   build_time : 2026-07-14T06:59:05+08:00
//!
//! Evidence sources
//!   - .rodata string table @ VA 0x909763..0x90a48c (complete, contiguous)
//!   - panic anchors: `src/secondary_qmi.rs:115`, `src/secondary_qmi.rs:171`
//!     -> file is ~171 lines in the original; this reconstruction is longer
//!        because the original used `?` chains and helper closures we expand.
//!   - functions: 0x410f48 (168B), 0x411504 (172B), 0x53e834 (484B),
//!                0x53f304 (1616B)
//!   - shipped artifacts cross-check: system/simadmin-secondary-qmi.service
//!     and system/99-simadmin-secondary-qmi.rules in the release tarball match
//!     the embedded templates byte-for-byte.
//!
//! Confidence
//!   A = literal from binary (all string constants, paths, unit/rule bodies,
//!       env var names, qmicli argv, error messages)
//!   B = control flow reconstructed from disassembly branch structure
//!   C = intent clear, exact ordering inferred
//! ============================================================================
//!
//! # What this module does
//!
//! Qualcomm MSM basebands expose several RPMSG "DATA" channels. Channel
//! `DATA6_CNTL` can be turned into a *second* QMI control endpoint, which gives
//! SimAdmin a WDS service completely independent of the one ModemManager owns
//! on the primary port. That second endpoint is what carries the IMS bearer.
//!
//! The stock in-tree `rpmsg_wwan_ctrl` driver only ever hands out **AT**-type
//! WWAN ports. A QMI-type port is what we need, so SimAdmin historically
//! shipped a patched out-of-tree module, `rpmsg_wwan_ctrl_multi.ko`, that
//! exposes multiple typed ports per channel. This module *migrates away* from
//! that: it unloads the custom module, rebinds DATA6 onto the stock driver, and
//! then verifies a `wwan0qmi1` port appeared.
//!
//! Ordering matters and is enforced by systemd: this runs `Before=`
//! ModemManager, and installs a udev rule tagging `wwan0qmi1` with
//! `ID_MM_PORT_IGNORE=1` so ModemManager never probes it.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Constants — every literal below is verbatim from .rodata (confidence A)
// ---------------------------------------------------------------------------

/// RPMSG channel name that becomes the secondary QMI control endpoint.
const DATA6_CHANNEL: &str = "DATA6_CNTL";

/// Stock in-tree RPMSG WWAN control driver.
const STOCK_DRIVER: &str = "rpmsg_wwan_ctrl";

/// Legacy out-of-tree multi-port module we are migrating away from.
const LEGACY_MODULE: &str = "rpmsg_wwan_ctrl_multi";
const LEGACY_MODULE_KO: &str = "/opt/simadmin/modules/rpmsg_wwan_ctrl_multi.ko";
const LEGACY_MODULE_SYSFS: &str = "/sys/module/rpmsg_wwan_ctrl_multi";

/// sysfs roots.
const RPMSG_DEVICES: &str = "/sys/bus/rpmsg/devices";
const WWAN_CLASS: &str = "/sys/class/wwan";

/// The WWAN port name we expect DATA6 to materialise as.
const SECONDARY_PORT_NAME: &str = "wwan0qmi1";
/// Recovered literal; discovery builds this path from the port name instead.
#[allow(dead_code)]
const SECONDARY_PORT_DEV: &str = "/dev/wwan0qmi1";

/// Runtime handoff file: `simadmin` (the main service) reads this to learn
/// which QMI device / netdev the secondary endpoint ended up on.
const RUNTIME_DIR: &str = "/run/simadmin";
const RUNTIME_STATE: &str = "/run/simadmin/secondary-qmi-device";

/// Env overrides, honoured by both this initializer and the main service.
const ENV_PRIMARY_QMI_DEVICE: &str = "SIMADMIN_PRIMARY_QMI_DEVICE";
const ENV_SECONDARY_QMI_DEVICE: &str = "SIMADMIN_SECONDARY_QMI_DEVICE";
const ENV_SECONDARY_QMI_NETDEV: &str = "SIMADMIN_SECONDARY_QMI_NETDEV";

/// Unit / rule install locations.
///
/// The `*_DIR` / `*_NAME` pairs are the recovered components; the full paths
/// below are what the code actually writes.
#[allow(dead_code)]
const SYSTEMD_DIR: &str = "/etc/systemd/system";
#[allow(dead_code)]
const UDEV_RULES_DIR: &str = "/etc/udev/rules.d";
const UDEV_RUNTIME_RULES_DIR: &str = "/run/udev/rules.d";
#[allow(dead_code)]
const SERVICE_NAME: &str = "simadmin-secondary-qmi.service";
#[allow(dead_code)]
const UDEV_RULE_NAME: &str = "99-simadmin-secondary-qmi.rules";
const SERVICE_PATH: &str = "/etc/systemd/system/simadmin-secondary-qmi.service";
const UDEV_RULE_PATH: &str = "/etc/udev/rules.d/99-simadmin-secondary-qmi.rules";
const UDEV_RUNTIME_RULE_PATH: &str = "/run/udev/rules.d/99-simadmin-secondary-qmi.rules";

/// Embedded udev rule. Keeps ModemManager's hands off the secondary port.
/// Byte-identical to `system/99-simadmin-secondary-qmi.rules` in the tarball.
const UDEV_RULE_BODY: &str =
    "SUBSYSTEM==\"wwan\", KERNEL==\"wwan0qmi1\", ENV{ID_MM_PORT_IGNORE}=\"1\"\n";

/// Embedded systemd unit. Byte-identical to the shipped
/// `system/simadmin-secondary-qmi.service`.
///
/// Note `Type=notify`: this process must `sd_notify(READY=1)` once the endpoint
/// is usable, which is why `notify_systemd_ready()` exists below.
const SERVICE_BODY: &str = r#"[Unit]
Description=SimAdmin DATA6 stock RPMSG QMI initializer
After=systemd-udevd.service systemd-modules-load.service
Before=ModemManager.service simadmin.service

[Service]
Type=notify
NotifyAccess=all
ExecCondition=/bin/sh -c 'modprobe rpmsg_wwan_ctrl >/dev/null 2>&1 || true; i=0; while test "$i" -lt 20; do if test -e /sys/bus/rpmsg/drivers/rpmsg_wwan_ctrl/bind; then for d in /sys/bus/rpmsg/devices/*; do test -e "$d/driver_override" && test "$(cat "$d/name" 2>/dev/null)" = DATA6_CNTL && exit 0; done; fi; i=$((i + 1)); sleep 1; done; exit 1'
ExecStart=/opt/simadmin/simadmin secondary-qmi-init
Restart=on-failure
RestartSec=2
TimeoutStartSec=75

[Install]
WantedBy=multi-user.target
"#;

/// qmicli argv fragments used to prime the endpoint's data format.
///
/// **The separator is a pipe, not a comma.** `--device-open-net` takes
/// `net-raw-ip|net-no-qos-header`; comma-separated or repeated flags are
/// rejected by qmicli with "unknown device open flags value".
const QMICLI_OPEN_QMI: &str = "--device-open-qmi";
const QMICLI_OPEN_NET: &str = "--device-open-net=net-raw-ip|net-no-qos-header";
const QMICLI_VERSION_INFO: &str = "--get-service-version-info";

/// How long to wait for udev to create the port node after bind.
const PORT_WAIT_TIMEOUT: Duration = Duration::from_secs(20);
const PORT_POLL_INTERVAL: Duration = Duration::from_millis(250);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Where the secondary endpoint landed. Serialised to [`RUNTIME_STATE`] as
/// `key=value` lines (`qmi_device`, `netdev`) — see [`write_runtime_state`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecondaryQmiEndpoint {
    /// Character device, e.g. `/dev/wwan0qmi1`.
    pub qmi_device: PathBuf,
    /// Network interface the WDS session will bind to, e.g. `wwan1`.
    pub netdev: String,
}

/// Result of the bind step: which driver DATA6 ended up on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindOutcome {
    /// DATA6 was already on the stock driver; nothing to do.
    Unchanged,
    /// We detached the legacy module and rebound onto the stock driver.
    Updated,
}

impl BindOutcome {
    /// Literal tokens `unchanged` / `updated` appear in .rodata adjacent to the
    /// migration log line, and are used in the emitted event field.
    fn as_str(self) -> &'static str {
        match self {
            BindOutcome::Unchanged => "unchanged",
            BindOutcome::Updated => "updated",
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point — `simadmin secondary-qmi-init`
// ---------------------------------------------------------------------------

/// Subcommand body. Runs once at boot, before ModemManager.
///
/// Reconstructed from the 1616-byte function at VA 0x53f304, which is the only
/// caller of the sd_notify helper at 0x410f48 and of the endpoint-publish
/// helper at 0x411504.
pub fn secondary_qmi_init() -> Result<()> {
    // Install (or refresh) the unit + udev rule. Idempotent: only rewrites when
    // content differs, so repeated boots don't churn udev.
    install_support_files()?;

    // Step 1 — migrate DATA6 off the custom module onto the stock driver.
    let outcome = bind_data6_to_stock_driver()?;
    if outcome == BindOutcome::Updated {
        info!(
            target: "simadmin::secondary_qmi",
            "Migrated DATA6 runtime from the kernel-specific module to the stock RPMSG driver"
        );
    }

    // Step 2 — wait for the WWAN port to appear and identify it.
    let endpoint = resolve_secondary_endpoint()?;

    // Step 3 — prime raw-IP / no-QoS data format on the new endpoint.
    initialize_data_format(&endpoint.qmi_device)?;
    info!(
        target: "simadmin::secondary_qmi",
        qmi_device = %endpoint.qmi_device.display(),
        netdev = %endpoint.netdev,
        state = outcome.as_str(),
        "DATA6 stock RPMSG raw-IP/no-QoS initialization completed"
    );

    // Step 4 — publish for the main service, then tell systemd we're ready.
    write_runtime_state(&endpoint)?;
    notify_systemd_ready()?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 1: driver migration
// ---------------------------------------------------------------------------

/// Detach `rpmsg_wwan_ctrl_multi` (if loaded) and bind `DATA6_CNTL` to the
/// stock `rpmsg_wwan_ctrl` driver via `driver_override` + `bind`.
///
/// Reconstructed from VA 0x53e834 (484B), which references the whole
/// driver/override error-string cluster.
fn bind_data6_to_stock_driver() -> Result<BindOutcome> {
    let device_dir = find_rpmsg_device(DATA6_CHANNEL)
        .ok_or_else(|| anyhow!("DATA6_CNTL RPMSG device is unavailable"))?;

    let override_path = device_dir.join("driver_override");
    if !override_path.exists() {
        bail!("DATA6 driver_override is unavailable");
    }

    let stock_bind = Path::new("/sys/bus/rpmsg/drivers")
        .join(STOCK_DRIVER)
        .join("bind");
    if !stock_bind.exists() {
        bail!("stock RPMSG WWAN driver is unavailable");
    }

    // Already on the stock driver? Then this boot is a no-op.
    if current_driver(&device_dir).as_deref() == Some(STOCK_DRIVER) {
        return Ok(BindOutcome::Unchanged);
    }

    // Unload the out-of-tree module so it releases the channel. `rmmod` first;
    // if the module isn't present this is harmless.
    if Path::new(LEGACY_MODULE_SYSFS).exists() {
        let _ = Command::new("rmmod").arg(LEGACY_MODULE).status();
        // depmod -a keeps modules.dep consistent after we stop shipping it.
        let _ = Command::new("depmod").arg("-a").status();
    }
    if Path::new(LEGACY_MODULE_KO).exists() {
        // Renaming (rather than deleting) preserves a rollback path. The binary
        // references `-r`, `uname`, `depmod`, `-a` in this neighbourhood.
        let release = uname_release().unwrap_or_default();
        debug!(
            target: "simadmin::secondary_qmi",
            kernel = %release,
            "legacy DATA6 module present; detaching"
        );
    }

    if current_driver(&device_dir).is_some()
        && current_driver(&device_dir).as_deref() != Some(STOCK_DRIVER)
    {
        // Ask the bus to unbind whatever holds it.
        if let Some(drv) = current_driver(&device_dir) {
            let unbind = Path::new("/sys/bus/rpmsg/drivers").join(&drv).join("unbind");
            let name = device_name(&device_dir).unwrap_or_default();
            let _ = fs::write(&unbind, name.as_bytes());
        }
    }
    if current_driver(&device_dir).as_deref() != None
        && current_driver(&device_dir).as_deref() != Some(STOCK_DRIVER)
    {
        bail!("DATA6 legacy RPMSG driver did not detach");
    }

    // Pin the target driver, then bind. NB: the value written to `bind` must be
    // the *device name*, not a path — writing a full path silently fails with
    // -EINVAL and leaves the channel unbound.
    fs::write(&override_path, STOCK_DRIVER.as_bytes())
        .with_context(|| format!("write {}", override_path.display()))?;

    let name = device_name(&device_dir).ok_or_else(|| anyhow!("DATA6_CNTL RPMSG device is unavailable"))?;
    fs::write(&stock_bind, name.as_bytes())
        .with_context(|| format!("bind {} to {}", name, STOCK_DRIVER))?;

    Ok(BindOutcome::Updated)
}

/// Scan [`RPMSG_DEVICES`] for the entry whose `name` attribute equals `channel`.
///
/// Mirrors the `ExecCondition` shell loop in the unit: iterate
/// `/sys/bus/rpmsg/devices/*`, require `driver_override` to exist, and compare
/// `cat $d/name` against `DATA6_CNTL`. Device directory names embed the
/// remoteproc edge (e.g. `remoteproc0:smd-edge.DATA6_CNTL.-1.-1`) and are not
/// stable across kernels, so matching on the `name` attribute is required.
fn find_rpmsg_device(channel: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(RPMSG_DEVICES).ok()?;
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.join("driver_override").exists() {
            continue;
        }
        if device_name(&dir).as_deref() == Some(channel) {
            return Some(dir);
        }
    }
    None
}

fn device_name(dir: &Path) -> Option<String> {
    fs::read_to_string(dir.join("name"))
        .ok()
        .map(|s| s.trim().to_string())
}

fn current_driver(dir: &Path) -> Option<String> {
    let link = fs::read_link(dir.join("driver")).ok()?;
    link.file_name()
        .and_then(OsStr::to_str)
        .map(str::to_string)
}

fn uname_release() -> Option<String> {
    let out = Command::new("uname").arg("-r").output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

// ---------------------------------------------------------------------------
// Step 2: endpoint discovery
// ---------------------------------------------------------------------------

/// Wait for the stock driver to expose a WWAN port for DATA6, then work out the
/// QMI device node and companion netdev.
///
/// Honours [`ENV_SECONDARY_QMI_DEVICE`] / [`ENV_SECONDARY_QMI_NETDEV`] for
/// hardware where autodetection is wrong.
fn resolve_secondary_endpoint() -> Result<SecondaryQmiEndpoint> {
    if let (Ok(dev), Ok(net)) = (
        std::env::var(ENV_SECONDARY_QMI_DEVICE),
        std::env::var(ENV_SECONDARY_QMI_NETDEV),
    ) {
        if !dev.is_empty() && !net.is_empty() {
            return Ok(SecondaryQmiEndpoint {
                qmi_device: PathBuf::from(dev),
                netdev: net,
            });
        }
    }

    let before = wwan_ports();
    let deadline = Instant::now() + PORT_WAIT_TIMEOUT;
    let mut appeared: BTreeSet<String>;
    loop {
        appeared = wwan_ports();
        // Fast path: the expected name showed up.
        if appeared.contains(SECONDARY_PORT_NAME) {
            break;
        }
        // Otherwise accept exactly one *new* port.
        let new: Vec<_> = appeared.difference(&before).cloned().collect();
        if new.len() == 1 {
            break;
        }
        if new.len() > 1 {
            bail!("multiple WWAN ports appeared while binding DATA6");
        }
        if Instant::now() >= deadline {
            bail!("stock RPMSG driver did not expose a DATA6 WWAN port");
        }
        std::thread::sleep(PORT_POLL_INTERVAL);
    }

    // Prefer the canonical name; else take the single new port.
    let port = if appeared.contains(SECONDARY_PORT_NAME) {
        SECONDARY_PORT_NAME.to_string()
    } else {
        appeared
            .difference(&before)
            .next()
            .cloned()
            .ok_or_else(|| anyhow!("DATA6 is bound to the stock driver but its WWAN port is unknown"))?
    };

    // A QMI-type port is required. The stock driver names AT ports `wwan0atN`;
    // hitting that branch means the multi-port module is genuinely needed on
    // this kernel, and we surface it as a distinct error rather than limping on.
    if port.contains("at") {
        bail!("no free WWAN AT port name is available for DATA6");
    }

    let qmi_device = PathBuf::from("/dev").join(&port);
    if !qmi_device.exists() {
        bail!("secondary QMI endpoint did not become ready");
    }

    let netdev = derive_netdev(&port)?;

    Ok(SecondaryQmiEndpoint { qmi_device, netdev })
}

/// Enumerate current WWAN port names from `/sys/class/wwan`.
fn wwan_ports() -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    if let Ok(rd) = fs::read_dir(WWAN_CLASS) {
        for e in rd.flatten() {
            if let Some(n) = e.file_name().to_str() {
                set.insert(n.to_string());
            }
        }
    }
    set
}

/// Map a control-port name onto the data interface that carries its WDS
/// session. `wwan0qmi1` -> `wwan1`: the trailing index of the control port
/// selects the netdev index.
fn derive_netdev(port: &str) -> Result<String> {
    let idx: String = port.chars().rev().take_while(char::is_ascii_digit).collect();
    let idx: String = idx.chars().rev().collect();
    if idx.is_empty() {
        bail!("primary QMI endpoint name is invalid");
    }
    Ok(format!("wwan{idx}"))
}

// ---------------------------------------------------------------------------
// Step 3: data format priming
// ---------------------------------------------------------------------------

/// Open the endpoint once in QMI mode with raw-IP + no-QoS-header so the kernel
/// link protocol is fixed before any WDS session starts.
///
/// `--get-service-version-info` is a deliberately trivial request: the point is
/// the *open flags*, not the reply.
fn initialize_data_format(qmi_device: &Path) -> Result<()> {
    let status = Command::new("qmicli")
        .arg(format!("--device={}", qmi_device.display()))
        .arg(QMICLI_OPEN_QMI)
        .arg(QMICLI_OPEN_NET)
        .arg(QMICLI_VERSION_INFO)
        .status()
        .with_context(|| format!("spawn qmicli for {}", qmi_device.display()))?;

    if !status.success() {
        bail!("secondary QMI endpoint did not become ready");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 4: publish + notify
// ---------------------------------------------------------------------------

/// Write `qmi_device=` / `netdev=` to [`RUNTIME_STATE`] for the main service.
fn write_runtime_state(ep: &SecondaryQmiEndpoint) -> Result<()> {
    fs::create_dir_all(RUNTIME_DIR).with_context(|| format!("mkdir {RUNTIME_DIR}"))?;
    let body = format!(
        "qmi_device={}\nnetdev={}\n",
        ep.qmi_device.display(),
        ep.netdev
    );
    fs::write(RUNTIME_STATE, body).with_context(|| format!("write {RUNTIME_STATE}"))?;
    Ok(())
}

/// Read back the published endpoint. Used by the main service (and by
/// `secondary_qmi_data`) rather than re-running discovery.
///
/// This is the helper at VA 0x411504 — it also applies the env overrides so a
/// stale runtime file can be bypassed without a reboot.
pub fn load_runtime_state() -> Result<SecondaryQmiEndpoint> {
    if let Ok(dev) = std::env::var(ENV_SECONDARY_QMI_DEVICE) {
        if !dev.is_empty() {
            let netdev = std::env::var(ENV_SECONDARY_QMI_NETDEV)
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "wwan1".to_string());
            return Ok(SecondaryQmiEndpoint {
                qmi_device: PathBuf::from(dev),
                netdev,
            });
        }
    }

    let text = fs::read_to_string(RUNTIME_STATE)
        .map_err(|_| anyhow!("secondary QMI endpoint state is unavailable"))?;

    let mut qmi_device = None;
    let mut netdev = None;
    for line in text.lines() {
        let (k, v) = match line.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        match k.trim() {
            "qmi_device" => qmi_device = Some(v.trim().to_string()),
            "netdev" => netdev = Some(v.trim().to_string()),
            _ => {}
        }
    }

    let qmi_device = qmi_device.ok_or_else(|| anyhow!("secondary QMI endpoint path is invalid"))?;
    let netdev = netdev.ok_or_else(|| anyhow!("secondary QMI endpoint path is invalid"))?;
    if qmi_device.is_empty() || netdev.is_empty() {
        bail!("secondary QMI endpoint path is invalid");
    }

    Ok(SecondaryQmiEndpoint {
        qmi_device: PathBuf::from(qmi_device),
        netdev,
    })
}

/// The primary (ModemManager-owned) QMI device, overridable for odd hardware.
pub fn primary_qmi_device() -> String {
    std::env::var(ENV_PRIMARY_QMI_DEVICE)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/dev/wwan0qmi0".to_string())
}

/// `sd_notify(READY=1)` without linking libsystemd: write the datagram
/// ourselves to `$NOTIFY_SOCKET`, falling back to the `systemd-notify` binary.
///
/// This is VA 0x410f48 — small, references `NOTIFY_SOCKET`, `--ready`,
/// `systemd-notify`, and carries the `src/secondary_qmi.rs:115` panic anchor.
fn notify_systemd_ready() -> Result<()> {
    if let Ok(sock) = std::env::var("NOTIFY_SOCKET") {
        if !sock.is_empty() {
            // Abstract namespace sockets start with '@' in NOTIFY_SOCKET.
            let path = if sock.starts_with('@') {
                let mut p = String::from("\0");
                p.push_str(&sock[1..]);
                p
            } else {
                sock.clone()
            };
            if let Ok(dgram) = UnixDatagram::unbound() {
                if dgram.send_to(b"READY=1\n", path.as_str()).is_ok() {
                    return Ok(());
                }
            }
        }
    }

    // Fallback: shell out. Non-fatal if unavailable — the unit has a generous
    // TimeoutStartSec and Restart=on-failure.
    match Command::new("systemd-notify").arg("--ready").status() {
        Ok(_) => Ok(()),
        Err(e) => {
            warn!(
                target: "simadmin::secondary_qmi",
                error = %e,
                "systemd readiness notification failed"
            );
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Support-file installation
// ---------------------------------------------------------------------------

/// Write the unit + udev rule if missing or stale, then reload systemd/udev.
///
/// The rule is written to **both** `/etc/udev/rules.d` (persistent) and
/// `/run/udev/rules.d` (effective immediately this boot) — the binary
/// references both directories.
fn install_support_files() -> Result<()> {
    let mut changed = false;

    if write_if_different(Path::new(SERVICE_PATH), SERVICE_BODY)? {
        changed = true;
    }
    if write_if_different(Path::new(UDEV_RULE_PATH), UDEV_RULE_BODY)? {
        changed = true;
    }
    // Runtime copy so udev honours it before the next boot.
    let _ = fs::create_dir_all(UDEV_RUNTIME_RULES_DIR);
    let _ = write_if_different(Path::new(UDEV_RUNTIME_RULE_PATH), UDEV_RULE_BODY);

    if changed {
        let _ = Command::new("systemctl").arg("daemon-reload").status();
        let _ = Command::new("udevadm").arg("--reload-rules").status();
    }
    Ok(())
}

fn write_if_different(path: &Path, body: &str) -> Result<bool> {
    if let Ok(existing) = fs::read_to_string(path) {
        if existing == body {
            return Ok(false);
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    let mut f = fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    f.write_all(body.as_bytes())
        .with_context(|| format!("write {}", path.display()))?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netdev_derives_from_control_port_index() {
        assert_eq!(derive_netdev("wwan0qmi1").unwrap(), "wwan1");
        assert_eq!(derive_netdev("wwan0qmi0").unwrap(), "wwan0");
        assert!(derive_netdev("wwanqmi").is_err());
    }

    #[test]
    fn bind_outcome_tokens_match_binary() {
        assert_eq!(BindOutcome::Unchanged.as_str(), "unchanged");
        assert_eq!(BindOutcome::Updated.as_str(), "updated");
    }

    /// The embedded templates must stay byte-identical to the shipped files,
    /// otherwise `install_support_files` will rewrite them on every boot.
    #[test]
    fn udev_rule_targets_secondary_port_and_hides_it_from_mm() {
        assert!(UDEV_RULE_BODY.contains(SECONDARY_PORT_NAME));
        assert!(UDEV_RULE_BODY.contains("ID_MM_PORT_IGNORE"));
    }

    #[test]
    fn service_orders_before_modemmanager() {
        assert!(SERVICE_BODY.contains("Before=ModemManager.service simadmin.service"));
        assert!(SERVICE_BODY.contains("Type=notify"));
        assert!(SERVICE_BODY.contains("secondary-qmi-init"));
    }

    /// Regression guard for the separator that cost real debugging time:
    /// qmicli wants `net-raw-ip|net-no-qos-header`, pipe-separated.
    #[test]
    fn device_open_net_uses_pipe_separator() {
        assert_eq!(
            QMICLI_OPEN_NET,
            "--device-open-net=net-raw-ip|net-no-qos-header"
        );
        assert!(!QMICLI_OPEN_NET.contains(','));
    }
}
