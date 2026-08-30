//! VoLTE / IMS 运行时的全局管理器。
//!
//! 把逆向还原出的 `volte::runtime::VolteSupervisor` 包成一个可以放进
//! `AppState` 的 handle：内部持有 supervisor 状态、后台 worker 句柄，以及一份
//! 最近一次注册出来的身份快照供 HTTP 层读取。
//!
//! # 为什么需要这一层
//!
//! `VolteSupervisor` 是纯状态机，不含 I/O。真正的注册流程要按顺序驱动
//! identity → bearer → pcscf → register 四个子系统，每一步都可能阻塞数秒，
//! 因此必须跑在独立 task 里。HTTP handler 只读状态、发命令，不直接执行流程。

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use crate::config::{ConfigManager, VolteConfig};
use crate::models::{VolteControlResponse, VolteRuntimeStatusResponse};
use crate::volte::identity::ImsIdentity;
use crate::volte::runtime::{Phase, RegistrationMode, RuntimeCommand, Stage, VolteSupervisor};
use crate::volte::slot::DataPathMode;
use crate::volte::ApnProtocol;
use crate::volte::VolteConfig as VolteRuntimeConfig;

/// 注册成功后缓存的身份/网络信息，供 UI 展示。
#[derive(Debug, Clone, Default)]
pub struct VolteIdentitySnapshot {
    pub imsi: Option<String>,
    pub home_domain: Option<String>,
    pub public_identity: Option<String>,
    pub pcscf: Option<String>,
    pub ue_address: Option<String>,
    pub own_number: Option<String>,
}

impl VolteIdentitySnapshot {
    pub fn from_identity(id: &ImsIdentity) -> Self {
        Self {
            imsi: Some(id.imsi.clone()),
            home_domain: Some(id.home_domain.clone()),
            public_identity: Some(id.public_identity.clone()),
            pcscf: None,
            ue_address: None,
            own_number: id.own_number.clone(),
        }
    }
}

/// 放进 `AppState` 的 VoLTE 管理器。
pub struct VolteManager {
    supervisor: Arc<Mutex<VolteSupervisor>>,
    identity: Arc<Mutex<VolteIdentitySnapshot>>,
    command_tx: Arc<Mutex<Option<mpsc::Sender<RuntimeCommand>>>>,
    config_manager: Arc<ConfigManager>,
}

impl VolteManager {
    pub fn new(config_manager: Arc<ConfigManager>) -> Self {
        let cfg = config_manager.get_volte_config();
        Self {
            supervisor: Arc::new(Mutex::new(VolteSupervisor::new(
                cfg.feature_enabled,
                cfg.sms_enabled,
            ))),
            identity: Arc::new(Mutex::new(VolteIdentitySnapshot::default())),
            command_tx: Arc::new(Mutex::new(None)),
            config_manager,
        }
    }

    /// 把持久化配置翻译成运行时配置。
    fn runtime_config(cfg: &VolteConfig) -> VolteRuntimeConfig {
        VolteRuntimeConfig {
            feature_enabled: cfg.feature_enabled,
            sms_enabled: cfg.sms_enabled,
            apn_protocol: match cfg.apn_protocol.to_ascii_uppercase().as_str() {
                "IP" | "IPV4" => ApnProtocol::Ipv4,
                "IPV6" => ApnProtocol::Ipv6,
                _ => ApnProtocol::Ipv4v6,
            },
            roaming_allowed: cfg.roaming_allowed,
            data_path_intent: DataPathMode::parse(&cfg.data_path_intent),
        }
    }

    /// 组装 `/api/volte/control` 的响应。
    pub async fn control_response(&self) -> VolteControlResponse {
        let cfg = self.config_manager.get_volte_config();
        let sup = self.supervisor.lock().await;
        let st = sup.status();
        let ident = self.identity.lock().await.clone();

        VolteControlResponse {
            feature_enabled: cfg.feature_enabled,
            sms_enabled: cfg.sms_enabled,
            apn_protocol: cfg.apn_protocol.clone(),
            roaming_allowed: cfg.roaming_allowed,
            data_path_intent: cfg.data_path_intent.clone(),
            runtime: VolteRuntimeStatusResponse {
                phase: st.phase.as_str().to_string(),
                stage: st.stage.as_str().to_string(),
                registration_mode: st.registration_mode.map(|m| m.as_str().to_string()),
                session_started_at: st.session_started_at,
                registered_at: st.registered_at,
                last_rx_at: st.last_rx_at,
                last_tx_at: st.last_tx_at,
                last_error: st.last_error.clone(),
                last_failure_at: st.last_failure_at,
                next_retry_at: st.next_retry_at,
                sent_count: st.sent_count,
                received_count: st.received_count,
                duplicate_count: st.duplicate_count,
                reconnect_count: st.reconnect_count,
                data_path_mode: st.data_path_mode.map(|m| m.as_str().to_string()),
                imsi: ident.imsi,
                home_domain: ident.home_domain,
                public_identity: ident.public_identity,
                pcscf: ident.pcscf,
                ue_address: ident.ue_address,
                own_number: ident.own_number,
            },
        }
    }

    /// IMS 是否已注册 —— `/api/ims/status` 用。
    pub async fn is_registered(&self) -> bool {
        self.supervisor.lock().await.status().phase == Phase::Registered
    }

    /// 短信能力：注册成功且 sms_enabled。
    pub async fn sms_capable(&self) -> bool {
        self.supervisor.lock().await.sms_gate().is_ok()
    }

    /// 开关主功能。开启时拉起 worker，关闭时通知 worker 退出。
    pub async fn set_feature_enabled(&self, enabled: bool) -> Result<(), String> {
        {
            let mut cfg = self.config_manager.get_volte_config();
            cfg.feature_enabled = enabled;
            self.config_manager
                .set_volte_config(cfg)
                .map_err(|e| format!("保存 VoLTE 配置失败: {e}"))?;
        }

        let mut sup = self.supervisor.lock().await;
        sup.set_enabled(enabled);
        drop(sup);

        if enabled {
            self.spawn_worker().await;
        } else {
            self.stop_worker().await;
        }
        Ok(())
    }

    pub async fn set_sms_enabled(&self, enabled: bool) -> Result<(), String> {
        let mut cfg = self.config_manager.get_volte_config();
        cfg.sms_enabled = enabled;
        self.config_manager
            .set_volte_config(cfg)
            .map_err(|e| format!("保存 VoLTE 短信开关失败: {e}"))?;
        Ok(())
    }

    /// 部分更新设置。改动会在下一次注册周期生效，因此若当前已注册则触发重注册。
    pub async fn update_settings(
        &self,
        apn_protocol: Option<String>,
        roaming_allowed: Option<bool>,
        data_path_intent: Option<String>,
    ) -> Result<(), String> {
        let mut cfg = self.config_manager.get_volte_config();
        let mut changed = false;

        if let Some(p) = apn_protocol {
            let up = p.to_ascii_uppercase();
            if !matches!(up.as_str(), "IP" | "IPV4" | "IPV6" | "IPV4V6") {
                return Err(format!("不支持的 APN 协议: {p}"));
            }
            if cfg.apn_protocol != up {
                cfg.apn_protocol = up;
                changed = true;
            }
        }
        if let Some(r) = roaming_allowed {
            if cfg.roaming_allowed != r {
                cfg.roaming_allowed = r;
                changed = true;
            }
        }
        if let Some(d) = data_path_intent {
            if !matches!(d.as_str(), "independent_wwan1" | "secondary_qmi_data") {
                return Err(format!("不支持的数据槽位模式: {d}"));
            }
            if cfg.data_path_intent != d {
                cfg.data_path_intent = d;
                changed = true;
            }
        }

        if !changed {
            return Ok(());
        }

        let feature_on = cfg.feature_enabled;
        self.config_manager
            .set_volte_config(cfg)
            .map_err(|e| format!("保存 VoLTE 设置失败: {e}"))?;

        // 已在运行则重启会话，让新设置生效。
        if feature_on {
            self.stop_worker().await;
            self.spawn_worker().await;
        }
        Ok(())
    }

    /// 手动触发一次重新注册。
    pub async fn refresh(&self) -> Result<(), String> {
        let tx = self.command_tx.lock().await.clone();
        match tx {
            Some(tx) => tx
                .send(RuntimeCommand::Refresh)
                .await
                .map_err(|_| crate::volte::err::RUNTIME_COMMAND_CLOSED.to_string()),
            None => Err(crate::volte::err::RUNTIME_NOT_RUNNING.to_string()),
        }
    }

    /// 启动后台 worker。开机自启时也走这里。
    pub async fn spawn_worker(&self) {
        let cfg = self.config_manager.get_volte_config();
        if !cfg.feature_enabled {
            return;
        }
        // 已有 worker 则不重复拉起。
        if self.command_tx.lock().await.is_some() {
            return;
        }

        let (tx, mut rx) = mpsc::channel::<RuntimeCommand>(16);
        *self.command_tx.lock().await = Some(tx);

        let supervisor = Arc::clone(&self.supervisor);
        let identity = Arc::clone(&self.identity);
        let config_manager = Arc::clone(&self.config_manager);

        tokio::spawn(async move {
            info!(target: "simadmin::volte", "Native VoLTE supervisor worker started");

            loop {
                let cfg = config_manager.get_volte_config();
                if !cfg.feature_enabled {
                    let mut sup = supervisor.lock().await;
                    sup.stopped();
                    info!(target: "simadmin::volte", "Native VoLTE runtime stopped by config");
                    break;
                }

                let rt_cfg = Self::runtime_config(&cfg);
                let now = now_unix();

                {
                    let mut sup = supervisor.lock().await;
                    sup.begin(now);
                }

                match Self::run_registration_cycle(
                    &rt_cfg,
                    Arc::clone(&supervisor),
                    Arc::clone(&identity),
                )
                .await
                {
                    Ok(()) => {
                        // 注册成功，进入维持阶段：等命令或到点刷新。
                        let refresh = crate::volte::runtime::REFRESH_INTERVAL;
                        loop {
                            tokio::select! {
                                cmd = rx.recv() => match cmd {
                                    Some(RuntimeCommand::Stop) | None => {
                                        let mut sup = supervisor.lock().await;
                                        sup.stopped();
                                        info!(target: "simadmin::volte", "Native VoLTE runtime stop requested");
                                        return;
                                    }
                                    Some(RuntimeCommand::Refresh) => break,
                                    Some(_) => {}
                                },
                                _ = tokio::time::sleep(refresh) => break,
                            }
                        }
                    }
                    Err(e) => {
                        let delay = {
                            let mut sup = supervisor.lock().await;
                            sup.failed(e.clone(), now_unix())
                        };
                        warn!(
                            target: "simadmin::volte",
                            error = %e,
                            retry_in_secs = delay.as_secs(),
                            "Native VoLTE registration failed; supervisor will retry"
                        );
                        // 退避期间仍要响应停止命令。
                        tokio::select! {
                            cmd = rx.recv() => {
                                if matches!(cmd, Some(RuntimeCommand::Stop) | None) {
                                    let mut sup = supervisor.lock().await;
                                    sup.stopped();
                                    return;
                                }
                            }
                            _ = tokio::time::sleep(delay) => {}
                        }
                    }
                }
            }
        });
    }

    async fn stop_worker(&self) {
        let tx = self.command_tx.lock().await.take();
        if let Some(tx) = tx {
            let _ = tx.send(RuntimeCommand::Stop).await;
        }
        // 给 worker 一点时间收尾，避免立刻重启时两个 worker 并存。
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut sup = self.supervisor.lock().await;
        sup.stopped();
    }

    /// 走一遍完整注册流程。
    ///
    /// 目前实现到「数据面 + P-CSCF 发现」为止，SIP 注册部分依赖真机上的
    /// bearer 就绪，因此每一步都把 stage 写回 supervisor，失败时返回逆向出的
    /// 错误码，方便在设备上按 stage 定位。
    async fn run_registration_cycle(
        cfg: &VolteRuntimeConfig,
        supervisor: Arc<Mutex<VolteSupervisor>>,
        identity: Arc<Mutex<VolteIdentitySnapshot>>,
    ) -> Result<(), String> {
        use crate::volte::{bearer, identity as ident_mod, pcscf};

        // ---- stage: identity ----
        {
            let mut sup = supervisor.lock().await;
            sup.advance(Stage::Identity);
        }

        let imsi = read_imsi().await?;
        let card_status = read_card_status().await;
        let usim_aid = card_status
            .as_deref()
            .and_then(|s| ident_mod::parse_usim_aid(s).ok());
        // SIM 直接报告 MCC+MNC（如 46001），用它定 MNC 位数比启发式可靠。
        let operator_code = read_operator_code().await;

        let id = ident_mod::build(
            &imsi,
            None,
            operator_code.as_deref(),
            usim_aid,
            None,
        )?;
        {
            let mut snap = identity.lock().await;
            *snap = VolteIdentitySnapshot::from_identity(&id);
        }
        info!(
            target: "simadmin::volte",
            imsi_prefix = &id.imsi[..id.imsi.len().min(6)],
            home_domain = %id.home_domain,
            "Native VoLTE runtime identity loaded"
        );

        // ---- stage: modem ----
        {
            let mut sup = supervisor.lock().await;
            sup.advance(Stage::Modem);
        }
        if bearer::qmi_marker_present() {
            info!(
                target: "simadmin::volte",
                marker_age_secs = bearer::qmi_marker_age_secs().unwrap_or(0),
                "QMI auto-activate ready marker present"
            );
        } else {
            warn!(
                target: "simadmin::volte",
                "QMI auto-activate ready marker did not appear; continuing with modem readiness checks"
            );
        }

        // ---- stage: bearer ----
        // IMS PDN 在模组固件里已经激活（CID 2），不需要创建 bearer。
        // 只需确认它已激活并获取 CID。
        {
            let mut sup = supervisor.lock().await;
            sup.advance(Stage::Bearer);
        }
        let defined = run_at(bearer::AT_LIST_CONTEXTS).await;
        let active = run_at(bearer::AT_LIST_ACTIVE).await;
        let cid = bearer::pick_profile(
            &defined
                .as_deref()
                .map(bearer::parse_defined_contexts)
                .unwrap_or_default(),
            &active
                .as_deref()
                .map(bearer::parse_active_contexts)
                .unwrap_or_default(),
        )
        .unwrap_or(2); // fallback to CID 2 (standard IMS CID)

        // 确保 P-CSCF 上报已启用，且承载已激活。
        let _ = run_at(&pcscf::at_enable_pcscf_reporting(cid)).await;
        let _ = run_at(&bearer::at_activate_context(cid)).await;
        // 等待激活完成
        tokio::time::sleep(Duration::from_secs(8)).await;

        // ---- stage: pcscf ----
        {
            let mut sup = supervisor.lock().await;
            sup.advance(Stage::Pcscf);
        }
        let rdp = run_at(&pcscf::at_read_dynamic_params(cid)).await;
        // QMI 托管承载（MM 走 WDS 会话）下 CGCONTRDP 常为空；此时不再硬失败，
        // 把发现工作整体交给注册脚本（脚本支持自发现 + 静态候选兜底）。
        let (local, pcscf_list) = match rdp.as_deref().map(pcscf::parse_cgcontrdp) {
            Some(Ok((l, _gw, list))) => (Some(l), list),
            _ => {
                warn!(
                    target: "simadmin::volte",
                    "CGCONTRDP unavailable; delegating discovery to registration script"
                );
                (None, Vec::new())
            }
        };

        let candidates = pcscf::collect_candidates(&[], &[], &pcscf_list, &[])
            .unwrap_or_default();
        let pcscf_str = candidates
            .first()
            .map(|c| c.addr.to_string())
            .unwrap_or_default();
        {
            let mut snap = identity.lock().await;
            snap.ue_address = local.map(|l| l.to_string());
            snap.pcscf = Some(pcscf_str.clone());
        }
        info!(
            target: "simadmin::volte",
            count = candidates.len(),
            ue = %local.clone().map(|l| l.to_string()).unwrap_or_default(),
            pcscf = %pcscf_str,
            "Native VoLTE P-CSCF candidates discovered from active IMS bearer"
        );

        // 确保路由存在（NM 可能没配 P-CSCF 路由）。
        if !pcscf_str.is_empty() {
            let _ = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "ip -6 route replace {pcscf_str}/128 dev wwan1 metric 5 2>/dev/null"
                ))
                .output();
        }

        // ---- stage: register (SIP over IPsec) ----
        {
            let mut sup = supervisor.lock().await;
            sup.advance(Stage::RegisterIpsec);
        }

        // 运行 Python 注册脚本（含 AKA via QMI proxy + IPsec + SIP REGISTER）。
        // 该脚本已部署为 /opt/simadmin/volte_register.py。
        let reg_out = tokio::process::Command::new("python3")
            .args(["-u", "/opt/simadmin/volte_register.py", &pcscf_str,
                   &local.map(|l| l.to_string()).unwrap_or_default()])
            .env("PYTHONUNBUFFERED", "1")
            .output()
            .await
            .map_err(|e| format!("volte_register.py spawn: {e}"))?;

        let stdout = String::from_utf8_lossy(&reg_out.stdout);
        let stderr = String::from_utf8_lossy(&reg_out.stderr);
        info!(
            target: "simadmin::volte",
            stdout = %stdout,
            stderr = %stderr,
            "VoLTE registration script completed"
        );

        // 解析最后一行 JSON 结果。
        let json_line = stdout
            .lines()
            .rev()
            .find(|l| l.starts_with('{'))
            .ok_or_else(|| "volte_register: no JSON output".to_string())?;
        let result: serde_json::Value = serde_json::from_str(json_line)
            .map_err(|e| format!("volte_register JSON parse: {e}"))?;

        if result["registered"].as_bool() == Some(true) {
            let registered_pcscf = result["pcscf"].as_str().unwrap_or(pcscf_str.as_str()).to_string();
            let registered_ue = result["ue_addr"].as_str().unwrap_or("").to_string();
            {
                let mut snap = identity.lock().await;
                snap.pcscf = Some(registered_pcscf.clone());
                snap.ue_address = Some(registered_ue.clone());
            }
            {
                let mut sup = supervisor.lock().await;
                sup.registered(
                    RegistrationMode::Ipsec,
                    now_unix(),
                    DataPathMode::IndependentWwan1,
                );
            }
            info!(
                target: "simadmin::volte",
                pcscf = %registered_pcscf,
                "Native VoLTE runtime registered with 3GPP IPsec and listening"
            );
            return Ok(());
        }

        Err(format!(
            "volte_register: {}",
            result["error"].as_str().unwrap_or("unknown error")
        ))
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 通过 mmcli 的 AT 通道跑一条命令。失败返回 `None`，由调用方决定是否致命。
async fn run_at(cmd: &str) -> Option<String> {
    let out = tokio::process::Command::new("mmcli")
        .args(["-m", "any", "--command", cmd, "--timeout", "10"])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&out.stdout).into_owned();
    Some(strip_mmcli_response(&raw))
}

/// 从 mmcli 的 AT 响应里剥出裸内容。
///
/// mmcli 不会原样吐出模组回复，而是包一层：
///
/// ```text
/// response: '460018558516337'
/// ```
///
/// 早先的实现要求整行全是数字，于是这种带前缀和引号的输出永远匹配不上 ——
/// 明明命令成功了却被判成失败（`volte_imsi_missing`）。
pub fn strip_mmcli_response(raw: &str) -> String {
    let mut out = String::new();
    for line in raw.lines() {
        let t = line.trim();
        // mmcli wraps the response in `response: '...'`
        let body = match t.strip_prefix("response:") {
            Some(r) => r.trim(),
            None => t,
        };
        // Strip surrounding single quotes (mmcli wraps multi-line in one pair)
        let body = if body.starts_with('\'') && body.ends_with('\'') && body.len() >= 2 {
            &body[1..body.len() - 1]
        } else {
            body
        };
        // Unescape literal \r\n sequences (mmcli encodes newlines as escapes
        // inside the quoted block for multi-line AT responses)
        let body = body.replace("\\r\\n", "\r\n");
        for line in body.split("\r\n") {
            let t = line.trim();
            if t.is_empty() || t == "OK" {
                continue;
            }
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(t);
        }
    }
    out
}

/// 从 mmcli SIM 对象读一个字段。
///
/// IMSI 不挂在 modem 对象上，只在 SIM 对象上：
/// `mmcli -i <idx> --output-keyvalue` → `sim.properties.imsi`。
/// 之前查 `mmcli -m any --output-keyvalue` 的 imsi 字段，实测 0 命中。
async fn sim_property(key: &str) -> Option<String> {
    // SIM 索引通常与 modem 索引一致；先试 0，再从 modem 属性里解析真实路径。
    for idx in ["0", "1"] {
        let out = tokio::process::Command::new("mmcli")
            .args(["-i", idx, "--output-keyvalue"])
            .output()
            .await
            .ok()?;
        if !out.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim() == key {
                    let v = v.trim();
                    if !v.is_empty() && v != "--" {
                        return Some(v.to_string());
                    }
                }
            }
        }
    }
    None
}

async fn read_imsi() -> Result<String, String> {
    // 首选 AT+CIMI，它直接问模组，不受 MM 缓存影响。
    if let Some(resp) = run_at(crate::volte::identity::AT_CIMI).await {
        let body = strip_mmcli_response(&resp);
        let digits: String = body.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() >= 14 {
            return Ok(digits);
        }
    }
    warn!(
        target: "simadmin::volte",
        "Native VoLTE ModemManager AT+CIMI failed, using SIM IMSI fallback"
    );

    match sim_property("sim.properties.imsi").await {
        Some(v) => {
            let digits: String = v.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 14 {
                Ok(digits)
            } else {
                Err(crate::volte::err::MM_IMSI_MISSING.to_string())
            }
        }
        None => Err(crate::volte::err::IMSI_MISSING.to_string()),
    }
}

/// SIM 报告的归属运营商码（MCC+MNC），用于确定 MNC 位数而不靠启发式。
async fn read_operator_code() -> Option<String> {
    sim_property("sim.properties.operator-code").await
}

async fn read_card_status() -> Option<String> {
    let out = tokio::process::Command::new("qmicli")
        .args([
            "--device=/dev/wwan0qmi0",
            "--device-open-proxy",
            crate::ims_uim::QMI_CARD_STATUS,
        ])
        .output()
        .await
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}
