//! IMS MT 短信监听（SIP MESSAGE over IPsec）
//!
//! 注册成功后绑定 UE 的 port_s（47482）接收网络侧 MT 短信：
//! SIP MESSAGE（Content-Type: application/vnd.3gpp.sms）→ RP-DATA
//! → SMS-DELIVER → 去重入库 → 200 OK（RP-ACK body，TS 24.341）。
//!
//! 与注册脚本共存：双方都开 SO_REUSEADDR。Linux 单播 UDP 在多绑定
//! 时投递给最后绑定者，脚本短暂持有端口（REGISTER#2 等 200 OK）期间
//! 响应归脚本；脚本退出后本监听恢复接收。

use crate::db::{beijing_sms_now_string, Database, SmsMessage};
use crate::ims_sms::{
    decode_rp_data, decode_sms_deliver, duplicate_key, encode_rp_ack, MultipartCache,
    MultipartOutcome,
};
use crate::notification::NotificationSender;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{error, info, warn};

/// 与 /opt/simadmin/volte_register.py 的 UE_PORT_S 保持一致。
pub const MT_SIP_PORT: u16 = 47482;

static LISTENER_STARTED: AtomicBool = AtomicBool::new(false);

lazy_static::lazy_static! {
    /// 期望监听的 UE 地址：重注册后地址可能变化（承载重连 -> 新 SLAAC），
    /// 监听任务定期核对并重绑。
    static ref DESIRED_UE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
}

/// 注册成功后调用；进程内只启动一次，重复调用只更新目标地址。
pub fn spawn_mt_listener(ue: String, db: Arc<Database>, notifier: Arc<NotificationSender>) {
    if ue.is_empty() {
        return;
    }
    if let Ok(mut want) = DESIRED_UE.lock() {
        if want.as_deref() != Some(ue.as_str()) {
            info!(target: "simadmin::volte", %ue, "IMS MT listener target address updated");
            *want = Some(ue);
        }
    }
    if LISTENER_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    tokio::spawn(async move {
        if let Err(e) = run(db, notifier).await {
            error!(target: "simadmin::volte", error = %e, "IMS MT SMS listener exited");
        }
    });
}

async fn run(db: Arc<Database>, notifier: Arc<NotificationSender>) -> Result<(), String> {
    let multipart = Arc::new(MultipartCache::new());
    let mut buf = vec![0u8; 65535];
    let mut socket: Option<Arc<UdpSocket>> = None;
    let mut bound_ue: Option<String> = None;
    loop {
        // 地址变化（或首次）时重绑。
        let want = DESIRED_UE.lock().ok().and_then(|g| g.as_ref().clone());
        if bound_ue != want {
            drop(socket.take());
            bound_ue = None;
            if let Some(ue) = want {
                match bind_reuse(&ue) {
                    Ok(s) => {
                        info!(target: "simadmin::volte", %ue, "IMS MT SMS listener bound");
                        socket = Some(Arc::new(s));
                        bound_ue = Some(ue);
                    }
                    Err(e) => {
                        warn!(target: "simadmin::volte", error = %e, "MT listener bind failed");
                    }
                }
            }
            if socket.is_none() {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                continue;
            }
        }
        let sock = socket.as_ref().expect("socket present");
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            sock.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok((len, peer))) => {
                let reply = handle_packet(&buf[..len], &db, &notifier, &multipart).await;
                if let Some(response) = reply {
                    let _ = sock.send_to(&response, peer).await;
                }
            }
            Ok(Err(e)) => {
                warn!(target: "simadmin::volte", error = %e, "MT listener recv error");
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Err(_) => {} // 超时：回到循环头核对目标地址
        }
    }
}

fn bind_reuse(ue: &str) -> Result<UdpSocket, String> {
    use socket2::{Domain, Protocol, Socket, Type};
    let addr: std::net::SocketAddr = format!("[{ue}]:{MT_SIP_PORT}")
        .parse()
        .map_err(|e| format!("MT listener addr parse: {e}"))?;
    let domain = match addr {
        std::net::SocketAddr::V4(_) => Domain::IPV4,
        std::net::SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| format!("MT listener socket: {e}"))?;
    sock.set_reuse_address(true)
        .map_err(|e| format!("MT listener reuseaddr: {e}"))?;
    sock.bind(&addr.into())
        .map_err(|e| format!("MT listener bind: {e}"))?;
    sock.set_nonblocking(true)
        .map_err(|e| format!("MT listener nonblocking: {e}"))?;
    let std_sock: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_sock).map_err(|e| format!("MT listener tokio: {e}"))
}

/// 处理一个入包；返回要回发的响应（无则 None）。
async fn handle_packet(
    data: &[u8],
    db: &Database,
    notifier: &Arc<NotificationSender>,
    multipart: &MultipartCache,
) -> Option<Vec<u8>> {
    let (head, body) = split_sip(data)?;
    let first = head.lines().next()?.to_string();

    if first.starts_with("SIP/2.0") {
        return None; // 响应，不归 MT 监听管
    }
    if !first.starts_with("MESSAGE ") {
        // OPTIONS 等其它请求：按通用格式回 200（空体）。
        if first.contains(" SIP/2.0") {
            return Some(build_response(&head, None, "200 OK"));
        }
        return None;
    }

    let rp = match decode_rp_data(body) {
        Ok(v) => v,
        Err(e) => {
            warn!(target: "simadmin::volte", error = %e, "MT RP-DATA decode failed");
            return Some(build_response(&head, None, "400 Bad RP-DATA"));
        }
    };
    let deliver = match decode_sms_deliver(&rp.tpdu) {
        Ok(v) => v,
        Err(e) => {
            warn!(target: "simadmin::volte", error = %e, "MT SMS-DELIVER decode failed");
            return Some(build_response(&head, None, "400 Bad TPDU"));
        }
    };

    let outcome = match multipart.offer(&deliver) {
        Ok(v) => v,
        Err(e) => {
            warn!(target: "simadmin::volte", error = %e, "MT multipart offer failed");
            return Some(build_response(&head, Some(rp.reference), "500 Multipart error"));
        }
    };
    let (sender, text) = match outcome {
        MultipartOutcome::Buffered { have, total } => {
            info!(target: "simadmin::volte", have, total, "IMS MT multipart segment buffered");
            return Some(build_response(&head, Some(rp.reference), "200 OK"));
        }
        MultipartOutcome::Complete { sender, text } => (sender, text),
    };

    // 重传去重：同一 (sender, scts, text) 只入库一次。
    let marker = duplicate_key(&sender, &deliver.scts, &text);
    match db.sms_exists_by_pdu(&marker) {
        Ok(true) => {
            info!(target: "simadmin::volte", sender = %sender, "IMS MT SMS duplicate, ack only");
            return Some(build_response(&head, Some(rp.reference), "200 OK"));
        }
        Ok(false) => {}
        Err(e) => warn!(target: "simadmin::volte", error = %e, "MT dedup check failed"),
    }

    let now = beijing_sms_now_string();
    match db.insert_sms_at("incoming", &sender, &text, &now, "received", Some(&marker)) {
        Ok(id) => {
            info!(target: "simadmin::volte", sender = %sender, id, "IMS MT SMS stored");
            let sms = SmsMessage {
                id,
                direction: "incoming".to_string(),
                phone_number: sender.clone(),
                content: text.clone(),
                timestamp: now,
                status: "received".to_string(),
                pdu: Some(marker),
            };
            let nf = Arc::clone(notifier);
            tokio::spawn(async move {
                let _ = nf.forward_sms(&sms).await;
            });
        }
        Err(e) => warn!(target: "simadmin::volte", error = %e, "Failed to store IMS MT SMS"),
    }

    Some(build_response(&head, Some(rp.reference), "200 OK"))
}

/// 按 \r\n\r\n 切出头部与体（体保持原始字节，Content-Length 以内）。
fn split_sip(data: &[u8]) -> Option<(String, &[u8])> {
    let pos = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)?;
    let head = String::from_utf8_lossy(&data[..pos]).into_owned();
    let rest = &data[pos..];
    let clen = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(rest.len());
    let body = &rest[..clen.min(rest.len())];
    Some((head, body))
}

/// 构造 SIP 响应：镜像 Via/From/To/Call-ID/CSeq；`rp_ack` 有值时带
/// application/vnd.3gpp.sms 体（TS 24.341 RP-ACK）。
fn build_response(head: &str, rp_ack: Option<u8>, status: &str) -> Vec<u8> {
    let mut via = String::new();
    let mut from = String::new();
    let mut to = String::new();
    let mut call_id = String::new();
    let mut cseq = String::new();
    for line in head.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        let grab = |dst: &mut String, l: &str| {
            if let Some((_, v)) = l.split_once(':') {
                *dst = v.trim().to_string();
            }
        };
        if via.is_empty() && lower.starts_with("via:") {
            grab(&mut via, line);
        } else if from.is_empty() && lower.starts_with("from:") {
            grab(&mut from, line);
        } else if to.is_empty() && lower.starts_with("to:") {
            grab(&mut to, line);
        } else if call_id.is_empty() && lower.starts_with("call-id:") {
            grab(&mut call_id, line);
        } else if cseq.is_empty() && lower.starts_with("cseq:") {
            grab(&mut cseq, line);
        }
    }
    if !to.is_empty() && !to.to_ascii_lowercase().contains("tag=") {
        let tag = format!("{:x}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 + d.as_secs())
            .unwrap_or(0));
        to.push_str(&format!(";tag={}", &tag[..8.min(tag.len())]));
    }

    let ack_body: Option<Vec<u8>> = rp_ack.map(encode_rp_ack);
    let mut out = String::new();
    out.push_str(&format!("SIP/2.0 {status}\r\n"));
    out.push_str(&format!("Via: {via}\r\n"));
    out.push_str(&format!("From: {from}\r\n"));
    out.push_str(&format!("To: {to}\r\n"));
    out.push_str(&format!("Call-ID: {call_id}\r\n"));
    out.push_str(&format!("CSeq: {cseq}\r\n"));
    match &ack_body {
        Some(b) => {
            out.push_str("Content-Type: application/vnd.3gpp.sms\r\n");
            out.push_str(&format!("Content-Length: {}\r\n\r\n", b.len()));
        }
        None => out.push_str("Content-Length: 0\r\n\r\n"),
    }
    let mut bytes = out.into_bytes();
    if let Some(b) = ack_body {
        bytes.extend_from_slice(&b);
    }
    bytes
}
