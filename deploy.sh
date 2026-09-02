#!/usr/bin/env bash
# ============================================================
# 一键部署：从 GitHub 拉取最新 release 包并部署 SimAdmin-VoLTE
#
# 用法（设备上直接运行，需要出网访问 GitHub）：
#   curl -fsSL https://github.com/jianglihai/simadmin-volte/releases/download/v1.1.12/deploy.sh | bash
#
# 或本地已有脚本：
#   bash deploy.sh
#   bash deploy.sh v1.1.12        # 指定版本
#   bash deploy.sh <github_url>   # 直接给 tar.gz 下载链接
#
# 部署内容 = OTA 包全量文件：simadmin + www/ + meta.json
#            + volte_register.py / volte_sms_send.py / qmi.py
#            + simadmin.service / simadmin-modem-recovery.service
# 全量备份 + 全量回滚；支持全新设备（无旧部署）直接安装。
# 环境要求：bash、curl、tar、systemctl、md5sum
# ============================================================
set -euo pipefail

OWNER=jianglihai
REPO=simadmin-volte
DEFAULT_TAG=v1.1.12
INSTALL_DIR=/opt/simadmin
BINARY_PATH="$INSTALL_DIR/simadmin"
SERVICE_NAME=simadmin
UNIT_DIR=/etc/systemd/system
OTA_DIR=/tmp/simadmin-ota-$$

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
die()  { printf '\n[ERROR] %s\n' "$*" >&2; exit 1; }

TAG="${1:-$DEFAULT_TAG}"
if [[ "$TAG" == http* ]]; then
  DOWNLOAD_URL="$TAG"
else
  DOWNLOAD_URL="https://github.com/$OWNER/$REPO/releases/download/$TAG/simadmin-aarch64.tar.gz"
fi
log "release 版本: $TAG"
log "下载: $DOWNLOAD_URL"

# 1) 系统前置检查 ------------------------------------------------
command -v curl >/dev/null      || die "缺少 curl"
command -v tar >/dev/null       || die "缺少 tar"
command -v systemctl >/dev/null || die "缺少 systemctl（此设备不跑 systemd？）"
command -v md5sum >/dev/null    || die "缺少 md5sum"
[[ "$(uname -m)" == "aarch64" ]] || die "当前只有 aarch64 包；本机架构: $(uname -m)"

if [[ -f "$BINARY_PATH" ]]; then
  log "检测到已有部署: $BINARY_PATH (md5: $(md5sum "$BINARY_PATH" | awk '{print $1}'))"
else
  log "未检测到旧部署，将执行全新安装（systemd 单元 + /opt/simadmin 全量）"
fi
log "磁盘: $(df -h / | tail -1)"

# 2) 下载 --------------------------------------------------------
mkdir -p "$OTA_DIR"
cd "$OTA_DIR"
curl -fsSL --retry 3 -o simadmin-aarch64.tar.gz "$DOWNLOAD_URL" \
  || die "下载失败（检查网络 / release 是否存在）"
log "下载完成: $(ls -la simadmin-aarch64.tar.gz | awk '{print $5, $9}')"

# 3) 完整性校验：meta.json 的 binary_md5 必须与包内二进制一致 ------
meta=$(tar xzf simadmin-aarch64.tar.gz -O meta.json) || die "包内无 meta.json"
log "meta.json: $meta"
meta_bin_md5=$(printf '%s' "$meta" | grep -o '"binary_md5": *"[0-9a-f]\{32\}"' | head -1 | grep -o '[0-9a-f]\{32\}')
meta_commit=$(printf '%s' "$meta" | grep -o '"commit": *"[^"]*"' | head -1 | grep -o '"[a-z0-9]\{7\}"' | tr -d '"')
[[ -n "$meta_bin_md5" ]] || die "meta.json 中未找到 binary_md5"

real_md5=$(tar xzf simadmin-aarch64.tar.gz -O simadmin | md5sum | awk '{print $1}')
if [[ "$meta_bin_md5" != "$real_md5" ]]; then
  die "md5 不一致！meta.json 声称 $meta_bin_md5，实际二进制 $real_md5 —— 包可能损坏，中止部署"
fi
log "md5 校验通过: $meta_bin_md5 (commit: $meta_commit)"

# 4) 全量备份（二进制 + www + 脚本 + 单元 + meta）-----------------
backup_ts=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$INSTALL_DIR-backup-${backup_ts}"
mkdir -p "$BACKUP_DIR"
for item in simadmin www meta.json volte_register.py volte_sms_send.py qmi.py \
            "$UNIT_DIR/simadmin.service" "$UNIT_DIR/simadmin-modem-recovery.service" \
            "$INSTALL_DIR/simadmin.service" "$INSTALL_DIR/simadmin-modem-recovery.service"; do
  [[ -e "$item" ]] && cp -a "$item" "$BACKUP_DIR/" 2>/dev/null || true
done
log "全量备份 -> $BACKUP_DIR"

# 5) 部署（全量文件落位）------------------------------------------
tar xzf simadmin-aarch64.tar.gz -C "$INSTALL_DIR/" --no-same-owner
chmod 755 "$BINARY_PATH"
# git 检出/下载路径可能带入 CRLF，python 脚本必须转 unix 行尾
for _PY in volte_register.py volte_sms_send.py qmi.py; do
  if [[ -f "$INSTALL_DIR/$_PY" ]]; then
    sed -i 's/\r$//' "$INSTALL_DIR/$_PY"
    chmod 755 "$INSTALL_DIR/$_PY"
  fi
done

# 6) 安装 systemd 单元（全新设备必需）-----------------------------
installed_unit=0
for _UNIT in simadmin.service simadmin-modem-recovery.service; do
  if [[ -f "$INSTALL_DIR/$_UNIT" ]]; then
    if [[ ! -f "$UNIT_DIR/$_UNIT" ]] || ! cmp -s "$INSTALL_DIR/$_UNIT" "$UNIT_DIR/$_UNIT"; then
      cp -f "$INSTALL_DIR/$_UNIT" "$UNIT_DIR/$_UNIT"
      installed_unit=1
      log "systemd 单元已安装: $UNIT_DIR/$_UNIT"
    fi
  fi
done
if [[ $installed_unit -eq 1 ]]; then
  systemctl daemon-reload
fi
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true

# 7) 部署完整性自检 ------------------------------------------------
missing=""
for f in simadmin meta.json volte_register.py volte_sms_send.py qmi.py; do
  [[ -f "$INSTALL_DIR/$f" ]] || missing="$missing $f"
done
[[ -d "$INSTALL_DIR/www" ]] || missing="$missing www/"
[[ -z "$missing" ]] || die "部署不完整，缺少:$missing （备份在 $BACKUP_DIR，可回滚）"
log "部署完整性 OK: $(md5sum "$BINARY_PATH" | awk '{print $1}')"

# 8) 重启 + 等待健康 ----------------------------------------------
systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || true
log "等待服务就绪..."
ready=0
for i in $(seq 1 12); do
  if curl -sf "http://127.0.0.1:3000/api/health" >/dev/null 2>&1; then
    log "服务就绪 (第 ${i} 次探测)"
    ready=1
    break
  fi
  sleep 2.5
done
[[ $ready -eq 1 ]] || die "服务未就绪，查看: journalctl -u $SERVICE_NAME -n 40"

# 9) 冒烟测试 ------------------------------------------------------
code=$(curl -s -m 12 -o /dev/null -w "%{http_code}" "http://127.0.0.1:3000/api/sms/list?limit=1" 2>/dev/null || echo 000)
if [[ "$code" == "200" ]]; then
  log "健康检查通过 (GET /api/sms/list = 200)"
else
  log "⚠ 接口异常 (HTTP $code)，请看日志: journalctl -u $SERVICE_NAME -n 60"
fi

log "=== 部署完成 ==="
log "  版本      : $meta_commit (binary md5 $real_md5)"
log "  全量备份  : $BACKUP_DIR"
log "  全量回滚  : systemctl stop $SERVICE_NAME; cp -a $BACKUP_DIR/* $INSTALL_DIR/ 2>/dev/null; [[ -f $BACKUP_DIR/simadmin.service ]] && cp $BACKUP_DIR/simadmin.service $UNIT_DIR/; systemctl daemon-reload && systemctl restart $SERVICE_NAME"

rm -rf "$OTA_DIR"
