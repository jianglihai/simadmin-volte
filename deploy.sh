#!/usr/bin/env bash
# ============================================================
# 一键部署：从 GitHub 拉取最新 release 包并部署 SimAdmin-volte
#
# 用法（设备上直接运行，需要 WiFi 出网下载 GitHub）：
#   curl -fsSL https://github.com/jianglihai/simadmin-volte/releases/download/v1.1.12/deploy.sh | bash
#
# 或本地已有脚本：
#   bash deploy.sh
#   bash deploy.sh v1.1.12        # 指定版本
#   bash deploy.sh <github_url>    # 直接给 tar.gz 下载链接
#
# 环境要求：bash、curl、tar、systemctl、md5sum、strings/grep
# 作者：Hermes Agent
# ============================================================
set -euo pipefail

OWNER=jianglihai
REPO=simadmin-volte
DEFAULT_TAG=v1.1.12
BACKUP_ROOT=/opt
BINARY_PATH=/opt/simadmin/simadmin
OTA_DIR=/tmp/simadmin-ota-$$

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
die()  { printf '\n[ERROR] %s\n' "$*" >&2; exit 1; }

TAG="${1:-$DEFAULT_TAG}"
if [[ "$TAG" == http* ]]; then DOWNLOAD_URL="$TAG"; else
  DOWNLOAD_URL="https://github.com/$OWNER/$REPO/releases/download/$TAG/simadmin-aarch64.tar.gz"
fi
log "release 版本: $TAG"
log "下载: $DOWNLOAD_URL"

# 1) 系统前置检查 ------------------------------------------------
command -v curl >/dev/null || die "缺少 curl"
command -v tar  >/dev/null || die "缺少 tar"
command -v systemctl >/dev/null || die "缺少 systemctl（此设备不跑 systemd？）"
command -v md5sum >/dev/null || die "缺少 md5sum"
[[ "$(uname -m)" == "aarch64" ]] || die "本脚本只提供 aarch64 包；当前架构: $(uname -m)"
[[ -f "$BINARY_PATH" ]] || die "未找到旧二进制 $BINARY_PATH（服务未部署？）"

log "磁盘: $(df -h / | tail -1)"

# 2) 下载 --------------------------------------------------------
cd "$OTA_DIR"
mkdir -p "$OTA_DIR"
curl -fsSL --retry 3 -o simadmin-aarch64.tar.gz "$DOWNLOAD_URL" \
  || die "下载失败（检查网络 / release 是否存在）"
log "下载完成: $(ls -la simadmin-aarch64.tar.gz | awk '{print $5, $9}')"

# 3) 校验 md5：包内 meta.json 的 binary_md5 必须等于解压出的二进制 md5 ----
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

# 4) 备份 --------------------------------------------------------
backup_ts=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$BACKUP_ROOT/simadmin-backup-${backup_ts}"
mkdir -p "$BACKUP_DIR"
cp -a "$BINARY_PATH" "$BACKUP_DIR/"
log "旧二进制已备份 -> $BACKUP_DIR/simadmin (md5: $(md5sum "$BINARY_PATH" | awk '{print $1}'))"

# 5) 部署 --------------------------------------------------------
tar xzf simadmin-aarch64.tar.gz -C /opt/simadmin/ --no-same-owner
chmod 755 "$BINARY_PATH"
log "部署完成: $(md5sum "$BINARY_PATH" | awk '{print $1}')"

# 6) 重启 + 等待健康 --------------------------------------------
systemctl restart simadmin >/dev/null 2>&1 || true
log "等待服务就绪..."
for i in $(seq 1 12); do
  if curl -sf "http://127.0.0.1:3000/api/health" >/dev/null 2>&1; then
    log "服务就绪 (第 ${i} 秒)"
    break
  fi
  [[ $i -eq 12 ]] && die "服务未在 30s 内就绪，请查看: journalctl -u simadmin -n 40"
  sleep 2.5
done

# 7) 冒烟测试：页面发送接口（发一条空内容探测，只看接口是否活着）----------
code=$(curl -s -m 12 -o /dev/null -w "%{http_code}" "http://127.0.0.1:3000/api/sms/list?limit=1" 2>/dev/null || echo 000)
if [[ "$code" == "200" ]]; then
  log "健康检查通过 (GET /api/sms/list = 200)"
else
  log "⚠ 接口异常 (HTTP $code)，请看日志: journalctl -u simadmin -n 60"
fi

log "版本: $(cat /opt/simadmin/simadmin* 2>/dev/null >/dev/null; "$BINARY_PATH" --version 2>/dev/null || echo 1.1.12)"
log "=== 部署完成 ==="
log "  新版本 md5 : $real_md5  commit: $meta_commit"
log "  回滚命令   : cp $BACKUP_DIR/simadmin $BINARY_PATH && systemctl restart simadmin"
log "  回滚备份   : $BACKUP_DIR"

# 清理临时目录
rm -rf "$OTA_DIR"
