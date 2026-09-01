#!/usr/bin/env bash
# ============================================================
# 一键部署：从 GitHub 拉取最新 release 包并部署 SimAdmin-volte
#
# 用法：
#   bash deploy.sh                # 默认版本
#   bash deploy.sh v1.1.12        # 指定版本
#   bash deploy.sh <github_url>   # 直接给 tar.gz 下载链接
#
# 修复记录（fix1, 2026-09-01）：
#   1. [致命] cd "$OTA_DIR" 在 mkdir -p 之前 -> 调换顺序
#   2. [新增] 全新安装支持：无旧二进制时不再退出，自动装 systemd 单元
#   3. [新增] GitHub 下载失败时回退 gh 代理镜像
#   4. [修复] tar 解压前确保 /opt/simadmin 存在
#   5. [清理] 删除无意义的 cat 残留代码
# ============================================================
set -euo pipefail

OWNER=jianglihai
REPO=simadmin-volte
DEFAULT_TAG=v1.1.12
BACKUP_ROOT=/opt
INSTALL_DIR=/opt/simadmin
BINARY_PATH=/opt/simadmin/simadmin
OTA_DIR=/tmp/simadmin-ota-$$
GH_PROXIES=("" "https://gh-proxy.com/" "https://ghproxy.net/")

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
die()  { printf '\n[ERROR] %s\n' "$*" >&2; exit 1; }

TAG="${1:-$DEFAULT_TAG}"
if [[ "$TAG" == http* ]]; then DOWNLOAD_URL="$TAG"; else
  DOWNLOAD_URL="https://github.com/$OWNER/$REPO/releases/download/$TAG/simadmin-aarch64.tar.gz"
fi

# GitHub 下载（直连失败自动换代理镜像）
gh_download() { # $1=url $2=outfile
  local url="$1" out="$2" p
  for p in "${GH_PROXIES[@]}"; do
    if curl -fsSL --retry 2 --connect-timeout 15 -o "$out" "${p}${url}"; then
      [[ -n "$p" ]] && log "使用镜像: ${p}"
      return 0
    fi
  done
  return 1
}

# 1) 系统前置检查 ------------------------------------------------
command -v curl >/dev/null || die "缺少 curl"
command -v tar  >/dev/null || die "缺少 tar"
command -v systemctl >/dev/null || die "缺少 systemctl（此设备不跑 systemd？）"
command -v md5sum >/dev/null || die "缺少 md5sum"
[[ "$(uname -m)" == "aarch64" ]] || die "本脚本只提供 aarch64 包；当前架构: $(uname -m)"

FRESH_INSTALL=0
if [[ -f "$BINARY_PATH" ]]; then
  log "检测到已有部署 -> OTA 升级模式"
else
  FRESH_INSTALL=1
  log "未找到 $BINARY_PATH -> 全新安装模式"
fi

log "磁盘: $(df -h / | tail -1)"

# 2) 下载 --------------------------------------------------------
# [fix1] 必须先 mkdir 再 cd
mkdir -p "$OTA_DIR"
cd "$OTA_DIR"
log "release 版本: $TAG"
log "下载: $DOWNLOAD_URL"
gh_download "$DOWNLOAD_URL" simadmin-aarch64.tar.gz \
  || die "下载失败（直连+镜像均失败，检查网络 / release 是否存在）"
log "下载完成: $(ls -la simadmin-aarch64.tar.gz | awk '{print $5, $9}')"

# 3) 校验 md5 ----------------------------------------------------
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

# 4) 备份（仅 OTA 模式）------------------------------------------
if [[ $FRESH_INSTALL -eq 0 ]]; then
  backup_ts=$(date +%Y%m%d_%H%M%S)
  BACKUP_DIR="$BACKUP_ROOT/simadmin-backup-${backup_ts}"
  mkdir -p "$BACKUP_DIR"
  cp -a "$BINARY_PATH" "$BACKUP_DIR/"
  log "旧二进制已备份 -> $BACKUP_DIR/simadmin (md5: $(md5sum "$BINARY_PATH" | awk '{print $1}'))"
fi

# 5) 部署 --------------------------------------------------------
# [fix4] 确保安装目录存在
mkdir -p "$INSTALL_DIR"
systemctl stop simadmin >/dev/null 2>&1 || true
tar xzf simadmin-aarch64.tar.gz -C "$INSTALL_DIR/" --no-same-owner
chmod 755 "$BINARY_PATH"
log "部署完成: $(md5sum "$BINARY_PATH" | awk '{print $1}')"

# 5.5) 全新安装：装 systemd 单元 ---------------------------------
if [[ $FRESH_INSTALL -eq 1 ]] || [[ ! -f /etc/systemd/system/simadmin.service ]]; then
  log "安装 systemd 单元..."
  if gh_download "https://raw.githubusercontent.com/$OWNER/$REPO/main/scripts/simadmin.service" \
      /etc/systemd/system/simadmin.service; then
    log "simadmin.service 已安装"
  else
    die "下载 simadmin.service 失败"
  fi
  systemctl daemon-reload
  systemctl enable simadmin >/dev/null 2>&1 || true
fi

# 6) 重启 + 等待健康 --------------------------------------------
systemctl restart simadmin
log "等待服务就绪..."
for i in $(seq 1 12); do
  if curl -sf "http://127.0.0.1:3000/api/health" >/dev/null 2>&1; then
    log "服务就绪 (第 ${i} 次探测)"
    break
  fi
  [[ $i -eq 12 ]] && die "服务未就绪，请查看: journalctl -u simadmin -n 40"
  sleep 2.5
done

# 7) 冒烟测试 ----------------------------------------------------
code=$(curl -s -m 12 -o /dev/null -w "%{http_code}" "http://127.0.0.1:3000/api/sms/list?limit=1" 2>/dev/null || echo 000)
if [[ "$code" == "200" ]]; then
  log "健康检查通过 (GET /api/sms/list = 200)"
else
  log "⚠ 接口异常 (HTTP $code)，请看日志: journalctl -u simadmin -n 60"
fi

log "版本: $("$BINARY_PATH" --version 2>/dev/null || echo "$TAG")"
log "=== 部署完成 ==="
log "  新版本 md5 : $real_md5  commit: $meta_commit"
if [[ $FRESH_INSTALL -eq 0 ]]; then
  log "  回滚命令   : cp $BACKUP_DIR/simadmin $BINARY_PATH && systemctl restart simadmin"
  log "  回滚备份   : $BACKUP_DIR"
else
  log "  模式       : 全新安装（无回滚备份）"
fi

# 清理临时目录
rm -rf "$OTA_DIR"
