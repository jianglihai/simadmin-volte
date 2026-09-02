#!/bin/sh
# ============================================================
# SimAdmin-VoLTE 独立一键安装（全新设备 / 无旧部署也可用）
#
# 用法：
#   curl -fsSL https://github.com/jianglihai/simadmin-volte/releases/download/v1.1.12/install.sh | sh
#
# 说明：本脚本是 install_latest.sh 的 fork 入口（默认指向
# jianglihai/simadmin-volte 的 release，包内含 VoLTE/IMS 全量文件：
# 二进制 + 前端 + volte_register/volte_sms_send/qmi.py + systemd 单元）。
# 官方原版安装：REPO=3899/SimAdmin sh install_latest.sh
# ============================================================
set -eu
REPO="${REPO:-jianglihai/simadmin-volte}"
export REPO
BRANCH="${BRANCH:-main}"

if command -v curl >/dev/null 2>&1; then
  sh -c "$(curl -fsSL "https://raw.githubusercontent.com/$REPO/$BRANCH/install_latest.sh")"
else
  sh -c "$(wget -qO- "https://raw.githubusercontent.com/$REPO/$BRANCH/install_latest.sh")"
fi
