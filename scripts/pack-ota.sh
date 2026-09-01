#!/bin/bash

# 打包 OTA 更新包
# 输出: release/simadmin_{version}_{target}.tar.gz

set -e

# 切换到项目根目录
cd "$(dirname "$0")/.."
PROJ_ROOT="$(pwd)"

# 记录调用者所在目录（输出路径锚点）

TARGET="${TARGET:-aarch64-unknown-linux-musl}"
for arg in "$@"; do
    case "$arg" in
        --target=aarch64|--target=arm64|--target=aarch64-unknown-linux-musl)
            TARGET="aarch64-unknown-linux-musl"
            ;;
        --target=x86_64|--target=amd64|--target=x86_64-unknown-linux-musl)
            TARGET="x86_64-unknown-linux-musl"
            ;;
        --help|-h)
            echo "用法: ./scripts/pack-ota.sh [--target=aarch64|x86_64]"
            exit 0
            ;;
        *)
            echo "❌ 错误: 未知选项: $arg" >&2
            exit 1
            ;;
    esac
done

case "$TARGET" in
    aarch64|arm64) TARGET="aarch64-unknown-linux-musl" ;;
    x86_64|amd64) TARGET="x86_64-unknown-linux-musl" ;;
    aarch64-unknown-linux-musl|x86_64-unknown-linux-musl) ;;
    *)
        echo "❌ 错误: 不支持的构建目标: $TARGET" >&2
        exit 1
        ;;
esac

echo "=========================================="
echo "  打包 OTA 更新包"
echo "=========================================="
echo ""

# 读取版本号（文件优先，否则用 workflow env，最后 fallback）
VERSION_FILE="VERSION"
if [ -f "$VERSION_FILE" ]; then
    _VF=$(tr -d '[:space:]' < "$VERSION_FILE")
    [ -n "$_VF" ] && VERSION="$_VF"
fi
VERSION="${VERSION:-1.1.12}"
echo "📍 版本号: $VERSION"

# 获取 Git commit
if command -v git &> /dev/null && [ -d ".git" ]; then
    COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
else
    COMMIT="unknown"
fi

# 构建时间
BUILD_TIME=$(TZ=Asia/Shanghai date +"%Y-%m-%dT%H:%M:%S+08:00")

# 目标架构
ARCH="$TARGET"

# 检查构建产物
BINARY_PATH="target/$TARGET/release/simadmin"
FRONTEND_DIR="frontend/dist"

if [ ! -f "$BINARY_PATH" ]; then
    echo "❌ 错误: 后端二进制不存在: $BINARY_PATH"
    echo "请先运行: ./scripts/build.sh"
    exit 1
fi

if [ ! -d "$FRONTEND_DIR" ]; then
    echo "❌ 错误: 前端构建产物不存在: $FRONTEND_DIR"
    echo "请先运行: ./scripts/build.sh"
    exit 1
fi

# 创建临时目录
OTA_TMP=$(mktemp -d)
trap "rm -rf $OTA_TMP" EXIT

echo "📦 版本: $VERSION"
echo "📝 Commit: $COMMIT"
echo "🕐 构建时间: $BUILD_TIME"
echo ""

# 复制 SimAdmin systemd 服务单元，OTA 一并带出，部署时安装到系统
echo "📋 复制 systemd 服务单元..."
for _UNIT in scripts/simadmin.service scripts/simadmin-modem-recovery.service; do
  if [ -f "$_UNIT" ]; then
    cp "$_UNIT" "$OTA_TMP/$(basename "$_UNIT")"
  fi
done
# 复制后端二进制
echo "📋 复制后端二进制..."
cp "$BINARY_PATH" "$OTA_TMP/simadmin"
chmod 755 "$OTA_TMP/simadmin"

# 复制 VoLTE Python 脚本（注册 / 发送 / QMI 封装），设备运行时动态调用
# 这些脚本必须随 OTA 一并部署，否则 IMS 注册/发送直接 No such file。
echo "📋 复制 VoLTE Python 脚本..."
for _PY in volte_register.py volte_sms_send.py qmi.py; do
  if [ -f "$_PY" ]; then
    cp "$_PY" "$OTA_TMP/$_PY"
    chmod 755 "$OTA_TMP/$_PY"
  else
    echo "⚠  脚本缺失: $_PY（将跳过）" >&2
  fi
done

# 计算二进制 MD5
if [[ "$OSTYPE" == "darwin"* ]]; then
    BINARY_MD5=$(md5 -q "$OTA_TMP/simadmin")
else
    BINARY_MD5=$(md5sum "$OTA_TMP/simadmin" | cut -d' ' -f1)
fi
echo "   MD5: $BINARY_MD5"

# 复制前端文件
echo "📋 复制前端文件..."
mkdir -p "$OTA_TMP/www"
cp -r "$FRONTEND_DIR"/* "$OTA_TMP/www/"

# 计算前端 MD5（所有文件的 hash，与 Rust 验证逻辑一致）
# 方式：每个文件的 MD5 排序后，用换行符连接，再计算整体 MD5
echo "📋 计算前端 MD5..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS: 收集所有 MD5，排序，每行一个，然后计算整体 MD5
    FRONTEND_MD5=$(find "$OTA_TMP/www" -type f -exec md5 -q {} \; | sort | tr '\n' '\n' | md5 -q)
else
    # Linux: 同样的逻辑
    FRONTEND_MD5=$(find "$OTA_TMP/www" -type f -exec md5sum {} \; | cut -d' ' -f1 | sort | md5sum | cut -d' ' -f1)
fi
echo "   MD5: $FRONTEND_MD5"
EDITION="${EDITION:-${VARIANT:-standard}}"
for arg in "$@"; do
    case "$arg" in
        --wfc|wfc) EDITION="wfc" ;;
        --edition=*|--variant=*) EDITION="${arg#*=}" ;;
    esac
done

# 生成 meta.json
echo "📋 生成 meta.json ( edition: $EDITION)..."
cat > "$OTA_TMP/meta.json" << EOF
{
    "version": "$VERSION",
    "commit": "$COMMIT",
    "build_time": "$BUILD_TIME",
    "binary_md5": "$BINARY_MD5",
    "frontend_md5": "$FRONTEND_MD5",
    "arch": "$ARCH",
    "edition": "$EDITION"
}
EOF

cat "$OTA_TMP/meta.json"
echo ""

# 创建输出目录
mkdir -p release

# 输出包名（防御空变量，避免输出路径等于目录）
: "${VERSION:?VERSION 为空}"
: "${TARGET:?TARGET 为空}"
OTA_FILE="release/simadmin_${VERSION}_${TARGET}.tar.gz"
OTA_OUT="$PROJ_ROOT/$OTA_FILE"
echo "📍 输出: $OTA_FILE"

# 打包：用 tar -C 切换归档根，全程不 cd，输出用绝对路径
# 显式文件列表 + 用 -C 加 www 目录，最干净地避免 GNU tar 目录参数歧义
echo "📦 打包 OTA 更新包..."
[ -e "$OTA_TMP/meta.json" ] && [ -e "$OTA_TMP/simadmin" ] \
  && [ -d "$OTA_TMP/www" ] \
  || die "❌ 打包准备失败: 资产不完整"
tar -czf "$OTA_OUT" \
  -C "$OTA_TMP" meta.json simadmin \
  $(test -e "$OTA_TMP/volte_register.py" && echo volte_register.py) \
  $(test -e "$OTA_TMP/volte_sms_send.py" && echo volte_sms_send.py) \
  $(test -e "$OTA_TMP/qmi.py" && echo qmi.py) \
  $(test -e "$OTA_TMP/simadmin.service" && echo simadmin.service) \
  $(test -e "$OTA_TMP/simadmin-modem-recovery.service" && echo simadmin-modem-recovery.service) \
  -C "$OTA_TMP" www
[ -f "$OTA_OUT" ] || die "❌ tar 未生成输出: $OTA_OUT"
[ -s "$OTA_OUT" ] || die "❌ 输出文件为空: $OTA_OUT"

# 显示结果
echo ""
echo "=========================================="
echo "✅ OTA 更新包打包完成！"
echo "=========================================="
echo ""
echo "📍 输出文件: $OTA_FILE"
ls -lh "$OTA_FILE"
echo ""
echo "📋 包内容:"
tar -tzf "$OTA_FILE" | head -20
echo "..."
echo ""

# 计算包的 MD5
if [[ "$OSTYPE" == "darwin"* ]]; then
    OTA_MD5=$(md5 -q "$OTA_FILE")
else
    OTA_MD5=$(md5sum "$OTA_FILE" | cut -d' ' -f1)
fi
echo "📝 OTA 包 MD5: $OTA_MD5"
