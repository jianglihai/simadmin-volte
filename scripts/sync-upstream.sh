#!/usr/bin/env bash
# ============================================================
# 从官方 3899/SimAdmin 同步源码到本仓库（保留 VoLTE 增量层）
#
# 用法：
#   bash scripts/sync-upstream.sh            # 同步官方 main
#   bash scripts/sync-upstream.sh v1.1.13    # 同步官方指定 tag
#
# 行为：
#   1. 拉取官方树，列出与我们 HEAD 的差异
#   2. 自动覆盖「与官方完全一致」的文件（252 个，零风险）
#   3. 对「我们修改过的官方文件」只打印报告，不覆盖 —— 需人工合并
#   4. 我们新增的文件（volte 层/脚本）不触碰
# ============================================================
set -euo pipefail

UPSTREAM_REPO="${UPSTREAM_REPO:-3899/SimAdmin}"
UPSTREAM_REF="${1:-main}"

command -v git >/dev/null || { echo "需要 git"; exit 1; }
command -v curl >/dev/null || { echo "需要 curl（或改用 git fetch）"; exit 1; }

cd "$(dirname "$0")/.."

echo "== 官方: $UPSTREAM_REPO@$UPSTREAM_REF"
# 优先用 git fetch（保留历史便于 diff），失败则退回 API+tar
if git remote get-url upstream >/dev/null 2>&1; then :; else
  git remote add upstream "https://github.com/$UPSTREAM_REPO.git" || true
fi
git fetch upstream "$UPSTREAM_REF" 2>/dev/null || {
  echo "⚠ git fetch 失败（离线？），仅输出差异报告模式不可用，退出"
  exit 1
}
UPSTREAM_TREE="FETCH_HEAD"

# 与我们修改过/新增的文件集合（这些不自动覆盖）
OWNED_RE='^(backend/src/(ims_sms|ims_uim|sip_listener|volte_manager)\.rs|backend/src/volte/|volte_(register|sms_send)\.py$|^qmi\.py$|^deploy\.sh$|^install\.sh$|^UPSTREAM\.md$|^docs/AI-README\.md$)'

changed=$(git diff --name-only "$UPSTREAM_TREE" HEAD -- . ':!backend/src/volte' || true)
synced=0; skipped=0
for f in $changed; do
  if echo "$f" | grep -qE "$OWNED_RE"; then
    echo "SKIP(ours)  $f"
    skipped=$((skipped+1))
  elif git cat-file -e "$UPSTREAM_TREE:$f" 2>/dev/null; then
    # 官方侧存在：判断我们是否改过（与 merge-base 比）
    base=$(git merge-base HEAD "$UPSTREAM_TREE" 2>/dev/null || echo "")
    if [ -n "$base" ] && git diff --quiet "$base" HEAD -- "$f" 2>/dev/null; then
      git checkout "$UPSTREAM_TREE" -- "$f"
      echo "SYNCED      $f"
      synced=$((synced+1))
    else
      echo "MERGE-ME    $f   # 我们改过、官方也改了 —— 人工合并"
      skipped=$((skipped+1))
    fi
  else
    # 官方已删除的文件：报告，不自动删
    echo "GONE-UP?    $f   # 官方已删除，请人工确认"
  fi
done
echo
echo "== 完成：自动同步 $synced 个文件；需人工处理 $skipped 个"
echo "== 下一步：人工合并 MERGE-ME 列表 → cargo check → dispatch CI → 打 tag"
