# UPSTREAM — 与官方 SimAdmin 的关系

本仓库 = **官方 [3899/SimAdmin](https://github.com/3899/SimAdmin) 的完整源码**
（v1.1.12，commit `306ac71`）+ VoLTE/IMS 增量层。**没有删改任何官方功能**。

## 组成（对官方 main 的精确差异，blob SHA 对比）

| 类别 | 数量 | 说明 |
|---|---|---|
| 与官方完全一致 | 252 个文件 | 官方更新时可直接覆盖同步 |
| 官方文件被修改 | 14 个 | 见下表，升级官方版本时需人工合并 |
| 本仓库新增 | 27 个文件 | VoLTE 层 + 部署脚本，官方没有 |

### 被修改的官方文件（升级时注意合并）

```
.gitattributes                    # 追加 *.sh/*.py/*.rs 强制 LF
.gitignore                        # 追加构建产物忽略
backend/src/config.rs             # VoLTE 配置项（VolteConfig）
backend/src/handlers.rs           # /api/volte/* 路由 + send_sms IMS 接管
backend/src/main.rs               # volte 模块声明 + 路由注册 + supervisor 启动
backend/src/models.rs             # VolteControlResponse 等响应模型
backend/src/state.rs              # VolteManager 装配进 AppState
crates/simadmin-device-runtime/src/apdu.rs  # UIM APDU 辅助
frontend/src/api/contracts.ts     # VolteControl 类型
frontend/src/api/current.ts       # /api/volte/* 前端调用
frontend/src/components/Layout/Sidebar.tsx  # 恢复"电话管理"入口
frontend/src/pages/Phone.tsx      # VoLTE 状态芯片 + 快捷开关 + 首位 tab
scripts/deploy.sh                 # 一键部署（全量备份/回滚/全新安装）
scripts/pack-ota.sh               # OTA 包打入 VoLTE 脚本 + systemd 单元
```

### 新增文件（官方没有）

- `backend/src/volte/`（identity/bearer/pcscf/aka/sip/ipsec/runtime/slot/mod）
- `backend/src/ims_sms.rs` `ims_uim.rs` `sip_listener.rs` `volte_manager.rs`
- `volte_register.py` `volte_sms_send.py` `qmi.py`（设备侧运行时脚本）
- `deploy.sh`（一键部署）`install.sh`（独立安装入口）
- `UPSTREAM.md`（本文档）`docs/AI-README.md`（技术交接）

## 官方出新版本时怎么同步

```bash
scripts/sync-upstream.sh          # 拉取官方 main，自动同步 252 个无冲突文件，
                                  # 报告需要人工合并的 14 个文件
# 然后逐个人工合并上表 14 个文件（都是小补丁，AI 可代做）
```

同步后打 tag / dispatch CI 即出新 OTA 包。

## 安装形态（与官方对齐）

- **OTA 升级**（已有旧部署）：设备上执行 `bash deploy.sh [版本|tar.gz URL]`，
  或管理界面 OTA 更新页（自动从本仓库 release 拉取）。
- **独立安装**（全新设备）：`curl -fsSL .../install.sh | sh`
  （内部走官方 `install_latest.sh` 全流程：系统依赖 + systemd + lpac，
  默认 REPO 指向本仓库的 release）。
