import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  FormControl,
  FormControlLabel,
  Grid,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  Switch,
  Tooltip,
  Typography,
} from '@mui/material'
import { Refresh, VpnKey } from '@mui/icons-material'

import type { VolteControl } from '../api/contracts'
import { useSimAdminApi } from '../contexts/ApiContext'

/** 轮询间隔：启动/降级阶段快一点，稳定注册后放慢。 */
const POLL_FAST_MS = 3000
const POLL_SLOW_MS = 15000

const PHASE_LABEL: Record<string, string> = {
  disabled: '已关闭',
  starting: '启动中',
  registered: '已注册',
  degraded: '降级重试',
  stopping: '停止中',
}

const STAGE_LABEL: Record<string, string> = {
  starting: '启动',
  identity: '读取身份',
  identity_aka: 'USIM 鉴权探测',
  radio: '等待驻网',
  modem: '等待调制解调器',
  bearer: '建立 IMS 承载',
  pcscf: '发现 P-CSCF',
  register_ipsec: 'SIP 注册（IPsec）',
  register_udp: 'SIP 注册（明文 UDP）',
  registered: '注册完成',
  stopping: '停止',
}

const MODE_LABEL: Record<string, string> = {
  register_ipsec: '3GPP IPsec',
  register_udp: '明文 UDP',
}

const DATA_PATH_LABEL: Record<string, string> = {
  independent_wwan1: '独立 wwan1（IMS 走 DATA6）',
  secondary_qmi_data: '用户数据走 DATA6（IMS 走主口）',
  both_data_slots_active: '两个槽位都被占用',
}

function phaseColor(phase: string): 'default' | 'success' | 'warning' | 'error' | 'info' {
  switch (phase) {
    case 'registered':
      return 'success'
    case 'starting':
    case 'stopping':
      return 'info'
    case 'degraded':
      return 'warning'
    default:
      return 'default'
  }
}

function formatTs(ts?: number | null): string {
  if (!ts) return '—'
  return new Date(ts * 1000).toLocaleString()
}

function formatCountdown(ts?: number | null): string {
  if (!ts) return '—'
  const secs = ts - Math.floor(Date.now() / 1000)
  if (secs <= 0) return '即将重试'
  if (secs < 60) return `${secs} 秒后`
  return `${Math.ceil(secs / 60)} 分钟后`
}

export default function VolteSettings() {
  // 走 context 而非直接 import，这样在 Hub 远程管理模式下会命中被替换的 transport。
  const api = useSimAdminApi()
  const [control, setControl] = useState<VolteControl | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const timer = useRef<number | null>(null)

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const res = await api.getVolteControl()
      if (res.status === 'ok' && res.data) {
        setControl(res.data)
        setError(null)
      } else if (!silent) {
        setError(res.message || '读取 VoLTE 状态失败')
      }
    } catch (e) {
      if (!silent) setError(e instanceof Error ? e.message : '读取 VoLTE 状态失败')
    } finally {
      if (!silent) setLoading(false)
    }
  }, [api])

  // 首次加载 + 自适应轮询。
  useEffect(() => {
    void load()
    return () => {
      if (timer.current) window.clearTimeout(timer.current)
    }
  }, [load])

  useEffect(() => {
    if (!control) return
    const phase = control.runtime.phase
    // 关闭状态无需轮询，省掉无意义的请求。
    if (!control.feature_enabled || phase === 'disabled') return
    const interval = phase === 'registered' ? POLL_SLOW_MS : POLL_FAST_MS
    timer.current = window.setTimeout(() => void load(true), interval)
    return () => {
      if (timer.current) window.clearTimeout(timer.current)
    }
  }, [control, load])

  const run = async (
    fn: () => Promise<{ status: string; message?: string }>,
    okMsg: string,
  ) => {
    setBusy(true)
    setError(null)
    setNotice(null)
    try {
      const res = await fn()
      if (res.status === 'ok') {
        setNotice(okMsg)
        await load(true)
      } else {
        setError(res.message || '操作失败')
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : '操作失败')
    } finally {
      setBusy(false)
    }
  }

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" py={6}>
        <CircularProgress />
      </Box>
    )
  }

  if (!control) {
    return (
      <Alert severity="error" action={<Button onClick={() => void load()}>重试</Button>}>
        {error || '无法读取 VoLTE 状态'}
      </Alert>
    )
  }

  const rt = control.runtime
  const enabled = control.feature_enabled

  return (
    <Stack spacing={2}>
      {error && (
        <Alert severity="error" onClose={() => setError(null)}>
          {error}
        </Alert>
      )}
      {notice && (
        <Alert severity="success" onClose={() => setNotice(null)}>
          {notice}
        </Alert>
      )}

      <Card>
        <CardContent>
          <Box display="flex" alignItems="center" justifyContent="space-between" flexWrap="wrap" gap={1}>
            <Box display="flex" alignItems="center" gap={1}>
              <VpnKey color={enabled ? 'primary' : 'disabled'} />
              <Typography variant="h6" fontWeight={700}>
                原生 VoLTE / IMS
              </Typography>
              <Chip
                size="small"
                label={PHASE_LABEL[rt.phase] || rt.phase}
                color={phaseColor(rt.phase)}
              />
              {rt.registration_mode && (
                <Chip
                  size="small"
                  variant="outlined"
                  label={MODE_LABEL[rt.registration_mode] || rt.registration_mode}
                />
              )}
            </Box>
            <Box display="flex" alignItems="center" gap={1}>
              <Tooltip title="立即重新注册">
                <span>
                  <Button
                    size="small"
                    startIcon={<Refresh />}
                    disabled={busy || !enabled || rt.phase === 'disabled'}
                    onClick={() => void run(() => api.refreshVolte(), '已触发重新注册')}
                  >
                    重新注册
                  </Button>
                </span>
              </Tooltip>
              <FormControlLabel
                control={
                  <Switch
                    checked={enabled}
                    disabled={busy}
                    onChange={(e) =>
                      void run(
                        () => api.setVolteFeature(e.target.checked),
                        e.target.checked ? 'VoLTE 已启用' : 'VoLTE 已关闭',
                      )
                    }
                  />
                }
                label={enabled ? '已启用' : '已关闭'}
              />
            </Box>
          </Box>

          {enabled && rt.phase !== 'registered' && (
            <Alert severity={rt.phase === 'degraded' ? 'warning' : 'info'} sx={{ mt: 2 }}>
              当前阶段：<strong>{STAGE_LABEL[rt.stage] || rt.stage}</strong>
              {rt.last_error && (
                <>
                  {' — '}
                  <code>{rt.last_error}</code>
                </>
              )}
              {rt.next_retry_at && <> （{formatCountdown(rt.next_retry_at)}重试）</>}
            </Alert>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Typography variant="subtitle1" fontWeight={600} gutterBottom>
            设置
          </Typography>
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, sm: 6 }}>
              <FormControl fullWidth size="small" disabled={busy}>
                <InputLabel id="volte-apn-proto">IMS APN 协议</InputLabel>
                <Select
                  labelId="volte-apn-proto"
                  label="IMS APN 协议"
                  value={control.apn_protocol}
                  onChange={(e) =>
                    void run(
                      () => api.setVolteSettings({ apn_protocol: String(e.target.value) }),
                      'APN 协议已保存',
                    )
                  }
                >
                  <MenuItem value="IPV4V6">IPv4v6（推荐）</MenuItem>
                  <MenuItem value="IPV6">仅 IPv6</MenuItem>
                  <MenuItem value="IP">仅 IPv4</MenuItem>
                </Select>
              </FormControl>
            </Grid>

            <Grid size={{ xs: 12, sm: 6 }}>
              <FormControl fullWidth size="small" disabled={busy}>
                <InputLabel id="volte-data-path">数据槽位</InputLabel>
                <Select
                  labelId="volte-data-path"
                  label="数据槽位"
                  value={control.data_path_intent}
                  onChange={(e) =>
                    void run(
                      () => api.setVolteSettings({ data_path_intent: String(e.target.value) }),
                      '数据槽位已保存',
                    )
                  }
                >
                  <MenuItem value="independent_wwan1">独立 wwan1（IMS 走 DATA6）</MenuItem>
                  <MenuItem value="secondary_qmi_data">用户数据走 DATA6</MenuItem>
                </Select>
              </FormControl>
            </Grid>

            <Grid size={{ xs: 12, sm: 6 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={control.sms_enabled}
                    disabled={busy}
                    onChange={(e) =>
                      void run(() => api.setVolteSms(e.target.checked), 'IMS 短信设置已保存')
                    }
                  />
                }
                label="IMS 短信（注册成功后生效）"
              />
            </Grid>

            <Grid size={{ xs: 12, sm: 6 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={control.roaming_allowed}
                    disabled={busy}
                    onChange={(e) =>
                      void run(
                        () => api.setVolteSettings({ roaming_allowed: e.target.checked }),
                        '漫游策略已保存',
                      )
                    }
                  />
                }
                label="漫游时允许注册"
              />
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Typography variant="subtitle1" fontWeight={600} gutterBottom>
            运行时详情
          </Typography>
          <Grid container spacing={1.5}>
            <Detail label="阶段" value={STAGE_LABEL[rt.stage] || rt.stage} />
            <Detail
              label="数据槽位（实际）"
              value={rt.data_path_mode ? DATA_PATH_LABEL[rt.data_path_mode] || rt.data_path_mode : '—'}
            />
            <Detail label="IMSI" value={rt.imsi || '—'} />
            <Detail label="归属域" value={rt.home_domain || '—'} />
            <Detail label="公开身份 (IMPU)" value={rt.public_identity || '—'} mono />
            <Detail label="P-CSCF" value={rt.pcscf || '—'} mono />
            <Detail label="UE 地址" value={rt.ue_address || '—'} mono />
            <Detail label="本机号码" value={rt.own_number || '—'} />
            <Detail label="会话开始" value={formatTs(rt.session_started_at)} />
            <Detail label="注册时间" value={formatTs(rt.registered_at)} />
            <Detail label="最近失败" value={formatTs(rt.last_failure_at)} />
            <Detail label="重连次数" value={String(rt.reconnect_count)} />
          </Grid>

          <Divider sx={{ my: 2 }} />

          <Typography variant="subtitle2" fontWeight={600} gutterBottom>
            IMS 短信计数
          </Typography>
          <Grid container spacing={1.5}>
            <Detail label="已发送" value={String(rt.sent_count)} />
            <Detail label="已接收" value={String(rt.received_count)} />
            <Detail label="重复丢弃" value={String(rt.duplicate_count)} />
            <Detail label="最近收发" value={`${formatTs(rt.last_rx_at)} / ${formatTs(rt.last_tx_at)}`} />
          </Grid>
        </CardContent>
      </Card>
    </Stack>
  )
}

function Detail({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <Grid size={{ xs: 12, sm: 6, md: 4 }}>
      <Typography variant="caption" color="text.secondary" display="block">
        {label}
      </Typography>
      <Typography
        variant="body2"
        sx={{
          fontFamily: mono ? 'monospace' : undefined,
          wordBreak: 'break-all',
        }}
      >
        {value}
      </Typography>
    </Grid>
  )
}
