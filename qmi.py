#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
qmi.py - 极简 QMUX/QMI 客户端（标准 QMUX 帧 + qmi-proxy 握手版），无第三方依赖。

帧结构：001 设备的 libqmi 是**厂商魔改版**，QMUX 头比标准多 1 个固定 0x00
字节（client 之后、txn 之前，各服务通用，经 qmi-proxy -v 日志实测确认）：
    01 | len(u16 LE) | flags | service | client | 00 | txn(u8) | msgid(u16 LE) | tlvlen(u16 LE) | TLVs...
      len   = 整帧长度 - 1
      flags = 0x00(request) / 0x80(response) / 0x04(indication)
      txn   = 1 字节，必须 1..255（为 0 时调制解调器不回包），响应原样回显
    TLV:  type(u8) + len(u16 LE) + value
    Result TLV(0x02) value: result(u16 LE) + error(u16 LE)

★ 历史注记：旧版手册声称「UIM 服务再多 1 个保留字节」——那是直连模式下的
  结论，未经代理路径证实。代理路径统一用上面的单字节格式，若 UIM 消息返回
  MalformedMsg 再试验双字节变体。直连模式已废弃（与 qmi-proxy 抢 UIM 会话，
  见手册 §4.1），现在一律走 @qmi-proxy。

qmi-proxy 握手（逆向 libqmi 源码 src/libqmi-glib/qmi-proxy.c 得到）：
  1. 连接抽象 UNIX socket @qmi-proxy（若代理未运行则自动拉起 /usr/libexec/qmi-proxy）；
  2. 第一条消息必须是 CTL 服务 msgid=0xFF00（INTERNAL_PROXY_OPEN），
     TLV 0x01 = 设备路径字符串（如 /dev/wwan0qmi0）；
  3. 代理回同 msgid 的 CTL 响应（Result TLV 成功）后，后续消息原样转发，
     代理按 (service, client) 路由响应与指示。
  旧版在这里 NO_REPLY 就是因为缺第 2 步。
"""
import os
import sys
import time
import select
import struct

SVC_CTL = 0x00
SVC_WDS = 0x01
SVC_DMS = 0x02
SVC_NAS = 0x03
SVC_UIM = 0x0B

CTL_ALLOCATE_CID = 0x0022
CTL_RELEASE_CID = 0x0023
CTL_INTERNAL_PROXY_OPEN = 0xFF00

WDS_START_NETWORK = 0x0020
WDS_STOP_NETWORK = 0x0021
WDS_GET_CURRENT_SETTINGS = 0x002D

UIM_OPEN_LOGICAL_CHANNEL = 0x0042
UIM_SEND_APDU = 0x003B
UIM_CLOSE_LOGICAL_CHANNEL = 0x003D
UIM_GET_CARD_STATUS = 0x002F   # 注意是 0x2F（libqmi 1.36），0x2B 会回"成功但无内容"

TLV_RESULT = 0x02

QMI_PROXY_BIN = "/usr/libexec/qmi-proxy"
# PROXY_OPEN 的 TLV 里必须放**modem 设备路径**（不是 socket 名！），
# 代理会自己去 open 这个设备；传错（比如把 "qmi-proxy" 传进去）代理会
# 静默丢弃请求 → 客户端表现为 NO_REPLY。
DEVICE_PATH = "/dev/wwan0qmi0"

QMI_ERR = {
    0x0000: "None", 0x0001: "MalformedMsg", 0x0002: "NoMemory", 0x0003: "Internal",
    0x0004: "Aborted", 0x0005: "ClientIdsExhausted", 0x0006: "UnabortableTransaction",
    0x0007: "InvalidClientId", 0x0008: "NoThresholds", 0x0009: "InvalidHandle",
    0x000A: "InvalidProfile", 0x000B: "InvalidPinId", 0x000C: "IncorrectPin",
    0x000D: "NoNetworkFound", 0x000E: "CallFailed", 0x000F: "OutOfCall",
    0x0010: "NotProvisioned", 0x0011: "MissingArg", 0x0012: "ArgTooLong",
    0x0013: "InvalidTxId", 0x0016: "MissingTlv", 0x0017: "InvalidTlv",
    0x002A: "NoEffect", 0x0030: "OpenLogicalChannelFailed", 0x0047: "InvalidQmiCommand",
    0x0052: "AccessDenied", 0x005A: "DeviceNotReady",
    0x005D: "InvalidArg", 0x0065: "InvalidServiceType",
}


def err_name(code):
    return QMI_ERR.get(code, "0x%04X" % code)


def tlv(t, v):
    """TLV = type(u8) + len(u16 LE) + value"""
    if isinstance(v, int):
        v = bytes([v])
    return bytes([t]) + struct.pack("<H", len(v)) + v


def parse_tlvs(data):
    """解析 TLV 流，容错：遇到长度越界的"伪 TLV"时按填充跳过一字节继续。"""
    out = {}
    i = 0
    n = len(data)
    while i + 3 <= n:
        t = data[i]
        (ln,) = struct.unpack("<H", data[i + 1:i + 3])
        if ln > n - i - 3:
            i += 1          # 不是合法 TLV，当作填充跳过
            continue
        out.setdefault(t, []).append(data[i + 3:i + 3 + ln])
        i += 3 + ln
    return out


def hexdump(b):
    return ":".join("%02X" % c for c in b)


class QmiError(Exception):
    pass


class Qmi:
    def __init__(self, path="/dev/wwan0qmi0", verbose=False):
        self.path = path
        self.is_socket = path.startswith("@")
        if self.is_socket:
            import socket as _sock
            s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
            try:
                s.connect(b"\x00" + path[1:].encode())
            except (FileNotFoundError, ConnectionRefusedError):
                self._spawn_proxy()
                s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
                last_err = None
                for _ in range(20):
                    try:
                        s.connect(b"\x00" + path[1:].encode())
                        last_err = None
                        break
                    except OSError as e:
                        last_err = e
                        time.sleep(0.2)
                if last_err:
                    raise QmiError("cannot connect %s: %s" % (path, last_err))
            self.sock = s
            self.fd = None
            self.txn = 0
            self._rx = b""
            self.verbose = verbose
            self._proxy_open(DEVICE_PATH)
        else:
            self.fd = os.open(path, os.O_RDWR | os.O_NOCTTY)
            self.sock = None
            self.txn = 0
            self._rx = b""
            self.verbose = verbose

    @staticmethod
    def _spawn_proxy():
        import subprocess
        try:
            subprocess.Popen([QMI_PROXY_BIN],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             start_new_session=True)
        except OSError as e:
            raise QmiError("cannot spawn %s: %s" % (QMI_PROXY_BIN, e))

    def _proxy_open(self, dev_path):
        """代理握手：CTL msgid=0xFF00 + TLV 0x01 设备路径，等 Result 成功。"""
        r = self.send(SVC_CTL, 0, CTL_INTERNAL_PROXY_OPEN,
                      tlv(0x01, dev_path.encode()), timeout=5.0)
        if r is None:
            raise QmiError("qmi-proxy: no reply to INTERNAL_PROXY_OPEN "
                           "(0xFF00), is this really the qmi-proxy socket?")
        rc, ec = self.result(r)
        if rc != 0:
            raise QmiError("qmi-proxy: proxy open failed rc=%s err=%s"
                           % (rc, err_name(ec or 0)))

    def close(self):
        try:
            if self.sock is not None:
                self.sock.close()
            if self.fd is not None:
                os.close(self.fd)
        except Exception:
            pass

    def _next_txn(self):
        self.txn = (self.txn % 255) + 1
        return self.txn

    @staticmethod
    def _build(flags, service, client, txn, msgid, tlvs=b""):
        # 厂商魔改帧：client 之后有 1 个固定 0x00 字节（@6，请求恒 0）。
        # ★ UIM(0x0B) 服务的 SDU 在 txn 与 msgid 之间**多 1 个保留字节 0x00**
        #   （qmicli 原始帧对比实测：不加的话 UIM 请求会被设备解析成
        #   msgid=0x0000 "Reset"，只回 Result 空响应）。手册旧结论正确。
        # 另：解析器要求 QMUX len 字段 >= 12，空 TLV 帧补 1 个 0x00 填充
        # （与 MM 的 WDA Get Version Info 帧同款）。
        extra = b"\x00" if service != SVC_CTL else b""
        sdu = bytes([0x00, txn & 0xFF]) + extra + struct.pack("<HH", msgid, len(tlvs)) + tlvs
        body = bytes([flags, service, client]) + sdu
        # 仅当 len 字段 < 12 才补填充（CTL 空 TLV 帧=11 需补；UIM 帧=12 不补，
        # 多补会让 TLV 计数对不上被代理丢弃）
        pad = b"\x00" if (len(body) + 2) < 12 else b""
        return bytes([0x01]) + struct.pack("<H", len(body) + 2 + len(pad)) + body + pad

    def _pump(self, timeout=0.2):
        fds = [self.sock] if self.sock is not None else [self.fd]
        r, _, _ = select.select(fds, [], [], timeout)
        if not r:
            return
        try:
            if self.sock is not None:
                d = self.sock.recv(8192)
            else:
                d = os.read(self.fd, 8192)
        except OSError:
            return
        if d:
            if self.verbose:
                print("RXX %s" % hexdump(d))
            self._rx += d

    def _frames(self):
        out = []
        while True:
            if len(self._rx) < 3:
                break
            if self._rx[0] != 0x01:
                idx = self._rx.find(b"\x01")
                if idx < 0:
                    self._rx = b""
                    break
                self._rx = self._rx[idx:]
                if len(self._rx) < 3:
                    break
            (ln,) = struct.unpack("<H", self._rx[1:3])
            total = ln + 1
            if len(self._rx) < total:
                break
            out.append(self._rx[:total])
            self._rx = self._rx[total:]
        return out

    @staticmethod
    def _parse(frame):
        # 布局: [01][len:u16][flags][service][client][00][txn][msgid:u16][tlvlen:u16][tlvs]
        # 非 CTL 服务（UIM/WDS/NAS...）在 txn 与 msgid 之间多 1 字节（16 位 txn 的高
        # 字节，厂商帧格式；见本文件头部说明），msgid/tlvlen 偏移 +1；
        # TLV 区域取到帧尾，宽松解析器剔除填充。
        try:
            if len(frame) < 12:
                return None
            extra = 1 if frame[4] != SVC_CTL else 0
            base = 8 + extra
            if len(frame) < base + 4:
                return None
            return {
                "flags": frame[3], "service": frame[4], "client": frame[5],
                "txn": frame[7],
                "msgid": struct.unpack("<H", frame[base:base + 2])[0],
                "tlvlen": struct.unpack("<H", frame[base + 2:base + 4])[0],
                "tlvs": parse_tlvs(frame[base + 4:]),
                "raw": frame,
            }
        except Exception:
            return None

    def send(self, service, client, msgid, tlvs=b"", timeout=2.0):
        txn = self._next_txn()
        frame = self._build(0x00, service, client, txn, msgid, tlvs)
        if self.verbose:
            print("<<< %s" % hexdump(frame))
        self._tx(frame)
        end = time.time() + timeout
        while time.time() < end:
            self._pump(0.15)
            for m in self._frames():
                if self.verbose:
                    print(">>> %s" % hexdump(m))
                p = self._parse(m)
                if not p:
                    continue
                if p["txn"] == txn and p["service"] == service and p["msgid"] == msgid:
                    return p
        return None

    def send_raw(self, service, client, msgid, tlvs=b"", timeout=2.0):
        """同 send，但返回匹配响应的原始帧字节（便于查看未知消息的回应）。"""
        txn = self._next_txn()
        frame = self._build(0x00, service, client, txn, msgid, tlvs)
        self._tx(frame)
        end = time.time() + timeout
        while time.time() < end:
            self._pump(0.15)
            for m in self._frames():
                p = self._parse(m)
                if not p:
                    continue
                if p["txn"] == txn and p["service"] == service and p["msgid"] == msgid:
                    return m
        return None

    def _tx(self, frame):
        if self.sock is not None:
            self.sock.sendall(frame)
        else:
            os.write(self.fd, frame)

    def result(self, resp):
        """返回 (result_code, error_code)，Result TLV 为 LE (u16 result, u16 error)"""
        if not resp:
            return (None, None)
        vals = resp["tlvs"].get(TLV_RESULT)
        if not vals or len(vals[0]) < 2:
            return (0, 0)
        v = vals[0]
        rc = struct.unpack("<H", v[0:2])[0]
        ec = struct.unpack("<H", v[2:4])[0] if len(v) >= 4 else 0
        return (rc, ec)

    def allocate_cid(self, service):
        r = self.send(SVC_CTL, 0, CTL_ALLOCATE_CID, tlv(0x01, bytes([service])))
        rc, ec = self.result(r)
        if rc != 0 or r is None:
            raise QmiError("allocate cid svc=0x%02X failed rc=%s err=%s" %
                           (service, rc, err_name(ec or 0)))
        info = r["tlvs"].get(0x01, [b""])[0]
        # Allocation Info TLV(0x01) = service(u8) + cid(u8)（libqmi 源码确认）；
        # 兼容老解析的 u16+u16 排布。
        if len(info) >= 2:
            return info[1] if info[0] == service else info[-1]
        return info[0] if info else None

    def release_cid(self, service, cid):
        # Release Info TLV(0x01) = service(u8) + cid(u8)
        self.send(SVC_CTL, 0, CTL_RELEASE_CID,
                  tlv(0x01, bytes([service, cid])))

    # ---------- UIM: USIM AKA (IMS) ----------
    def uim_open_logical_channel(self, cid, aid, slot=1):
        """打开逻辑通道到指定 AID（USIM）。msgid 0x0042。
        TLV 0x01 = Slot (uint8，001 卡在 slot 1)；TLV 0x10 = AID
        （value = [1 字节 aid 长度][aid 字节]）"""
        tlvs = tlv(0x01, bytes([slot])) + tlv(0x10, bytes([len(aid)]) + bytes(aid))
        r = self.send(SVC_UIM, cid, UIM_OPEN_LOGICAL_CHANNEL, tlvs)
        rc, ec = self.result(r)
        return r, rc, ec

    def uim_close_logical_channel(self, cid, channel):
        """关闭逻辑通道。msgid 0x003D。TLV 0x01 = channel id (uint8)"""
        r = self.send(SVC_UIM, cid, UIM_CLOSE_LOGICAL_CHANNEL, tlv(0x01, bytes([channel])))
        rc, ec = self.result(r)
        return r, rc, ec

    def uim_send_apdu(self, cid, channel, apdu, slot=1):
        """在逻辑通道上发送 APDU。msgid 0x003B。
        TLV 0x10 = channel id (uint8)；TLV 0x01 = slot (uint8)；
        TLV 0x02 = APDU command，值 = [2 字节 LE 长度][apdu 字节]。
        （1 字节前缀会导致 tlvlen 错位 -> MalformedMsg）"""
        apdu_tlv = struct.pack("<H", len(apdu)) + bytes(apdu)
        tlvs = tlv(0x10, bytes([channel])) + tlv(0x01, bytes([slot])) + tlv(0x02, apdu_tlv)
        r = self.send(SVC_UIM, cid, UIM_SEND_APDU, tlvs)
        rc, ec = self.result(r)
        return r, rc, ec


# ===================== CLI =====================
def cmd_selftest(q):
    print("== selftest: allocate CID for UIM (0x0B) ==")
    try:
        cid = q.allocate_cid(SVC_UIM)
        print("OK  UIM client id = 0x%02X" % cid)
    except QmiError as e:
        print("FAIL %s" % e)
        return
    print("\n== UIM Get Card Status (msgid 0x002F) ==")
    r = q.send(SVC_UIM, cid, UIM_GET_CARD_STATUS, b"", timeout=3.0)
    rc, ec = q.result(r)
    print("result rc=%s err=%s" % (rc, err_name(ec or 0)))
    if r:
        for k, vs in sorted(r["tlvs"].items()):
            print("  TLV 0x%02X x%d  %s" % (k, len(vs), hexdump(vs[0])[:120]))
    q.release_cid(SVC_UIM, cid)
    print("\nreleased cid 0x%02X" % cid)


def cmd_probe(q, service, lo, hi):
    print("probing service=0x%02X msgid 0x%04X..0x%04X (empty TLV)" % (service, lo, hi))
    try:
        cid = q.allocate_cid(service)
    except QmiError as e:
        print("allocate cid failed: %s" % e)
        return
    print("client id = 0x%02X\n" % cid)
    hits = []
    for mid in range(lo, hi + 1):
        r = q.send(service, cid, mid, b"", timeout=1.0)
        rc, ec = q.result(r)
        if r is None:
            print("---- 0x%04X  no reply" % mid)
            continue
        exists = ec not in (0x0047,)
        if exists:
            hits.append((mid, ec))
        print("%s 0x%04X  rc=%s err=%s" %
              ("HIT " if exists else "MISS", mid, rc, err_name(ec or 0)))
    print("\n== EXISTS (%d) ==" % len(hits))
    for mid, ec in hits:
        print("  0x%04X  err=%s" % (mid, err_name(ec or 0)))
    q.release_cid(service, cid)


USIM_AID = bytes.fromhex("A0000000871002FF86FFFF89FFFFFFFF")


def cmd_aka(q, aid_hex=None):
    aid = bytes.fromhex(aid_hex) if aid_hex else USIM_AID
    print("== AKA test: open logical channel, send STATUS APDU ==")
    print("USIM AID = %s" % hexdump(aid))
    try:
        cid = q.allocate_cid(SVC_UIM)
    except QmiError as e:
        print("FAIL allocate: %s" % e)
        return
    print("UIM client id = 0x%02X" % cid)
    try:
        r, rc, ec = q.uim_open_logical_channel(cid, aid)
        print("open logical channel: rc=%s err=%s" % (rc, err_name(ec or 0)))
        if r is None:
            print("  NO REPLY"); return
        for k, vs in sorted(r["tlvs"].items()):
            print("  TLV 0x%02X x%d  %s" % (k, len(vs), hexdump(vs[0])[:160]))
        ch = r["tlvs"].get(0x10, [b"\x01"])[0][0]
        print("=> logical channel id = %d" % ch)
        if ec != 0 or ch == 0:
            print("  open failed, abort"); return
        # STATUS APDU on the logical channel: CLA=ch, INS=F2 (GET RESPONSE/STATUS)
        apdu = bytes([ch, 0xF2, 0x00, 0x00, 0x00])
        print("\n-- SEND APDU (STATUS): %s" % hexdump(apdu))
        r2, rc2, ec2 = q.uim_send_apdu(cid, ch, apdu)
        print("send apdu: rc=%s err=%s" % (rc2, err_name(ec2 or 0)))
        if r2:
            for k, vs in sorted(r2["tlvs"].items()):
                print("  TLV 0x%02X x%d  %s" % (k, len(vs), hexdump(vs[0])[:200]))
        print("\n-- closing logical channel %d" % ch)
        q.uim_close_logical_channel(cid, ch)
    finally:
        q.release_cid(SVC_UIM, cid)
        print("released cid 0x%02X" % cid)


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", default="@qmi-proxy")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("selftest")

    p = sub.add_parser("probe")
    p.add_argument("--service", type=lambda x: int(x, 0), default=SVC_UIM)
    p.add_argument("--lo", type=lambda x: int(x, 0), default=0x20)
    p.add_argument("--hi", type=lambda x: int(x, 0), default=0x50)

    p = sub.add_parser("aka")
    p.add_argument("--aid", default=None, help="hex AID, default USIM AID")

    args = ap.parse_args()
    q = Qmi(args.dev, verbose=args.verbose)
    try:
        if args.cmd == "selftest":
            cmd_selftest(q)
        elif args.cmd == "probe":
            cmd_probe(q, args.service, args.lo, args.hi)
        elif args.cmd == "aka":
            cmd_aka(q, args.aid)
        else:
            ap.print_help()
    finally:
        q.close()


if __name__ == "__main__":
    sys.exit(main())
