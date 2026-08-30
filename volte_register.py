#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
volte_register.py - simadmin 后端调用的 VoLTE IMS 注册脚本
用法: python3 -u volte_register.py <P-CSCF> <UE地址>
输出: 最后一行 JSON {"registered":bool,"pcscf":..,"ue_addr":..,"error":..}

流程（2026-08-30 实证 200 OK，Unicom 46001）:
  REGISTER#1 明文(5060): 空 Authorization(AKAv1-MD5) + Security-Client
                         + Require/Proxy-Require: sec-agree -> 401
  USIM AKA: QMI proxy + UIM 逻辑通道 AUTHENTICATE(LV格式)
            AUTS 失步 -> 重同步 REGISTER -> 新 nonce 循环
  digest: password = raw RES 字节, 无 qop
  xfrm: OUT spi=pc spi-s / IN spi=ue spi-s, auth-trunc hmac(md5) IK 96,
        enc ecb(cipher_null) ''（空字符串密钥）
  REGISTER#2: cli(port-c)->P-CSCF:port-s 经 ESP, 响应 srv(port-s) 接收
        Via/Contact 写 port-s, branch 每事务唯一（重点：Security-Verify
        头名只能拼一次，重复会导致 P-CSCF 500 Server Internal Error）
"""
import base64
import hashlib
import json
import re
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, "/opt/simadmin")
sys.path.insert(1, "/root")
from qmi import Qmi, SVC_UIM, USIM_AID  # noqa: E402

IMSI = "460018558516337"
DOMAIN = "ims.mnc001.mcc460.3gppnetwork.org"
URI = "sip:" + DOMAIN
UE_SPI_C = 3711733336
UE_SPI_S = 3136756474
UE_PORT_C = 42986
UE_PORT_S = 47482

# Unicom 已知可用的 P-CSCF（2026-08-30 实证 3:: 可达且注册 200 OK）
CANDIDATES = [
    "2408:8142:6001:3::",
    "2408:8142:6001:407::1",
    "2408:8142:6001:801::",
]


def dec_groups_to_ip(groups):
    """AT+CGCONTRDP 的十进制组地址（16 段=IPv6, 4 段=IPv4）转文本。"""
    nums = [int(x) for x in groups]
    if len(nums) == 16:
        return ":".join("%x" % (nums[i] * 256 + nums[i + 1])
                        for i in range(0, 16, 2))
    if len(nums) == 4:
        return ".".join(str(n) for n in nums)
    return None


def discover_pcscf():
    """APN=ims 的 CGCONTRDP 里的 P-CSCF 优先，静态候选兜底，ping 验证。"""
    cands = []
    for cid in (2, 3, 4, 1):
        r = sh("mmcli -m any --command='AT+CGCONTRDP=%d'" % cid, t=15)
        for line in r.splitlines():
            if "+CGCONTRDP:" not in line:
                continue
            parts = [p.strip() for p in line.split(":", 1)[1].split(",")]
            if len(parts) < 3 or "ims" not in parts[2].lower():
                continue
            for p in parts:
                if p.count(".") >= 3:
                    a = dec_groups_to_ip(p.split("."))
                    if a and ":" in a and a not in cands:
                        cands.append(a)
    cands += [c for c in CANDIDATES if c not in cands]
    for c in cands:
        if "time=" in sh("ping6 -c1 -W2 -I wwan1 %s 2>/dev/null" % c):
            log("P-CSCF 发现: %s" % c)
            return c
    return None


def discover_ue():
    r = sh("ip -6 addr show dev wwan1 scope global 2>/dev/null | "
           "awk '/inet6/{print $2; exit}'")
    return r.split("/")[0] if r else None


def log(m):
    print("[volte] %s %s" % (time.strftime("%H:%M:%S"), m), flush=True)


def sh(cmd, t=60):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
    return (p.stdout + p.stderr).strip()


def md5h(b):
    return hashlib.md5(b).hexdigest()


def sip_status(text):
    m = re.match(r"SIP/2\.0\s+(\d+)", text)
    return int(m.group(1)) if m else 0


def usim_aka(rand, autn):
    """USIM AKA。返回 (res, ck, ik, auts)。"""
    q = Qmi("@qmi-proxy")
    cid = q.allocate_cid(SVC_UIM)
    try:
        r, rc, ec = q.uim_open_logical_channel(cid, USIM_AID)
        if r is None or ec != 0:
            raise RuntimeError("open channel failed ec=%s" % ec)
        ch = r["tlvs"].get(0x10, [b"\x01"])[0][0]

        def send_apdu(apdu):
            r2, _, _ = q.uim_send_apdu(cid, ch, apdu)
            vs = r2["tlvs"].get(0x10, [b""])[0] if r2 else b""
            if len(vs) >= 2 and struct.unpack("<H", vs[0:2])[0] == len(vs) - 2:
                vs = vs[2:]
            return vs[:-2], vs[-2], vs[-1]

        auth_data = bytes([len(rand)]) + rand + bytes([len(autn)]) + autn
        apdu = bytes([0x00, 0x88, 0x00, 0x81, len(auth_data)]) + auth_data + b"\x00"
        data, sw1, sw2 = send_apdu(apdu)
        if sw1 == 0x61:
            data, sw1, sw2 = send_apdu(bytes([0x00, 0xC0, 0x00, 0x00, sw2]))
        if (sw1, sw2) != (0x90, 0x00):
            raise RuntimeError("AKA APDU SW=%02X%02X" % (sw1, sw2))
        if data[:1] not in (b"\xdb", b"\xdc"):
            if len(data) >= 3 and data[1] == 0x81:
                data = data[3:]
            elif len(data) >= 2:
                data = data[2:]
        if data[:1] == b"\xdc":
            ln = data[1] if data[1] == 0x0E else 14
            auts = data[2:2 + ln]
            q.uim_close_logical_channel(cid, ch)
            log("USIM AUTS (SQN 失步): %s" % auts.hex())
            return None, None, None, auts
        if data[:1] != b"\xdb":
            raise RuntimeError("AKA unexpected DO %s" % data.hex())
        off = 1
        ln = data[off]; res = data[off + 1:off + 1 + ln]; off += 1 + ln
        ln = data[off]; ck = data[off + 1:off + 1 + ln]; off += 1 + ln
        ln = data[off]; ik = data[off + 1:off + 1 + ln]
        q.uim_close_logical_channel(cid, ch)
        return res, ck, ik, None
    finally:
        try:
            q.release_cid(SVC_UIM, cid)
        except Exception:
            pass


def xfrm_setup(ue, pc, pc_spi_s, ik):
    key = "0x" + ik.hex()
    sh("ip xfrm state flush; ip xfrm policy flush")
    sh('ip xfrm state add src %s dst %s proto esp spi %d mode transport '
       'auth-trunc "hmac(md5)" %s 96 enc "ecb(cipher_null)" ""'
       % (ue, pc, pc_spi_s, key))
    sh('ip xfrm state add src %s dst %s proto esp spi %d mode transport '
       'auth-trunc "hmac(md5)" %s 96 enc "ecb(cipher_null)" ""'
       % (pc, ue, UE_SPI_S, key))
    sh('ip xfrm policy add src %s dst %s dir out '
       'tmpl src %s dst %s proto esp spi %d mode transport'
       % (ue, pc, ue, pc, pc_spi_s))
    sh('ip xfrm policy add src %s dst %s dir in '
       'tmpl src %s dst %s proto esp spi %d mode transport'
       % (pc, ue, pc, ue, UE_SPI_S))


def build_register(ue, pcscf, cseq, port, tag, callid, authorization=None,
                   sec_verify=None, scli=None, expires=3600, branch=None):
    if branch is None:
        branch = "branch=z9hG4bK" + md5h(callid.encode())
    lines = [
        "REGISTER sip:%s SIP/2.0" % DOMAIN,
        "Via: SIP/2.0/UDP [%s]:%d;%s;rport" % (ue, port, branch),
        "Max-Forwards: 70",
        "From: <sip:%s@%s>;tag=%s" % (IMSI, DOMAIN, tag),
        "To: <sip:%s@%s>" % (IMSI, DOMAIN),
        "Call-ID: %s" % callid,
        "CSeq: %d REGISTER" % cseq,
    ]
    if authorization:
        lines.append(authorization)
    lines.append('Contact: <sip:%s@[%s]:%d;transport=UDP>;'
                 '+g.3gpp.accesstype="3GPP-E-UTRAN-FDD";+g.3gpp.smsip;expires=%d'
                 % (IMSI, ue, port, expires))
    lines.append("Accept: application/vnd.3gpp.sms")
    lines.append("Route: <sip:[%s]:5060;lr>" % pcscf)
    lines.append("Expires: %d" % expires)
    lines.append("Supported: path, gruu, sec-agree")
    lines.append("Allow: INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,MESSAGE,REFER,"
                 "NOTIFY,INFO,OPTIONS")
    lines.append("P-Preferred-Identity: <sip:%s@%s>" % (IMSI, DOMAIN))
    lines.append('P-Visited-Network-ID: "%s"' % DOMAIN)
    lines.append("P-Access-Network-Info: 3GPP-E-UTRAN-FDD;"
                 "utran-cell-id-3gpp=%s0000000;cell-info-age=0" % IMSI[:5])
    lines.append("Require: sec-agree")
    lines.append("Proxy-Require: sec-agree")
    if sec_verify:
        lines.append("Security-Verify: %s" % sec_verify)
    if scli:
        lines.append("Security-Client: %s" % scli)
    lines.append("User-Agent: SimAdmin VoLTE")
    lines.append("Content-Length: 0")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode()


def register(pcscf, ue):
    sh("ip link set wwan1 up 2>/dev/null")
    # 必须先清残留 xfrm：否则 OUT 策略会把明文 REGISTER#1 也包成 ESP，
    # P-CSCF 对"已注册+受保护但无新质询"的包直接丢弃（超时）
    sh("ip xfrm state flush; ip xfrm policy flush")
    sh("ip -6 addr replace %s/64 dev wwan1 2>/dev/null" % ue)
    gw = sh("ip -6 route show dev wwan1 | grep default | awk '{print $3}'").split()[0:1]
    gw = gw[0] if gw else None
    if gw:
        sh("ip -6 route replace %s/128 via %s dev wwan1 metric 5 2>/dev/null"
           % (pcscf, gw))

    callid = md5h(str(time.time()).encode())
    tag = md5h(callid.encode())[:8]
    scli = ("ipsec-3gpp;alg=hmac-md5-96;prot=esp;mod=trans;ealg=null;"
            "spi-c=%d;spi-s=%d;port-c=%d;port-s=%d"
            % (UE_SPI_C, UE_SPI_S, UE_PORT_C, UE_PORT_S))

    auth_empty = ('Authorization: Digest username="%s@%s",realm="%s",nonce="",'
                  'uri="%s",response="",algorithm=AKAv1-MD5'
                  % (IMSI, DOMAIN, DOMAIN, URI))
    reg1 = build_register(ue, pcscf, 1, 5060, tag, callid,
                          authorization=auth_empty, scli=scli)

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((ue, 5060))
    sock.settimeout(12)
    sec_server = ""
    nonce = ""
    try:
        sock.sendto(reg1, (pcscf, 5060))
        log("REGISTER#1 sent")
        data, _ = sock.recvfrom(8192)
        text = data.decode("utf-8", "replace")
        log("REGISTER#1 <- %s" % text.split("\r\n", 1)[0])
        m = re.search(r'nonce="([^"]+)"', text)
        if not m or sip_status(text) not in (401, 421):
            raise RuntimeError("REGISTER#1: %s" % text.split("\r\n", 1)[0])
        nonce = m.group(1)
        sec_server = re.search(
            r"Security-Server: ipsec-3gpp;(.*)", text).group(1).strip()
        pc_spi_s = int(re.search(r"spi-s=(\d+)", sec_server).group(1))
        pc_port_s = int(re.search(r"port-s=(\d+)", sec_server).group(1))
        log("Security-Server: spi-s=%d port-s=%d" % (pc_spi_s, pc_port_s))
    finally:
        sock.close()
    service_route = ""

    res = ck = ik = None
    for attempt in range(5):
        nonce_raw = base64.b64decode(nonce + "=" * ((4 - len(nonce) % 4) % 4))
        rand, autn = nonce_raw[:16], nonce_raw[16:32]
        log("AKA attempt %d: RAND=%s" % (attempt, rand.hex()))
        try:
            res, ck, ik, auts = usim_aka(rand, autn)
        except Exception as e:
            log("AKA 异常: %s" % e)
            time.sleep(5)
            continue
        if auts:
            log("SQN 失步 -> AUTS 重同步 REGISTER")
            auts_b64 = base64.b64encode(auts).decode()
            ha1e = md5h(("%s@%s:%s:" % (IMSI, DOMAIN, DOMAIN)).encode())
            ha2e = md5h(("REGISTER:%s" % URI).encode())
            resp_empty = md5h(("%s:%s" % (ha1e, nonce)).encode())
            auth_auts = ('Authorization: Digest username="%s@%s",realm="%s",'
                         'nonce="%s",uri="%s",response="%s",'
                         'algorithm=AKAv1-MD5,auts="%s"'
                         % (IMSI, DOMAIN, DOMAIN, nonce, URI,
                            resp_empty, auts_b64))
            reg_sync = build_register(ue, pcscf, 2 + attempt, 5060, tag, callid,
                                      authorization=auth_auts, scli=scli,
                                      branch="branch=z9hG4bK"
                                      + md5h((callid + str(attempt)
                                              + "sync").encode()))
            s2 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s2.bind((ue, 5060))
            s2.settimeout(12)
            got_new_nonce = False
            try:
                s2.sendto(reg_sync, (pcscf, 5060))
                data, _ = s2.recvfrom(8192)
                text = data.decode("utf-8", "replace")
                log("重同步 <- %s" % text.split("\r\n", 1)[0])
                m = re.search(r'nonce="([^"]+)"', text)
                if m and m.group(1) != nonce and sip_status(text) in (401, 421):
                    nonce = m.group(1)
                    sec_server = re.search(
                        r"Security-Server: ipsec-3gpp;(.*)",
                        text).group(1).strip()
                    got_new_nonce = True
            finally:
                s2.close()
            if got_new_nonce:
                log("拿到新 nonce，重新 AKA")
                continue
            time.sleep(6)
            continue
        break

    if res is None:
        raise RuntimeError("AKA 未成功")

    log("AKA OK: RES=%s IK=%s" % (res.hex()[:16], ik.hex()[:16]))

    # digest：password = raw RES 字节，无 qop（Unicom 实证）
    username = "%s@%s" % (IMSI, DOMAIN)
    ha1 = md5h(username.encode() + b":" + DOMAIN.encode() + b":" + res)
    ha2 = md5h(("REGISTER:%s" % URI).encode())
    response = md5h(("%s:%s:%s" % (ha1, nonce, ha2)).encode())

    xfrm_setup(ue, pcscf, pc_spi_s, ik)

    auth2 = ('Authorization: Digest username="%s@%s",realm="%s",nonce="%s",'
             'uri="%s",response="%s",algorithm=AKAv1-MD5'
             % (IMSI, DOMAIN, DOMAIN, nonce, URI, response))
    # 注意：build_register 自己加 "Security-Verify: " 前缀，这里只传值
    sec_verify = "ipsec-3gpp;%s" % sec_server
    reg2 = build_register(ue, pcscf, 2, UE_PORT_S, tag, callid,
                          authorization=auth2, sec_verify=sec_verify,
                          scli=scli, expires=3600,
                          branch="branch=z9hG4bK"
                          + md5h((callid + "reg2").encode()))

    cli = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    cli.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cli.bind((ue, UE_PORT_C))
    srv = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((ue, UE_PORT_S))
    srv.settimeout(15)
    try:
        cli.sendto(reg2, (pcscf, pc_port_s))
        log("REGISTER#2 (protected) %d -> %d" % (UE_PORT_C, pc_port_s))
        data, addr = srv.recvfrom(8192)
        text = data.decode("utf-8", "replace")
        log("REGISTER#2 <- %s: %s" % (addr[0], text.split("\r\n", 1)[0]))
        if "SIP/2.0 200" not in text:
            raise RuntimeError("REGISTER#2: %s" % text.split("\r\n", 1)[0])
        m = re.search(r"Service-Route:\s*(\S+)", text)
        service_route = m.group(1) if m else ""
        # 默认 IMPU = P-Associated-URI 里第一个 sip:+ 形式（MO 短信用）
        impu = ""
        m = re.search(r"P-Associated-URI:\s*<sip:\+[^>]+>", text)
        if m:
            impu = m.group(0).split("<", 1)[1].rstrip(">")
        log(">>> IMS REGISTERED OK <<<")
        return True, None, service_route, impu
    finally:
        cli.close()
        srv.close()


def main():
    pcscf = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] else None
    ue = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None
    if not ue:
        ue = discover_ue()
    if not pcscf:
        # 必须先清残留 xfrm：旧 IN 策略会丢弃 P-CSCF 的明文 ICMP 应答，
        # 导致 ping 探测全部失败；旧 OUT 策略会把明文 REGISTER#1 包成 ESP
        sh("ip xfrm state flush; ip xfrm policy flush")
        pcscf = discover_pcscf()
    if not ue or not pcscf:
        print(json.dumps({"registered": False, "pcscf": pcscf or "",
                          "ue_addr": ue or "",
                          "error": "discovery failed: ue=%s pcscf=%s"
                                   % (ue, pcscf)}, ensure_ascii=False))
        return 1
    try:
        ok, err, _sr = register(pcscf, ue)
    except Exception as e:
        ok, err = False, str(e)
        log("注册失败: %s" % e)
    print(json.dumps({"registered": ok, "pcscf": pcscf, "ue_addr": ue,
                      "error": err or ""}, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
