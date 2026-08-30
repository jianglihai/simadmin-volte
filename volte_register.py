#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
volte_register.py — VoLTE IMS SIP 注册（完整流程）
用法: python3 volte_register.py <P-CSCF_addr> [UE_addr]
输出: 最后行 JSON {"registered":true/false, "pcscf":"..", "ue_addr":"..", ...}
依赖: 仅 stdlib + @qmi-proxy Unix socket（root 权限）
"""
import base64, hashlib, json, os, socket, struct, sys, time

# ---- config ----
IMSI = "460018558516337"
DOMAIN = "ims.mnc001.mcc460.3gppnetwork.org"
REALM = DOMAIN
URI = "sip:" + DOMAIN
AID = bytes.fromhex("A0000000871002FF86FFFF89FFFFFFFF")
PROXY_PATH = b"/dev/wwan0qmi0"

PCSCF = sys.argv[1] if len(sys.argv) > 1 else "2408:8142:6001:3::"
# UE addr: 从 wwan1 上取第一个 global 地址
def get_ue_addr():
    try:
        out = os.popen("ip -6 addr show dev wwan1 scope global 2>/dev/null").read()
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet6") and "temporary" not in line and "mngtmpaddr" not in line:
                addr = line.split()[1].split("/")[0]
                if not addr.startswith("fe80"):
                    return addr
        # fallback: any global
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet6") and "fe80" not in line:
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return None

UE = get_ue_addr() or sys.argv[2] if len(sys.argv) > 2 else get_ue_addr()
if not UE:
    print(json.dumps({"registered": False, "error": "no wwan1 address"}))
    sys.exit(1)

print("UE=" + UE, file=sys.stderr)
print("PCSCF=" + PCSCF, file=sys.stderr)

# ---- QMI UIM transport ----
SVC_CTL = 0x00
SVC_UIM = 0x0B

def qmi_build(svc, client, txn, msgid, tlvs):
    extra = b"\x00" if svc != 0x00 else b""
    sdu = bytes([0x00, txn & 0xFF]) + extra + struct.pack("<HH", msgid, len(tlvs)) + tlvs
    body = bytes([0x00, svc, client]) + sdu
    pad = b"\x00" if not tlvs else b""
    return bytes([0x01]) + struct.pack("<H", len(body) + 2 + len(pad)) + body + pad

def qmi_parse(data):
    if len(data) < 12 or data[0] != 0x01:
        return None
    flags, svc, cli = data[3], data[4], data[5]
    extra = 1 if svc != 0x00 else 0
    off = 6 + extra
    txn = data[off]
    msgid = int.from_bytes(data[off+1:off+3], "little")
    tlvlen = int.from_bytes(data[off+3:off+5], "little")
    tlvs_raw = data[off+5:off+5+tlvlen]
    tlvs = {}
    i = 0
    while i + 3 <= len(tlvs_raw):
        t = tlvs_raw[i]
        l = int.from_bytes(tlvs_raw[i+1:i+3], "little")
        if i + 3 + l > len(tlvs_raw):
            break
        tlvs.setdefault(t, []).append(tlvs_raw[i+3:i+3+l])
        i += 3 + l
    return {"flags": flags, "svc": svc, "txn": txn, "msgid": msgid, "tlvs": tlvs}

class QmiUim:
    def __init__(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(b"\x00qmi-proxy")
        self.txn = 0
        self._proxy_open()

    def _next_txn(self):
        self.txn = (self.txn % 255) + 1
        return self.txn

    def _proxy_open(self):
        tlv = bytes([0x01]) + struct.pack("<H", len(PROXY_PATH)) + PROXY_PATH
        self.sock.sendall(qmi_build(SVC_CTL, 0, self._next_txn(), 0xFF00, tlv))
        self._read_frame()

    def _read_frame(self, timeout=10):
        self.sock.settimeout(timeout)
        buf = b""
        while True:
            try:
                d = self.sock.recv(4096)
            except socket.timeout:
                return None
            if not d:
                return None
            buf += d
            if len(buf) >= 3:
                ln = int.from_bytes(buf[1:3], "little")
                if len(buf) >= ln + 1:
                    return qmi_parse(buf[:ln+1])

    def _send_recv(self, svc, client, msgid, tlvs):
        self.sock.sendall(qmi_build(svc, client, self._next_txn(), msgid, tlvs))
        end = time.time() + 15
        while time.time() < end:
            r = self._read_frame(3)
            if r and r.get("txn") == self.txn and r.get("svc") == svc and r.get("msgid") == msgid:
                return r
        return None

    def allocate_cid(self):
        r = self._send_recv(SVC_CTL, 0, 0x0022, bytes([0x01, SVC_UIM]))
        info = r["tlvs"].get(0x01, [b""])[0]
        return info[1] if len(info) >= 2 else 1

    def open_channel(self, cid, aid):
        tlv = bytes([0x01, 0x01]) + bytes([0x10, len(aid)]) + aid
        r = self._send_recv(SVC_UIM, cid, 0x0042, tlv)
        return r["tlvs"].get(0x10, [b"\x01"])[0][0]

    def send_apdu(self, cid, ch, apdu):
        inner = struct.pack("<H", len(apdu)) + apdu
        tlv = bytes([0x10, ch]) + bytes([0x01, 0x01]) + bytes([0x02]) + struct.pack("<H", len(inner)) + inner
        r = self._send_recv(SVC_UIM, cid, 0x003B, tlv)
        vs = r["tlvs"].get(0x10, [b""])[0]
        if len(vs) >= 2 and int.from_bytes(vs[0:2], "little") == len(vs) - 2:
            vs = vs[2:]
        return vs[:-2], vs[-2], vs[-1]

    def close_channel(self, cid, ch):
        tlv = bytes([0x01, 0x01]) + bytes([0x10, ch])
        self._send_recv(SVC_UIM, cid, 0x003D, tlv)

    def release_cid(self, cid):
        self._send_recv(SVC_CTL, 0, 0x0023, bytes([SVC_UIM, cid]))

    def close(self):
        self.sock.close()


def usim_aka(rand, autn):
    q = QmiUim()
    try:
        cid = q.allocate_cid()
        ch = q.open_channel(cid, AID)
        auth_data = bytes([len(rand)]) + rand + bytes([len(autn)]) + autn
        apdu = bytes([0x00, 0x88, 0x00, 0x81, len(auth_data)]) + auth_data + b"\x00"
        data, sw1, sw2 = q.send_apdu(cid, ch, apdu)
        if sw1 == 0x61:
            data, sw1, sw2 = q.send_apdu(cid, ch, bytes([0x00, 0xC0, 0x00, 0x00, sw2]))
        q.close_channel(cid, ch)
        if (sw1, sw2) != (0x90, 0x00):
            return {"error": "SW=%02X%02X" % (sw1, sw2)}
        if data[:1] == b"\xdb":
            off = 1
            def take(off):
                ln = data[off]
                return data[off+1:off+1+ln], off + 1 + ln
            res, off = take(off)
            ck, off = take(off)
            ik, _ = take(off)
            return {"res": res.hex(), "ck": ck.hex(), "ik": ik.hex()}
        elif data[:1] == b"\xdc":
            auts = data[2:2+data[1]]
            return {"auts": auts.hex()}
        return {"error": "unknown tag"}
    finally:
        try:
            q.release_cid(cid)
        except Exception:
            pass
        q.close()


# ---- SIP helpers ----
def md5h(b):
    return hashlib.md5(b).hexdigest()

def digest_resp(user, realm, pwd_bytes, nonce, cnonce=None, qop=None, nc=None):
    ha1 = md5h(user.encode() + b":" + realm.encode() + b":" + pwd_bytes)
    ha2 = md5h(("REGISTER:" + URI).encode())
    if qop:
        raw = "%s:%s:%s:%s:%s:%s" % (ha1, nonce, nc, cnonce, qop, ha2)
    else:
        raw = "%s:%s:%s" % (ha1, nonce, ha2)
    return md5h(raw.encode())

def build_register(ue, pcscf, cseq, port, tag, callid, auth_line=None, secv=None, scli=None):
    branch = "z9hG4bK" + md5h((callid + str(cseq)).encode())
    lines = [
        "REGISTER sip:%s SIP/2.0" % DOMAIN,
        "Via: SIP/2.0/UDP [%s]:%d;branch=%s;rport" % (ue, port, branch),
        "Max-Forwards: 70",
        "From: <sip:%s@%s>;tag=%s" % (IMSI, DOMAIN, tag),
        "To: <sip:%s@%s>" % (IMSI, DOMAIN),
        "Call-ID: %s" % callid,
        "CSeq: %d REGISTER" % cseq,
    ]
    if auth_line:
        lines.append(auth_line)
    lines.append('Contact: <sip:%s@[%s]:%d;transport=UDP>;'
                 '+g.3gpp.accesstype="3GPP-E-UTRAN-FDD";+g.3gpp.smsip;expires=3600' % (IMSI, ue, port))
    lines.append("Accept: application/vnd.3gpp.sms")
    lines.append("Route: <sip:[%s]:5060;lr>" % pcscf)
    lines.append("Expires: 3600")
    lines.append("Supported: path, gruu, sec-agree")
    lines.append("Allow: INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,MESSAGE,REFER,NOTIFY,INFO,OPTIONS")
    lines.append("P-Preferred-Identity: <sip:%s@%s>" % (IMSI, DOMAIN))
    lines.append('P-Visited-Network-ID: "%s"' % DOMAIN)
    lines.append("P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=%s0000000;cell-info-age=0" % IMSI[:5])
    if secv:
        lines.append("Require: sec-agree")
        lines.append("Proxy-Require: sec-agree")
        lines.append("Security-Verify: %s" % secv)
    if scli:
        lines.append("Security-Client: %s" % scli)
    lines.append("User-Agent: SimAdmin VoLTE")
    lines.append("Content-Length: 0")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode()


def parse_sip_response(data):
    text = data.decode("utf-8", "replace")
    lines = text.split("\r\n")
    status = int(lines[0].split()[1]) if len(lines[0].split()) > 1 else 0
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, val = line.split(":", 1)
            headers.setdefault(k.strip().lower(), []).append(val.strip())
    return {"status": status, "text": text, "headers": headers}


# ---- main registration flow ----
def main():
    callid = md5h(str(time.time()).encode()) + "@simadmin-volte"
    tag = md5h(callid.encode())[:8]
    spi_c = int(md5h((callid + "sc").encode())[:7], 16)
    spi_s = int(md5h((callid + "ss").encode())[:7], 16)
    port_c = 1024 + int(md5h((callid + "pc").encode())[:3], 16) % 30000
    port_s = 1024 + int(md5h((callid + "ps").encode())[:3], 16) % 30000
    scli = ("ipsec-3gpp;prot=esp;mod=trans;spi-c=%d;spi-s=%d;port-c=%d;port-s=%d;"
            "alg=hmac-md5-96;ealg=null" % (spi_c, spi_s, port_c, port_s))

    username = "%s@%s" % (IMSI, DOMAIN)
    nonce = ""
    opaque = ""
    sec_server_raw = ""

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((UE, 5060))
    sock.settimeout(12)

    # --- REGISTER#1 ---
    for attempt in range(3):
        cseq = attempt + 1
        reg1 = build_register(UE, PCSCF, cseq, 5060, tag, callid, scli=scli)
        sock.sendto(reg1, (PCSCF, 5060))
        print("REGISTER#1 sent (attempt %d)" % attempt, file=sys.stderr)
        try:
            data, _ = sock.recvfrom(8192)
        except socket.timeout:
            continue
        resp = parse_sip_response(data)
        if resp["status"] in (401, 421):
            break
        if resp["status"] == 403 and "different algorithm" in resp["text"]:
            continue  # 重试可能因节点缓存变化而通过
        print(resp["text"][:500], file=sys.stderr)
        return

    if resp["status"] not in (401, 421):
        print(json.dumps({"registered": False, "error": "unexpected status %d" % resp["status"]}))
        return

    # --- parse 401 ---
    hdrs = resp["headers"]
    www = hdrs.get("www-authenticate", [""])[0]
    sec_server = hdrs.get("security-server", [""])[0]
    nonce_m = __import__("re").search(r'nonce="([^"]+)"', www)
    if nonce_m:
        nonce = nonce_m.group(1)
    sec_server = __import__("re").search(r"ipsec-3gpp;(.*)", sec_server).group(1).strip() if sec_server else sec_server
    print("401 parsed, nonce len=%d" % len(nonce), file=sys.stderr)

    nonce_raw = base64.b64decode(nonce + "=" * ((4 - len(nonce) % 4) % 4))
    rand, autn = nonce_raw[:16], nonce_raw[16:32]

    # --- USIM AKA (含 AUTS 重同步) ---
    for aka_attempt in range(4):
        aka = usim_aka(rand, autn)
        if "error" in aka:
            print("AKA error: %s" % aka["error"], file=sys.stderr)
            return

        if "auts" in aka:
            # SQN 失步 → 发重同步 REGISTER
            auts_b64 = base64.b64encode(bytes.fromhex(aka["auts"])).decode()
            ha1e = md5h(username.encode() + b":")
            ha2e = md5h(("REGISTER:" + URI).encode())
            resp_empty = md5h((ha1e + ":" + nonce).encode())
            auth_auts = ('Authorization: Digest username="%s",realm="%s",nonce="%s",'
                         'uri="%s",response="%s",algorithm=AKAv1-MD5,auts="%s"'
                         % (username, DOMAIN, nonce, URI, resp_empty, auts_b64))
            cseq += 1
            reg_sync = build_register(UE, PCSCF, cseq, 5060, tag, callid, auth_line=auth_auts, scli=scli)
            sock.sendto(reg_sync, (PCSCF, 5060))
            print("AUTS resync sent", file=sys.stderr)
            try:
                data, _ = sock.recvfrom(8192)
                resp = parse_sip_response(data)
                nonce_m = __import__("re").search(r'nonce="([^"]+)"', resp["text"])
                if nonce_m:
                    nonce = nonce_m.group(1)
                    rand_n = base64.b64decode(nonce + "=" * ((4-len(nonce)%4)%4))
                    rand, autn = rand_n[:16], rand_n[16:32]
                continue
            except socket.timeout:
                continue

        # --- 正常 AKA 成功 ---
        if "res" in aka:
            break
    else:
        print(json.dumps({"registered": False, "error": "AKA failed after retries"}))
        return

    res = bytes.fromhex(aka["res"])
    ck = bytes.fromhex(aka["ck"])
    ik = bytes.fromhex(aka["ik"])
    print("AKA OK RES=%s IK=%s" % (res.hex()[:16], ik.hex()[:16]), file=sys.stderr)

    # --- digest ---
    pwd = res  # raw RES bytes (dev22 实证)
    response = digest_resp(username, DOMAIN, pwd, nonce)
    auth_line = ('Authorization: Digest username="%s",realm="%s",nonce="%s",'
                 'uri="%s",response="%s",algorithm=AKAv1-MD5'
                 % (username, DOMAIN, nonce, URI, response))

    # --- REGISTER#2 (protected) ---
    cseq += 1
    secv = ("ipsec-3gpp;" + sec_server) if sec_server else ""
    reg2 = build_register(UE, PCSCF, cseq, port_s, tag, callid, auth_line=auth_line, secv=secv, scli=scli)
    psock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    psock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    psock.bind((UE, port_s))
    psock.settimeout(15)
    psock.sendto(reg2, (PCSCF, 9900))
    print("REGISTER#2 sent (protected)", file=sys.stderr)

    try:
        data, _ = psock.recvfrom(8192)
        resp2 = parse_sip_response(data)
        print("REGISTER#2 <- %d" % resp2["status"], file=sys.stderr)
        if resp2["status"] == 200:
            print(json.dumps({
                "registered": True,
                "pcscf": PCSCF,
                "ue_addr": UE,
                "status": 200,
            }))
            return
    except socket.timeout:
        pass
    print(json.dumps({"registered": False, "error": "REGISTER#2 failed"}))


if __name__ == "__main__":
    main()
