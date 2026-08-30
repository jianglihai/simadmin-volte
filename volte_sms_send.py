#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
volte_sms_send.py - IMS MO 短信发送（SIP MESSAGE over IPsec）
用法: python3 volte_sms_send.py <文本> [收件人] [P-CSCF] [UE地址]
  收件人默认本机号码（自发自收闭环测试）
流程: 确认 xfrm SA 存在（无则先完整注册）→ RP-DATA(SMS-SUBMIT) 封装
      → SIP MESSAGE（受保护）→ 200 OK + RP-ACK
RPDU/SIP 构造对齐 dev22 探针（TS 24.011 / 24.341 / 23.040）
"""
import base64
import hashlib
import json
import random
import re
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/opt/simadmin")
from volte_register import (  # noqa: E402
    DOMAIN, IMSI, UE_PORT_C, UE_PORT_S, URI, discover_pcscf, discover_ue,
    log, register, sh,
)

SMSC = "+8613010500500"  # AT+CSCA? 实测值
OWN_NUMBER = "+8618588557735"


# ---------------- 地址与编码（TS 23.040） ----------------

def normalized_address_digits(address):
    stripped = address.strip()
    international = stripped.startswith("+")
    digits = "".join(ch for ch in stripped if ch.isdigit())
    if not digits or len(digits) > 20:
        raise ValueError("invalid address: %s" % address)
    return digits, international


def encode_semi_octets(digits):
    out = bytearray()
    for i in range(0, len(digits), 2):
        low = int(digits[i])
        high = int(digits[i + 1]) if i + 1 < len(digits) else 0x0F
        out.append(low | (high << 4))
    return bytes(out)


def encode_address_value(address):
    digits, international = normalized_address_digits(address)
    return bytes([0x91 if international else 0x81]) + encode_semi_octets(digits)


GSM7_EXT = {"^": 0x14, "{": 0x28, "}": 0x29, "\\": 0x2F, "[": 0x3C,
            "~": 0x3D, "]": 0x3E, "|": 0x40, "€": 0x65}


def _gsm7_septets(text):
    table = {
        "@": 0x00, "$": 0x02, "\n": 0x0A, "\r": 0x0D, " ": 0x20,
        "!": 0x21, '"': 0x22, "#": 0x23, "%": 0x25, "&": 0x26, "'": 0x27,
        "(": 0x28, ")": 0x29, "*": 0x2A, "+": 0x2B, ",": 0x2C, "-": 0x2D,
        ".": 0x2E, "/": 0x2F,
        **{str(i): 0x30 + i for i in range(10)},
        ":": 0x3A, ";": 0x3B, "<": 0x3C, "=": 0x3D, ">": 0x3E, "?": 0x3F,
        **{chr(ord("A") + i): 0x41 + i for i in range(26)},
        **{chr(ord("a") + i): 0x61 + i for i in range(26)},
    }
    septets = []
    for ch in text:
        if ch in table:
            septets.append(table[ch])
        elif ch in GSM7_EXT:
            septets.extend([0x1B, GSM7_EXT[ch]])
        else:
            return None
    return septets


def encode_user_data(text):
    septets = _gsm7_septets(text)
    if septets is not None and len(septets) <= 160:
        out = bytearray((len(septets) * 7 + 7) // 8)
        for index, septet in enumerate(septets):
            bit_index = index * 7
            for bit in range(7):
                if septet & (1 << bit):
                    target = bit_index + bit
                    out[target // 8] |= 1 << (target % 8)
        return 0x00, len(septets), bytes(out)
    user_data = text.encode("utf-16-be")
    if len(user_data) > 140:
        raise ValueError("single-part SMS too long")
    return 0x08, len(user_data), user_data


def build_mo_sms_body(recipient, text, smsc):
    """RP-DATA(MO) = RP-MTI|MR|空源地址|SMSC|TPDU。"""
    mr = random.randrange(0, 256)
    destination = encode_address_value(recipient)
    digits, _intl = normalized_address_digits(recipient)
    dcs, udl, user_data = encode_user_data(text)
    tpdu = bytearray([0x01, mr, len(digits)])
    tpdu.extend(destination)
    tpdu.extend([0x00, dcs, udl])
    tpdu.extend(user_data)
    sc_address = encode_address_value(smsc)
    body = bytearray([0x00, mr, 0x00, len(sc_address)])
    body.extend(sc_address)
    body.append(len(tpdu))
    body.extend(tpdu)
    return mr, bytes(body)


# ---------------- SIP MESSAGE ----------------

def md5h(b):
    return hashlib.md5(b).hexdigest()


def send_message(pcscf, ue, recipient, text, service_route, impu):
    # 用户部分保留 "+"（E.164），vendor 探针同款
    phone_user = "+" + "".join(ch for ch in recipient if ch.isdigit())
    to_uri = "sip:%s@%s;user=phone" % (phone_user, DOMAIN)
    # TS 24.341：MO MESSAGE 的 Request-URI = SMSC / IP-SM-GW 身份（非收件人）
    smsc_user = "+" + "".join(ch for ch in SMSC if ch.isdigit())
    request_uri = "sip:%s@%s;user=phone" % (smsc_user, DOMAIN)
    mr, body = build_mo_sms_body(recipient, text, SMSC)
    callid = md5h(str(time.time()).encode())[:24] + "@simadmin-volte"
    branch = "branch=z9hG4bK" + md5h((callid + "msg").encode())
    routes = ["<sip:[%s]:5060;lr>" % pcscf]
    if service_route:
        routes.append(service_route)
    lines = [
        "MESSAGE %s SIP/2.0" % request_uri,
        "Via: SIP/2.0/UDP [%s]:%d;%s;rport" % (ue, UE_PORT_S, branch),
        "Max-Forwards: 70",
        "Route: %s" % ", ".join(routes),
        "From: <%s>;tag=%s" % (impu or ("sip:%s@%s" % (IMSI, DOMAIN)),
                               md5h(callid.encode())[:8]),
        "To: <%s>" % to_uri,
        "Call-ID: %s" % callid,
        "CSeq: 1 MESSAGE",
        "P-Preferred-Identity: <%s>" % (impu or ("sip:%s@%s" % (IMSI, DOMAIN))),
        "P-Access-Network-Info: 3GPP-E-UTRAN-FDD",
        "Accept-Contact: *;+g.3gpp.smsip",
        "User-Agent: SimAdmin VoLTE",
        "Content-Type: application/vnd.3gpp.sms",
        "Content-Length: %d" % len(body),
        "", "",
    ]
    packet = "\r\n".join(lines).encode() + body

    cli = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    cli.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cli.bind((ue, UE_PORT_C))
    srv = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((ue, UE_PORT_S))
    srv.settimeout(20)
    try:
        cli.sendto(packet, (pcscf, 9900))
        log("MESSAGE (MO SMS) 发送 MR=%d, %d 字节" % (mr, len(body)))
        data, addr = srv.recvfrom(8192)
        text_resp = data.decode("utf-8", "replace")
        status = text_resp.split("\r\n", 1)[0]
        log("MO <- %s: %s" % (addr[0], status))
        if not status.startswith("SIP/2.0 2"):
            print(text_resp[:900])
        has_ack = "application/vnd.3gpp.sms" in text_resp
        return status, has_ack
    finally:
        cli.close()
        srv.close()


def main():
    text = sys.argv[1] if len(sys.argv) > 1 else "SimAdmin VoLTE test"
    recipient = sys.argv[2] if len(sys.argv) > 2 else OWN_NUMBER
    pcscf = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None
    ue = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else None

    if not ue:
        ue = discover_ue()
    if not ue:
        print(json.dumps({"sent": False, "error": "discovery failed: ue"}))
        return 1

    service_route = ""
    impu = ""
    # 每次发送前完整注册：拿 Service-Route + IMPU + 新 SA
    # （旧 SA 对端地址可能与 ping 发现的不一致，直接重建最稳）
    sh("ip xfrm state flush; ip xfrm policy flush")
    if not pcscf:
        pcscf = discover_pcscf()
    if not pcscf:
        print(json.dumps({"sent": False, "error": "discovery failed: pcscf"}))
        return 1
    ok, err, service_route, impu = register(pcscf, ue)
    if not ok:
        print(json.dumps({"sent": False, "error": "register: %s" % err}))
        return 1
    log("IMPU: %s" % impu)

    status, has_ack = send_message(pcscf, ue, recipient, text,
                                   service_route, impu)
    sent = status.startswith("SIP/2.0 2")
    print(json.dumps({"sent": sent, "status": status,
                      "rp_ack": has_ack, "to": recipient,
                      "mr": None}, ensure_ascii=False))
    return 0 if sent else 1


if __name__ == "__main__":
    sys.exit(main())
