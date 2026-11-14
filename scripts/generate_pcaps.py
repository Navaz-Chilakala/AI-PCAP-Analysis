#!/usr/bin/env python3
"""
Synthetic 5G PCAP generator for the research project demo:
"AI-Based PCAP Analysis for Anomaly Detection and Performance Optimization
 in Telecom Networks" - Navaz Chilakala (241VMBR01593)

Generates realistic simulated call flows:
  1. pdu_session_success.pcap   - Full successful 5G PDU Session Establishment
                                  (SBI HTTP/2 on N11/N7 + PFCP on N4)
  2. pdu_session_fail_pfcp.pcap - PDU session fails: UPF rejects PFCP Session
                                  Establishment (Cause: No resources available)
  3. sbi_fail_404_pcf.pcap      - PDU session fails: PCF returns HTTP/2 404 on
                                  Npcf_SMPolicyControl (N7 interface)
  4. volte_call_486_busy.pcap   - VoLTE SIP call rejected with 486 Busy Here
  5. sbi_timeout_n4.pcap        - SMF sends PFCP Establishment, UPF never
                                  responds (timeout / missing response)
  6. ue_registration_fail_auth.pcap - UE Registration fails: AUSF rejects the
                                  5G-AKA confirmation with 403 on N12
                                  (Report Table 17, TS 33.501 / TS 23.502)
"""
import time
from scapy.all import Ether, IP, UDP, TCP, Raw, wrpcap
import os
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "public", "sample_pcaps")
os.makedirs(OUT, exist_ok=True)

T0 = time.time()

# ---- NF endpoint addressing (typical lab 5G core) ----
AMF = "10.10.1.10"   # Access & Mobility Mgmt
SMF = "10.10.1.20"   # Session Mgmt
UPF = "10.10.2.30"   # User Plane
PCF = "10.10.1.40"   # Policy Control
AUSF = "10.10.1.50"  # Authentication Server
UDM = "10.10.1.60"   # Unified Data Mgmt
UE  = "192.168.5.77" # UE / IMS client
PCSCF = "10.20.1.5"  # IMS P-CSCF

MAC_A = "02:00:00:00:01:aa"
MAC_B = "02:00:00:00:02:bb"


def pkt(src, dst, sport, dport, payload, t, proto="tcp", flags="PA"):
    l4 = TCP(sport=sport, dport=dport, flags=flags) if proto == "tcp" \
         else UDP(sport=sport, dport=dport)
    p = Ether(src=MAC_A, dst=MAC_B) / IP(src=src, dst=dst) / l4 / Raw(load=payload)
    p.time = t
    return p


# ---------- HTTP/2 SBI helpers (simplified h2 frames, headers kept readable) ----------
def h2_headers_frame(pseudo_headers, stream_id=1):
    """Simplified HTTP/2 HEADERS frame; header strings literal (no Huffman)
    so they are visible to packet analyzers - mirrors SbiSim debug mode."""
    block = b""
    for k, v in pseudo_headers:
        k_b, v_b = k.encode(), v.encode()
        block += b"\x00" + bytes([len(k_b)]) + k_b + bytes([len(v_b)]) + v_b
    ln = len(block)
    frame = ln.to_bytes(3, "big") + b"\x01" + b"\x04" + stream_id.to_bytes(4, "big")
    return frame + block


def h2_data_frame(data, stream_id=1, end=True):
    flags = b"\x01" if end else b"\x00"
    return len(data).to_bytes(3, "big") + b"\x00" + flags + stream_id.to_bytes(4, "big") + data


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


# ---------- PFCP helpers (TS 29.244) ----------
def pfcp_msg(msg_type, seq, ies=b"", seid=None):
    """PFCP header: ver=1 | msg type | length | [SEID] | seq | spare"""
    flags = 0x21 if seid is not None else 0x20  # S-flag if SEID present
    body = (seid.to_bytes(8, "big") if seid is not None else b"")
    body += seq.to_bytes(3, "big") + b"\x00"
    body += ies
    length = len(body)
    return bytes([flags, msg_type]) + length.to_bytes(2, "big") + body


def ie(ie_type, value):
    return ie_type.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


IE_NODE_ID = 60
IE_CAUSE = 19
IE_FSEID = 57
CAUSE_ACCEPTED = bytes([1])
CAUSE_NO_RESOURCES = bytes([70])   # "No resources available" TS 29.244 8.2.1

PFCP_SER = 50   # Session Establishment Request
PFCP_SERSP = 51 # Session Establishment Response


# =====================================================================
# 1. SUCCESSFUL PDU SESSION ESTABLISHMENT
# =====================================================================
def gen_success():
    pkts, t = [], T0
    # N11: AMF -> SMF  Nsmf_PDUSession_CreateSMContext
    pkts.append(pkt(AMF, SMF, 41001, 8080, H2_PREFACE, t)); t += 0.002
    pkts.append(pkt(AMF, SMF, 41001, 8080, h2_headers_frame([
        (":method", "POST"), (":path", "/nsmf-pdusession/v1/sm-contexts"),
        (":authority", "smf.5gc.mnc001.mcc001"), ("content-type", "application/json"),
        ("user-agent", "AMF-sbisim"),
    ]) + h2_data_frame(b'{"supi":"imsi-001011234567895","pduSessionId":5,"dnn":"internet","sNssai":{"sst":1}}'), t)); t += 0.004
    # SMF -> PCF  Npcf_SMPolicyControl Create (N7)
    pkts.append(pkt(SMF, PCF, 42002, 8080, H2_PREFACE, t)); t += 0.001
    pkts.append(pkt(SMF, PCF, 42002, 8080, h2_headers_frame([
        (":method", "POST"), (":path", "/npcf-smpolicycontrol/v1/sm-policies"),
        (":authority", "pcf.5gc.mnc001.mcc001"), ("content-type", "application/json"),
    ]) + h2_data_frame(b'{"supi":"imsi-001011234567895","pduSessionId":5,"dnn":"internet"}'), t)); t += 0.006
    # PCF -> SMF 201 Created
    pkts.append(pkt(PCF, SMF, 8080, 42002, h2_headers_frame([
        (":status", "201"), ("location", "/npcf-smpolicycontrol/v1/sm-policies/pol-00042"),
        ("content-type", "application/json"),
    ]) + h2_data_frame(b'{"sessRules":{"rule1":{"authSessAmbr":{"uplink":"500 Mbps","downlink":"1 Gbps"}}}}'), t)); t += 0.003
    # N4: SMF -> UPF PFCP Session Establishment Request
    pkts.append(pkt(SMF, UPF, 8805, 8805, pfcp_msg(PFCP_SER, 1001,
        ie(IE_NODE_ID, b"\x00" + bytes(map(int, SMF.split("."))))
        + ie(IE_FSEID, b"\x02" + (0xABCD0001).to_bytes(8, "big") + bytes(map(int, SMF.split(".")))),
        seid=0), t, proto="udp")); t += 0.005
    # UPF -> SMF PFCP Session Establishment Response (Cause: accepted)
    pkts.append(pkt(UPF, SMF, 8805, 8805, pfcp_msg(PFCP_SERSP, 1001,
        ie(IE_NODE_ID, b"\x00" + bytes(map(int, UPF.split("."))))
        + ie(IE_CAUSE, CAUSE_ACCEPTED)
        + ie(IE_FSEID, b"\x02" + (0xDEAD0001).to_bytes(8, "big") + bytes(map(int, UPF.split(".")))),
        seid=0xABCD0001), t, proto="udp")); t += 0.004
    # SMF -> AMF 201 Created (SM context)
    pkts.append(pkt(SMF, AMF, 8080, 41001, h2_headers_frame([
        (":status", "201"), ("location", "/nsmf-pdusession/v1/sm-contexts/ctx-00077"),
        ("content-type", "application/json"),
    ]) + h2_data_frame(b'{"status":"ACTIVE","ueIpv4Address":"10.45.0.7"}'), t)); t += 0.002
    wrpcap(OUT + "/pdu_session_success.pcap", pkts)
    print("pdu_session_success.pcap", len(pkts), "packets")


# =====================================================================
# 2. PDU SESSION FAILS - PFCP REJECT (No resources available)
# =====================================================================
def gen_pfcp_fail():
    pkts, t = [], T0 + 100
    pkts.append(pkt(AMF, SMF, 41003, 8080, H2_PREFACE, t)); t += 0.002
    pkts.append(pkt(AMF, SMF, 41003, 8080, h2_headers_frame([
        (":method", "POST"), (":path", "/nsmf-pdusession/v1/sm-contexts"),
        (":authority", "smf.5gc.mnc001.mcc001"), ("content-type", "application/json"),
    ]) + h2_data_frame(b'{"supi":"imsi-001011234567901","pduSessionId":6,"dnn":"internet","sNssai":{"sst":1}}'), t)); t += 0.004
    pkts.append(pkt(SMF, PCF, 42004, 8080, h2_headers_frame([
        (":method", "POST"), (":path", "/npcf-smpolicycontrol/v1/sm-policies"),
        (":authority", "pcf.5gc.mnc001.mcc001"),
    ]) + h2_data_frame(b'{"supi":"imsi-001011234567901","pduSessionId":6}'), t)); t += 0.005
    pkts.append(pkt(PCF, SMF, 8080, 42004, h2_headers_frame([
        (":status", "201"), ("location", "/npcf-smpolicycontrol/v1/sm-policies/pol-00043"),
    ]) + h2_data_frame(b'{"sessRules":{}}'), t)); t += 0.003
    # PFCP Establishment -> REJECTED cause 70
    pkts.append(pkt(SMF, UPF, 8805, 8805, pfcp_msg(PFCP_SER, 1002,
        ie(IE_NODE_ID, b"\x00" + bytes(map(int, SMF.split("."))))
        + ie(IE_FSEID, b"\x02" + (0xABCD0002).to_bytes(8, "big") + bytes(map(int, SMF.split(".")))),
        seid=0), t, proto="udp")); t += 0.006
    pkts.append(pkt(UPF, SMF, 8805, 8805, pfcp_msg(PFCP_SERSP, 1002,
        ie(IE_NODE_ID, b"\x00" + bytes(map(int, UPF.split("."))))
        + ie(IE_CAUSE, CAUSE_NO_RESOURCES),
        seid=0xABCD0002), t, proto="udp")); t += 0.004
    # SMF -> AMF 500 with ProblemDetails
    pkts.append(pkt(SMF, AMF, 8080, 41003, h2_headers_frame([
        (":status", "500"), ("content-type", "application/problem+json"),
    ]) + h2_data_frame(b'{"title":"PDU_SESSION_ESTABLISHMENT_FAILED","cause":"NETWORK_FAILURE","detail":"N4 PFCP Session Establishment rejected by UPF: NO_RESOURCES_AVAILABLE"}'), t)); t += 0.002
    wrpcap(OUT + "/pdu_session_fail_pfcp.pcap", pkts)
    print("pdu_session_fail_pfcp.pcap", len(pkts), "packets")


# =====================================================================
# 3. SBI FAILURE - PCF RETURNS 404 ON N7
# =====================================================================
def gen_sbi_404():
    pkts, t = [], T0 + 200
    pkts.append(pkt(AMF, SMF, 41005, 8080, H2_PREFACE, t)); t += 0.002
    pkts.append(pkt(AMF, SMF, 41005, 8080, h2_headers_frame([
        (":method", "POST"), (":path", "/nsmf-pdusession/v1/sm-contexts"),
        (":authority", "smf.5gc.mnc001.mcc001"),
    ]) + h2_data_frame(b'{"supi":"imsi-001011234567950","pduSessionId":9,"dnn":"ims"}'), t)); t += 0.004
    # SMF queries PCF for an existing policy -> 404 Not Found
    pkts.append(pkt(SMF, PCF, 42006, 8080, h2_headers_frame([
        (":method", "POST"), (":path", "/npcf-smpolicycontrol/v1/sm-policies"),
        (":authority", "pcf.5gc.mnc001.mcc001"),
    ]) + h2_data_frame(b'{"supi":"imsi-001011234567950","pduSessionId":9,"dnn":"ims"}'), t)); t += 0.007
    pkts.append(pkt(PCF, SMF, 8080, 42006, h2_headers_frame([
        (":status", "404"), ("content-type", "application/problem+json"),
    ]) + h2_data_frame(b'{"title":"Not Found","status":404,"cause":"USER_UNKNOWN","detail":"Subscriber imsi-001011234567950 not found in UDR policy data"}'), t)); t += 0.003
    pkts.append(pkt(SMF, AMF, 8080, 41005, h2_headers_frame([
        (":status", "403"), ("content-type", "application/problem+json"),
    ]) + h2_data_frame(b'{"title":"Forbidden","status":403,"cause":"SUBSCRIPTION_DENIED","detail":"SM Policy association failed on N7: USER_UNKNOWN"}'), t)); t += 0.002
    wrpcap(OUT + "/sbi_fail_404_pcf.pcap", pkts)
    print("sbi_fail_404_pcf.pcap", len(pkts), "packets")


# =====================================================================
# 4. VoLTE SIP CALL - 486 BUSY HERE
# =====================================================================
def gen_sip_486():
    pkts, t = [], T0 + 300
    cid = "a84b4c76e66710@ue.ims.mnc001.mcc001"
    invite = (f"INVITE sip:+919876500001@ims.mnc001.mcc001.3gppnetwork.org SIP/2.0\r\n"
              f"Via: SIP/2.0/UDP {UE}:5060;branch=z9hG4bK776asdhds\r\n"
              f"From: <sip:+919876500777@ims.mnc001.mcc001.3gppnetwork.org>;tag=1928301774\r\n"
              f"To: <sip:+919876500001@ims.mnc001.mcc001.3gppnetwork.org>\r\n"
              f"Call-ID: {cid}\r\nCSeq: 314159 INVITE\r\n"
              f"Contact: <sip:ue@{UE}:5060>\r\nContent-Type: application/sdp\r\n"
              f"P-Access-Network-Info: 3GPP-NR-FDD\r\nContent-Length: 129\r\n\r\n"
              f"v=0\r\no=ue 2890844526 2890844526 IN IP4 {UE}\r\ns=-\r\n"
              f"c=IN IP4 {UE}\r\nt=0 0\r\nm=audio 49170 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\n")
    def sip(code_line, extra=""):
        return (f"SIP/2.0 {code_line}\r\n"
                f"Via: SIP/2.0/UDP {UE}:5060;branch=z9hG4bK776asdhds\r\n"
                f"From: <sip:+919876500777@ims.mnc001.mcc001.3gppnetwork.org>;tag=1928301774\r\n"
                f"To: <sip:+919876500001@ims.mnc001.mcc001.3gppnetwork.org>;tag=8321234356\r\n"
                f"Call-ID: {cid}\r\nCSeq: 314159 INVITE\r\n{extra}Content-Length: 0\r\n\r\n")
    pkts.append(pkt(UE, PCSCF, 5060, 5060, invite.encode(), t, proto="udp")); t += 0.020
    pkts.append(pkt(PCSCF, UE, 5060, 5060, sip("100 Trying").encode(), t, proto="udp")); t += 0.180
    pkts.append(pkt(PCSCF, UE, 5060, 5060, sip("180 Ringing").encode(), t, proto="udp")); t += 2.400
    pkts.append(pkt(PCSCF, UE, 5060, 5060, sip("486 Busy Here", "Retry-After: 120\r\n").encode(), t, proto="udp")); t += 0.015
    ack = (f"ACK sip:+919876500001@ims.mnc001.mcc001.3gppnetwork.org SIP/2.0\r\n"
           f"Via: SIP/2.0/UDP {UE}:5060;branch=z9hG4bK776asdhds\r\n"
           f"Call-ID: {cid}\r\nCSeq: 314159 ACK\r\nContent-Length: 0\r\n\r\n")
    pkts.append(pkt(UE, PCSCF, 5060, 5060, ack.encode(), t, proto="udp"))
    wrpcap(OUT + "/volte_call_486_busy.pcap", pkts)
    print("volte_call_486_busy.pcap", len(pkts), "packets")


# =====================================================================
# 5. PFCP TIMEOUT - UPF NEVER RESPONDS (missing response anomaly)
# =====================================================================
def gen_timeout():
    pkts, t = [], T0 + 400
    pkts.append(pkt(AMF, SMF, 41007, 8080, h2_headers_frame([
        (":method", "POST"), (":path", "/nsmf-pdusession/v1/sm-contexts"),
        (":authority", "smf.5gc.mnc001.mcc001"),
    ]) + h2_data_frame(b'{"supi":"imsi-001011234567999","pduSessionId":3,"dnn":"internet"}'), t)); t += 0.004
    # SMF sends PFCP SER ... and retransmits 3x (T1 timer), no response ever
    for i, gap in enumerate([0.0, 3.0, 3.0, 3.0]):
        t += gap
        pkts.append(pkt(SMF, UPF, 8805, 8805, pfcp_msg(PFCP_SER, 1077,
            ie(IE_NODE_ID, b"\x00" + bytes(map(int, SMF.split("."))))
            + ie(IE_FSEID, b"\x02" + (0xABCD0077).to_bytes(8, "big") + bytes(map(int, SMF.split(".")))),
            seid=0), t, proto="udp"))
    t += 3.0
    pkts.append(pkt(SMF, AMF, 8080, 41007, h2_headers_frame([
        (":status", "504"), ("content-type", "application/problem+json"),
    ]) + h2_data_frame(b'{"title":"Gateway Timeout","status":504,"cause":"UPF_NOT_RESPONDING","detail":"PFCP Session Establishment Response not received within N1*T1 timer (TS 29.244)"}'), t))
    wrpcap(OUT + "/sbi_timeout_n4.pcap", pkts)
    print("sbi_timeout_n4.pcap", len(pkts), "packets")


# =====================================================================
# 6. UE REGISTRATION FAILS - AUSF REJECTS 5G-AKA AUTHENTICATION (N12)
# =====================================================================
def gen_registration_fail():
    pkts, t = [], T0 + 500
    # N12: AMF -> AUSF  Nausf_UEAuthentication (initial request)
    pkts.append(pkt(AMF, AUSF, 41009, 8080, H2_PREFACE, t)); t += 0.002
    pkts.append(pkt(AMF, AUSF, 41009, 8080, h2_headers_frame([
        (":method", "POST"), (":path", "/nausf-auth/v1/ue-authentications"),
        (":authority", "ausf.5gc.mnc001.mcc001"), ("content-type", "application/json"),
    ]) + h2_data_frame(b'{"supiOrSuci":"suci-0-001-01-0000-0-0-1234567988","servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org"}'), t)); t += 0.006
    # AUSF -> AMF 201 Created with 5G-AKA challenge
    pkts.append(pkt(AUSF, AMF, 8080, 41009, h2_headers_frame([
        (":status", "201"), ("location", "/nausf-auth/v1/ue-authentications/authctx-0088"),
        ("content-type", "application/3gppHal+json"),
    ]) + h2_data_frame(b'{"authType":"5G_AKA","5gAuthData":{"rand":"a8f1...","autn":"7c02...","hxresStar":"9be4..."}}'), t)); t += 0.045
    # N12: AMF -> AUSF  5G-AKA confirmation (RES* from UE)
    pkts.append(pkt(AMF, AUSF, 41009, 8080, h2_headers_frame([
        (":method", "PUT"), (":path", "/nausf-auth/v1/ue-authentications/authctx-0088/5g-aka-confirmation"),
        (":authority", "ausf.5gc.mnc001.mcc001"), ("content-type", "application/json"),
    ]) + h2_data_frame(b'{"resStar":"0000deadbeef0000"}'), t)); t += 0.008
    # AUSF -> AMF 403: RES* verification failed -> authentication rejected
    pkts.append(pkt(AUSF, AMF, 8080, 41009, h2_headers_frame([
        (":status", "403"), ("content-type", "application/problem+json"),
    ]) + h2_data_frame(b'{"title":"Forbidden","status":403,"cause":"AUTHENTICATION_REJECTED","detail":"RES* verification failed for suci-0-001-01-0000-0-0-1234567988 (TS 33.501 5G-AKA)"}'), t)); t += 0.003
    wrpcap(OUT + "/ue_registration_fail_auth.pcap", pkts)
    print("ue_registration_fail_auth.pcap", len(pkts), "packets")


if __name__ == "__main__":
    gen_success(); gen_pfcp_fail(); gen_sbi_404(); gen_sip_486(); gen_timeout()
    gen_registration_fail()
    print("All synthetic PCAPs generated.")
