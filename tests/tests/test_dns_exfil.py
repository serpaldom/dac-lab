#!/usr/bin/env python3
import time
import subprocess
from scapy.all import IP, UDP, DNS, DNSQR, send
TARGET_IP ="10.0.2.11"
ALERT_FILE = "/var/log/snort/snort.alert.fast"
RULE_MSG = "DAC DNS exfil - base64-like label in query"

def clear_alerts():
    open(ALERT_FILE, "w").close()

def send_dns_query_with_label(target=TARGET_IP, label=""):
    qname = label + ".example.com"
    pkt = IP(dst=target)/UDP(sport=33333,dport=53)/DNS(rd=1,qd=DNSQR(qname=qname))
    send(pkt, verbose=False)
    time.sleep(0.2)

def test_dns_exfil_positive():
    clear_alerts()
    big_label = "A"*60  # simplistic base64-like long label (replace with actual base64 chars)
    send_dns_query_with_label(label=big_label)
    time.sleep(1)
    with open(ALERT_FILE,"r") as f:
        alerts = f.read()
    assert RULE_MSG in alerts

def test_dns_exfil_negative():
    clear_alerts()
    send_dns_query_with_label(label="normallabel")
    time.sleep(1)
    with open(ALERT_FILE,"r") as f:
        alerts = f.read()
    assert RULE_MSG not in alerts
