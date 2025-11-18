#!/usr/bin/env python3
import time
import subprocess
from scapy.all import IP, TCP, send
TARGET_IP ="127.0.0.1"
ALERT_FILE = "/var/log/snort/snort.alert.fast"
RULE_MSG = "DAC SSH SYN scan - multiple SYNs to 22"

def clear_alerts():
    open(ALERT_FILE, "w").close()

def read_alerts():
    with open(ALERT_FILE, "r") as f:
        return f.read()

def send_syn_scan(target=TARGET_IP, dport=22, count=12):
    for sport in range(40000, 40000+count):
        pkt = IP(dst=target)/TCP(sport=sport, dport=dport, flags="S")
        send(pkt, verbose=False)
    time.sleep(0.5)

def test_ssh_syn_scan_positive():
    clear_alerts()
    send_syn_scan(count=12)
    time.sleep(1)
    alerts = read_alerts()
    assert RULE_MSG in alerts, "Expected SSH SYN alert not found"

def test_ssh_syn_scan_negative():
    clear_alerts()
    time.sleep(8)
    send_syn_scan(count=3)
    time.sleep(1)
    alerts = read_alerts()
    assert RULE_MSG not in alerts, "False positive: SSH SYN alert triggered on low volume"
