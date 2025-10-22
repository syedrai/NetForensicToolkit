#!/usr/bin/env python3
"""
netforensic.py
- Capture live packets (timeout or count)
- Save capture.pcap
- Quick analysis: top talkers (src IP) and protocol breakdown
- Requires: pyshark, pandas, tshark installed
"""

import argparse
import time
from collections import Counter
import pyshark
import pandas as pd
import os
import sys

def capture_packets(interface, timeout=None, packet_count=None, output_file="capture.pcap"):
    print(f"[+] Starting capture on interface='{interface}' (timeout={timeout}s, count={packet_count})")
    cap = pyshark.LiveCapture(interface=interface, output_file=output_file)
    if packet_count:
        cap.sniff(packet_count=packet_count)
    else:
        cap.sniff(timeout=timeout)
    print(f"[+] Capture finished. Saved -> {output_file}")
    return output_file

def analyze_pcap(pcap_file, top_n=10):
    print(f"[+] Analyzing pcap: {pcap_file} (this may take a few seconds)")
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)
    src_ips = []
    dst_ips = []
    protocols = []

    for i, pkt in enumerate(cap):
        try:
            # src/dst
            if hasattr(pkt, "ip"):
                src_ips.append(pkt.ip.src)
                dst_ips.append(pkt.ip.dst)
                protocols.append(pkt.highest_layer)
            elif hasattr(pkt, "ipv6"):
                src_ips.append(pkt.ipv6.src)
                dst_ips.append(pkt.ipv6.dst)
                protocols.append(pkt.highest_layer)
            else:
                # non-IP packets (ARP, etc)
                protocols.append(pkt.highest_layer)
        except Exception:
            continue
        # don't load everything into memory (pyshark with keep_packets=False helps)
        if i and i % 1000 == 0:
            print(f"  processed {i} packets...")

    # Counters
    top_src = Counter(src_ips).most_common(top_n)
    top_dst = Counter(dst_ips).most_common(top_n)
    proto_counts = Counter(protocols).most_common()

    print("\n=== Top source IPs ===")
    for ip, c in top_src:
        print(f"{ip:20} {c}")

    print("\n=== Top destination IPs ===")
    for ip, c in top_dst:
        print(f"{ip:20} {c}")

    print("\n=== Protocol breakdown ===")
    for proto, c in proto_counts:
        print(f"{proto:15} {c}")

    # save summary CSV
    summary = {
        "top_src": top_src,
        "top_dst": top_dst,
        "protocols": proto_counts
    }
    # simple CSVs for portability
    pd.DataFrame(top_src, columns=["src_ip", "count"]).to_csv("top_src.csv", index=False)
    pd.DataFrame(top_dst, columns=["dst_ip", "count"]).to_csv("top_dst.csv", index=False)
    pd.DataFrame(proto_counts, columns=["protocol", "count"]).to_csv("protocols.csv", index=False)
    print("\n[+] Saved CSVs: top_src.csv, top_dst.csv, protocols.csv")
    cap.close()

def list_interfaces():
    try:
        cap = pyshark.LiveCapture()
        print("[+] Available interfaces (pyshark):")
        print(cap.interfaces)
    except Exception as e:
        print("[!] Could not list interfaces via pyshark:", e)
        print("Use your OS tools (ipconfig / ifconfig / Wireshark) to find interface names.")

def parse_args():
    p = argparse.ArgumentParser(description="NetForensicToolkit - quick capture & analysis")
    p.add_argument("--iface", "-i", required=False, help="Interface name (e.g. Wi-Fi, eth0). If omitted, lists interfaces.")
    p.add_argument("--timeout", "-t", type=int, default=30, help="Capture timeout in seconds (default 30)")
    p.add_argument("--count", "-c", type=int, help="Capture packet count (overrides timeout)")
    p.add_argument("--out", "-o", default="capture.pcap", help="Output pcap filename")
    return p.parse_args()

def main():
    args = parse_args()
    if not args.iface:
        list_interfaces()
        print("\nRun again with --iface <INTERFACE_NAME> to capture.")
        sys.exit(0)
    # capture
    pcap = capture_packets(args.iface, timeout=args.timeout, packet_count=args.count, output_file=args.out)
    # analyze
    analyze_pcap(pcap)

if __name__ == "__main__":
    main()
