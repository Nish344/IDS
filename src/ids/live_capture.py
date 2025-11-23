# src/ids/live_capture.py
"""
Live capture + detection demo.

Requirements:
- scapy (for sniffing)
- run with sudo/administrator to sniff interfaces (or use an interface in pcap mode)

Usage example:
    sudo python -m ids.live_capture --iface eth0 --rules data/sample_rules.rules --verbose

Notes:
- The script listens on the given interface and processes TCP packets with payload.
- For safety in demos, prefer using a mirrored or isolated network, or use loopback and generate traffic locally.
"""

import argparse
import json
import sys
import time

from scapy.all import sniff, raw
from ids.reassembler_stream import StreamReassembler
from ids.rules.parser import parse_rules_file
from ids.rules.compiler import compile_rules
from ids.normalizer import normalize_payload
from ids.matcher.hybrid_detector import HybridDetector


def live_worker(interface: str, rules_path: str, verbose: bool = False):
    # load rules & detector
    rules = parse_rules_file(rules_path)
    crs = compile_rules(rules)
    detector = HybridDetector(crs)

    reasm = StreamReassembler()

    print(f"[+] Starting live capture on {interface}. Press Ctrl+C to stop.")
    def on_packet(pkt):
        try:
            rb = raw(pkt)
        except Exception:
            return
        # feed raw bytes into reassembler
        events = reasm.feed_packet(rb, ts=time.time())
        for ev in events:
            # ev: {flow_key, direction, new_bytes, assembled, meta}
            flow_key = ev["flow_key"]
            a_ip, a_port, b_ip, b_port = flow_key
            direction = ev["direction"]
            assembled = ev["assembled"]
            new_bytes = ev["new_bytes"]
            # we normally normalize full assembled stream (or new_bytes if you want alg)
            norm = normalize_payload(assembled)
            # create flow_info for detector using direction context
            if direction == "a2b":
                flow_info = {"src": (a_ip, a_port), "dst": (b_ip, b_port), "direction": "a2b"}
            else:
                flow_info = {"src": (b_ip, b_port), "dst": (a_ip, a_port), "direction": "b2a"}
            alerts = detector.match_stream(norm, flow_info)
            for a in alerts:
                if verbose:
                    print(json.dumps(a))
                else:
                    print(f"[ALERT] {a['sid']} {a['msg']} {a['src']}->{a['dst']} pat={a['pattern']}")
        # continue sniffing

    # start sniff; store=0 to avoid keeping packets in memory
    sniff(iface=interface, prn=on_packet, store=0)


def main():
    parser = argparse.ArgumentParser(description="Live capture IDS demo")
    parser.add_argument("--iface", required=True, help="Interface to capture on (e.g., lo, eth0)")
    parser.add_argument("--rules", required=True, help="Path to rules file")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    live_worker(args.iface, args.rules, verbose=args.verbose)


if __name__ == "__main__":
    main()

