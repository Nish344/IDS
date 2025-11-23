# src/ids/main.py

"""
Full IDS pipeline runner:
    python -m ids.main --pcap <file> --rules <file>

Steps:
1. Load rules & compile.
2. Parse PCAP, rebuild TCP streams.
3. Normalize streams.
4. Run hybrid detector.
5. Print alerts.
"""

import argparse
import json
from ids.rules.parser import parse_rules_file
from ids.rules.compiler import compile_rules
from ids.reassembly import reassemble_tcp_streams_from_pcap
from ids.normalizer import normalize_payload
from ids.matcher.hybrid_detector import HybridDetector


def run_ids(pcap_path: str, rules_path: str, verbose: bool = False):
    # 1. Load rules
    rules = parse_rules_file(rules_path)
    crs = compile_rules(rules)
    detector = HybridDetector(crs)

    # 2. Reassemble streams
    flows = reassemble_tcp_streams_from_pcap(pcap_path)

    alerts = []

    # 3. For each flow + direction
    for flow_key, info in flows.items():
        a_ip, a_port, b_ip, b_port = flow_key

        # a→b
        if info["a2b"]:
            norm = normalize_payload(info["a2b"])
            flow_info = {
                "src": (a_ip, a_port),
                "dst": (b_ip, b_port),
                "direction": "a2b"
            }
            a2b_alerts = detector.match_stream(norm, flow_info)
            alerts.extend(a2b_alerts)

        # b→a
        if info["b2a"]:
            norm = normalize_payload(info["b2a"])
            flow_info = {
                "src": (b_ip, b_port),
                "dst": (a_ip, a_port),
                "direction": "b2a"
            }
            b2a_alerts = detector.match_stream(norm, flow_info)
            alerts.extend(b2a_alerts)

    # 4. Print alerts
    if verbose:
        print(json.dumps(alerts, indent=2))
    else:
        for a in alerts:
            print(f"[ALERT] SID {a['sid']} | {a['msg']} | {a['src']} -> {a['dst']} | pattern={a['pattern']}")

    return alerts


def main():
    parser = argparse.ArgumentParser(description="IDS Mega-DFA Runner")
    parser.add_argument("--pcap", required=True, help="Path to pcap file")
    parser.add_argument("--rules", required=True, help="Path to rules file")
    parser.add_argument("--verbose", action="store_true", help="Verbose JSON output")
    args = parser.parse_args()

    run_ids(args.pcap, args.rules, verbose=args.verbose)


if __name__ == "__main__":
    main()
