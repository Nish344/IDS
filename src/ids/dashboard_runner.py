# src/ids/dashboard_runner.py

# CRITICAL: Monkey patch MUST be first, before any other imports
import eventlet
eventlet.monkey_patch()

import threading
import time
from ids.dashboard.server import create_app, socketio, emit_alert
from ids.live_capture import live_worker
from ids.rules.parser import parse_rules_file
from ids.rules.compiler import compile_rules
from ids.matcher.hybrid_detector import HybridDetector
from ids.reassembler_stream import StreamReassembler
from ids.normalizer import normalize_payload
from scapy.all import sniff, raw
import argparse


def capture_thread(iface, crs):
    detector = HybridDetector(crs)
    reasm = StreamReassembler()

    print(f"[+] Listening on {iface}...")

    def on_packet(pkt):
        try:
            rb = raw(pkt)
        except:
            return

        events = reasm.feed_packet(rb, ts=time.time())
        for ev in events:
            assembled = ev["assembled"]
            direction = ev["direction"]
            a_ip, a_port = ev["meta"]["a"]
            b_ip, b_port = ev["meta"]["b"]

            norm = normalize_payload(assembled)

            flow_info = {
                "src": (b_ip, b_port) if direction=="b2a" else (a_ip, a_port),
                "dst": (a_ip, a_port) if direction=="b2a" else (b_ip, b_port),
                "direction": direction
            }

            alerts = detector.match_stream(norm, flow_info)
            for alert in alerts:
                print("[+] ALERT:", alert)
                
                # Format alert for frontend
                formatted_alert = {
                    'sid': alert.get('sid', 0),
                    'msg': alert.get('msg', 'Unknown'),
                    'pattern': alert.get('pattern', ''),
                    'src': f"{alert['src'][0]}:{alert['src'][1]}" if 'src' in alert else 'unknown',
                    'dst': f"{alert['dst'][0]}:{alert['dst'][1]}" if 'dst' in alert else 'unknown',
                    'direction': alert.get('direction', 'unknown')
                }
                
                print(f"[+] Emitting to dashboard: {formatted_alert}")
                emit_alert(formatted_alert)

    sniff(iface=iface, prn=on_packet, store=0)


def run_dashboard(iface, rules_path):
    rules = parse_rules_file(rules_path)
    crs = compile_rules(rules)

    app = create_app()

    # Start sniffing in eventlet greenthread
    eventlet.spawn(capture_thread, iface, crs)

    print("[+] Starting dashboard at http://127.0.0.1:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)


def main():
    parser = argparse.ArgumentParser(description="IDS Dashboard + Live Capture")
    parser.add_argument("--iface", required=True, help="Network interface (e.g., lo, eth0)")
    parser.add_argument("--rules", required=True, help="Rules file path")
    args = parser.parse_args()

    run_dashboard(args.iface, args.rules)


if __name__ == "__main__":
    main()