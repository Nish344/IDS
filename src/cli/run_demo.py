# src/cli/run_demo.py

"""
Convenience script for demonstration:

python src/cli/run_demo.py
"""

from ids.main import run_ids

def main():
    print("[+] Running demo on sample PCAP and sample rules.")
    alerts = run_ids("data/sample_pcaps/http_get_small.pcap",
                     "data/sample_rules.rules",
                     verbose=True)

    if not alerts:
        print("[-] No alerts")
    else:
        print(f"[+] {len(alerts)} alerts triggered.")

if __name__ == "__main__":
    main()
