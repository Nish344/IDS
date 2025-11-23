# tests/integration/test_full_pipeline.py

import os
from ids.main import run_ids

def test_full_pipeline(tmp_path):
    # create rule
    rules_file = tmp_path / "rules.rules"
    rules_file.write_text(
        'alert tcp any any -> any 80 ( msg:"SQLi"; content:"UNION SELECT"; nocase; sid:9001; )'
    )

    # create minimal pcap using scapy
    from scapy.all import Ether, IP, TCP, wrpcap

    payload = b"GET /test UNION SELECT something"
    pkt = (
        Ether() /
        IP(src="10.0.0.1", dst="10.0.0.2") /
        TCP(sport=12345, dport=80, seq=1, flags="PA") /
        payload
    )

    pcap_path = tmp_path / "test.pcap"
    wrpcap(str(pcap_path), pkt)

    alerts = run_ids(str(pcap_path), str(rules_file))

    assert len(alerts) == 1
    assert alerts[0]["sid"] == 9001
