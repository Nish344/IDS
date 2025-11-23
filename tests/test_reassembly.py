# tests/test_reassembly.py
import os
from ids.reassembly import reassemble_tcp_streams_from_pcap

# This test generates a pcap with two TCP segments that together form a single HTTP GET.
# We use scapy to create the pcap inside the test env so it's deterministic.

def test_reassembly_two_segments(tmp_path):
    from scapy.all import Ether, IP, TCP, wrpcap

    # build two TCP segments from same 4-tuple forming a contiguous payload
    ip_a = "10.0.0.1"
    ip_b = "10.0.0.2"
    sport = 11111
    dport = 80

    # segment 1: "GET /te"
    payload1 = b"GET /te"
    pkt1 = (
        Ether() /
        IP(src=ip_a, dst=ip_b) /
        TCP(sport=sport, dport=dport, seq=1, flags="PA") /
        payload1
    )

    # segment 2: "st HTTP/1.1\r\nHost: ex\r\n\r\n"
    payload2 = b"st HTTP/1.1\r\nHost: ex\r\n\r\n"
    # second packet has seq = 1 + len(payload1) = 1 + 7 = 8
    pkt2 = (
        Ether() /
        IP(src=ip_a, dst=ip_b) /
        TCP(sport=sport, dport=dport, seq=1 + len(payload1), flags="PA") /
        payload2
    )

    pcap_path = tmp_path / "two_seg.pcap"
    wrpcap(str(pcap_path), [pkt1, pkt2])

    # reassemble
    res = reassemble_tcp_streams_from_pcap(str(pcap_path))
    # there should be one flow
    assert len(res) == 1
    fk, info = next(iter(res.items()))
    a2b = info["a2b"]
    # full payload should be concatenation
    expected = payload1 + payload2
    assert a2b == expected

    # ensure http path present
    assert b"/test" in a2b
    assert b"Host" in a2b
