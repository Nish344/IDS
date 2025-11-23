import os
from ids.pcap_reader import extract_tcp_payloads_from_pcap
from ids.normalizer import normalize_payload


def test_pcap_small_sample():
    """
    Use a small synthetic PCAP generated below.
    Expect:
        - exactly 1 packet
        - payload contains 'GET /test HTTP/1.1'
    """
    pcap_path = "data/sample_pcaps/http_get_small.pcap"
    assert os.path.exists(pcap_path)

    packets = list(extract_tcp_payloads_from_pcap(pcap_path))
    assert len(packets) == 1

    metadata, payload = packets[0]

    assert metadata["sport"] > 0
    assert metadata["dport"] in (80, 8080, 8000, 443)  # common http ports

    norm = normalize_payload(payload)

    assert "get" in norm
    assert "/test" in norm
    assert "http/1.1" in norm
