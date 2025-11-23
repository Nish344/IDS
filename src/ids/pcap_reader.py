"""
pcap_reader.py
---------------
Reads PCAP files (or live capture later) and extracts packet-layer information.

This module:
- Uses dpkt for packet parsing
- Extracts IPv4/IPv6, TCP, UDP payloads
- Returns a normalized payload (latin1-decoded string)
- Does NOT perform TCP reassembly (Phase 3)
"""

import dpkt
import socket
from typing import Generator, Tuple


def inet_to_str(inet) -> str:
    """Convert inet object to a string (IPv4 or IPv6)."""
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def extract_tcp_payloads_from_pcap(pcap_path: str) -> Generator[Tuple[dict, bytes], None, None]:
    """
    Yield (metadata_dict, raw_payload_bytes) for each TCP packet payload.

    metadata = {
        "src": ip,
        "dst": ip,
        "sport": port,
        "dport": port,
        "timestamp": ts
    }

    NOTE:
    - No deduplication or reassembly here.
    - If payload is empty, skip.
    """

    with open(pcap_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            # Ethernet
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue

            # IP (v4/v6)
            ip = eth.data
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue

            # TCP only (for now)
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue

            tcp = ip.data
            if len(tcp.data) == 0:
                continue

            metadata = {
                "src": inet_to_str(ip.src),
                "dst": inet_to_str(ip.dst),
                "sport": tcp.sport,
                "dport": tcp.dport,
                "timestamp": ts
            }

            yield metadata, tcp.data
