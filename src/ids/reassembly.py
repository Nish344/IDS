# src/ids/reassembly.py
"""
TCP reassembly helper for demo IDS.

Provides:
    reassemble_tcp_streams_from_pcap(pcap_path: str) -> dict

Returned structure:
{
    flow_key: {
        "a2b": bytes,   # reassembled payload from side A -> B
        "b2a": bytes,   # reassembled payload from side B -> A
        "meta": {
            "a": (ip, port),
            "b": (ip, port),
        }
    },
    ...
}

Flow key is a tuple: (ip_a, port_a, ip_b, port_b) where (ip_a,port_a) <= (ip_b,port_b)
so flows are canonicalized and bidirectional.
"""

from collections import defaultdict, namedtuple
import dpkt
import socket
from typing import Dict, Tuple

# simple namedtuple for segment representation
_Segment = namedtuple("_Segment", ["seq", "data"])


def inet_to_str(inet) -> str:
    """Convert inet object to a string (IPv4 or IPv6)."""
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except Exception:
        return socket.inet_ntop(socket.AF_INET6, inet)


def _canonical_flow_tuple(src_ip: str, src_port: int, dst_ip: str, dst_port: int):
    """
    Canonicalize the 4-tuple so that flow key is order-independent (bi-directional).
    We also track which endpoint is 'a' vs 'b' so we can return per-direction streams.
    """
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return (a[0], a[1], b[0], b[1]), ("a2b", "b2a")
    else:
        return (b[0], b[1], a[0], a[1]), ("b2a", "a2b")


def _stitch_segments(segments):
    """
    Stitch a list of _Segment(seq:int, data:bytes) into a contiguous bytes stream.
    Strategy:
      - Sort by seq
      - Walk and append non-overlapping parts; if overlap, prefer earlier-seen bytes (first in sorted order)
    Note: This is a simple approach and assumes seq wrap/huge gaps are not present in tests.
    """
    if not segments:
        return b""

    # sort by seq (ascending)
    segments_sorted = sorted(segments, key=lambda s: s.seq)
    out = bytearray()
    next_seq = segments_sorted[0].seq

    for seg in segments_sorted:
        seg_seq = seg.seq
        seg_data = seg.data
        if len(seg_data) == 0:
            continue

        # if segment starts after next_seq, fill gap by skipping (we don't synthesize data)
        if seg_seq > next_seq:
            # gap: skip until seg_seq, advance next_seq to seg_seq
            # we do not insert placeholder bytes; we just advance to seg_seq position
            pad = seg_seq - next_seq
            # for our IDS reassembly we simply move next_seq forward (do not fill)
            # This keeps alignment of later segments.
            next_seq = seg_seq

        # If segment starts before next_seq, we may have overlap; calculate overlap length
        overlap = next_seq - seg_seq
        if overlap < 0:
            overlap = 0

        if overlap >= len(seg_data):
            # segment entirely overlapped by already consumed data; skip
            continue

        # append the non-overlapped suffix
        to_append = seg_data[overlap:]
        out.extend(to_append)
        next_seq = seg_seq + len(seg_data)

    return bytes(out)


def reassemble_tcp_streams_from_pcap(pcap_path: str) -> Dict[Tuple[str, int, str, int], Dict]:
    """
    Reassemble TCP streams from a pcap and return a dict mapping canonical flow keys to reassembled
    directional payloads.

    Directions are 'a2b' and 'b2a' relative to the canonical tuple order.
    """
    # data structures:
    # flows[flow_key]["a2b"] -> list of _Segment
    # flows_meta stores endpoint tuples
    flows_segments = defaultdict(lambda: {"a2b": [], "b2a": [], "meta": {}})

    with open(pcap_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue

            ip = eth.data
            # accept IPv4 and IPv6
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue

            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue

            tcp = ip.data
            if tcp is None:
                continue

            payload = tcp.data
            if payload is None:
                payload = b""

            # do not process empty payloads (no application data)
            if len(payload) == 0:
                continue

            src_ip = inet_to_str(ip.src)
            dst_ip = inet_to_str(ip.dst)
            sport = tcp.sport
            dport = tcp.dport

            # canonicalize flow
            flow_key, dir_map = _canonical_flow_tuple(src_ip, sport, dst_ip, dport)
            # dir_map tells us which direction label corresponds to this packet
            # If dir_map == ("a2b","b2a"), then src->dst is a2b, else it's b2a
            dir_label = dir_map[0]  # the label corresponding to src->dst

            # store meta endpoints if not present
            if not flows_segments[flow_key]["meta"]:
                # store canonical endpoints
                a_ip, a_port, b_ip, b_port = flow_key
                flows_segments[flow_key]["meta"] = {"a": (a_ip, a_port), "b": (b_ip, b_port)}

            # record segment with sequence number
            seq = tcp.seq
            flows_segments[flow_key][dir_label].append(_Segment(seq=seq, data=bytes(payload)))

    # now stitch segments per direction
    reassembled = {}
    for fk, val in flows_segments.items():
        a2b_segments = val["a2b"]
        b2a_segments = val["b2a"]
        a2b_stream = _stitch_segments(a2b_segments)
        b2a_stream = _stitch_segments(b2a_segments)

        reassembled[fk] = {
            "a2b": a2b_stream,
            "b2a": b2a_stream,
            "meta": val["meta"],
        }

    return reassembled
