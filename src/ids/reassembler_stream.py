# src/ids/reassembler_stream.py
"""
Streaming TCP reassembler for demo purposes.

Usage:
    re = StreamReassembler()
    alerts = re.feed_packet(raw_pkt_bytes, ts)  # returns list of (flow_key, direction, new_stream_bytes)
The class keeps per-flow segment lists and returns the cumulative assembled bytes
for a given direction whenever new payload extends that direction's stream.

Notes / Limitations:
- Lightweight: handles seq ordering, overlap by preferring earlier bytes, no SACK support.
- Keeps flows in memory until idle timeout (configurable).
- Designed to be fed Ethernet frames (raw bytes) as produced by scapy's sniff(store=0, prn=...).
"""

import socket
import time
from collections import defaultdict, namedtuple, OrderedDict
from typing import Tuple, Dict, List

import dpkt

_Segment = namedtuple("_Segment", ["seq", "data"])

def inet_to_str(inet) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except Exception:
        return socket.inet_ntop(socket.AF_INET6, inet)


def _canonical_flow_tuple(src_ip: str, src_port: int, dst_ip: str, dst_port: int):
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return (a[0], a[1], b[0], b[1]), ("a2b", "b2a")
    else:
        return (b[0], b[1], a[0], a[1]), ("b2a", "a2b")


class StreamReassembler:
    def __init__(self, idle_timeout: float = 120.0, max_flow_buffers: int = 1000):
        """
        idle_timeout: seconds after which a flow with no updates will be evicted
        max_flow_buffers: number of flows to keep (LRU eviction)
        """
        self.idle_timeout = idle_timeout
        self.max_flow_buffers = max_flow_buffers
        # maps flow_key -> { "a2b": [segments], "b2a":[segments], "meta":..., "last_seen": ts, "assembled": {"a2b":bytes,"b2a":bytes} }
        self.flows: Dict[Tuple[str,int,str,int], Dict] = OrderedDict()

    def _ensure_flow(self, flow_key, a_ip, a_port, b_ip, b_port, now_ts):
        if flow_key not in self.flows:
            # LRU eviction
            if len(self.flows) >= self.max_flow_buffers:
                # pop oldest
                self.flows.popitem(last=False)
            self.flows[flow_key] = {
                "a2b": [],
                "b2a": [],
                "meta": {"a": (a_ip, a_port), "b": (b_ip, b_port)},
                "last_seen": now_ts,
                "assembled": {"a2b": b"", "b2a": b""}
            }
        else:
            # update LRU: move to end
            item = self.flows.pop(flow_key)
            item["last_seen"] = now_ts
            self.flows[flow_key] = item

    def _stitch_segments(self, segments: List[_Segment]) -> bytes:
        """Same strategy as batch reassembler: sort, skip gaps, prefer earlier bytes on overlap."""
        if not segments:
            return b""
        segments_sorted = sorted(segments, key=lambda s: s.seq)
        out = bytearray()
        next_seq = segments_sorted[0].seq
        for seg in segments_sorted:
            seg_seq = seg.seq
            seg_data = seg.data
            if len(seg_data) == 0:
                continue
            if seg_seq > next_seq:
                # gap -> advance pointer (we do not synthesize)
                next_seq = seg_seq
            overlap = next_seq - seg_seq
            if overlap < 0:
                overlap = 0
            if overlap >= len(seg_data):
                continue
            to_append = seg_data[overlap:]
            out.extend(to_append)
            next_seq = seg_seq + len(seg_data)
        return bytes(out)

    def feed_packet(self, raw_pkt_bytes: bytes, ts: float = None):
        """
        Feed a single raw Ethernet frame (bytes). Returns list of events:
          [ { "flow_key": (...), "direction": "a2b"/"b2a", "new_bytes": b'...' , "meta": {...} }, ... ]
        new_bytes is the newly available assembled bytes beyond what was previously reported
        for that direction. If no new assembled bytes were produced (e.g., packet only repeats existing data),
        no event for that direction is emitted.
        """
        now = ts if ts is not None else time.time()
        events = []
        # parse with dpkt Ethernet (same parsing as batch code)
        # try:
        #     eth = dpkt.ethernet.Ethernet(raw_pkt_bytes)
        # except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        #     return events

        # ip = eth.data

                # Try Ethernet first
        ip = None
        try:
            eth = dpkt.ethernet.Ethernet(raw_pkt_bytes)
            ip = eth.data
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            pass

        # If Ethernet failed (loopback), try Linux SLL header
        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            try:
                sll = dpkt.sll.SLL(raw_pkt_bytes)
                ip = sll.data
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                return events  # Not IP even in SLL

        # Now proceed ONLY if IP
        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return events

        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return events
        if not isinstance(ip.data, dpkt.tcp.TCP):
            return events

        tcp = ip.data
        payload = tcp.data or b""
        if len(payload) == 0:
            # no application data to process
            return events

        src_ip = inet_to_str(ip.src)
        dst_ip = inet_to_str(ip.dst)
        sport = tcp.sport
        dport = tcp.dport

        flow_key, dir_map = _canonical_flow_tuple(src_ip, sport, dst_ip, dport)
        dir_label = dir_map[0]  # maps this packet's direction -> a2b or b2a relative to canonical flow

        # ensure flow exists
        a_ip, a_port, b_ip, b_port = flow_key
        self._ensure_flow(flow_key, a_ip, a_port, b_ip, b_port, now)

        # append segment
        seg = _Segment(seq=tcp.seq, data=bytes(payload))
        self.flows[flow_key][dir_label].append(seg)

        # stitch segments and compute delta beyond last assembled
        new_assembled = self._stitch_segments(self.flows[flow_key][dir_label])
        old_assembled = self.flows[flow_key]["assembled"][dir_label]
        if len(new_assembled) > len(old_assembled):
            # compute only the new bytes (suffix)
            new_bytes = new_assembled[len(old_assembled):]
            self.flows[flow_key]["assembled"][dir_label] = new_assembled
            self.flows[flow_key]["last_seen"] = now
            events.append({
                "flow_key": flow_key,
                "direction": dir_label,
                "new_bytes": new_bytes,
                "assembled": new_assembled,
                "meta": self.flows[flow_key]["meta"]
            })

        # cleanup idle flows
        self._evict_idle(now)
        return events

    def _evict_idle(self, now_ts):
        # remove flows older than idle_timeout
        remove = []
        for fk, v in list(self.flows.items()):
            if now_ts - v.get("last_seen", now_ts) > self.idle_timeout:
                remove.append(fk)
        for fk in remove:
            try:
                del self.flows[fk]
            except KeyError:
                pass
