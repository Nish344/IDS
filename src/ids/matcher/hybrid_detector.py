# src/ids/matcher/hybrid_detector.py

"""
Hybrid detection engine:
- AC (Aho–Corasick) fast path to catch literal content matches
- Rule expansion via pattern_map
- Metadata checks: proto, ports, direction
- PCRE fallback
- Returns list of alerts for a given reassembled stream
"""

from typing import List, Dict, Any
from ids.rules.compiler import CompiledRuleSet
from ids.rules.parser import Rule


class HybridDetector:
    def __init__(self, compiled_ruleset: CompiledRuleSet):
        self.crs = compiled_ruleset

    def match_stream(self, stream_str: str, flow_info: Dict) -> List[Dict]:
        """
        Evaluate the normalized stream string against compiled rules.
        
        stream_str: normalized string (latin1)
        flow_info: {
            "src": (ip, port)
            "dst": (ip, port)
            "direction": "a2b" or "b2a"
        }

        Returns: list of alerts (dict)
        """
        alerts = []

        # 1. AC fast path
        matches = self.crs.ac.find_all(stream_str)

        # 2. For each literal hit, expand to candidate rules
        for (pattern, start, end) in matches:
            if pattern not in self.crs.pattern_map:
                continue

            cand_rules = self.crs.pattern_map[pattern]

            for (sid, content_index, nocase) in cand_rules:
                rule = self.crs.rules_by_sid[sid]

                # 3. Metadata checks
                if not self._match_rule_metadata(rule, flow_info):
                    continue

                # 4. PCRE fallback if rule has pcre(s)
                if sid in self.crs.pcre_map:
                    if not self._run_pcres(sid, stream_str):
                        continue

                # 5. Passed all tests → generate alert
                alerts.append({
                    "sid": sid,
                    "msg": rule.msg,
                    "pattern": pattern,
                    "start": start,
                    "end": end,
                    "src": flow_info["src"],
                    "dst": flow_info["dst"],
                    "direction": flow_info["direction"]
                })

        return alerts

    def _match_rule_metadata(self, rule: Rule, flow_info: Dict) -> bool:
        """
        Checks:
        - proto == tcp
        - port match (rule.sport/dport with flow ports)
        - direction: rule.direction must match flow_info["direction"]
        """

        # proto
        if rule.proto.lower() != "tcp":
            return False

        src_ip, src_port = flow_info["src"]
        dst_ip, dst_port = flow_info["dst"]

        # ports match (simple ANY or exact string)
        if rule.sport.lower() != "any" and str(src_port) != rule.sport:
            return False

        if rule.dport.lower() != "any" and str(dst_port) != rule.dport:
            return False

        # direction check
        if rule.direction == "->":
            return flow_info["direction"] == "a2b"
        elif rule.direction == "<-":
            return flow_info["direction"] == "b2a"
        elif rule.direction == "<>":
            return True    # bidirectional
        else:
            return False

    def _run_pcres(self, sid: int, stream_str: str) -> bool:
        """Return True if ALL pcre patterns of this sid match the stream."""
        for (raw, regex_obj) in self.crs.pcre_map[sid]:
            if not regex_obj.search(stream_str):
                return False
        return True
