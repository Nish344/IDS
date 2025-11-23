# src/ids/rules/compiler.py
"""
Rule compiler: converts parsed Rule objects into a compiled ruleset:
- builds an Aho-Corasick automaton with literal content patterns
- keeps mapping pattern -> list of rule SIDs (and which content index)
- precompiles PCRE regex entries into Python regex objects (using 'regex' module if available)

API:
    compile_rules(rules: List[Rule]) -> CompiledRuleSet
    CompiledRuleSet:
        - ac: AhoCorasick automaton (built)
        - pattern_map: dict mapping literal -> list of (sid, content_index, nocase)
        - pcre_map: dict mapping sid -> list of compiled regex objects
        - rules_by_sid: dict sid -> Rule
"""

from typing import List, Dict, Tuple, Any
from ids.rules.parser import Rule, ContentLiteral
from ids.matcher.ac_automaton import AhoCorasick
import re

try:
    import regex as _regex_mod  # prefer 'regex' if installed
except Exception:
    _regex_mod = re


class CompiledRuleSet:
    def __init__(self):
        self.ac: AhoCorasick = AhoCorasick()
        # literal pattern (str) -> list of (sid:int, content_index:int, nocase:bool)
        self.pattern_map: Dict[str, List[Tuple[int, int, bool]]] = {}
        # sid -> list of compiled regex objects (pattern_str, compiled_obj)
        self.pcre_map: Dict[int, List[Tuple[str, Any]]] = {}
        self.rules_by_sid: Dict[int, Rule] = {}

    def add_literal(self, lit: str, sid: int, content_index: int, nocase: bool = False):
        """Add literal (string) to automaton and mapping."""
        if nocase:
            key = lit.lower()
        else:
            key = lit
        # add to AC only once (avoid duplicates)
        # Note: AC implementation allows duplicates; we guard pattern_map instead
        if key not in self.pattern_map:
            self.pattern_map[key] = []
            self.ac.add(key)
        self.pattern_map[key].append((sid, content_index, nocase))

    def add_pcre(self, sid: int, pcre_raw: str, pattern: str, flags: str):
        """Compile pcre into regex object and store."""
        # map pcre flags to python flags
        re_flags = 0
        if flags:
            if 'i' in flags:
                re_flags |= _regex_mod.IGNORECASE
            # other flags like m, s can be added if needed

        try:
            compiled = _regex_mod.compile(pattern, flags=re_flags)
        except Exception as e:
            raise ValueError(f"Failed to compile pcre for sid {sid}: {e}")

        if sid not in self.pcre_map:
            self.pcre_map[sid] = []
        self.pcre_map[sid].append((pcre_raw, compiled))

    def build(self):
        """Finalize the AC automaton."""
        self.ac.build()


def compile_rules(rules: List[Rule]) -> CompiledRuleSet:
    crs = CompiledRuleSet()
    for rule in rules:
        crs.rules_by_sid[rule.sid] = rule
        # add contents in order with indices
        for idx, content in enumerate(rule.contents):
            # note: we store the raw literal; handling nocase by storing lowered key in add_literal
            crs.add_literal(content.raw, rule.sid, idx, content.nocase)
        # add pcres
        for p in rule.pcres:
            crs.add_pcre(rule.sid, p.raw, p.pattern, p.flags)
    # build the automaton
    crs.build()
    return crs
