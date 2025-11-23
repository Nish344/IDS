# src/ids/rules/parser.py
"""
Simple Snort-ish rule parser (Option A).

Supported (simplified) rule structure:
    alert tcp any any -> any 80 ( msg:"SQLi"; content:"union select"; nocase; pcre:"/UNION\s+SELECT/i"; sid:10001; )

We parse:
- action (ignored for now)
- proto (tcp/udp) and the 4-tuple parts (we store them as raw strings)
- option list inside parentheses: msg, content (multiple allowed), nocase (applies to previous content), pcre, sid

Outputs a list of Rule dataclasses:
    Rule(
        sid=int,
        msg=str,
        proto=str,
        src=str,
        sport=str,
        direction='->' or '<>',
        dst=str,
        dport=str,
        contents=[ {"raw":"...", "nocase":bool} , ... ],
        pcres=[ {"raw":"/.../flags", "pattern":"...", "flags":"i"} , ... ]
    )
This is intentionally simple and forgiving for demo purposes.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# regex helpers
_HEADER_RE = re.compile(r'^\s*(alert)\s+(\w+)\s+(\S+)\s+(\S+)\s+([\-<>]+)\s+(\S+)\s+(\S+)\s*\(',
                        flags=re.IGNORECASE)
# capture everything inside parentheses (greedy)
_OPTIONS_RE = re.compile(r'\(\s*(.*)\s*\)\s*$', flags=re.DOTALL)

# option extractors
_CONTENT_RE = re.compile(r'content\s*:\s*"([^"]*)"\s*;', flags=re.IGNORECASE)
_PCRE_RE = re.compile(r'pcre\s*:\s*"(/.*?/[^"]*)"\s*;', flags=re.IGNORECASE)
_MSG_RE = re.compile(r'msg\s*:\s*"([^"]*)"\s*;', flags=re.IGNORECASE)
_SID_RE = re.compile(r'sid\s*:\s*(\d+)\s*;', flags=re.IGNORECASE)
_NOCASE_RE = re.compile(r'\b(nocase)\b', flags=re.IGNORECASE)


@dataclass
class ContentLiteral:
    raw: str
    nocase: bool = False


@dataclass
class PcreEntry:
    raw: str           # like /UNION\s+SELECT/i
    pattern: str       # inner pattern without the surrounding slashes
    flags: str = ""


@dataclass
class Rule:
    sid: int
    msg: str = ""
    proto: str = "tcp"
    src: str = "any"
    sport: str = "any"
    direction: str = "->"
    dst: str = "any"
    dport: str = "any"
    contents: List[ContentLiteral] = field(default_factory=list)
    pcres: List[PcreEntry] = field(default_factory=list)


def _parse_header(line: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (header_match_text, header_tail) where header_tail is the rest that starts at '('
    If not found, returns (None, None)
    """
    m = _HEADER_RE.search(line)
    if not m:
        return None, None
    # we want the matched group span so we can find the '(' position
    # find '(' position
    idx = line.find('(')
    if idx == -1:
        return m.group(0), ""
    return line[:idx], line[idx:]


def parse_rule_line(line: str) -> Rule:
    """
    Parse a single simplified rule line and return a Rule object.
    Raises ValueError on parse errors.
    """
    header, options_tail = _parse_header(line)
    if header is None:
        raise ValueError("Invalid rule header")

    # header tokens: we can extract proto and src/dst info using splitting
    # header example: "alert tcp any any -> any 80 ("
    hdr_tokens = header.strip().split()
    # Expect at least: action proto src sport direction dst dport
    if len(hdr_tokens) < 7:
        raise ValueError("Incomplete header tokens")

    action = hdr_tokens[0]
    proto = hdr_tokens[1]
    src = hdr_tokens[2]
    sport = hdr_tokens[3]
    direction = hdr_tokens[4]
    dst = hdr_tokens[5]
    dport = hdr_tokens[6]

    # extract options between parentheses
    mopt = _OPTIONS_RE.search(line)
    if not mopt:
        raise ValueError("Options block missing")
    options_text = mopt.group(1)

    # parse options
    msg_match = _MSG_RE.search(options_text)
    msg = msg_match.group(1) if msg_match else ""

    sid_match = _SID_RE.search(options_text)
    if not sid_match:
        raise ValueError("sid is required")
    sid = int(sid_match.group(1))

    # Find all content occurrences in order, but we need to detect if each content has nocase nearby.
    contents = []
    # We'll scan the options_text left-to-right to preserve order and associate nocase with the preceding content if present
    pos = 0
    for cm in _CONTENT_RE.finditer(options_text):
        raw = cm.group(1)
        start, end = cm.span()
        # search for 'nocase' between end and next semicolon or up to few chars ahead
        # simple heuristic: check substring from end to end+20 for nocase
        tail = options_text[end:end + 50]
        nocase = bool(_NOCASE_RE.search(tail))
        contents.append(ContentLiteral(raw=raw, nocase=nocase))
        pos = end

    # parse pcres
    pcres = []
    for pm in _PCRE_RE.finditer(options_text):
        raw = pm.group(1)  # like /.../i or /.../
        # strip leading and trailing slash and trailing flags
        # raw format: /pattern/flags OR /pattern/
        if len(raw) >= 2 and raw[0] == '/':
            # find last slash
            last_slash = raw.rfind('/')
            pattern = raw[1:last_slash]
            flags = raw[last_slash + 1:] if last_slash + 1 < len(raw) else ""
            pcres.append(PcreEntry(raw=raw, pattern=pattern, flags=flags))

    rule = Rule(
        sid=sid,
        msg=msg,
        proto=proto,
        src=src,
        sport=sport,
        direction=direction,
        dst=dst,
        dport=dport,
        contents=contents,
        pcres=pcres
    )
    return rule


def parse_rules_file(path: str) -> List[Rule]:
    """Parse a rules file (one rule per line or multiline rule in file). For simplicity, we parse by line here."""
    rules = []
    with open(path, "r", encoding="utf-8") as fh:
        # naive: read whole file and split by newline, but support rules spanning lines inside parentheses
        data = fh.read()
    # split by ';)\n' or ')\n' to get blocks — simpler: find all occurrences of 'alert' -> '(' ... ')'
    # We'll use a simple regex to find blocks starting with 'alert' and ending with ')'
    BLOCK_RE = re.compile(r'(alert\s+.*?\))', flags=re.IGNORECASE | re.DOTALL)
    for bm in BLOCK_RE.finditer(data):
        block = bm.group(1)
        try:
            rule = parse_rule_line(block)
            rules.append(rule)
        except Exception as e:
            # skip invalid rule but continue
            # in production you'd collect errors; for demo just raise
            raise

    return rules
