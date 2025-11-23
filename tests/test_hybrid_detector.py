# tests/test_hybrid_detector.py

from ids.rules.parser import parse_rule_line
from ids.rules.compiler import compile_rules
from ids.matcher.hybrid_detector import HybridDetector


def test_hybrid_detector_simple():
    # Rule will match content "union select" nocase
    rule_text = (
        'alert tcp any any -> any 80 ( msg:"SQLi"; content:"UNION SELECT"; nocase; sid:5001; )'
    )
    rule = parse_rule_line(rule_text)
    crs = compile_rules([rule])

    hd = HybridDetector(crs)

    # Fake flow_info for testing
    flow_info = {
        "src": ("10.0.0.1", 12345),
        "dst": ("10.0.0.2", 80),
        "direction": "a2b"
    }

    # normalized stream (lowercase)
    stream = "random data union select inside request"

    alerts = hd.match_stream(stream, flow_info)
    assert len(alerts) == 1

    a = alerts[0]
    assert a["sid"] == 5001
    assert "sql" in a["msg"].lower()
    assert a["pattern"] == "union select"
