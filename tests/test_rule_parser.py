# tests/test_rule_parser.py
import os
from ids.rules.parser import parse_rule_line, parse_rules_file
from ids.rules.compiler import compile_rules
from ids.matcher.ac_automaton import AhoCorasick


def test_parse_single_rule():
    rule_text = (
        'alert tcp any any -> any 80 ( msg:"SQL Injection"; content:"UNION SELECT"; nocase; '
        'pcre:"/UNION\\s+SELECT/i"; sid:1001; )'
    )
    rule = parse_rule_line(rule_text)
    assert rule.sid == 1001
    assert rule.msg.lower().startswith("sql")
    assert rule.proto.lower() == "tcp"
    assert len(rule.contents) == 1
    assert rule.contents[0].raw == "UNION SELECT"
    assert rule.contents[0].nocase is True
    assert len(rule.pcres) == 1
    assert rule.pcres[0].pattern.lower().startswith("union")

def test_compile_and_match_ac(tmp_path):
    # create a tiny rules file and compile it
    rules_file = tmp_path / "demo.rules"
    rules_file.write_text(
        'alert tcp any any -> any 80 ( msg:"SQLi"; content:"UNION SELECT"; nocase; sid:2001; )\n'
        'alert tcp any any -> any 80 ( msg:"wget"; content:"wget http"; sid:2002; )\n'
    )
    rules = parse_rules_file(str(rules_file))
    compiled = compile_rules(rules)

    # The automaton should contain the patterns (lowercased for nocase)
    patterns = compiled.ac.patterns()
    assert "union select" in patterns
    assert "wget http" in patterns

    # run AC on a sample text
    text = "normal text ... UNION Select ... other ... wget http://evil"
    # normalize to latin1 + lower-case as our pipeline would
    text_proc = text.lower()
    matches = compiled.ac.find_all(text_proc)
    matched_patterns = {m[0] for m in matches}
    assert "union select" in matched_patterns
    assert "wget http" in matched_patterns

    # pcre_map: ensure empty (none in this tiny example) or present for others
    # For the simple rule above, there were no pcre except if specified
    # compile_rules should have registered rules_by_sid
    assert 2001 in compiled.rules_by_sid
    assert 2002 in compiled.rules_by_sid
