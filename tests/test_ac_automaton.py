# tests/test_ac_automaton.py
import pytest
from ids.matcher.ac_automaton import AhoCorasick


def test_basic_example_classic():
    # classic example from many Aho-Corasick descriptions
    patterns = ["he", "she", "his", "hers"]
    ac = AhoCorasick()
    for p in patterns:
        ac.add(p)
    ac.build()

    text = "ushers"
    # collect matches as (pattern, start, end)
    matches = ac.find_all(text)
    # sort by start then by pattern length to be deterministic
    matches_sorted = sorted(matches, key=lambda x: (x[1], -(x[2] - x[1])))
    assert ("she", 1, 4) in matches_sorted  # 'she' at text[1:4] == 'she'
    assert ("he", 2, 4) in matches_sorted   # 'he' at text[2:4] == 'he'
    # ensure no unexpected matches
    assert all(m[0] in patterns for m in matches_sorted)


def test_overlapping_and_suffixes():
    patterns = ["a", "aa", "aaa"]
    ac = AhoCorasick()
    for p in patterns:
        ac.add(p)
    ac.build()

    text = "aaaa"  # indices 0,1,2,3
    matches = ac.find_all(text)
    # Count expected matches manually:
    # At idx 0: 'a' -> (0,1)
    # At idx 1: 'a' (1,2), 'aa' (0,2)
    # At idx 2: 'a' (2,3), 'aa' (1,3), 'aaa' (0,3)
    # At idx 3: 'a' (3,4), 'aa' (2,4), 'aaa' (1,4)
    expected = {
        ("a", 0, 1),
        ("a", 1, 2),
        ("a", 2, 3),
        ("a", 3, 4),
        ("aa", 0, 2),
        ("aa", 1, 3),
        ("aa", 2, 4),
        ("aaa", 0, 3),
        ("aaa", 1, 4),
    }
    assert set(matches) == expected


def test_no_patterns():
    ac = AhoCorasick()
    ac.build()
    assert ac.find_all("anything") == []


def test_add_empty_pattern_rejected():
    ac = AhoCorasick()
    with pytest.raises(ValueError):
        ac.add("")


def test_iter_requires_build():
    ac = AhoCorasick()
    ac.add("x")
    with pytest.raises(RuntimeError):
        list(ac.iter("x"))
