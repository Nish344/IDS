# src/ids/matcher/ac_automaton.py
"""
Aho-Corasick automaton (pure Python).
API:
    AhoCorasick()
    add(pattern: str)
    build()
    iter(text: str) -> yields (pattern: str, start: int, end: int) with end exclusive
Notes:
- This implementation treats text and patterns as Python str objects.
- Use .lower() outside if you want case-insensitive matching (not done automatically here).
"""

from collections import deque
from typing import Dict, List, Tuple, Generator


class _Node:
    __slots__ = ("next", "fail", "output")

    def __init__(self):
        # transitions: char -> _Node
        self.next: Dict[str, _Node] = {}
        # fail link: _Node
        self.fail: "_Node" = None
        # output: list of pattern indices
        self.output: List[int] = []


class AhoCorasick:
    def __init__(self):
        self._root = _Node()
        self._patterns: List[str] = []
        self._built = False

    def add(self, pattern: str) -> None:
        """Add a pattern to the trie. Patterns must be non-empty strings."""
        if not pattern:
            raise ValueError("Empty patterns are not supported")
        node = self._root
        for ch in pattern:
            if ch not in node.next:
                node.next[ch] = _Node()
            node = node.next[ch]
        # store index of pattern
        self._patterns.append(pattern)
        node.output.append(len(self._patterns) - 1)
        self._built = False

    def build(self) -> None:
        """Build failure links (BFS). Must be called after all adds and before searching."""
        root = self._root
        queue = deque()

        # Initialize fail links of depth-1 nodes to root
        for ch, node in list(root.next.items()):
            node.fail = root
            queue.append(node)

        # BFS
        while queue:
            current = queue.popleft()
            for ch, child in list(current.next.items()):
                queue.append(child)
                # set fail for child
                f = current.fail
                while f is not None and ch not in f.next:
                    f = f.fail
                child.fail = f.next[ch] if (f and ch in f.next) else root
                # append output links
                if child.fail.output:
                    child.output += child.fail.output
        self._built = True

    def iter(self, text: str) -> Generator[Tuple[str, int, int], None, None]:
        """
        Iterate over all matches in text.
        Yields tuples (pattern, start, end) where end is exclusive.
        """
        if not self._built:
            raise RuntimeError("Automaton not built. Call build() before iter().")
        node = self._root
        for idx, ch in enumerate(text):
            # follow transitions; if missing, follow fail links
            while node is not self._root and ch not in node.next:
                node = node.fail
            if ch in node.next:
                node = node.next[ch]
            # report outputs if any
            if node.output:
                for pat_idx in node.output:
                    pat = self._patterns[pat_idx]
                    start = idx - len(pat) + 1
                    end = idx + 1  # exclusive
                    yield (pat, start, end)

    def find_all(self, text: str) -> List[Tuple[str, int, int]]:
        """Convenience: return a list of matches."""
        return list(self.iter(text))

    def patterns(self) -> List[str]:
        """Return added patterns in insertion order."""
        return list(self._patterns)
