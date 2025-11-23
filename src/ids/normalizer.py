"""
normalizer.py
--------------
Responsible for converting raw bytes to normalized text for AC + regex.

Steps:
1. Convert bytes to str using latin1 (lossless)
2. Lowercase if requested
3. URL decode (safe)
4. (Phase 3/4) Add more normalization: HTML entity decode, double URL decode, whitespace compression
"""

import urllib.parse


def bytes_to_str_latin1(payload: bytes) -> str:
    """Safe lossless conversion from raw bytes to Python str."""
    return payload.decode("latin1")


def url_decode_if_needed(s: str) -> str:
    """
    URL-decode string if percent-encodings appear.
    urllib.parse.unquote returns str automatically.
    """
    if "%" in s:
        try:
            return urllib.parse.unquote(s)
        except Exception:
            return s
    return s


def normalize_payload(payload_bytes: bytes, *, to_lower=True) -> str:
    """
    Full normalization pipeline.
    More steps can be added later (HTML decode, Base64 heuristics, etc.)
    """
    s = bytes_to_str_latin1(payload_bytes)
    s = url_decode_if_needed(s)
    if to_lower:
        s = s.lower()
    return s
