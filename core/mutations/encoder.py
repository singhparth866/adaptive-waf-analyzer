"""
Encoding-based payload mutations.
All techniques are documented in the OWASP Testing Guide and used by
security professionals to evaluate WAF detection coverage.
"""
from __future__ import annotations

import re
from urllib.parse import quote


class Encoder:
    """
    Produces encoding variants of an input string.
    Each method returns a transformed string or None if the
    transformation produces an identical output (skip to avoid dupes).
    """

    # Characters that are meaningful to WAF pattern matchers
    _SPECIAL = set('<>"\'`=();/\\&|')

    # ── URL encoding ─────────────────────────────────────────────────────────

    @staticmethod
    def url_encode(value: str) -> str | None:
        """Percent-encode every special/non-safe character."""
        encoded = quote(value, safe='')
        return encoded if encoded != value else None

    @staticmethod
    def double_url_encode(value: str) -> str | None:
        """
        Encode once, then encode the percent signs of the first pass.
        Some WAFs decode only a single layer; double-encoding may pass
        normalisation checks on a single-decode implementation.
        """
        first = quote(value, safe='')
        second = first.replace('%', '%25')
        return second if second != value else None

    # ── Unicode / escape sequences ────────────────────────────────────────────

    @staticmethod
    def unicode_escape(value: str) -> str | None:
        """
        Replace ASCII special characters with their \\uXXXX representation.
        Browsers and some server-side parsers expand these before evaluation.
        """
        result = []
        changed = False
        for ch in value:
            if ch in Encoder._SPECIAL:
                result.append(f"\\u{ord(ch):04x}")
                changed = True
            else:
                result.append(ch)
        return "".join(result) if changed else None

    @staticmethod
    def html_entity_encode(value: str) -> str | None:
        """
        Encode special chars as HTML decimal entities (&#60; for <, etc.).
        Relevant for reflected-XSS payloads that pass through HTML contexts.
        """
        _MAP = {"<": "&#60;", ">": "&#62;", '"': "&#34;", "'": "&#39;",
                "&": "&#38;", "/": "&#47;"}
        result = []
        changed = False
        for ch in value:
            if ch in _MAP:
                result.append(_MAP[ch])
                changed = True
            else:
                result.append(ch)
        return "".join(result) if changed else None

    @staticmethod
    def hex_encode_chars(value: str) -> str | None:
        """
        Replace special characters with \\xHH hex escapes.
        Used to assess context-aware parsers.
        """
        result = []
        changed = False
        for ch in value:
            if ch in Encoder._SPECIAL:
                result.append(f"\\x{ord(ch):02x}")
                changed = True
            else:
                result.append(ch)
        return "".join(result) if changed else None

    # ── Null-byte ─────────────────────────────────────────────────────────────

    @staticmethod
    def null_byte_prefix(value: str) -> str | None:
        """
        Prepend a URL-encoded null byte.  Some WAFs truncate pattern
        matching at null bytes while the backend may ignore or strip them.
        """
        return f"%00{value}"
