"""
Structural obfuscation mutations — case variation, whitespace, comment injection,
and character substitution.  All techniques are standard OWASP-documented methods
used to evaluate WAF signature coverage depth.
"""
from __future__ import annotations

import re
import random


class Obfuscator:
    """Produces structural variants of input strings without re-encoding them."""

    # ── Case manipulation ─────────────────────────────────────────────────────

    @staticmethod
    def mixed_case(value: str) -> str | None:
        """
        Alternate character casing.  Effective against WAFs using case-sensitive
        regex patterns on HTML tags / SQL keywords.
        e.g. <script> → <ScRiPt>
        """
        result = []
        upper_next = False
        for i, ch in enumerate(value):
            if ch.isalpha():
                result.append(ch.upper() if i % 2 == 0 else ch.lower())
            else:
                result.append(ch)
        result_str = "".join(result)
        return result_str if result_str != value else None

    @staticmethod
    def random_case(value: str) -> str | None:
        """Randomly case each alpha character."""
        result = "".join(
            ch.upper() if random.random() > 0.5 else ch.lower()
            for ch in value
        )
        return result if result != value else None

    # ── SQL inline comments ───────────────────────────────────────────────────

    _SQL_KEYWORDS = re.compile(
        r'\b(SELECT|INSERT|UPDATE|DELETE|UNION|FROM|WHERE|OR|AND|NOT|NULL'
        r'|ORDER|GROUP|BY|HAVING|LIKE|IN|IS|AS|ON|JOIN|DROP|CREATE|ALTER'
        r'|EXEC|EXECUTE|CAST|CONVERT|SLEEP|WAITFOR|DELAY|INFORMATION_SCHEMA'
        r'|TABLE_NAME|COLUMN_NAME|DATABASE|VERSION)\b',
        re.I
    )

    @staticmethod
    def sql_inline_comment(value: str) -> str | None:
        """
        Inject /**/ between SQL keywords and surrounding tokens.
        Breaks keyword-level pattern matching; parsed identically by most SQL engines.
        e.g. UNION SELECT → UNION/**/SELECT
        """
        def _insert(match: re.Match) -> str:
            return f"/**/{match.group(0)}/**/"

        result = Obfuscator._SQL_KEYWORDS.sub(_insert, value)
        # Collapse leading/trailing /**/ duplicates
        result = re.sub(r'(/\*\*/){2,}', '/**/', result).strip('/')
        result = re.sub(r'^\*\*/', '', result)
        return result if result != value else None

    @staticmethod
    def sql_whitespace_comment(value: str) -> str | None:
        """Replace spaces between SQL tokens with /**/ (no space variant)."""
        result = re.sub(r' +', '/**/', value)
        return result if result != value else None

    # ── Whitespace variants ───────────────────────────────────────────────────

    @staticmethod
    def html_tag_whitespace(value: str) -> str | None:
        """
        Insert extra whitespace inside HTML tags.
        Some WAFs match <script> literally but miss < script >.
        e.g. <script> → <script >
        """
        result = re.sub(r'<(\w)', r'< \1', value)
        result = re.sub(r'(\w)>', r'\1 >', result)
        return result if result != value else None

    @staticmethod
    def newline_inject(value: str) -> str | None:
        """Inject URL-encoded newlines around delimiters."""
        result = value.replace(' ', '%0a')
        return result if result != value else None

    # ── Character substitution ────────────────────────────────────────────────

    # Well-known lookalike / equivalent substitutions used in research
    _CHAR_TABLE: dict[str, list[str]] = {
        'a': ['а', '\u0430'],   # Cyrillic а
        'e': ['е', '\u0435'],   # Cyrillic е
        'o': ['о', '\u043e'],   # Cyrillic о
        '<': ['\uff1c'],        # Fullwidth <
        '>': ['\uff1e'],        # Fullwidth >
        "'": ['\u2019', '\u02bc'],
        '"': ['\u201c', '\u201d', '\uff02'],
    }

    @staticmethod
    def char_substitute(value: str) -> str | None:
        """Replace characters with visually/semantically similar Unicode codepoints."""
        result = list(value)
        changed = False
        for i, ch in enumerate(result):
            subs = Obfuscator._CHAR_TABLE.get(ch)
            if subs:
                result[i] = subs[0]
                changed = True
        return "".join(result) if changed else None
