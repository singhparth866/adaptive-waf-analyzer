"""Unit tests for encoding and obfuscation mutation engines."""
from __future__ import annotations
import pytest
from core.mutations.encoder    import Encoder
from core.mutations.obfuscator import Obfuscator


class TestEncoder:
    def test_url_encode_special_chars(self):
        result = Encoder.url_encode("<script>alert(1)</script>")
        assert result is not None
        assert "%" in result
        assert "<" not in result

    def test_url_encode_plain_returns_none(self):
        # No special chars → should return None (no change)
        result = Encoder.url_encode("hello")
        # "hello" URL-encodes to "hello" → None
        assert result is None or result == "hello"

    def test_double_encode_has_percent25(self):
        result = Encoder.double_url_encode("<script>")
        assert result is not None
        assert "%25" in result

    def test_unicode_escape_replaces_specials(self):
        result = Encoder.unicode_escape('<img src=x>')
        assert result is not None
        assert "\\u003c" in result or "\\u" in result

    def test_html_entity_encode(self):
        result = Encoder.html_entity_encode('<script>')
        assert result is not None
        assert "&#60;" in result
        assert "&#62;" in result

    def test_null_byte_prefix(self):
        result = Encoder.null_byte_prefix("UNION SELECT")
        assert result is not None
        assert result.startswith("%00")

    def test_hex_encode(self):
        result = Encoder.hex_encode_chars("<XSS>")
        assert result is not None
        assert "\\x" in result


class TestObfuscator:
    def test_mixed_case_changes_alpha(self):
        result = Obfuscator.mixed_case("script")
        assert result is not None
        assert result.lower() == "script"
        assert result != "script"  # casing changed

    def test_mixed_case_no_alpha_returns_none(self):
        result = Obfuscator.mixed_case("123")
        assert result is None

    def test_sql_inline_comment_inserts_comment(self):
        result = Obfuscator.sql_inline_comment("UNION SELECT 1")
        assert result is not None
        assert "/**/" in result

    def test_sql_whitespace_comment(self):
        result = Obfuscator.sql_whitespace_comment("SELECT 1 FROM users")
        assert result is not None
        assert "/**/" in result
        assert " " not in result or result.count(" ") < 3

    def test_html_tag_whitespace(self):
        result = Obfuscator.html_tag_whitespace("<script>alert(1)</script>")
        assert result is not None
        assert "< " in result or " >" in result

    def test_char_substitute_known_chars(self):
        result = Obfuscator.char_substitute("<script>")
        assert result is not None
        assert result != "<script>"

    def test_newline_inject(self):
        result = Obfuscator.newline_inject("SELECT 1")
        assert result is not None
        assert "%0a" in result


class TestPayloadLoader:
    def test_load_originals_xss(self):
        from payloads.loader import load_originals, PayloadKind
        payloads = load_originals(PayloadKind.XSS)
        assert len(payloads) > 0
        assert all(p.kind.value == "original" for p in payloads)

    def test_load_originals_sqli(self):
        from payloads.loader import load_originals, PayloadKind
        payloads = load_originals(PayloadKind.SQLI)
        assert len(payloads) > 0

    def test_load_mutated_deduplicates(self):
        from payloads.loader import load_mutated, PayloadKind
        payloads = load_mutated(PayloadKind.XSS, max_mutations=4)
        values = [p.value for p in payloads]
        assert len(values) == len(set(values))  # no duplicates

    def test_load_mutated_more_than_originals(self):
        from payloads.loader import load_originals, load_mutated, PayloadKind
        originals = load_originals(PayloadKind.XSS)
        mutated   = load_mutated(PayloadKind.XSS, max_mutations=2)
        assert len(mutated) > len(originals)
