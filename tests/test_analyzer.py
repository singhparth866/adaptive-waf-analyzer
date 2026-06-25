"""Unit tests for the response analyzer."""
from __future__ import annotations
from unittest.mock import MagicMock
import pytest
from core.analyzers.response_analyzer import ResponseAnalyzer
from core.models import ResponseClass


def _mock(status: int, body: str = "", headers: dict | None = None, content_len: int | None = None):
    r = MagicMock()
    r.status_code = status
    r.text        = body
    r.headers     = headers or {}
    r.content     = (b"x" * content_len) if content_len is not None else body.encode()
    return r


class TestResponseAnalyzer:
    def setup_method(self):
        self.a = ResponseAnalyzer(baseline_length=0)

    def test_200_no_signals_is_allowed(self):
        r = _mock(200, "Hello world")
        result = self.a.analyse(r, 0.1)
        assert result.classification == ResponseClass.ALLOWED
        assert not result.blocked

    def test_403_is_blocked(self):
        r = _mock(403, "Access Denied")
        result = self.a.analyse(r, 0.1)
        assert result.classification == ResponseClass.BLOCKED
        assert result.blocked

    def test_406_is_blocked(self):
        r = _mock(406, "")
        result = self.a.analyse(r, 0.1)
        assert result.classification == ResponseClass.BLOCKED

    def test_captcha_body_is_challenged(self):
        r = _mock(200, "Please complete the CAPTCHA to continue")
        result = self.a.analyse(r, 0.1)
        assert result.classification == ResponseClass.CHALLENGED

    def test_block_page_body_is_blocked(self):
        r = _mock(200, "Your request has been blocked due to suspicious activity")
        result = self.a.analyse(r, 0.1)
        assert result.classification == ResponseClass.BLOCKED

    def test_length_change_flagged(self):
        a = ResponseAnalyzer(baseline_length=1000, length_threshold=0.15)
        r = _mock(200, "short", content_len=100)  # 90% drop
        result = a.analyse(r, 0.1)
        # Should be flagged as filtered due to length change
        assert any("length" in s.lower() for s in result.signals)

    def test_500_is_error(self):
        r = _mock(500, "Internal Server Error")
        result = self.a.analyse(r, 0.1)
        assert result.classification == ResponseClass.ERROR

    def test_block_header_adds_signal(self):
        r = _mock(200, "", headers={"x-blocked-by": "WAF"})
        result = self.a.analyse(r, 0.1)
        assert any("block" in s.lower() for s in result.signals)
