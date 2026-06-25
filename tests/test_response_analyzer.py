"""Unit tests for the response analyzer."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from unittest.mock import MagicMock
from core.models import ResponseClass
from core.analyzers.response_analyzer import ResponseAnalyzer


def _mock_resp(status: int, headers: dict | None = None, body: str = "") -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.headers = MagicMock()
    r.headers.items = lambda: (headers or {}).items()
    r.text = body
    r.content = body.encode()
    return r


class TestResponseAnalyzer:
    az = ResponseAnalyzer()

    def test_403_classified_blocked(self):
        r = _mock_resp(403, body="Access Denied")
        result = self.az.analyse(r, 0.1)
        assert result.classification == ResponseClass.BLOCKED
        assert result.blocked is True

    def test_200_clean_classified_allowed(self):
        r = _mock_resp(200, body="<html>Welcome</html>")
        result = self.az.analyse(r, 0.05)
        assert result.classification == ResponseClass.ALLOWED
        assert result.blocked is False

    def test_captcha_body_classified_challenged(self):
        r = _mock_resp(200, body="Please complete the CAPTCHA to continue")
        result = self.az.analyse(r, 0.1)
        assert result.classification == ResponseClass.CHALLENGED

    def test_429_rate_limited(self):
        r = _mock_resp(429, body="Too many requests")
        result = self.az.analyse(r, 0.05)
        assert result.classification in (
            ResponseClass.RATE_LIMITED, ResponseClass.CHALLENGED
        )

    def test_500_error(self):
        r = _mock_resp(500, body="Internal Server Error")
        result = self.az.analyse(r, 0.1)
        assert result.classification == ResponseClass.ERROR

    def test_length_delta_signals_filter(self):
        az = ResponseAnalyzer(baseline_length=1000, length_threshold=0.15)
        r  = _mock_resp(200, body="x" * 100)   # 90% shorter than baseline
        result = az.analyse(r, 0.1)
        signal_text = " ".join(result.signals).lower()
        assert "length changed" in signal_text

    def test_block_header_detected(self):
        r = _mock_resp(200, headers={"x-blocked-by": "waf"}, body="OK")
        result = self.az.analyse(r, 0.05)
        assert any("block header" in s.lower() for s in result.signals)

    def test_response_time_recorded(self):
        r = _mock_resp(200, body="ok")
        result = self.az.analyse(r, 0.42)
        assert abs(result.resp_time - 0.42) < 0.001

