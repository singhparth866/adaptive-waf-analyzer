"""Unit tests for payload loading and mutation pipeline."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import MutationKind, PayloadKind
from payloads.loader import load_originals, load_mutated, load_all


class TestPayloadLoader:
    def test_load_originals_xss_nonempty(self):
        items = load_originals(PayloadKind.XSS)
        assert len(items) > 0

    def test_load_originals_sqli_nonempty(self):
        items = load_originals(PayloadKind.SQLI)
        assert len(items) > 0

    def test_originals_have_original_mutation_kind(self):
        items = load_originals(PayloadKind.XSS)
        assert all(p.kind == MutationKind.ORIGINAL for p in items)

    def test_load_mutated_returns_more_than_originals(self):
        originals = load_originals(PayloadKind.XSS)
        mutated   = load_mutated(PayloadKind.XSS, max_mutations=4)
        assert len(mutated) > len(originals)

    def test_no_duplicate_payload_values(self):
        items = load_mutated(PayloadKind.XSS, max_mutations=9)
        values = [p.value for p in items]
        assert len(values) == len(set(values)), "Duplicate payload values found"

    def test_max_mutations_respected(self):
        raw = load_originals(PayloadKind.SQLI)
        mutated = load_mutated(PayloadKind.SQLI, max_mutations=2)
        # At most (max_mutations + 1) per base payload
        assert len(mutated) <= len(raw) * 3  # original + up to 2 variants each

    def test_load_all_contains_both_categories(self):
        items = load_all(max_mutations=2)
        cats  = {p.category for p in items}
        assert PayloadKind.XSS  in cats
        assert PayloadKind.SQLI in cats

    def test_category_set_correctly(self):
        xss   = load_originals(PayloadKind.XSS)
        sqli  = load_originals(PayloadKind.SQLI)
        assert all(p.category == PayloadKind.XSS  for p in xss)
        assert all(p.category == PayloadKind.SQLI for p in sqli)

