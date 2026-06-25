"""
Payload loader — reads payload text files and feeds them to the mutation engine.
"""
from __future__ import annotations

from pathlib import Path
from core.models import MutatedPayload, MutationKind, PayloadKind
from core.mutations.encoder   import Encoder
from core.mutations.obfuscator import Obfuscator


_PAYLOAD_DIR = Path(__file__).parent
_FILES = {
    PayloadKind.XSS:  _PAYLOAD_DIR / "xss.txt",
    PayloadKind.SQLI: _PAYLOAD_DIR / "sqli.txt",
}


def _load_raw(kind: PayloadKind) -> list[str]:
    path = _FILES[kind]
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]


def load_originals(kind: PayloadKind) -> list[MutatedPayload]:
    """Return payloads with no transformation applied."""
    return [
        MutatedPayload(
            value=p, kind=MutationKind.ORIGINAL,
            original=p, category=kind,
        )
        for p in _load_raw(kind)
    ]


def load_mutated(kind: PayloadKind, max_mutations: int = 4) -> list[MutatedPayload]:
    """
    Return original + mutated variants for every base payload.
    Deduplication is applied so the same encoded string is never sent twice.
    *max_mutations* caps how many mutation techniques are applied per payload.
    """
    results: list[MutatedPayload] = []
    seen: set[str] = set()

    _MUTATION_PIPELINE: list[tuple[MutationKind, callable]] = [
        (MutationKind.URL_ENCODE,      Encoder.url_encode),
        (MutationKind.DOUBLE_ENCODE,   Encoder.double_url_encode),
        (MutationKind.UNICODE_ESCAPE,  Encoder.unicode_escape),
        (MutationKind.HTML_ENTITY,     Encoder.html_entity_encode),
        (MutationKind.MIXED_CASE,      Obfuscator.mixed_case),
        (MutationKind.INLINE_COMMENT,  Obfuscator.sql_inline_comment),
        (MutationKind.WHITESPACE_VAR,  Obfuscator.html_tag_whitespace),
        (MutationKind.CHAR_SUBSTITUTE, Obfuscator.char_substitute),
        (MutationKind.NULL_BYTE,       Encoder.null_byte_prefix),
    ]

    for raw in _load_raw(kind):
        # Always include the original
        if raw not in seen:
            seen.add(raw)
            results.append(MutatedPayload(
                value=raw, kind=MutationKind.ORIGINAL,
                original=raw, category=kind,
            ))

        applied = 0
        for mut_kind, fn in _MUTATION_PIPELINE:
            if applied >= max_mutations:
                break
            try:
                mutated = fn(raw)
            except Exception:
                continue
            if mutated and mutated not in seen:
                seen.add(mutated)
                results.append(MutatedPayload(
                    value=mutated, kind=mut_kind,
                    original=raw, category=kind,
                ))
                applied += 1

    return results


def load_all(max_mutations: int = 4) -> list[MutatedPayload]:
    """Convenience: load XSS + SQLi with mutations."""
    return load_mutated(PayloadKind.XSS, max_mutations) + \
           load_mutated(PayloadKind.SQLI, max_mutations)
