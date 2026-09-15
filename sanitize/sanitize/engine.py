"""Detection engine: layer orchestration and span merging."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider

from .recognizers.custom import load_custom_recognizers
from .recognizers.entropy import EntropyRecognizer
from .recognizers.gliner import GlinerRecognizer
from .recognizers.gitleaks import _PRIVATE_KEY_BLOCK, load_gitleaks_recognizers

log = logging.getLogger(__name__)


@dataclass
class Span:
    start: int
    end: int
    type: str
    score: float
    detector: str


def merge_spans(spans: list[Span]) -> list[Span]:
    """Merge overlapping spans: keep the one with highest score, break ties by widest."""
    if not spans:
        return []

    sorted_spans = sorted(spans, key=lambda s: s.start)
    merged: list[Span] = []

    for span in sorted_spans:
        if not merged:
            merged.append(span)
            continue

        last = merged[-1]
        if span.start < last.end:
            if span.score > last.score or (
                span.score == last.score and (span.end - span.start) > (last.end - last.start)
            ):
                merged[-1] = span
            elif span.end > last.end:
                merged[-1] = Span(
                    start=last.start,
                    end=max(last.end, span.end),
                    type=last.type,
                    score=last.score,
                    detector=last.detector,
                )
        else:
            merged.append(span)

    return merged


def _build_analyzer(policy_config: dict) -> tuple[AnalyzerEngine, list[str]]:
    registry = RecognizerRegistry()
    detectors_run: list[str] = []

    for rec in load_gitleaks_recognizers():
        registry.add_recognizer(rec)
    detectors_run.append("gitleaks")

    registry.add_recognizer(EntropyRecognizer(
        threshold=policy_config.get("detectors", {}).get("entropy", {}).get("threshold", 4.0)
    ))
    detectors_run.append("entropy")

    try:
        default_registry = RecognizerRegistry()
        default_registry.load_predefined_recognizers()
        for rec in default_registry.recognizers:
            registry.add_recognizer(rec)
        detectors_run.append("presidio")
    except Exception:
        log.warning("Could not load Presidio predefined recognizers (spaCy model missing?)", exc_info=True)

    gliner_config = policy_config.get("detectors", {}).get("gliner", {})
    gliner_labels = gliner_config.get("labels")
    gliner_threshold = gliner_config.get("threshold", 0.5)
    registry.add_recognizer(GlinerRecognizer(
        labels=gliner_labels,
        threshold=gliner_threshold,
    ))
    detectors_run.append("gliner")

    for rec in load_custom_recognizers(policy_config):
        registry.add_recognizer(rec)
    detectors_run.append("custom")

    try:
        nlp_engine = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }).create_engine()
    except Exception:
        log.warning("spaCy model not available, using default NLP engine", exc_info=True)
        nlp_engine = NlpEngineProvider().create_engine()

    analyzer = AnalyzerEngine(
        registry=registry,
        supported_languages=["en"],
        nlp_engine=nlp_engine,
        default_score_threshold=0.0,
    )

    return analyzer, detectors_run


_analyzer_cache: dict[int, tuple[AnalyzerEngine, list[str], list]] | None = None


def _get_pattern_recognizers(analyzer: AnalyzerEngine) -> list:
    """Extract recognizers that work without NLP artifacts (regex/pattern-based)."""
    recs = []
    for rec in analyzer.registry.recognizers:
        if hasattr(rec, "patterns") and rec.patterns:
            recs.append(rec)
        elif type(rec).__name__ in (
            "PrivateKeyRecognizer",
            "EntropyRecognizer",
            "GlinerRecognizer",
        ):
            recs.append(rec)
    return recs


def _get_analyzer(policy_config: dict) -> tuple[AnalyzerEngine, list[str], list]:
    global _analyzer_cache
    config_id = id(policy_config)
    if _analyzer_cache is not None and config_id in _analyzer_cache:
        return _analyzer_cache[config_id]
    analyzer, detectors = _build_analyzer(policy_config)
    pattern_recs = _get_pattern_recognizers(analyzer)
    _analyzer_cache = {config_id: (analyzer, detectors, pattern_recs)}
    return analyzer, detectors, pattern_recs


_PLACEHOLDER_PATTERN = r"\[\[[A-Z_]+_\d+\]\]"

_FORMAT_PRESERVING_PATTERN = re.compile(
    "|".join([
        r"user\d+@redacted\.example",
        r"10\.0\.\d{1,3}\.\d{1,3}",
        r"555-000-\d{4}",
        r"4000-0000-0000-\d{4}",
        r"AKIA0+\d+",
        r"Person_\d+",
        r"Org_\d+",
        r"\d+ Redacted St, Anytown, XX 00000",
        r"https://redacted\.example/path/\d+",
        r"postgres://user\d+:pass@redacted\.example:5432/db\d+",
        r"\[PRIVATE_KEY_\d+_REDACTED\]",
        r"REDACTED_SECRET_\d+",
        r"ghp_0+\d+",
        r"eyJ_REDACTED_\d+",
        r"sk_test_0+\d+",
        r"host\d+\.redacted\.internal",
        r"Project_\d+",
    ])
)

_CHUNK_PREFILTER = re.compile(
    "|".join([
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        r"(?<!\d)(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d)",
        r"(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",
        r"-----BEGIN",
        r"gh[pousr]_[A-Za-z0-9_]{20,}",
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ",
        r"(?:postgres|mysql|mongodb|redis|amqp)://\S+:\S+@",
        r"(?:password|passwd|secret|token|api_key|apikey|api-key|secret_access_key)\s*[=:]",
        r"sk_(?:live|test)_[A-Za-z0-9]{20,}",
        r"xox[bpoas]-",
        r"sk-ant-",
    ])
)

CHUNK_THRESHOLD = 4096
CHUNK_TARGET = 2048
_CLEAN_CHUNK_CACHE: dict[str, bool] = {}
CLEAN_CACHE_MAX = 4096


def _chunk_text(text: str) -> list[tuple[int, str]]:
    """Split text into chunks at line boundaries. Returns (offset, chunk) pairs."""
    chunks: list[tuple[int, str]] = []
    pos = 0
    while pos < len(text):
        end = min(pos + CHUNK_TARGET, len(text))
        if end < len(text):
            nl = text.rfind("\n", pos, end + 1)
            if nl > pos:
                end = nl + 1
        chunks.append((pos, text[pos:end]))
        pos = end
    return chunks


def _chunk_hash(chunk: str, policy_fp: str = "") -> str:
    return hashlib.sha256((policy_fp + chunk).encode("utf-8", errors="replace")).hexdigest()


def _prescan_blocks(text: str) -> list[Span]:
    """Pre-scan full text for multi-line block patterns that span chunk boundaries."""
    spans = []
    for m in _PRIVATE_KEY_BLOCK.finditer(text):
        spans.append(Span(
            start=m.start(),
            end=m.end(),
            type="PRIVATE_KEY",
            score=0.99,
            detector="regex:gitleaks",
        ))
    return spans


def _policy_fingerprint(policy_config: dict) -> str:
    try:
        return hashlib.sha256(
            json.dumps(policy_config, sort_keys=True, default=str).encode()
        ).hexdigest()[:16]
    except Exception:
        return ""


def _detect_chunk_fast(
    text: str,
    pattern_recs: list,
    allow_list: list[str],
) -> list[Span]:
    """Fast chunk detection: run regex recognizers directly, bypassing spaCy NLP."""
    raw_results = []
    for rec in pattern_recs:
        try:
            raw_results.extend(
                rec.analyze(text=text, entities=rec.supported_entities, nlp_artifacts=None)
            )
        except Exception:
            continue

    fp_spans = [(m.start(), m.end()) for m in _FORMAT_PRESERVING_PATTERN.finditer(text)]
    ph_spans = [(m.start(), m.end()) for m in re.finditer(_PLACEHOLDER_PATTERN, text)]
    safe_spans = ph_spans + fp_spans

    spans: list[Span] = []
    for r in raw_results:
        if r.score < 0.3:
            continue
        overlaps_safe = any(r.start < se and r.end > ss for ss, se in safe_spans)
        if overlaps_safe:
            continue
        matched = text[r.start : r.end]
        if matched in allow_list:
            continue

        rec_name = ""
        if r.recognition_metadata:
            rec_name = r.recognition_metadata.get("recognizer_name", "")
        detector = "presidio"
        if "gitleaks" in rec_name.lower() or "private" in rec_name.lower():
            detector = "regex:gitleaks"
        elif "entropy" in rec_name.lower():
            detector = "entropy"
        elif "gliner" in rec_name.lower():
            detector = "gliner"

        spans.append(Span(
            start=r.start,
            end=r.end,
            type=r.entity_type,
            score=round(r.score, 4),
            detector=detector,
        ))

    return spans


def _detect_single(
    text: str,
    analyzer: AnalyzerEngine,
    allow_list: list[str],
) -> list[Span]:
    """Run detection on a single piece of text, returning un-merged spans."""
    import re as _re
    escaped_allow = [_re.escape(a) for a in allow_list]
    try:
        results = analyzer.analyze(
            text=text,
            language="en",
            allow_list=escaped_allow + [_PLACEHOLDER_PATTERN],
            score_threshold=0.3,
        )
    except Exception:
        log.warning("Presidio analysis failed, falling back to empty", exc_info=True)
        results = []

    placeholder_spans = [(m.start(), m.end()) for m in _re.finditer(_PLACEHOLDER_PATTERN, text)]
    fp_spans = [(m.start(), m.end()) for m in _FORMAT_PRESERVING_PATTERN.finditer(text)]
    safe_spans = placeholder_spans + fp_spans

    spans: list[Span] = []
    for r in results:
        overlaps_safe = False
        for s_start, s_end in safe_spans:
            if r.start < s_end and r.end > s_start:
                overlaps_safe = True
                break
        if overlaps_safe:
            continue

        matched = text[r.start : r.end]
        if matched in allow_list:
            continue

        detector = "presidio"
        rec_name = ""
        if r.recognition_metadata:
            rec_name = r.recognition_metadata.get("recognizer_name", "")
        if "gitleaks" in rec_name.lower() or "private" in rec_name.lower():
            detector = "regex:gitleaks"
        elif "entropy" in rec_name.lower():
            detector = "entropy"
        elif "gliner" in rec_name.lower():
            detector = "gliner"
        elif "custom" in rec_name.lower() or "pattern" in rec_name.lower():
            detector = "custom" if rec_name.startswith("Custom") else f"regex:{rec_name}"

        spans.append(Span(
            start=r.start,
            end=r.end,
            type=r.entity_type,
            score=round(r.score, 4),
            detector=detector,
        ))

    return spans


def detect(
    text: str,
    hints: dict | None = None,
    policy_config: dict | None = None,
) -> tuple[list[Span], dict]:
    global _CLEAN_CHUNK_CACHE

    if policy_config is None:
        from .policy import load_policy
        policy_config = load_policy()

    start_time = time.monotonic()
    analyzer, detectors_run, pattern_recs = _get_analyzer(policy_config)
    allow_list = policy_config.get("allow", [])

    if len(text) <= CHUNK_THRESHOLD:
        spans = _detect_single(text, analyzer, allow_list)
    else:
        spans = _prescan_blocks(text)
        policy_fp = _policy_fingerprint(policy_config)
        chunks = _chunk_text(text)
        for offset, chunk in chunks:
            if not _CHUNK_PREFILTER.search(chunk):
                continue
            h = _chunk_hash(chunk, policy_fp)
            if h in _CLEAN_CHUNK_CACHE:
                continue
            chunk_spans = _detect_chunk_fast(chunk, pattern_recs, allow_list)
            if not chunk_spans:
                if len(_CLEAN_CHUNK_CACHE) < CLEAN_CACHE_MAX:
                    _CLEAN_CHUNK_CACHE[h] = True
            else:
                for s in chunk_spans:
                    spans.append(Span(
                        start=s.start + offset,
                        end=s.end + offset,
                        type=s.type,
                        score=s.score,
                        detector=s.detector,
                    ))

    merged = merge_spans(spans)
    elapsed_ms = round((time.monotonic() - start_time) * 1000)

    stats = {
        "ms": elapsed_ms,
        "detectors_run": detectors_run,
    }

    return merged, stats
