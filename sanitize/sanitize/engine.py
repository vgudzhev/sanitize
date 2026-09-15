"""Detection engine: layer orchestration and span merging."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider

from .recognizers.custom import load_custom_recognizers
from .recognizers.entropy import EntropyRecognizer
from .recognizers.gitleaks import load_gitleaks_recognizers

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


_analyzer_cache: dict[int, tuple[AnalyzerEngine, list[str]]] | None = None


def _get_analyzer(policy_config: dict) -> tuple[AnalyzerEngine, list[str]]:
    global _analyzer_cache
    config_id = id(policy_config)
    if _analyzer_cache is not None and config_id in _analyzer_cache:
        return _analyzer_cache[config_id]
    analyzer, detectors = _build_analyzer(policy_config)
    _analyzer_cache = {config_id: (analyzer, detectors)}
    return analyzer, detectors


_PLACEHOLDER_PATTERN = r"\[\[[A-Z_]+_\d+\]\]"


def detect(
    text: str,
    hints: dict | None = None,
    policy_config: dict | None = None,
) -> tuple[list[Span], dict]:
    if policy_config is None:
        from .policy import load_policy
        policy_config = load_policy()

    start_time = time.monotonic()
    analyzer, detectors_run = _get_analyzer(policy_config)

    allow_list = policy_config.get("allow", [])

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

    spans: list[Span] = []
    for r in results:
        overlaps_placeholder = False
        for ph_start, ph_end in placeholder_spans:
            if r.start < ph_end and r.end > ph_start:
                overlaps_placeholder = True
                break
        if overlaps_placeholder:
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
        elif "custom" in rec_name.lower() or "pattern" in rec_name.lower():
            detector = "custom" if rec_name.startswith("Custom") else f"regex:{rec_name}"

        spans.append(Span(
            start=r.start,
            end=r.end,
            type=r.entity_type,
            score=round(r.score, 4),
            detector=detector,
        ))

    merged = merge_spans(spans)
    elapsed_ms = round((time.monotonic() - start_time) * 1000)

    stats = {
        "ms": elapsed_ms,
        "detectors_run": detectors_run,
    }

    return merged, stats
