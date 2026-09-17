"""Tests for the GLiNER recognizer (layer 4)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sanitize.recognizers.gliner import (
    DEFAULT_LABELS,
    DEFAULT_THRESHOLD,
    GlinerRecognizer,
    LABEL_TO_ENTITY,
    _flatten_gliner2,
)


class TestGlinerRecognizerWithMock:
    """Test GLiNER recognizer with a mocked GLiNER model."""

    def _make_recognizer_with_mock(self, predictions: list[dict]) -> GlinerRecognizer:
        rec = GlinerRecognizer()
        mock_model = MagicMock()
        mock_model.predict_entities.return_value = predictions
        rec._model = mock_model
        rec._available = True
        return rec

    def test_detects_person_name(self):
        rec = self._make_recognizer_with_mock([
            {"label": "person", "start": 10, "end": 20, "score": 0.92},
        ])
        results = rec.analyze("Contact me John Smith for details", ["PERSON"])
        assert len(results) == 1
        assert results[0].entity_type == "PERSON"
        assert results[0].start == 10
        assert results[0].end == 20
        assert results[0].score == 0.92

    def test_detects_organization(self):
        rec = self._make_recognizer_with_mock([
            {"label": "organization", "start": 5, "end": 15, "score": 0.85},
        ])
        results = rec.analyze("Join Acme Corp today", ["ORGANIZATION"])
        assert len(results) == 1
        assert results[0].entity_type == "ORGANIZATION"

    def test_detects_address(self):
        rec = self._make_recognizer_with_mock([
            {"label": "address", "start": 8, "end": 38, "score": 0.90},
        ])
        results = rec.analyze("Address 123 Main St, Springfield, IL", ["ADDRESS"])
        assert len(results) == 1
        assert results[0].entity_type == "ADDRESS"

    def test_filters_below_threshold(self):
        rec = self._make_recognizer_with_mock([
            {"label": "person", "start": 0, "end": 5, "score": 0.3},
        ])
        results = rec.analyze("hello world", ["PERSON"])
        assert len(results) == 0

    def test_multiple_entities(self):
        rec = self._make_recognizer_with_mock([
            {"label": "person", "start": 0, "end": 10, "score": 0.9},
            {"label": "organization", "start": 20, "end": 30, "score": 0.85},
            {"label": "address", "start": 40, "end": 60, "score": 0.90},
        ])
        results = rec.analyze("x" * 80, ["PERSON", "ORGANIZATION", "ADDRESS"])
        assert len(results) == 3
        types = {r.entity_type for r in results}
        assert types == {"PERSON", "ORGANIZATION", "ADDRESS"}

    def test_custom_labels(self):
        rec = GlinerRecognizer(labels=["internal hostname", "project codename"])
        mock_model = MagicMock()
        mock_model.predict_entities.return_value = [
            {"label": "internal hostname", "start": 0, "end": 15, "score": 0.88},
        ]
        rec._model = mock_model
        rec._available = True

        results = rec.analyze("db-prod-us-east.internal", ["INTERNAL_HOSTNAME"])
        assert len(results) == 1
        assert results[0].entity_type == "INTERNAL_HOSTNAME"

    def test_custom_threshold(self):
        rec = GlinerRecognizer(threshold=0.9)
        mock_model = MagicMock()
        mock_model.predict_entities.return_value = [
            {"label": "person", "start": 0, "end": 5, "score": 0.85},
        ]
        rec._model = mock_model
        rec._available = True

        results = rec.analyze("hello", ["PERSON"])
        assert len(results) == 0

    def test_prediction_failure_returns_empty(self):
        rec = self._make_recognizer_with_mock([])
        rec._model.predict_entities.side_effect = RuntimeError("model error")
        results = rec.analyze("test text", ["PERSON"])
        assert results == []


class TestGlinerUnavailable:
    """Test graceful degradation when gliner is not installed."""

    def test_returns_empty_when_unavailable(self):
        rec = GlinerRecognizer()
        rec._available = False
        results = rec.analyze("John Smith lives at 123 Main St", ["PERSON", "ADDRESS"])
        assert results == []

    def test_import_failure_sets_unavailable(self):
        rec = GlinerRecognizer()
        with patch.dict("sys.modules", {"gliner": None, "gliner2": None}):
            rec._available = None
            available = rec._ensure_model()
            assert available is False
            assert rec._available is False


class TestV1Fallback:
    def test_fallback_drops_gliner2_only_labels_and_raises_threshold(self):
        import types

        fake_gliner = types.ModuleType("gliner")
        fake_cls = MagicMock()
        fake_cls.from_pretrained.return_value = MagicMock()
        fake_gliner.GLiNER = fake_cls

        rec = GlinerRecognizer(labels=["person", "password", "api_key", "medical condition"])
        with patch.dict("sys.modules", {"gliner2": None, "gliner": fake_gliner}):
            assert rec._ensure_model() is True

        assert rec._backend == "gliner"
        fake_cls.from_pretrained.assert_called_once_with("urchade/gliner_multi_pii-v1")
        assert rec.labels == ["person", "medical condition"]
        assert rec.threshold == 0.85


class TestGliner2Backend:
    """gliner2 returns {"entities": {label: [{text, start, end, confidence}]}}."""

    def test_flatten_nested_output(self):
        result = {
            "entities": {
                "person": [{"text": "Tim Cook", "start": 15, "end": 23, "confidence": 0.92}],
                "email": ["no-span-form-is-skipped"],
            }
        }
        assert _flatten_gliner2(result) == [
            {"label": "person", "start": 15, "end": 23, "score": 0.92},
        ]

    def test_flatten_passes_through_flat_list(self):
        flat = [{"label": "person", "start": 0, "end": 3, "score": 0.9}]
        assert _flatten_gliner2(flat) == flat

    def test_analyze_uses_extract_entities_long(self):
        rec = GlinerRecognizer()
        mock_model = MagicMock()
        mock_model.extract_entities_long.return_value = {
            "entities": {"api_key": [{"text": "abc", "start": 4, "end": 7, "confidence": 0.8}]}
        }
        rec._model = mock_model
        rec._available = True
        rec._backend = "gliner2"

        results = rec.analyze("key abc", ["API_KEY"])
        assert len(results) == 1
        assert results[0].entity_type == "API_KEY"
        assert (results[0].start, results[0].end) == (4, 7)
        kwargs = mock_model.extract_entities_long.call_args.kwargs
        assert kwargs["include_spans"] is True
        assert kwargs["threshold"] == DEFAULT_THRESHOLD
        mock_model.predict_entities.assert_not_called()


class TestLabelMapping:
    def test_all_default_labels_have_mapping(self):
        for label in DEFAULT_LABELS:
            assert label in LABEL_TO_ENTITY

    def test_supported_entities_match_labels(self):
        rec = GlinerRecognizer()
        expected = {LABEL_TO_ENTITY[lb] for lb in DEFAULT_LABELS}
        assert set(rec.supported_entities) == expected
