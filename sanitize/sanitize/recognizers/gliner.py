"""Layer 4: GLiNER zero-shot NER recognizer for contextual PII.

Catches person names, addresses, org names, internal hostnames, and
project codenames using configurable labels. Lazy-loads the model on
first use to avoid startup cost when not needed.

Requires: gliner (which depends on torch>=2.0). When unavailable, the
recognizer silently returns no results and logs a warning once.
"""

from __future__ import annotations

import logging
from typing import Any

from presidio_analyzer import EntityRecognizer, RecognizerResult

log = logging.getLogger(__name__)

DEFAULT_LABELS = [
    "person",
    "address",
    "organization",
    "internal hostname",
    "project codename",
]

LABEL_TO_ENTITY: dict[str, str] = {
    "person": "PERSON",
    "address": "ADDRESS",
    "organization": "ORGANIZATION",
    "internal hostname": "INTERNAL_HOSTNAME",
    "project codename": "PROJECT_CODENAME",
}

DEFAULT_THRESHOLD = 0.85
DEFAULT_MODEL = "urchade/gliner_multi_pii-v1"


class GlinerRecognizer(EntityRecognizer):
    """Zero-shot NER using GLiNER for configurable entity labels."""

    def __init__(
        self,
        labels: list[str] | None = None,
        threshold: float = DEFAULT_THRESHOLD,
        model_name: str = DEFAULT_MODEL,
    ) -> None:
        self.labels = labels or DEFAULT_LABELS
        self.threshold = threshold
        self.model_name = model_name
        self._model: Any = None
        self._available: bool | None = None

        entities = [LABEL_TO_ENTITY.get(lb, lb.upper().replace(" ", "_")) for lb in self.labels]
        super().__init__(
            supported_entities=entities,
            supported_language="en",
            name="GlinerRecognizer",
        )

    def load(self) -> None:
        pass

    def _ensure_model(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            from gliner import GLiNER
            self._model = GLiNER.from_pretrained(self.model_name)
            self._available = True
            log.info("GLiNER model loaded: %s", self.model_name)
        except ImportError:
            log.warning(
                "gliner package not installed (requires torch). "
                "Layer 4 (contextual PII) is disabled. "
                "Install with: pip install gliner"
            )
            self._available = False
        except Exception:
            log.warning("Failed to load GLiNER model %s", self.model_name, exc_info=True)
            self._available = False
        return self._available

    def analyze(
        self, text: str, entities: list[str], nlp_artifacts: Any = None
    ) -> list[RecognizerResult]:
        if not self._ensure_model():
            return []

        try:
            predictions = self._model.predict_entities(
                text, self.labels, threshold=self.threshold
            )
        except Exception:
            log.warning("GLiNER prediction failed", exc_info=True)
            return []

        results: list[RecognizerResult] = []
        for pred in predictions:
            label = pred.get("label", "")
            entity_type = LABEL_TO_ENTITY.get(label, label.upper().replace(" ", "_"))
            start = pred.get("start", 0)
            end = pred.get("end", 0)
            score = pred.get("score", 0.0)

            if end <= start or score < self.threshold:
                continue

            results.append(
                RecognizerResult(
                    entity_type=entity_type,
                    start=start,
                    end=end,
                    score=round(score, 4),
                    analysis_explanation=None,
                    recognition_metadata={
                        RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                        RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
                    },
                )
            )

        return results
