"""Layer 4: GLiNER zero-shot NER recognizer for contextual PII.

Catches person names, addresses, org names, credentials, financial data,
and more using configurable labels. Lazy-loads the model on first use to
avoid startup cost when not needed.

Supports two backends:
  - gliner2 (preferred): fastino/gliner2-privacy-filter-PII-multi (42 PII types)
  - gliner (fallback):   urchade/gliner_multi_pii-v1

When neither is installed, the recognizer silently returns no results and
logs a warning once.
"""

from __future__ import annotations

import logging
from typing import Any

from presidio_analyzer import EntityRecognizer, RecognizerResult

log = logging.getLogger(__name__)

DEFAULT_LABELS = [
    "person",
    "email",
    "phone_number",
    "address",
    "organization",
    "government_id",
    "password",
    "secret",
    "api_key",
    "access_token",
    "ip_address",
    "bank_account",
    "iban",
    "payment_card",
    "date_of_birth",
    "internal hostname",
    "project codename",
]

LABEL_TO_ENTITY: dict[str, str] = {
    "person": "PERSON",
    "full_name": "PERSON",
    "first_name": "PERSON",
    "last_name": "PERSON",
    "email": "EMAIL_ADDRESS",
    "phone_number": "PHONE_NUMBER",
    "address": "ADDRESS",
    "street_address": "ADDRESS",
    "city": "ADDRESS",
    "state_or_region": "ADDRESS",
    "postal_code": "ADDRESS",
    "country": "ADDRESS",
    "organization": "ORGANIZATION",
    "government_id": "GOVERNMENT_ID",
    "national_id_number": "GOVERNMENT_ID",
    "passport_number": "PASSPORT_NUMBER",
    "drivers_license_number": "DRIVERS_LICENSE",
    "tax_id": "TAX_ID",
    "tax_number": "TAX_ID",
    "bank_account": "BANK_ACCOUNT",
    "account_number": "BANK_ACCOUNT",
    "routing_number": "ROUTING_NUMBER",
    "iban": "IBAN",
    "payment_card": "PAYMENT_CARD",
    "card_number": "PAYMENT_CARD",
    "card_expiry": "PAYMENT_CARD_EXPIRY",
    "card_cvv": "PAYMENT_CARD_CVV",
    "username": "USERNAME",
    "ip_address": "IP_ADDRESS",
    "password": "PASSWORD",
    "secret": "GENERIC_SECRET",
    "api_key": "API_KEY",
    "access_token": "ACCESS_TOKEN",
    "recovery_code": "RECOVERY_CODE",
    "date_of_birth": "DATE_OF_BIRTH",
    "internal hostname": "INTERNAL_HOSTNAME",
    "project codename": "PROJECT_CODENAME",
}

DEFAULT_THRESHOLD = 0.5
DEFAULT_MODEL = "fastino/gliner2-privacy-filter-PII-multi"
FALLBACK_MODEL = "urchade/gliner_multi_pii-v1"
FALLBACK_THRESHOLD = 0.85

# Labels the v1 PII model was not trained on. It matches the literal words
# ("password", "secret") instead of values, and the deterministic layers
# already cover these categories, so they are dropped on fallback.
GLINER2_ONLY_LABELS = frozenset({
    "email", "phone_number", "government_id", "password", "secret", "api_key",
    "access_token", "username", "ip_address", "bank_account", "iban",
    "payment_card", "date_of_birth", "recovery_code", "account_id",
})


def _flatten_gliner2(result: Any) -> list[dict]:
    """Normalize gliner2 output to the flat {label, start, end, score} shape."""
    if isinstance(result, list):
        return result
    entities = result.get("entities", {}) if isinstance(result, dict) else {}
    flat: list[dict] = []
    for label, items in entities.items():
        for item in items:
            if not isinstance(item, dict) or "start" not in item or "end" not in item:
                continue
            flat.append({
                "label": label,
                "start": item["start"],
                "end": item["end"],
                "score": item.get("confidence", item.get("score", 1.0)),
            })
    return flat


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
        self._backend: str | None = None

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

        # Try gliner2 first (supports fastino/gliner2-* models). Requires the
        # `gliner2[local]` extra; the bare package is only an API client.
        try:
            import gliner2
            loader = getattr(gliner2, "AutoExtractor", None) or gliner2.GLiNER2
            self._model = loader.from_pretrained(self.model_name)
            self._backend = "gliner2"
            self._available = True
            log.info("GLiNER2 model loaded: %s (gliner2 backend)", self.model_name)
            return True
        except ImportError:
            pass
        except Exception:
            log.debug("gliner2 failed to load %s, trying gliner fallback", self.model_name, exc_info=True)

        # Fall back to gliner package (supports urchade/* models)
        try:
            from gliner import GLiNER
            fallback = self.model_name
            # gliner v1 doesn't support gliner2 checkpoints — use fallback model
            if self.model_name.startswith("fastino/"):
                fallback = FALLBACK_MODEL
                # urchade model needs higher threshold than fastino
                if self.threshold < FALLBACK_THRESHOLD:
                    self.threshold = FALLBACK_THRESHOLD
                self.labels = [lb for lb in self.labels if lb not in GLINER2_ONLY_LABELS]
                log.info("gliner2 not installed, falling back to %s (threshold %.2f, %d labels)",
                         fallback, self.threshold, len(self.labels))
            self._model = GLiNER.from_pretrained(fallback)
            self._backend = "gliner"
            self._available = True
            log.info("GLiNER model loaded: %s (gliner backend)", fallback)
            return True
        except ImportError:
            log.warning(
                "Neither gliner2 nor gliner package installed. "
                "Layer 4 (contextual PII) is disabled. "
                "Install with: pip install gliner2"
            )
            self._available = False
        except Exception:
            log.warning("Failed to load GLiNER model", exc_info=True)
            self._available = False
        return self._available

    def _predict(self, text: str) -> list[dict]:
        if self._backend == "gliner2":
            # extract_entities_long windows the text (384-token model limit)
            # and returns {"entities": {label: [{text, start, end, confidence}]}}
            result = self._model.extract_entities_long(
                text, self.labels, threshold=self.threshold,
                include_confidence=True, include_spans=True,
            )
            return _flatten_gliner2(result)
        # gliner v1 API
        return self._model.predict_entities(
            text, self.labels, threshold=self.threshold
        )

    def analyze(
        self, text: str, entities: list[str], nlp_artifacts: Any = None
    ) -> list[RecognizerResult]:
        if not self._ensure_model():
            return []

        try:
            predictions = self._predict(text)
        except Exception:
            log.warning("GLiNER prediction failed", exc_info=True)
            return []

        results: list[RecognizerResult] = []
        for pred in predictions:
            label = pred.get("label", "")
            entity_type = LABEL_TO_ENTITY.get(label, label.upper().replace(" ", "_"))
            start = pred.get("start", 0)
            end = pred.get("end", 0)
            score = pred.get("score", pred.get("confidence", 0.0))

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
