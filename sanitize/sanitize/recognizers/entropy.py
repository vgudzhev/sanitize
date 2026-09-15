"""Layer 2: Shannon entropy detector for high-entropy strings in secret-like contexts."""

from __future__ import annotations

import math
import re
from collections import Counter

from presidio_analyzer import EntityRecognizer, RecognizerResult


_CONTEXT_PATTERN = re.compile(
    r"(?i)(?:=|:|Bearer\s+|Authorization[:\s]+|token[=:\s]+|key[=:\s]+|secret[=:\s]+"
    r"|password[=:\s]+|passwd[=:\s]+|pwd[=:\s]+|api_key[=:\s]+)\s*['\"]?"
    r"([A-Za-z0-9+/=_\-]{20,})"
    r"['\"]?"
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


class EntropyRecognizer(EntityRecognizer):
    """Flags high-entropy strings appearing in credential-like contexts."""

    ENTITIES = ["HIGH_ENTROPY_SECRET"]

    def __init__(self, threshold: float = 4.0) -> None:
        super().__init__(
            supported_entities=self.ENTITIES,
            supported_language="en",
            name="EntropyRecognizer",
        )
        self.threshold = threshold

    def load(self) -> None:
        pass

    def analyze(
        self, text: str, entities: list[str], nlp_artifacts=None
    ) -> list[RecognizerResult]:
        results: list[RecognizerResult] = []
        for m in _CONTEXT_PATTERN.finditer(text):
            candidate = m.group(1)
            if shannon_entropy(candidate) >= self.threshold:
                results.append(
                    RecognizerResult(
                        entity_type="HIGH_ENTROPY_SECRET",
                        start=m.start(1),
                        end=m.end(1),
                        score=0.7,
                        analysis_explanation=None,
                        recognition_metadata={
                            RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                            RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
                        },
                    )
                )
        return results
