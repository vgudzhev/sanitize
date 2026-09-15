"""Layer 5: Custom patterns and literals from policy config."""

from __future__ import annotations

import re

from presidio_analyzer import Pattern, PatternRecognizer


def load_custom_recognizers(policy_config: dict) -> list[PatternRecognizer]:
    custom = policy_config.get("custom", {})
    recognizers: list[PatternRecognizer] = []

    for entry in custom.get("patterns", []):
        name = entry.get("name", "CUSTOM")
        regex = entry.get("regex", "")
        if not regex:
            continue
        entity = name.upper().replace("-", "_").replace(" ", "_")
        recognizers.append(
            PatternRecognizer(
                supported_entity=entity,
                patterns=[Pattern(name=name, regex=regex, score=0.90)],
            )
        )

    literals = custom.get("literals", [])
    if literals:
        escaped = [re.escape(lit) for lit in literals if lit]
        if escaped:
            regex = r"(?:" + "|".join(escaped) + r")"
            recognizers.append(
                PatternRecognizer(
                    supported_entity="CUSTOM_LITERAL",
                    patterns=[Pattern(name="custom_literals", regex=regex, score=0.90)],
                )
            )

    return recognizers
