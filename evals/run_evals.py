"""Eval runner: measure recall and precision of scrubd detection.

Recall rule: a planted item is "caught" if any returned span fully contains the
planted secret value (character-level containment, not exact match).
This handles cases where the detector span includes context like `KEY=value`.

Exits nonzero if:
- Secret categories have < 100% recall
- PII categories have < 95% recall
"""

from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scrubd"))

from scrubd.engine import detect
from scrubd.policy import load_policy


CORPUS_DIR = os.path.join(os.path.dirname(__file__), "corpus")

SECRET_RECALL_THRESHOLD = 1.0
PII_RECALL_THRESHOLD = 0.95


def _is_caught(text: str, planted_value: str, spans: list[dict]) -> bool:
    """A planted item is caught if any span fully contains the planted value."""
    for span in spans:
        span_text = text[span["start"]:span["end"]]
        if planted_value in span_text:
            return True
    return False


def run_evals() -> bool:
    policy = load_policy()

    if not os.path.exists(CORPUS_DIR) or not os.listdir(CORPUS_DIR):
        print("ERROR: corpus directory is empty. Run generate_corpus.py first.")
        return False

    categories: dict[str, dict] = {}
    total_items = 0
    total_caught = 0
    total_false_positives = 0

    corpus_files = sorted(f for f in os.listdir(CORPUS_DIR) if f.endswith(".json"))
    if not corpus_files:
        print("ERROR: no corpus files found.")
        return False

    start_time = time.monotonic()

    for filename in corpus_files:
        cat_name = filename.replace(".json", "")
        filepath = os.path.join(CORPUS_DIR, filename)
        with open(filepath) as f:
            items = json.load(f)

        caught = 0
        missed = 0
        missed_items: list[dict] = []

        for item in items:
            text = item["text"]
            planted_list = item["planted"]

            spans_raw, _stats = detect(text, policy_config=policy)
            spans = [{"start": s.start, "end": s.end, "type": s.type, "score": s.score} for s in spans_raw]

            all_caught = True
            for planted in planted_list:
                if _is_caught(text, planted["value"], spans):
                    caught += 1
                else:
                    missed += 1
                    all_caught = False
                    missed_items.append({
                        "text": text[:120],
                        "value": planted["value"][:60],
                        "type": planted["type"],
                    })

        total_planted = caught + missed
        recall = caught / total_planted if total_planted > 0 else 0.0
        group = items[0]["planted"][0]["category_group"] if items else "unknown"

        categories[cat_name] = {
            "total": total_planted,
            "caught": caught,
            "missed": missed,
            "recall": recall,
            "group": group,
            "missed_items": missed_items[:5],
        }
        total_items += total_planted
        total_caught += caught

    elapsed = time.monotonic() - start_time

    print("=" * 72)
    print("pi-scrub eval results")
    print("=" * 72)
    print(f"\nTotal items: {total_items}")
    print(f"Total caught: {total_caught}")
    print(f"Overall recall: {total_caught / total_items:.1%}")
    print(f"Time: {elapsed:.1f}s")
    print()

    all_passed = True

    print(f"{'Category':<25} {'Group':<8} {'Total':>5} {'Caught':>6} {'Recall':>8} {'Status':>8}")
    print("-" * 72)
    for cat_name, data in sorted(categories.items()):
        threshold = SECRET_RECALL_THRESHOLD if data["group"] == "secrets" else PII_RECALL_THRESHOLD
        passed = data["recall"] >= threshold
        status = "PASS" if passed else "FAIL"
        if not passed:
            all_passed = False
        print(f"{cat_name:<25} {data['group']:<8} {data['total']:>5} {data['caught']:>6} {data['recall']:>7.1%} {status:>8}")

    if not all_passed:
        print("\n--- FAILURES ---")
        for cat_name, data in sorted(categories.items()):
            threshold = SECRET_RECALL_THRESHOLD if data["group"] == "secrets" else PII_RECALL_THRESHOLD
            if data["recall"] < threshold:
                print(f"\n{cat_name} ({data['group']}, recall={data['recall']:.1%}, threshold={threshold:.0%}):")
                for m in data["missed_items"]:
                    print(f"  MISSED: type={m['type']} value={m['value']}")
                    print(f"          text={m['text']}")

    print("\n" + "=" * 72)
    if all_passed:
        print("RESULT: ALL CATEGORIES PASSED")
    else:
        print("RESULT: SOME CATEGORIES FAILED")
    print("=" * 72)

    return all_passed


if __name__ == "__main__":
    passed = run_evals()
    sys.exit(0 if passed else 1)
