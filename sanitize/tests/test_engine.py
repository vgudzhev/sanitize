"""Unit tests for the detection engine."""

from __future__ import annotations

import pytest

from sanitize.engine import (
    CHUNK_THRESHOLD,
    CHUNK_TARGET,
    CLEAN_CACHE_MAX,
    Span,
    _chunk_hash,
    _chunk_text,
    detect,
    merge_spans,
)
from sanitize.policy import load_policy


@pytest.fixture()
def policy():
    return load_policy()


# ── merge_spans ──────────────────────────────────────────────────────────


class TestMergeSpans:
    def test_empty(self):
        assert merge_spans([]) == []

    def test_no_overlap(self):
        spans = [
            Span(0, 5, "A", 0.9, "d1"),
            Span(10, 15, "B", 0.8, "d2"),
        ]
        result = merge_spans(spans)
        assert len(result) == 2

    def test_overlap_higher_score_wins(self):
        spans = [
            Span(0, 10, "A", 0.7, "d1"),
            Span(5, 15, "B", 0.9, "d2"),
        ]
        result = merge_spans(spans)
        assert len(result) == 1
        assert result[0].type == "B"
        assert result[0].score == 0.9

    def test_overlap_same_score_wider_wins(self):
        spans = [
            Span(0, 20, "A", 0.9, "d1"),
            Span(5, 15, "B", 0.9, "d2"),
        ]
        result = merge_spans(spans)
        assert len(result) == 1
        assert result[0].type == "A"
        assert result[0].end == 20

    def test_contained_span_wider_keeps_extent(self):
        spans = [
            Span(0, 10, "A", 0.9, "d1"),
            Span(3, 8, "B", 0.5, "d2"),
        ]
        result = merge_spans(spans)
        assert len(result) == 1
        assert result[0].type == "A"

    def test_adjacent_no_merge(self):
        spans = [
            Span(0, 5, "A", 0.9, "d1"),
            Span(5, 10, "B", 0.9, "d2"),
        ]
        result = merge_spans(spans)
        assert len(result) == 2


# ── Detection: secrets ───────────────────────────────────────────────────


class TestSecretDetection:
    def test_aws_access_key(self, policy):
        text = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        spans, _ = detect(text, policy_config=policy)
        types = {s.type for s in spans}
        assert "AWS_ACCESS_KEY" in types
        for s in spans:
            if s.type == "AWS_ACCESS_KEY":
                assert text[s.start : s.end] == "AKIAIOSFODNN7EXAMPLE"

    def test_private_key_block(self, policy):
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AEEk3k2f\n"
            "-----END RSA PRIVATE KEY-----"
        )
        spans, _ = detect(text, policy_config=policy)
        types = {s.type for s in spans}
        assert "PRIVATE_KEY" in types
        for s in spans:
            if s.type == "PRIVATE_KEY":
                assert s.start == 0
                assert s.end == len(text)

    def test_db_connection_url(self, policy):
        text = "DATABASE_URL=postgresql://admin:s3cretP@ss@db.host.com:5432/mydb"
        spans, _ = detect(text, policy_config=policy)
        types = {s.type for s in spans}
        assert "DB_CONNECTION_URL" in types

    def test_generic_password_assignment(self, policy):
        text = "password=MyS3cretPassw0rd!"
        spans, _ = detect(text, policy_config=policy)
        types = {s.type for s in spans}
        assert types & {"GENERIC_SECRET", "PASSWORD"}

    def test_github_token(self, policy):
        text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        spans, _ = detect(text, policy_config=policy)
        types = {s.type for s in spans}
        assert "GITHUB_TOKEN" in types

    def test_jwt(self, policy):
        text = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        spans, _ = detect(text, policy_config=policy)
        types = {s.type for s in spans}
        assert "JWT" in types

    def test_stripe_key(self, policy):
        text = "STRIPE_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc"
        spans, _ = detect(text, policy_config=policy)
        types = {s.type for s in spans}
        assert "STRIPE_KEY" in types

    def test_anthropic_key(self, policy):
        text = "sk-ant-api03-" + "A" * 93 + "AA"
        spans, _ = detect(text, policy_config=policy)
        types = {s.type for s in spans}
        assert "ANTHROPIC_KEY" in types


# ── Detection: PII (Presidio built-in) ───────────────────────────────────


class TestPIIDetection:
    def test_email(self, policy):
        text = "Contact john.doe@company.com for details"
        spans, _ = detect(text, policy_config=policy)
        types = {s.type for s in spans}
        assert "EMAIL_ADDRESS" in types

    def test_phone(self, policy):
        text = "My phone number is +12125551234"
        spans, _ = detect(text, policy_config=policy)
        types = {s.type for s in spans}
        assert "PHONE_NUMBER" in types or "US_PHONE_NUMBER" in types or len(spans) > 0

    def test_credit_card(self, policy):
        text = "Card: 4111 1111 1111 1111"
        spans, _ = detect(text, policy_config=policy)
        types = {s.type for s in spans}
        assert "CREDIT_CARD" in types

    def test_ip_address(self, policy):
        text = "Server at 192.168.1.100"
        spans, _ = detect(text, policy_config=policy)
        types = {s.type for s in spans}
        assert "IP_ADDRESS" in types


# ── Entropy detection ────────────────────────────────────────────────────


class TestEntropyDetection:
    def test_high_entropy_secret(self, policy):
        text = "token=aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7cD9eF1gH"
        spans, _ = detect(text, policy_config=policy)
        found_types = {s.type for s in spans}
        assert "GENERIC_SECRET" in found_types or "HIGH_ENTROPY_SECRET" in found_types


# ── Custom patterns ──────────────────────────────────────────────────────


class TestCustomPatterns:
    def test_custom_pattern(self):
        policy = load_policy()
        policy["custom"] = {
            "patterns": [{"name": "CUSTOMER_ID", "regex": r"CUST-[0-9]{8}"}],
            "literals": [],
        }
        import sanitize.engine
        sanitize.engine._analyzer_cache = {}
        text = "Customer CUST-12345678 placed an order"
        spans, _ = detect(text, policy_config=policy)
        types = {s.type for s in spans}
        assert "CUSTOMER_ID" in types

    def test_custom_literal(self):
        policy = load_policy()
        policy["custom"] = {
            "patterns": [],
            "literals": ["acme-internal.example"],
        }
        import sanitize.engine
        sanitize.engine._analyzer_cache = {}
        text = "Deploy to acme-internal.example server"
        spans, _ = detect(text, policy_config=policy)
        types = {s.type for s in spans}
        assert "CUSTOM_LITERAL" in types


# ── Allow list ───────────────────────────────────────────────────────────


class TestAllowList:
    def test_allowed_ip_not_flagged(self, policy):
        text = "Connect to 127.0.0.1 for local testing"
        spans, _ = detect(text, policy_config=policy)
        for s in spans:
            assert text[s.start : s.end] != "127.0.0.1"

    def test_allowed_domain_not_flagged(self, policy):
        text = "Visit example.com for documentation"
        spans, _ = detect(text, policy_config=policy)
        for s in spans:
            assert "example.com" not in text[s.start : s.end]


# ── Placeholder idempotence ──────────────────────────────────────────────


class TestPlaceholderIdempotence:
    def test_placeholders_not_detected(self, policy):
        text = "The email is [[EMAIL_2]] and key is [[AWS_ACCESS_KEY_1]]"
        spans, _ = detect(text, policy_config=policy)
        assert len(spans) == 0

    def test_placeholder_in_context(self, policy):
        text = "password=[[GENERIC_SECRET_3]] and host=[[IP_1]]"
        spans, _ = detect(text, policy_config=policy)
        for s in spans:
            matched = text[s.start : s.end]
            assert "[[" not in matched


# ── §6 config.yaml fixture (real detector) ──────────────────────────────


class TestConfigYamlDetection:
    """Verify the real engine detects all §6 items in the config.yaml fixture."""

    CONFIG_YAML = (
        "database:\n"
        "  url: postgres://admin:s3cr3tP4ss@db.internal:5432/myapp\n"
        "\n"
        "aws:\n"
        "  access_key_id: AKIAIOSFODNN7EXAMPLE\n"
        "  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "\n"
        "ssl:\n"
        "  private_key: |\n"
        "    -----BEGIN RSA PRIVATE KEY-----\n"
        "    MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB\n"
        "    aFDrBz9vFqU4yBwr3U0M3O4PU18A9sVw7PbUexw7t/IZ8FLqOdZby0O1Nj93v0oG\n"
        "    -----END RSA PRIVATE KEY-----"
    )

    def test_detects_all_items(self, policy):
        spans, _ = detect(self.CONFIG_YAML, policy_config=policy)
        types = {s.type for s in spans}
        assert "DB_CONNECTION_URL" in types
        assert "AWS_ACCESS_KEY" in types
        assert "PRIVATE_KEY" in types

    def test_db_url_span_covers_credentials(self, policy):
        spans, _ = detect(self.CONFIG_YAML, policy_config=policy)
        for s in spans:
            if s.type == "DB_CONNECTION_URL":
                matched = self.CONFIG_YAML[s.start : s.end]
                assert "s3cr3tP4ss" in matched
                assert "db.internal" in matched
                break
        else:
            pytest.fail("DB_CONNECTION_URL span not found")

    def test_private_key_span_covers_full_block(self, policy):
        spans, _ = detect(self.CONFIG_YAML, policy_config=policy)
        for s in spans:
            if s.type == "PRIVATE_KEY":
                matched = self.CONFIG_YAML[s.start : s.end]
                assert "-----BEGIN RSA PRIVATE KEY-----" in matched
                assert "-----END RSA PRIVATE KEY-----" in matched
                break
        else:
            pytest.fail("PRIVATE_KEY span not found")

    def test_aws_secret_key_detected(self, policy):
        spans, _ = detect(self.CONFIG_YAML, policy_config=policy)
        found = False
        for s in spans:
            matched = self.CONFIG_YAML[s.start : s.end]
            if "wJalrXUtnFEMI" in matched:
                found = True
                break
        assert found, "AWS secret access key not covered by any span"


# ── Clean text ───────────────────────────────────────────────────────────


class TestCleanText:
    def test_no_secrets(self, policy):
        text = "The quick brown fox jumps over the lazy dog."
        spans, _ = detect(text, policy_config=policy)
        assert len(spans) == 0

    def test_code_without_secrets(self, policy):
        text = "def hello():\n    print('Hello, world!')\n    return 42"
        spans, _ = detect(text, policy_config=policy)
        assert len(spans) == 0


# ── Chunking + hash cache ──────────────────────────────────────────────


class TestChunkText:
    def test_small_text_single_chunk(self):
        text = "hello\nworld\n"
        chunks = _chunk_text(text)
        assert len(chunks) == 1
        assert chunks[0] == (0, text)

    def test_splits_at_line_boundaries(self):
        lines = [f"line {i}\n" for i in range(500)]
        text = "".join(lines)
        assert len(text) > CHUNK_TARGET
        chunks = _chunk_text(text)
        assert len(chunks) > 1
        for _offset, chunk in chunks:
            assert chunk.endswith("\n") or chunk == chunks[-1][1]

    def test_reassembles_to_original(self):
        lines = [f"line {i}: {'x' * 80}\n" for i in range(100)]
        text = "".join(lines)
        chunks = _chunk_text(text)
        reassembled = "".join(chunk for _, chunk in chunks)
        assert reassembled == text

    def test_offsets_are_correct(self):
        lines = [f"line {i}: {'y' * 60}\n" for i in range(100)]
        text = "".join(lines)
        chunks = _chunk_text(text)
        for offset, chunk in chunks:
            assert text[offset : offset + len(chunk)] == chunk


class TestChunkHash:
    def test_deterministic(self):
        assert _chunk_hash("hello") == _chunk_hash("hello")

    def test_different_input_different_hash(self):
        assert _chunk_hash("hello") != _chunk_hash("world")


class TestChunkedDetection:
    def test_small_text_uses_direct_path(self, policy):
        text = "aws_key = AKIAIOSFODNN7EXAMPLE"
        assert len(text) <= CHUNK_THRESHOLD
        spans, stats = detect(text, policy_config=policy)
        assert len(spans) > 0

    def test_large_text_with_secret_detects_at_correct_offset(self, policy):
        import sanitize.engine
        sanitize.engine._CLEAN_CHUNK_CACHE.clear()
        sanitize.engine._analyzer_cache = {}

        padding = "# This is a harmless comment line\n" * 200
        secret = "password=SuperSecretValue123456\n"
        text = padding + secret + padding
        assert len(text) > CHUNK_THRESHOLD

        spans, stats = detect(text, policy_config=policy)
        found = False
        for s in spans:
            matched = text[s.start : s.end]
            if "SuperSecretValue123456" in matched:
                found = True
                break
        assert found, "Secret in large text not detected with correct offset"

    def test_clean_chunks_are_cached(self, policy):
        import sanitize.engine
        sanitize.engine._CLEAN_CHUNK_CACHE.clear()
        sanitize.engine._analyzer_cache = {}

        # Text passes prefilter (token=) but has no real detections
        clean_text = "# set token= then restart\n" * 200
        assert len(clean_text) > CHUNK_THRESHOLD

        detect(clean_text, policy_config=policy)
        cached_before = len(sanitize.engine._CLEAN_CHUNK_CACHE)
        assert cached_before > 0

    def test_second_call_uses_cache(self, policy):
        import sanitize.engine
        from unittest.mock import patch
        sanitize.engine._CLEAN_CHUNK_CACHE.clear()
        sanitize.engine._analyzer_cache = {}

        clean_text = "# set token= then restart\n" * 200
        assert len(clean_text) > CHUNK_THRESHOLD

        detect(clean_text, policy_config=policy)
        with patch.object(sanitize.engine, "_detect_chunk_fast", wraps=sanitize.engine._detect_chunk_fast) as spy:
            detect(clean_text, policy_config=policy)
            assert spy.call_count == 0, "Cached chunks should skip _detect_chunk_fast"

    def test_private_key_straddling_boundary(self, policy):
        import sanitize.engine
        sanitize.engine._CLEAN_CHUNK_CACHE.clear()
        sanitize.engine._analyzer_cache = {}

        body = "\n".join("A" * 64 for _ in range(60))
        text = "# pad\n" * 200 + f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n"
        assert len(text) > CHUNK_THRESHOLD

        spans, _ = detect(text, policy_config=policy)
        assert any(s.type == "PRIVATE_KEY" for s in spans)

    def test_format_preserving_fakes_not_redetected(self, policy):
        fakes = [
            "email: user1@redacted.example",
            "Server at 10.0.0.1",
            "call 555-000-0001",
            "card 4000-0000-0000-0001",
            "host1.redacted.internal",
            "https://redacted.example/path/1",
        ]
        for text in fakes:
            spans, _ = detect(text, policy_config=policy)
            assert len(spans) == 0, f"Format-preserving fake re-detected in: {text}"

    def test_policy_change_invalidates_cache(self):
        import sanitize.engine
        from unittest.mock import patch
        sanitize.engine._CLEAN_CHUNK_CACHE.clear()
        sanitize.engine._analyzer_cache = {}

        policy_a = load_policy()
        clean_text = "# set token= then restart\n" * 200
        detect(clean_text, policy_config=policy_a)
        cached_a = len(sanitize.engine._CLEAN_CHUNK_CACHE)
        assert cached_a > 0

        # Same text, different policy — cache should not be reused
        policy_b = load_policy()
        policy_b["extra_flag"] = True
        sanitize.engine._analyzer_cache = {}
        with patch.object(sanitize.engine, "_detect_chunk_fast", wraps=sanitize.engine._detect_chunk_fast) as spy:
            detect(clean_text, policy_config=policy_b)
            assert spy.call_count > 0, "Different policy should not reuse cached chunks"

    def test_prefilter_skips_clean_chunks(self, policy):
        import sanitize.engine
        from unittest.mock import patch
        sanitize.engine._CLEAN_CHUNK_CACHE.clear()
        sanitize.engine._analyzer_cache = {}

        clean_text = "# just a plain code comment\n" * 500
        assert len(clean_text) > CHUNK_THRESHOLD

        with patch.object(sanitize.engine, "_detect_chunk_fast", wraps=sanitize.engine._detect_chunk_fast) as spy:
            spans, _ = detect(clean_text, policy_config=policy)
            assert spy.call_count == 0, "Chunks with no PII/secret indicators should be skipped"
            assert len(spans) == 0
