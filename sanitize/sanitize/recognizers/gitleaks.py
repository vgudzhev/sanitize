"""Layer 1: Secret patterns derived from gitleaks rule set.

Hand-written top ~30 patterns covering the critical secret categories.
Full gitleaks.toml has 200+ rules; this covers the high-priority ones for MVP.
"""

from __future__ import annotations

import re

from presidio_analyzer import Pattern, PatternRecognizer


def _pr(
    entity: str,
    patterns: list[tuple[str, str, float]],
    *,
    context: list[str] | None = None,
) -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity=entity,
        patterns=[Pattern(name=n, regex=r, score=s) for n, r, s in patterns],
        context=context or [],
    )


_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [\w ]+ PRIVATE KEY-----[\s\S]*?-----END [\w ]+ PRIVATE KEY-----"
)


class PrivateKeyRecognizer(PatternRecognizer):
    """Detects PEM private key blocks as single spans."""

    def __init__(self) -> None:
        super().__init__(
            supported_entity="PRIVATE_KEY",
            patterns=[Pattern(name="pem_header", regex=r"-----BEGIN [\w ]+ PRIVATE KEY-----", score=0.1)],
        )

    def analyze(self, text: str, entities: list[str], nlp_artifacts=None, regex_flags=None):  # type: ignore[override]
        from presidio_analyzer import RecognizerResult

        results = []
        for m in _PRIVATE_KEY_BLOCK.finditer(text):
            results.append(
                RecognizerResult(
                    entity_type="PRIVATE_KEY",
                    start=m.start(),
                    end=m.end(),
                    score=0.99,
                    analysis_explanation=None,
                    recognition_metadata={
                        RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                        RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
                    },
                )
            )
        return results


def load_gitleaks_recognizers() -> list[PatternRecognizer]:
    return [
        # --- Cloud provider keys (prefix-based, high confidence) ---
        _pr(
            "AWS_ACCESS_KEY",
            [("aws_access_key", r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b", 0.95)],
            context=["aws", "access", "key", "akia", "asia"],
        ),
        _pr(
            "AWS_SECRET_KEY",
            [("aws_secret", r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", 0.90)],
            context=["aws", "secret"],
        ),
        _pr(
            "GCP_API_KEY",
            [("gcp_api_key", r"\bAIza[0-9A-Za-z\-_]{35}\b", 0.95)],
            context=["google", "gcp", "api"],
        ),
        _pr(
            "AZURE_AD_CLIENT_SECRET",
            [("azure_ad", r"(?:^|[\\'\"\x60\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.\-]{31,34})(?:$|[\\'\"\x60\s<),])", 0.90)],
            context=["azure", "client", "secret"],
        ),

        # --- Code platform tokens ---
        _pr(
            "GITHUB_TOKEN",
            [
                ("github_pat", r"\b(ghp_[A-Za-z0-9]{36,255})\b", 0.95),
                ("github_oauth", r"\b(gho_[A-Za-z0-9]{36,255})\b", 0.95),
                ("github_user", r"\b(ghu_[A-Za-z0-9]{36,255})\b", 0.95),
                ("github_server", r"\b(ghs_[A-Za-z0-9]{36,255})\b", 0.95),
                ("github_refresh", r"\b(ghr_[A-Za-z0-9]{36,255})\b", 0.95),
                ("github_fine", r"\b(github_pat_[A-Za-z0-9_]{22,255})\b", 0.95),
            ],
        ),
        _pr(
            "GITLAB_TOKEN",
            [("gitlab_pat", r"\b(glpat-[A-Za-z0-9\-_]{20,})\b", 0.95)],
        ),
        _pr(
            "NPM_TOKEN",
            [("npm_token", r"\b(npm_[A-Za-z0-9]{36,})\b", 0.95)],
        ),
        _pr(
            "PYPI_TOKEN",
            [("pypi_token", r"\b(pypi-[A-Za-z0-9\-_]{50,})\b", 0.95)],
        ),

        # --- Communication / SaaS ---
        _pr(
            "SLACK_TOKEN",
            [
                ("slack_bot", r"\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,})\b", 0.95),
                ("slack_user", r"\b(xoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,})\b", 0.95),
                ("slack_app", r"\b(xapp-[0-9]-[A-Z0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{60,})\b", 0.95),
            ],
        ),
        _pr(
            "TELEGRAM_BOT_TOKEN",
            [("telegram", r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}", 0.85)],
        ),

        # --- Payment ---
        _pr(
            "STRIPE_KEY",
            [
                ("stripe_live", r"\b(sk_live_[A-Za-z0-9]{24,})\b", 0.95),
                ("stripe_test", r"\b(sk_test_[A-Za-z0-9]{24,})\b", 0.90),
                ("stripe_restricted", r"\b(rk_live_[A-Za-z0-9]{24,})\b", 0.95),
            ],
        ),

        # --- AI provider keys ---
        _pr(
            "OPENAI_KEY",
            [("openai", r"\b(sk-[a-zA-Z0-9]{20,})\b", 0.85)],
            context=["openai", "api", "key"],
        ),
        _pr(
            "ANTHROPIC_KEY",
            [
                ("anthropic_api", r"\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)\b", 0.95),
                ("anthropic_admin", r"\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)\b", 0.95),
            ],
        ),

        # --- Infrastructure ---
        _pr(
            "HEROKU_API_KEY",
            [
                ("heroku_assignment", r"(?i)(?:heroku)[\s\w.\-_]{0,25}['\"]?\s*[=:]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?", 0.90),
                ("heroku_netrc", r"(?i)heroku[.\w]*[\s\S]{0,50}?password\s+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", 0.85),
            ],
            context=["heroku"],
        ),
        _pr(
            "SENDGRID_KEY",
            [("sendgrid", r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b", 0.95)],
        ),
        _pr(
            "TWILIO_AUTH_TOKEN",
            [("twilio", r"(?i)(?:twilio)(?:[\s\w.\-]{0,20})['\"]?\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?", 0.85)],
            context=["twilio"],
        ),
        _pr(
            "MAILGUN_KEY",
            [("mailgun", r"\b(key-[A-Za-z0-9]{32})\b", 0.90)],
            context=["mailgun"],
        ),
        _pr(
            "DIGITALOCEAN_TOKEN",
            [("digitalocean_pat", r"\b(dop_v1_[a-f0-9]{64})\b", 0.95),
             ("digitalocean_oauth", r"\b(doo_v1_[a-f0-9]{64})\b", 0.95)],
        ),
        _pr(
            "DATADOG_KEY",
            [("datadog_api", r"(?i)(?:datadog)(?:[\s\w.\-]{0,20})['\"]?\s*[=:]\s*['\"]?([a-z0-9]{32,40})['\"]?", 0.85)],
            context=["datadog"],
        ),

        # --- JWT ---
        _pr(
            "JWT",
            [("jwt", r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+", 0.90)],
        ),

        # --- Generic secrets (context-based, lower confidence) ---
        _pr(
            "GENERIC_SECRET",
            [("password_assignment", r"(?i)(?:password|passwd|pwd|token|secret|api_key|apikey|access_key|auth_token|client_secret)\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?", 0.85)],
        ),

        # --- Database connection URLs with credentials ---
        _pr(
            "DB_CONNECTION_URL",
            [("db_url", r"(?i)(?:mysql|postgres|postgresql|mongodb|redis|amqp|mssql)://[^:\s]+:[^@\s]+@[^\s]+", 1.0)],
        ),

        # --- HTTPS/HTTP URLs with embedded credentials ---
        _pr(
            "URL_WITH_CREDENTIALS",
            [("url_creds", r"https?://[^:/\s]+:[^@\s]+@[^\s'\")>]+", 1.0)],
        ),

        # --- US phone numbers (supplement Presidio, higher score to beat DATE_TIME) ---
        _pr(
            "PHONE_NUMBER",
            [
                ("us_phone_parens", r"(?:\+1[\s.-]?)?\(\d{3}\)\s*\d{3}[\s.-]\d{4}", 0.90),
                ("us_phone_dashes", r"(?:\+1[\s.-]?)?\d{3}[\s.-]\d{3}[\s.-]\d{4}", 0.80),
            ],
            context=["phone", "tel", "cell", "mobile", "fax", "call", "contact"],
        ),

        # --- Email (catch-all for non-standard TLDs) ---
        _pr(
            "EMAIL_ADDRESS",
            [("email_catchall", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", 0.60)],
        ),

        # --- PEM certificate / private key blocks ---
        PrivateKeyRecognizer(),
    ]
