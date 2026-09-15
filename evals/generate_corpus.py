"""Generate a synthetic eval corpus with planted secrets and PII.

Each item is a realistic log/config snippet with one or more planted sensitive values.
Items are generated independently of the detection rule set to avoid tautological testing.

Output: evals/corpus/ directory with JSON files, one per category.
Each JSON file: list of {text, planted: [{value, type, category_group}]}
"""

from __future__ import annotations

import json
import os
import random
import string

CORPUS_DIR = os.path.join(os.path.dirname(__file__), "corpus")

random.seed(42)


def _rand_hex(n: int) -> str:
    return "".join(random.choices("0123456789abcdef", k=n))


def _rand_alnum(n: int) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def _rand_upper_alnum(n: int) -> str:
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=n))


def _rand_b64(n: int) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits + "+/", k=n))


def _rand_b64url(n: int) -> str:
    """URL-safe base64 (used by JWTs)."""
    return "".join(random.choices(string.ascii_letters + string.digits + "-_", k=n))


# --- Secret generators ---

def gen_aws_access_keys(count: int = 18) -> list[dict]:
    items = []
    prefixes = ["AKIA", "ASIA", "ABIA"]
    templates = [
        "export AWS_ACCESS_KEY_ID={key}",
        "aws_access_key_id = {key}",
        '[default]\naws_access_key_id = {key}\naws_secret_access_key = dummysecret',
        "credentials:\n  access_key: {key}\n  region: us-east-1",
        'os.environ["AWS_ACCESS_KEY_ID"] = "{key}"',
        "AWS_ACCESS_KEY_ID={key} aws s3 ls",
        "config.access_key = '{key}'",
        '# Production AWS credentials\nAWS_KEY={key}',
        'curl -H "X-Amz-Access: {key}" https://api.example.com',
        '{{ "AccessKeyId": "{key}", "Status": "Active" }}',
    ]
    for i in range(count):
        prefix = prefixes[i % len(prefixes)]
        suffix = "".join(random.choices(string.ascii_uppercase + "234567", k=16))
        key = f"{prefix}{suffix}"
        text = templates[i % len(templates)].format(key=key)
        items.append({"text": text, "planted": [{"value": key, "type": "AWS_ACCESS_KEY", "category_group": "secrets"}]})
    return items


def gen_github_tokens(count: int = 12) -> list[dict]:
    items = []
    prefixes = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]
    templates = [
        "GITHUB_TOKEN={token}",
        'git clone https://{token}@github.com/org/repo.git',
        'Authorization: token {token}',
        'export GH_TOKEN="{token}"',
        '  token: {token}\n  host: github.com',
        'curl -H "Authorization: Bearer {token}" https://api.github.com/user',
    ]
    for i in range(count):
        prefix = prefixes[i % len(prefixes)]
        token = f"{prefix}{_rand_alnum(36)}"
        text = templates[i % len(templates)].format(token=token)
        items.append({"text": text, "planted": [{"value": token, "type": "GITHUB_TOKEN", "category_group": "secrets"}]})
    return items


def gen_gitlab_tokens(count: int = 10) -> list[dict]:
    items = []
    templates = [
        "GITLAB_TOKEN=glpat-{rest}",
        'private_token: "glpat-{rest}"',
        '  token = glpat-{rest}\n  url = https://gitlab.example.com',
        "export CI_JOB_TOKEN=glpat-{rest}",
        "PRIVATE-TOKEN: glpat-{rest}",
    ]
    for i in range(count):
        rest = _rand_alnum(20)
        token = f"glpat-{rest}"
        text = templates[i % len(templates)].format(rest=rest)
        items.append({"text": text, "planted": [{"value": token, "type": "GITLAB_TOKEN", "category_group": "secrets"}]})
    return items


def gen_slack_tokens(count: int = 10) -> list[dict]:
    items = []
    prefixes = ["xoxb-", "xoxp-", "xoxa-", "xoxo-"]
    for i in range(count):
        prefix = prefixes[i % len(prefixes)]
        rest = f"{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{_rand_alnum(24)}"
        token = f"{prefix}{rest}"
        templates = [
            f"SLACK_BOT_TOKEN={token}",
            f'slack_token: "{token}"',
            f"export SLACK_TOKEN={token}",
            f'  "token": "{token}",\n  "channel": "#general"',
            f"curl -H 'Authorization: Bearer {token}' https://slack.com/api/chat.postMessage",
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": token, "type": "SLACK_TOKEN", "category_group": "secrets"}]})
    return items


def gen_stripe_keys(count: int = 10) -> list[dict]:
    items = []
    prefixes = ["sk_live_", "rk_live_", "sk_test_"]
    for i in range(count):
        prefix = prefixes[i % len(prefixes)]
        key = f"{prefix}{_rand_alnum(24)}"
        templates = [
            f"STRIPE_SECRET_KEY={key}",
            f'stripe.api_key = "{key}"',
            f"export STRIPE_KEY={key}",
            f'  secret_key: {key}\n  publishable_key: pk_live_example',
            f'Stripe.configure do |config|\n  config.api_key = "{key}"\nend',
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": key, "type": "STRIPE_KEY", "category_group": "secrets"}]})
    return items


def gen_private_keys(count: int = 12) -> list[dict]:
    items = []
    key_types = ["RSA", "EC", "DSA", "OPENSSH", "ED25519"]
    for i in range(count):
        kt = key_types[i % len(key_types)]
        body = "\n".join([_rand_b64(64) for _ in range(4)])
        key_block = f"-----BEGIN {kt} PRIVATE KEY-----\n{body}\n-----END {kt} PRIVATE KEY-----"
        templates = [
            f"# Server key\n{key_block}",
            f"private_key: |\n  {key_block}",
            f"KEY_DATA='{key_block}'",
            f"ssl:\n  key: |\n    {key_block}\n  cert: /etc/ssl/cert.pem",
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": key_block, "type": "PRIVATE_KEY", "category_group": "secrets"}]})
    return items


def gen_jwts(count: int = 12) -> list[dict]:
    items = []
    for i in range(count):
        header = "eyJ" + _rand_b64url(20)
        payload = "eyJ" + _rand_b64url(40)
        sig = _rand_b64url(43)
        jwt = f"{header}.{payload}.{sig}"
        templates = [
            f"Authorization: Bearer {jwt}",
            f'token = "{jwt}"',
            f"JWT_SECRET={jwt}",
            f'curl -H "Authorization: Bearer {jwt}" https://api.example.com/v1/data',
            f"access_token: {jwt}",
            f'{{"token": "{jwt}", "expires_in": 3600}}',
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": jwt, "type": "JWT", "category_group": "secrets"}]})
    return items


def gen_generic_passwords(count: int = 18) -> list[dict]:
    items = []
    keywords = ["password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "access_key", "auth_token"]
    for i in range(count):
        kw = keywords[i % len(keywords)]
        pw = _rand_alnum(random.randint(12, 32))
        templates = [
            f'{kw} = "{pw}"',
            f"{kw}={pw}",
            f'{kw}: "{pw}"',
            f'export {kw.upper()}="{pw}"',
            f"config.{kw} = '{pw}'",
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": pw, "type": "GENERIC_SECRET", "category_group": "secrets"}]})
    return items


def gen_db_connection_urls(count: int = 18) -> list[dict]:
    items = []
    schemes = ["postgres", "postgresql", "mysql", "mongodb", "redis", "amqp", "mssql"]
    for i in range(count):
        scheme = schemes[i % len(schemes)]
        user = f"user{i}"
        pw = _rand_alnum(16)
        host = f"db{i}.internal.example.com"
        port = random.choice([5432, 3306, 27017, 6379, 5672, 1433])
        dbname = f"app_db_{i}"
        url = f"{scheme}://{user}:{pw}@{host}:{port}/{dbname}"
        templates = [
            f"DATABASE_URL={url}",
            f'connection_string: "{url}"',
            f'db_url = "{url}"',
            f"export DB_URL={url}",
            f'spring.datasource.url={url}',
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": url, "type": "DB_CONNECTION_URL", "category_group": "secrets"}]})
    return items


def gen_openai_keys(count: int = 10) -> list[dict]:
    items = []
    for i in range(count):
        key = f"sk-{_rand_alnum(48)}"
        templates = [
            f"OPENAI_API_KEY={key}",
            f'openai.api_key = "{key}"',
            f"export OPENAI_KEY={key}",
            f'  "api_key": "{key}",\n  "model": "gpt-4"',
            f'Authorization: Bearer {key}',
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": key, "type": "OPENAI_KEY", "category_group": "secrets"}]})
    return items


def gen_anthropic_keys(count: int = 8) -> list[dict]:
    items = []
    for i in range(count):
        key = f"sk-ant-api03-{_rand_alnum(93)}AA"
        templates = [
            f"ANTHROPIC_API_KEY={key}",
            f'anthropic_key: "{key}"',
            f"export ANTHROPIC_KEY={key}",
            f'client = Anthropic(api_key="{key}")',
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": key, "type": "ANTHROPIC_KEY", "category_group": "secrets"}]})
    return items


def gen_google_api_keys(count: int = 8) -> list[dict]:
    items = []
    for i in range(count):
        key = f"AIza{_rand_alnum(35)}"
        templates = [
            f"GOOGLE_API_KEY={key}",
            f'api_key: "{key}"',
            f"maps.key = {key}",
            f'<script src="https://maps.googleapis.com/maps/api/js?key={key}"></script>',
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": key, "type": "GOOGLE_API_KEY", "category_group": "secrets"}]})
    return items


def gen_npm_tokens(count: int = 8) -> list[dict]:
    items = []
    for i in range(count):
        token = f"npm_{_rand_alnum(36)}"
        templates = [
            f"//registry.npmjs.org/:_authToken={token}",
            f"NPM_TOKEN={token}",
            f'  "authToken": "{token}"',
            f'export NPM_AUTH_TOKEN="{token}"',
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": token, "type": "NPM_TOKEN", "category_group": "secrets"}]})
    return items


def gen_pypi_tokens(count: int = 8) -> list[dict]:
    items = []
    for i in range(count):
        token = f"pypi-{_rand_alnum(55)}"
        templates = [
            f"TWINE_PASSWORD={token}",
            f'password = "{token}"',
            f"export PYPI_TOKEN={token}",
            f"[pypi]\nusername = __token__\npassword = {token}",
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": token, "type": "PYPI_TOKEN", "category_group": "secrets"}]})
    return items


def gen_heroku_keys(count: int = 8) -> list[dict]:
    items = []
    for i in range(count):
        key = _rand_hex(8) + "-" + _rand_hex(4) + "-" + _rand_hex(4) + "-" + _rand_hex(4) + "-" + _rand_hex(12)
        templates = [
            f"HEROKU_API_KEY={key}",
            f'heroku_api_key: "{key}"',
            f'export HEROKU_KEY="{key}"',
            f'heroku_token: "{key}"',
            f"HEROKU_AUTH_TOKEN={key}",
            f'config.heroku_api_key = "{key}"',
            f"machine api.heroku.com\n  login user@example.com\n  password {key}",
            f"heroku_secret = '{key}'",
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": key, "type": "HEROKU_API_KEY", "category_group": "secrets"}]})
    return items


def gen_sendgrid_keys(count: int = 8) -> list[dict]:
    items = []
    for i in range(count):
        key = f"SG.{_rand_alnum(22)}.{_rand_alnum(43)}"
        templates = [
            f"SENDGRID_API_KEY={key}",
            f'sendgrid_key: "{key}"',
            f"export SENDGRID_KEY={key}",
            f'  api_key = "{key}"',
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": key, "type": "SENDGRID_KEY", "category_group": "secrets"}]})
    return items


def gen_telegram_tokens(count: int = 8) -> list[dict]:
    items = []
    for i in range(count):
        bot_id = str(random.randint(100000000, 9999999999))
        rest = _rand_alnum(35)
        token = f"{bot_id}:{rest}"
        templates = [
            f"TELEGRAM_BOT_TOKEN={token}",
            f'bot_token: "{token}"',
            f"export TELEGRAM_TOKEN={token}",
            f"telegram_token = '{token}'",
            f'  "token": "{token}",\n  "chat_id": "123456"',
            f"BOT_TOKEN={token}",
            f"curl https://api.telegram.org/bot{token}/getUpdates",
            f"export BOT_API_TOKEN={token}",
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": token, "type": "TELEGRAM_BOT_TOKEN", "category_group": "secrets"}]})
    return items


# --- PII generators ---

def gen_emails(count: int = 18) -> list[dict]:
    items = []
    domains = ["gmail.com", "company.io", "example.org", "corp.internal", "yahoo.com", "corp.net"]
    for i in range(count):
        user = f"user.{_rand_alnum(6).lower()}"
        domain = domains[i % len(domains)]
        email = f"{user}@{domain}"
        templates = [
            f"Contact: {email}",
            f"email: {email}",
            f"FROM: {email}\nTO: admin@example.com",
            f'  "email": "{email}",\n  "name": "Test User"',
            f"User {email} logged in at 2024-01-15",
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": email, "type": "EMAIL_ADDRESS", "category_group": "pii"}]})
    return items


def gen_phone_numbers(count: int = 15) -> list[dict]:
    items = []
    for i in range(count):
        area = random.randint(200, 999)
        mid = random.randint(200, 999)
        last = random.randint(1000, 9999)
        formats = [
            f"({area}) {mid}-{last}",
            f"{area}-{mid}-{last}",
            f"+1-{area}-{mid}-{last}",
            f"+1 ({area}) {mid}-{last}",
        ]
        phone = formats[i % len(formats)]
        templates = [
            f"Phone: {phone}",
            f"contact_phone: {phone}",
            f"Call {phone} for support",
            f'  "phone": "{phone}"',
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": phone, "type": "PHONE_NUMBER", "category_group": "pii"}]})
    return items


def gen_credit_cards(count: int = 15) -> list[dict]:
    items = []
    for i in range(count):
        prefixes = ["4", "51", "52", "53"]
        prefix = prefixes[i % len(prefixes)]
        total_len = 16
        remaining = total_len - len(prefix) - 1
        body = "".join([str(random.randint(0, 9)) for _ in range(remaining)])
        partial = prefix + body
        checksum = _luhn_checkdigit(partial)
        formatted_cc = partial + str(checksum)
        templates = [
            f"card_number: {formatted_cc}",
            f"Payment with card ending {formatted_cc[-4:]}\nFull: {formatted_cc}",
            f'  "credit_card": "{formatted_cc}"',
            f"CC: {formatted_cc} Exp: 12/28",
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": formatted_cc, "type": "CREDIT_CARD", "category_group": "pii"}]})
    return items


def _luhn_checkdigit(partial: str) -> int:
    """Compute check digit so partial+checkdigit passes Luhn."""
    digits = [int(d) for d in partial]
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - (total % 10)) % 10


def gen_ip_addresses(count: int = 18) -> list[dict]:
    items = []
    for i in range(count):
        octets = [random.randint(1, 254) for _ in range(4)]
        while octets == [127, 0, 0, 1]:
            octets = [random.randint(1, 254) for _ in range(4)]
        ip = ".".join(map(str, octets))
        templates = [
            f"server_ip: {ip}",
            f"Connected to {ip}:8080",
            f"Denied request from {ip}",
            f"bind_address: {ip}\nport: 443",
            f"Host: {ip}\nUser-Agent: curl/7.68.0",
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": ip, "type": "IP_ADDRESS", "category_group": "pii"}]})
    return items


def _iban_check_digits(country: str, bban: str) -> str:
    """Compute IBAN check digits (ISO 13616)."""
    rearranged = bban + country + "00"
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        else:
            numeric += str(ord(ch.upper()) - ord("A") + 10)
    remainder = int(numeric) % 97
    check = 98 - remainder
    return f"{check:02d}"


def _gen_bban(country: str) -> str:
    """Generate a structurally valid BBAN for the given country."""
    alpha_bban = {
        "GB": lambda: "".join(random.choices(string.ascii_uppercase, k=4)) + "".join(str(random.randint(0, 9)) for _ in range(14)),
        "NL": lambda: "".join(random.choices(string.ascii_uppercase, k=4)) + "".join(str(random.randint(0, 9)) for _ in range(10)),
        "FR": lambda: "".join(str(random.randint(0, 9)) for _ in range(10)) + "".join(random.choices(string.ascii_uppercase + string.digits, k=11)) + "".join(str(random.randint(0, 9)) for _ in range(2)),
        "IT": lambda: random.choice(string.ascii_uppercase) + "".join(str(random.randint(0, 9)) for _ in range(10)) + "".join(random.choices(string.ascii_uppercase + string.digits, k=12)),
        "CH": lambda: "".join(str(random.randint(0, 9)) for _ in range(17)),
    }
    numeric_bban_lengths = {"DE": 18, "ES": 20, "AT": 16, "BE": 12, "PL": 24, "FI": 14, "PT": 21, "SI": 15, "EE": 16, "LT": 16}

    if country in alpha_bban:
        return alpha_bban[country]()
    bban_len = numeric_bban_lengths[country]
    return "".join(str(random.randint(0, 9)) for _ in range(bban_len))


def gen_ibans(count: int = 10) -> list[dict]:
    items = []
    countries = ["DE", "ES", "AT", "BE", "PL", "FI", "PT", "SI", "GB", "NL", "FR", "IT", "CH", "EE", "LT"]
    for i in range(count):
        country = countries[i % len(countries)]
        bban = _gen_bban(country)
        check = _iban_check_digits(country, bban)
        iban = f"{country}{check}{bban}"
        templates = [
            f"IBAN: {iban}",
            f'bank_account: "{iban}"',
            f"Transfer to {iban}",
            f"  iban: {iban}\n  bic: DEUTDEDB",
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": iban, "type": "IBAN_CODE", "category_group": "pii"}]})
    return items


def gen_urls_with_creds(count: int = 10) -> list[dict]:
    items = []
    for i in range(count):
        user = f"admin{i}"
        pw = _rand_alnum(12)
        host = f"service{i}.example.com"
        scheme = "https" if i % 2 == 0 else "http"
        url = f"{scheme}://{user}:{pw}@{host}/api/v1"
        templates = [
            f"API_URL={url}",
            f'endpoint: "{url}"',
            f"export SERVICE_URL={url}",
            f"curl {url}/status",
            f"fetch('{url}/data')",
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": url, "type": "URL_WITH_CREDS", "category_group": "pii"}]})
    return items


def gen_dates_of_birth(count: int = 10) -> list[dict]:
    items = []
    for i in range(count):
        year = random.randint(1950, 2005)
        month = random.randint(1, 12)
        day = random.randint(1, 28)
        formats = [
            f"{month:02d}/{day:02d}/{year}",
            f"{year}-{month:02d}-{day:02d}",
            f"{day:02d}.{month:02d}.{year}",
        ]
        dob = formats[i % len(formats)]
        templates = [
            f"date_of_birth: {dob}",
            f"DOB: {dob}",
            f'  "birthdate": "{dob}",\n  "name": "Test"',
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": dob, "type": "DATE_OF_BIRTH", "category_group": "pii"}]})
    return items


# --- High-entropy (for entropy detector) ---

def gen_high_entropy_secrets(count: int = 18) -> list[dict]:
    items = []
    for i in range(count):
        secret = _rand_alnum(random.randint(24, 48))
        keywords = ["SECRET", "API_KEY", "AUTH_TOKEN", "ACCESS_TOKEN", "PRIVATE_KEY"]
        kw = keywords[i % len(keywords)]
        templates = [
            f"{kw}={secret}",
            f'export {kw}="{secret}"',
            f"  {kw.lower()}: {secret}",
        ]
        text = templates[i % len(templates)]
        items.append({"text": text, "planted": [{"value": secret, "type": "HIGH_ENTROPY_SECRET", "category_group": "secrets"}]})
    return items


# --- Build full corpus ---

GENERATORS = {
    "aws_access_key": gen_aws_access_keys,
    "github_token": gen_github_tokens,
    "gitlab_token": gen_gitlab_tokens,
    "slack_token": gen_slack_tokens,
    "stripe_key": gen_stripe_keys,
    "private_key": gen_private_keys,
    "jwt": gen_jwts,
    "generic_password": gen_generic_passwords,
    "db_connection_url": gen_db_connection_urls,
    "openai_key": gen_openai_keys,
    "anthropic_key": gen_anthropic_keys,
    "google_api_key": gen_google_api_keys,
    "npm_token": gen_npm_tokens,
    "pypi_token": gen_pypi_tokens,
    "heroku_api_key": gen_heroku_keys,
    "sendgrid_key": gen_sendgrid_keys,
    "telegram_bot_token": gen_telegram_tokens,
    "high_entropy_secret": gen_high_entropy_secrets,
    "email_address": gen_emails,
    "phone_number": gen_phone_numbers,
    "credit_card": gen_credit_cards,
    "ip_address": gen_ip_addresses,
    "iban_code": gen_ibans,
    "url_with_creds": gen_urls_with_creds,
    "date_of_birth": gen_dates_of_birth,
}


def generate():
    os.makedirs(CORPUS_DIR, exist_ok=True)
    total = 0
    for name, gen_fn in GENERATORS.items():
        items = gen_fn()
        path = os.path.join(CORPUS_DIR, f"{name}.json")
        with open(path, "w") as f:
            json.dump(items, f, indent=2)
        total += len(items)
        print(f"  {name}: {len(items)} items")
    print(f"\nTotal: {total} planted items across {len(GENERATORS)} categories")
    return total


if __name__ == "__main__":
    generate()
