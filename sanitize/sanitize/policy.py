from __future__ import annotations

import copy
import logging
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

DEFAULTS: dict = {
    "sanitize": {
        "url": "http://127.0.0.1:7411",
        "timeout_ms": 4000,
        "fail_open": False,
    },
    "placeholders": {
        "open": "[[",
        "close": "]]",
        "format_preserving": False,
    },
    "deny_paths": [
        "~/.ssh/**",
        "**/.env*",
        "**/*.pem",
        "**/*.key",
        "**/*.p12",
        "~/.aws/credentials",
        "~/.kube/config",
        "~/.netrc",
        "**/*.ovpn",
        "**/*.tfstate",
    ],
    "detectors": {
        "gliner": {
            "model": "fastino/gliner2-privacy-filter-PII-multi",
            "labels": [
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
            ],
            "threshold": 0.5,
        },
        "llm": {
            "enabled": False,
        },
    },
    "custom": {
        "patterns": [],
        "literals": [],
    },
    "allow": [
        "127.0.0.1",
        "example.com",
    ],
    "org": {
        "policy_url": None,
        "token": None,
        "audit_url": None,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Permissive merge for personal mode — override wins."""
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        elif key in merged and isinstance(merged[key], list) and isinstance(value, list):
            merged[key] = merged[key] + value
        else:
            merged[key] = copy.deepcopy(value)
    return merged


# Threshold fields where LOWER = tighter (more detection)
_THRESHOLD_FIELDS = {
    ("detectors", "gliner", "threshold"),
    ("detectors", "entropy", "threshold"),
}


def _tighten_merge(central: dict, local: dict) -> dict:
    """Org-mode merge: local configs can only tighten the central policy.

    - deny_paths, custom.patterns, custom.literals, detectors.gliner.labels: local can ADD
    - allow: local can REMOVE (set difference), never add
    - thresholds: local can LOWER (more detection), never raise
    - fail_open: always False, cannot be overridden
    - everything else: central wins
    """
    merged = copy.deepcopy(central)

    if "deny_paths" in local and isinstance(local["deny_paths"], list):
        existing = set(merged.get("deny_paths", []))
        for p in local["deny_paths"]:
            if p not in existing:
                merged.setdefault("deny_paths", []).append(p)

    custom_local = local.get("custom", {})
    if isinstance(custom_local, dict):
        for list_key in ("patterns", "literals"):
            if list_key in custom_local and isinstance(custom_local[list_key], list):
                merged.setdefault("custom", {}).setdefault(list_key, []).extend(
                    copy.deepcopy(custom_local[list_key])
                )

    gliner_local = local.get("detectors", {}).get("gliner", {})
    if isinstance(gliner_local, dict) and "labels" in gliner_local:
        existing_labels = set(merged.get("detectors", {}).get("gliner", {}).get("labels", []))
        for label in gliner_local["labels"]:
            if label not in existing_labels:
                merged.setdefault("detectors", {}).setdefault("gliner", {}).setdefault("labels", []).append(label)

    if "allow" in local and isinstance(local["allow"], list):
        central_allow = set(merged.get("allow", []))
        local_allow = set(local["allow"])
        merged["allow"] = sorted(central_allow & local_allow)

    for path in _THRESHOLD_FIELDS:
        local_val = local
        central_val = merged
        for key in path[:-1]:
            local_val = local_val.get(key, {}) if isinstance(local_val, dict) else {}
            central_val = central_val.get(key, {}) if isinstance(central_val, dict) else {}
        field = path[-1]
        if isinstance(local_val, dict) and field in local_val:
            lv = local_val[field]
            cv = central_val.get(field) if isinstance(central_val, dict) else None
            if isinstance(lv, (int, float)) and isinstance(cv, (int, float)) and lv < cv:
                target = merged
                for key in path[:-1]:
                    target = target.setdefault(key, {})
                target[field] = lv

    merged.setdefault("sanitize", {})["fail_open"] = False

    return merged


def _load_yaml(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        log.warning("Failed to load %s", path, exc_info=True)
        return None


def load_policy(
    project_dir: str | Path | None = None,
    central_policy: dict | None = None,
) -> dict:
    """Load policy config.

    In personal mode (no central_policy): permissive deep merge.
    In org mode (central_policy provided): tightening-only merge.
    """
    if central_policy is not None:
        config = copy.deepcopy(central_policy)
        config.setdefault("sanitize", {})["fail_open"] = False

        global_yaml = _load_yaml(Path.home() / ".pi" / "agent" / "sanitize.yaml")
        if global_yaml:
            config = _tighten_merge(config, global_yaml)

        if project_dir:
            proj_yaml = _load_yaml(Path(project_dir) / ".pi" / "sanitize.yaml")
            if proj_yaml:
                config = _tighten_merge(config, proj_yaml)

        return config

    config = copy.deepcopy(DEFAULTS)

    global_yaml = _load_yaml(Path.home() / ".pi" / "agent" / "sanitize.yaml")
    if global_yaml:
        config = _deep_merge(config, global_yaml)

    if project_dir:
        proj_yaml = _load_yaml(Path(project_dir) / ".pi" / "sanitize.yaml")
        if proj_yaml:
            config = _deep_merge(config, proj_yaml)

    return config
