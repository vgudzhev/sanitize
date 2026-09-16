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
            "labels": [
                "person",
                "address",
                "organization",
                "internal hostname",
                "project codename",
            ],
            "threshold": 0.85,
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
}


def _deep_merge(base: dict, override: dict) -> dict:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        elif key in merged and isinstance(merged[key], list) and isinstance(value, list):
            merged[key] = merged[key] + value
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def load_policy(project_dir: str | Path | None = None) -> dict:
    config = copy.deepcopy(DEFAULTS)

    global_path = Path.home() / ".pi" / "agent" / "sanitize.yaml"
    if global_path.is_file():
        try:
            with open(global_path) as f:
                user_config = yaml.safe_load(f) or {}
            config = _deep_merge(config, user_config)
        except Exception:
            log.warning("Failed to load global sanitize.yaml at %s", global_path, exc_info=True)

    if project_dir:
        project_path = Path(project_dir) / ".pi" / "sanitize.yaml"
        if project_path.is_file():
            try:
                with open(project_path) as f:
                    proj_config = yaml.safe_load(f) or {}
                config = _deep_merge(config, proj_config)
            except Exception:
                log.warning("Failed to load project sanitize.yaml at %s", project_path, exc_info=True)

    return config
