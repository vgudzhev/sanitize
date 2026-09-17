"""Tests for Phase 4: org-mode tightening-only policy merge."""

from __future__ import annotations

import copy

import pytest

from sanitize.policy import DEFAULTS, _deep_merge, _tighten_merge, load_policy


@pytest.fixture()
def central() -> dict:
    return copy.deepcopy(DEFAULTS)


class TestTightenMerge:
    def test_local_cannot_add_to_allow_list(self, central):
        local = {"allow": ["127.0.0.1", "example.com", "evil.com"]}
        result = _tighten_merge(central, local)
        assert "evil.com" not in result["allow"]
        assert "127.0.0.1" in result["allow"]
        assert "example.com" in result["allow"]

    def test_local_can_remove_from_allow_list(self, central):
        local = {"allow": ["127.0.0.1"]}
        result = _tighten_merge(central, local)
        assert "127.0.0.1" in result["allow"]
        assert "example.com" not in result["allow"]

    def test_local_can_add_deny_paths(self, central):
        local = {"deny_paths": ["**/secrets.json"]}
        result = _tighten_merge(central, local)
        assert "**/secrets.json" in result["deny_paths"]
        assert "~/.ssh/**" in result["deny_paths"]

    def test_local_cannot_remove_deny_paths(self, central):
        local = {"deny_paths": []}
        result = _tighten_merge(central, local)
        assert "~/.ssh/**" in result["deny_paths"]

    def test_local_can_lower_gliner_threshold(self, central):
        local = {"detectors": {"gliner": {"threshold": 0.5}}}
        result = _tighten_merge(central, local)
        assert result["detectors"]["gliner"]["threshold"] == 0.5

    def test_local_cannot_raise_gliner_threshold(self, central):
        local = {"detectors": {"gliner": {"threshold": 0.95}}}
        result = _tighten_merge(central, local)
        assert result["detectors"]["gliner"]["threshold"] == 0.5

    def test_local_can_add_gliner_labels(self, central):
        local = {"detectors": {"gliner": {"labels": ["medical condition"]}}}
        result = _tighten_merge(central, local)
        assert "medical condition" in result["detectors"]["gliner"]["labels"]
        assert "person" in result["detectors"]["gliner"]["labels"]

    def test_local_can_add_custom_patterns(self, central):
        local = {"custom": {"patterns": [{"name": "EMPLOYEE_ID", "regex": "EMP-\\d+"}]}}
        result = _tighten_merge(central, local)
        assert len(result["custom"]["patterns"]) == 1
        assert result["custom"]["patterns"][0]["name"] == "EMPLOYEE_ID"

    def test_local_can_add_custom_literals(self, central):
        local = {"custom": {"literals": ["internal.corp"]}}
        result = _tighten_merge(central, local)
        assert "internal.corp" in result["custom"]["literals"]

    def test_fail_open_always_false(self, central):
        local = {"sanitize": {"fail_open": True}}
        result = _tighten_merge(central, local)
        assert result["sanitize"]["fail_open"] is False

    def test_fail_open_false_even_in_central(self):
        central = copy.deepcopy(DEFAULTS)
        central["sanitize"]["fail_open"] = True
        result = _tighten_merge(central, {})
        assert result["sanitize"]["fail_open"] is False

    def test_empty_local_preserves_central(self, central):
        result = _tighten_merge(central, {})
        assert result["deny_paths"] == central["deny_paths"]
        assert result["allow"] == sorted(central["allow"])
        assert result["detectors"]["gliner"]["threshold"] == 0.5


class TestPermissiveMerge:
    """Verify personal mode keeps the old permissive behavior."""

    def test_local_can_add_to_allow_in_personal_mode(self):
        base = copy.deepcopy(DEFAULTS)
        override = {"allow": ["evil.com"]}
        result = _deep_merge(base, override)
        assert "evil.com" in result["allow"]

    def test_local_can_raise_threshold_in_personal_mode(self):
        base = copy.deepcopy(DEFAULTS)
        override = {"detectors": {"gliner": {"threshold": 0.99}}}
        result = _deep_merge(base, override)
        assert result["detectors"]["gliner"]["threshold"] == 0.99


class TestLoadPolicyCentralMode:
    def test_central_policy_used_as_base(self):
        central = copy.deepcopy(DEFAULTS)
        central["deny_paths"].append("**/central-only.txt")
        result = load_policy(central_policy=central)
        assert "**/central-only.txt" in result["deny_paths"]

    def test_central_policy_fail_open_forced_false(self):
        central = copy.deepcopy(DEFAULTS)
        central["sanitize"]["fail_open"] = True
        result = load_policy(central_policy=central)
        assert result["sanitize"]["fail_open"] is False


class TestOrgDefaults:
    def test_defaults_include_org_section(self):
        assert "org" in DEFAULTS
        assert DEFAULTS["org"]["policy_url"] is None
        assert DEFAULTS["org"]["token"] is None
        assert DEFAULTS["org"]["audit_url"] is None
