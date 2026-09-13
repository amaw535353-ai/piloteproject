#!/usr/bin/env python3
"""Validate a local-only security engagement scope record."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
REQUIRED_TOP_LEVEL = {
    "schema_version",
    "engagement_id",
    "phase",
    "status",
    "traceability",
    "authorization",
    "owners",
    "source_target",
    "targets",
    "allowed_techniques",
    "prohibited_techniques",
    "data_rules",
    "identity_rules",
    "external_network",
    "cost_rules",
    "limits",
    "stop_conditions",
    "evidence_rules",
    "rollback",
    "responsible_disclosure",
}
REQUIRED_POSITIVE_LIMITS = {
    "max_concurrent_requests",
    "max_test_duration_seconds",
    "max_file_size_mb",
    "max_tokens_per_request",
    "max_memory_mb",
    "max_storage_mb",
}


def _require_false(section: dict[str, Any], field: str, errors: list[str]) -> None:
    if section.get(field) is not False:
        errors.append(f"{field} must be false")


def validate_scope(record: dict[str, Any]) -> list[str]:
    """Return all validation errors. Return an empty list for a safe record."""
    errors: list[str] = []
    missing = sorted(REQUIRED_TOP_LEVEL - record.keys())
    if missing:
        errors.append(f"missing required fields: {', '.join(missing)}")
        return errors

    source_target = record["source_target"]
    if source_target.get("repository") != "amaw535353-ai/piloteproject":
        errors.append("source_target.repository is not the authorized fork")
    commit = source_target.get("commit", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        errors.append("source_target.commit must be a full lowercase commit SHA")

    targets = record["targets"]
    if not targets:
        errors.append("targets must not be empty")
    for index, target in enumerate(targets):
        endpoint = target.get("endpoint", "")
        hostname = urlparse(endpoint).hostname
        if hostname not in LOOPBACK_HOSTS:
            errors.append(f"targets[{index}].endpoint is not loopback-only")

    network = record["external_network"]
    if network.get("mode") != "deny-by-default":
        errors.append("external_network.mode must be deny-by-default")
    if set(network.get("allowed_hosts", [])) - LOOPBACK_HOSTS:
        errors.append("external_network.allowed_hosts contains a non-loopback host")
    for field in (
        "external_api_calls_allowed",
        "external_connectors_allowed",
        "external_forwarding_proxy_allowed",
    ):
        _require_false(network, field, errors)

    data_rules = record["data_rules"]
    if data_rules.get("synthetic_only") is not True:
        errors.append("data_rules.synthetic_only must be true")
    for field in (
        "real_customer_data_allowed",
        "production_backups_allowed",
        "real_credentials_allowed",
        "real_accounts_allowed",
    ):
        _require_false(data_rules, field, errors)

    cost_rules = record["cost_rules"]
    for field in (
        "billable_resources_allowed",
        "paid_apis_allowed",
        "paid_saas_allowed",
        "credit_card_trials_allowed",
    ):
        _require_false(cost_rules, field, errors)

    limits = record["limits"]
    for field in sorted(REQUIRED_POSITIVE_LIMITS):
        value = limits.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            errors.append(f"limits.{field} must be a positive integer")

    errors.extend(
        f"{field} must not be empty"
        for field in (
            "allowed_techniques",
            "prohibited_techniques",
            "stop_conditions",
            "rollback",
        )
        if not record[field]
    )

    disclosure = record["responsible_disclosure"]
    _require_false(disclosure, "public_issue_for_vulnerabilities_allowed", errors)
    if disclosure.get("sanitize_reproduction_evidence") is not True:
        errors.append("sanitize_reproduction_evidence must be true")

    return errors


def load_scope(path: Path) -> dict[str, Any]:
    """Load one JSON scope record."""
    with path.open(encoding="utf-8") as scope_file:
        value = json.load(scope_file)
    if not isinstance(value, dict):
        raise ValueError("scope record must be a JSON object")
    return value


def main(arguments: list[str]) -> int:
    if len(arguments) != 1:
        print("usage: validate_scope.py PATH", file=sys.stderr)
        return 2

    try:
        record = load_scope(Path(arguments[0]))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"scope validation failed: {error}", file=sys.stderr)
        return 1

    errors = validate_scope(record)
    if errors:
        for error in errors:
            print(f"scope validation failed: {error}", file=sys.stderr)
        return 1

    print("scope validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
