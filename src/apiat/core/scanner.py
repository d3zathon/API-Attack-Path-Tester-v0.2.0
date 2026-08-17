from __future__ import annotations

from pathlib import Path

import yaml

from apiat.checks.authorization import AuthorizationChecks
from apiat.checks.escalation import EscalationChecks
from apiat.checks.tampering import ParameterTamperingChecks
from apiat.checks.workflow import WorkflowChecks
from apiat.core.attack_paths import build_attack_paths
from apiat.core.http import HttpClient
from apiat.core.openapi import enumerate_endpoints, load_spec
from apiat.models.schema import Role, ScanResult


def load_roles(path: str) -> list[Role]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    roles = []
    for item in data.get("roles", []):
        if not item.get("name"):
            raise ValueError("Each role must have a name")
        headers = {str(k): str(v) for k, v in (item.get("headers") or {}).items()}
        roles.append(Role(name=str(item["name"]), headers=headers))
    if not roles:
        raise ValueError("No roles were found in the roles file")
    return roles


def load_seed(path: str | None) -> dict:
    if not path:
        return {}
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return data.get("seed", {})


def scan(spec_path, roles_path, base_url, seed_path=None, timeout=10, verify_tls=True):
    spec = load_spec(spec_path)
    endpoints = enumerate_endpoints(spec)
    if not endpoints:
        raise ValueError("The OpenAPI document contains no supported endpoints under `paths`.")
    roles = load_roles(roles_path)
    seed = load_seed(seed_path)
    client = HttpClient(base_url, timeout, verify_tls)
    try:
        findings = []
        findings += AuthorizationChecks(client, endpoints, roles, seed).run()
        findings += EscalationChecks(client, endpoints, roles).run()
        findings += ParameterTamperingChecks(client, endpoints, roles, seed).run()
        if roles:
            findings += WorkflowChecks(client, endpoints, roles[0]).run()
        for index, finding in enumerate(findings, 1):
            suffix = finding.id.rsplit("-", 1)[-1]
            finding.id = f"APIAT-{index:04d}-{suffix}"
        return ScanResult(
            target=base_url,
            findings=findings,
            attack_paths=build_attack_paths(findings),
            scanned_endpoints=len(endpoints),
            requests_sent=client.requests_sent,
        )
    finally:
        client.client.close()
