from dataclasses import dataclass, field
from typing import Any


@dataclass
class Role:
    name: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Endpoint:
    method: str
    path: str
    operation_id: str = ""
    parameters: list[dict[str, Any]] = field(default_factory=list)
    request_body: dict[str, Any] | None = None
    tags: list[str] = field(default_factory=list)


@dataclass
class Observation:
    status: int
    headers: dict[str, str]
    body: Any
    elapsed_ms: float


@dataclass
class Finding:
    id: str
    kind: str
    title: str
    severity: str
    confidence: str
    endpoint: str
    source_role: str
    target_role: str | None
    summary: str
    evidence: dict[str, Any]
    prerequisites: list[str] = field(default_factory=list)
    impact: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    verified: bool = True


@dataclass
class ScanResult:
    target: str
    findings: list[Finding]
    attack_paths: list[dict[str, Any]]
    scanned_endpoints: int
    requests_sent: int
