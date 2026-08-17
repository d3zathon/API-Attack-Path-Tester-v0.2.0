import json
from pathlib import Path
import yaml
from apiat.models.schema import Endpoint

METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}

def load_spec(path: str) -> dict:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    return json.loads(text) if p.suffix.lower() == ".json" else yaml.safe_load(text)

def _resolve_local(spec: dict, obj):
    if isinstance(obj, dict) and "$ref" in obj and obj["$ref"].startswith("#/"):
        cur = spec
        for part in obj["$ref"][2:].split("/"):
            cur = cur[part]
        return cur
    return obj

def enumerate_endpoints(spec: dict) -> list[Endpoint]:
    endpoints = []
    for path, path_item in spec.get("paths", {}).items():
        common_params = path_item.get("parameters", [])
        for method, op in path_item.items():
            if method.lower() not in METHODS or not isinstance(op, dict):
                continue
            params = [_resolve_local(spec, p) for p in common_params + op.get("parameters", [])]
            endpoints.append(Endpoint(
                method=method.upper(), path=path,
                operation_id=op.get("operationId", f"{method}_{path}"),
                parameters=params,
                request_body=_resolve_local(spec, op.get("requestBody")) if op.get("requestBody") else None,
                tags=op.get("tags", []),
            ))
    return endpoints
