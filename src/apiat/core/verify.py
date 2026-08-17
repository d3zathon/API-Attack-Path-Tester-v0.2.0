from collections.abc import Callable
from apiat.models.schema import Observation

AUTH_DENY = {401, 403}

def is_denied(o: Observation) -> bool:
    return o.status in AUTH_DENY

def normalized_body(o: Observation):
    b = o.body
    if isinstance(b, dict):
        return {k: v for k, v in b.items() if k not in {"timestamp", "request_id", "trace_id"}}
    return b

def materially_different(a: Observation, b: Observation) -> bool:
    if a.status != b.status:
        return True
    if isinstance(a.body, dict) and isinstance(b.body, dict):
        return normalized_body(a) != normalized_body(b)
    return normalized_body(a) != normalized_body(b)

def verify(predicate: Callable[[], bool]) -> bool:
    try:
        return bool(predicate())
    except Exception:
        return False
