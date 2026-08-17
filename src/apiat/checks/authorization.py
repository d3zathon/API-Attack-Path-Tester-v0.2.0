from apiat.models.schema import Endpoint, Finding, Observation, Role
from apiat.core.verify import is_denied, materially_different, AUTH_DENY

class AuthorizationChecks:
    def __init__(self, client, endpoints, roles, seed_values):
        self.client, self.endpoints, self.roles, self.seed = client, endpoints, roles, seed_values
        self.n = 0

    def _id(self, kind: str):
        self.n += 1
        return f"AAPT-{self.n:04d}-{kind.upper()}"

    def _path_values(self, endpoint: Endpoint):
        return {p.get("name"): self.seed.get(p.get("name"), 1) for p in endpoint.parameters if p.get("in") == "path"}

    def _body(self, endpoint: Endpoint):
        schema = ((endpoint.request_body or {}).get("content") or {}).get("application/json", {}).get("schema", {})
        props = schema.get("properties", {})
        return {name: self.seed.get(name, self._example(prop)) for name, prop in props.items() if name != "id"}

    @staticmethod
    def _example(prop):
        t = prop.get("type")
        return 999999 if t in {"integer", "number"} else (True if t == "boolean" else "aapt-test")

    def run(self):
        findings = []
        for ep in self.endpoints:
            if not any(p.get("in") == "path" for p in ep.parameters) and not ep.parameters and not ep.request_body:
                # Still useful for function-level matrix testing.
                pass
            obs = {r.name: self.client.request(r, ep.method, ep.path, path_values=self._path_values(ep), json_body=self._body(ep)) for r in self.roles}
            # Broken function-level authorization: lower role can reach an endpoint a higher role reaches,
            # while nearby privileged routes are denied to the lower role.
            if len(self.roles) >= 2:
                low, high = self.roles[0], self.roles[-1]
                lo, hi = obs[low.name], obs[high.name]
                if not is_denied(hi) and not is_denied(lo) and materially_different(lo, hi):
                    findings.append(Finding(
                        self._id("bfla"), "BFLA", "Possible broken function-level authorization", "high", "high",
                        f"{ep.method} {ep.path}", low.name, high.name,
                        "A lower-privilege identity received a materially different successful response on an operation exercised by a higher-privilege identity.",
                        {"low_role": lo.status, "high_role": hi.status, "low_body": lo.body, "high_body": hi.body},
                        impact=["Lower-privilege users may access privileged functionality."],
                        remediation=["Enforce authorization on the server for every operation, not only at the UI/router layer."],
                    ))
            # IDOR/BOLA verification: substitute known object identifiers against the same role.
            for p in [p for p in ep.parameters if p.get("in") == "path" and p.get("name") in {"id", "user_id", "account_id", "order_id", "document_id", "project_id"}]:
                values = [self.seed.get(p["name"], 1), self.seed.get(f"other_{p['name']}", 2)]
                if values[0] == values[1]:
                    continue
                role = self.roles[0]
                own = self.client.request(role, ep.method, ep.path, path_values={p["name"]: values[0]})
                other = self.client.request(role, ep.method, ep.path, path_values={p["name"]: values[1]})
                if other.status not in AUTH_DENY and other.status == own.status and materially_different(other, own):
                    findings.append(Finding(
                        self._id("bola"), "BOLA", "Broken object-level authorization (BOLA/IDOR)", "high", "high",
                        f"{ep.method} {ep.path}", role.name, None,
                        "Changing the object identifier returned a different object without an authorization denial.",
                        {"parameter": p["name"], "own_status": own.status, "other_status": other.status, "own_body": own.body, "other_body": other.body},
                        impact=["An attacker may read or modify another user's object by changing an identifier."],
                        remediation=["Authorize object ownership or tenant membership on every object access and mutation."],
                    ))
        return findings
