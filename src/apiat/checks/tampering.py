from copy import deepcopy
from apiat.models.schema import Finding
from apiat.core.verify import is_denied, materially_different

class ParameterTamperingChecks:
    def __init__(self, client, endpoints, roles, seed): self.client,self.endpoints,self.roles,self.seed,self.n=client,endpoints,roles,seed,0
    def _id(self): self.n+=1; return f"AAPT-{self.n:04d}-PT"
    def run(self):
        findings=[]
        if not self.roles: return findings
        role=self.roles[0]
        for ep in self.endpoints:
            schema=((ep.request_body or {}).get("content") or {}).get("application/json", {}).get("schema", {})
            for name, prop in schema.get("properties", {}).items():
                if name not in {"role","is_admin","admin","owner_id","tenant_id","price","discount","status","approved","permissions"}: continue
                baseline={name:self.seed.get(name, self._x(prop))}
                tampered={name:self.seed.get(f"elevated_{name}", self.seed.get("other_user_id", 2))}
                base=self.client.request(role, ep.method, ep.path, json_body=baseline)
                test=self.client.request(role, ep.method, ep.path, json_body=tampered)
                if not is_denied(test) and test.status < 400 and materially_different(base,test):
                    findings.append(Finding(self._id(), "PARAMETER_TAMPERING", f"Sensitive parameter accepted: {name}", "medium", "medium",
                        f"{ep.method} {ep.path}", role.name, None,
                        "A security-sensitive parameter changed server behavior without being rejected or normalized.",
                        {"parameter":name,"baseline":base.body,"tampered":test.body,"baseline_status":base.status,"tampered_status":test.status},
                        impact=["Client-controlled authorization or workflow fields may be trusted by the server."],
                        remediation=["Derive privilege-sensitive fields from server-side identity and state; reject forbidden client overrides."]))
        return findings
    def _x(self,p): return True if p.get("type")=="boolean" else (0 if p.get("type") in {"integer","number"} else "admin")
