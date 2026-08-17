from apiat.models.schema import Finding
from apiat.core.verify import is_denied

class EscalationChecks:
    def __init__(self, client, endpoints, roles):
        self.client, self.endpoints, self.roles = client, endpoints, roles
        self.n = 0
    def _id(self):
        self.n += 1; return f"AAPT-{self.n:04d}-PE"
    def run(self):
        findings=[]
        if len(self.roles)<2: return findings
        low, high = self.roles[0], self.roles[-1]
        for ep in self.endpoints:
            low_o = self.client.request(low, ep.method, ep.path)
            high_o = self.client.request(high, ep.method, ep.path)
            if not is_denied(high_o) and not is_denied(low_o) and low_o.status == high_o.status and low_o.status < 400:
                if any(x in ep.path.lower() for x in ("admin", "manage", "role", "permission", "billing", "user")):
                    findings.append(Finding(self._id(), "PRIVILEGE_ESCALATION", "Potential vertical privilege escalation", "high", "medium",
                        f"{ep.method} {ep.path}", low.name, high.name,
                        "A lower-privilege role reached an operation whose path suggests elevated administrative capability.",
                        {"low_status": low_o.status, "high_status": high_o.status, "response": low_o.body},
                        prerequisites=["Authenticated low-privilege account"], impact=["Privilege boundaries may be bypassed."],
                        remediation=["Use explicit server-side permission checks tied to the authenticated principal."]))
        return findings
