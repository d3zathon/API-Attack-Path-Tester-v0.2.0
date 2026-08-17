from apiat.models.schema import Finding
from apiat.core.verify import is_denied

class WorkflowChecks:
    def __init__(self, client, endpoints, role): self.client,self.endpoints,self.role,self.n=client,endpoints,role,0
    def _id(self): self.n+=1; return f"AAPT-{self.n:04d}-WF"
    def run(self):
        findings=[]
        names={e.operation_id.lower():e for e in self.endpoints}
        sequences=[]
        for trigger, skip in (("approve", "create"),("complete","start"),("ship","pay"),("refund","pay"),("publish","create")):
            a=next((e for k,e in names.items() if trigger in k),None)
            b=next((e for k,e in names.items() if skip in k),None)
            if a and not b: continue
            if a:
                o=self.client.request(self.role,a.method,a.path)
                if not is_denied(o) and o.status < 400:
                    sequences.append((a,trigger,skip,o.status,o.body))
        for e,trigger,skip,status,body in sequences:
            findings.append(Finding(self._id(),"BUSINESS_LOGIC",f"Workflow step '{trigger}' may be callable out of order","medium","low",
                f"{e.method} {e.path}",self.role.name,None,
                "A workflow-sensitive operation succeeded without evidence that its prerequisite state was established.",
                {"trigger":trigger,"expected_prerequisite":skip,"status":status,"response":body},
                impact=["Attackers may skip business workflow controls or reach invalid states."],
                remediation=["Validate server-side state transitions and prerequisite conditions for each workflow action." ]))
        return findings
