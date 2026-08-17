from collections import defaultdict

def build_attack_paths(findings):
    paths=[]
    by_role=defaultdict(list)
    for f in findings:
        by_role[f.source_role].append(f)
    for role, fs in by_role.items():
        ordered=sorted(fs,key=lambda x:(x.severity != "critical", x.severity != "high", x.severity != "medium"))
        for i,f in enumerate(ordered):
            for nxt in ordered[i+1:]:
                if f.kind in {"BOLA","BFLA","PRIVILEGE_ESCALATION","PARAMETER_TAMPERING"} and nxt.kind in {"PRIVILEGE_ESCALATION","BUSINESS_LOGIC","BFLA"}:
                    paths.append({"entry_role":role,"steps":[
                        {"finding_id":f.id,"kind":f.kind,"endpoint":f.endpoint},
                        {"finding_id":nxt.id,"kind":nxt.kind,"endpoint":nxt.endpoint}],
                        "hypothesis":"A confirmed authorization weakness can provide the prerequisite access for the next confirmed operation."})
    # de-duplicate identical 2-step paths
    seen=set(); out=[]
    for p in paths:
        key=tuple(s["finding_id"] for s in p["steps"])
        if key not in seen: seen.add(key); out.append(p)
    return out
