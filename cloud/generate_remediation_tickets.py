import json
from pathlib import Path

INPUT_FILE = Path("cloud_discovery.json")
OUTPUT_FILE = Path("../output/remediation_tickets.json")

PRIORITY_MAP = {
    "Critical": "P1",
    "High": "P2",
    "Medium": "P3",
    "Low": "P4"
}

def load_findings():
    with INPUT_FILE.open("r") as f:
        return json.load(f)

def build_ticket(finding):
    severity = finding["severity"]
    priority = PRIORITY_MAP.get(severity, "P4")

    return {
        "title": f"[{finding['provider']}] {finding['issue_type']} on {finding['resource_id']}",
        "provider": finding["provider"],
        "resource_id": finding["resource_id"],
        "resource_type": finding["resource_type"],
        "issue_type": finding["issue_type"],
        "severity": severity,
        "priority": priority,
        "owner_team": finding["owner_team"],
        "environment": finding["environment"],
        "description": finding["details"],
        "recommended_action": finding["recommended_action"],
        "status": "Open",
        "escalation_path": f"Route to {finding['owner_team']} and track to remediation closure"
    }

def main():
    findings = load_findings()
    tickets = [build_ticket(f) for f in findings]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("w") as f:
        json.dump(tickets, f, indent=2)

    print(f"Generated {len(tickets)} remediation tickets at {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
