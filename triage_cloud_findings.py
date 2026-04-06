import json
from pathlib import Path

INPUT_FILE = Path("cloud/cloud_findings.json")

def load_findings():
    with INPUT_FILE.open("r") as f:
        return json.load(f)

def main():
    findings = load_findings()

    print("=== Cloud Security Findings ===")
    for finding in findings:
        print(f"""
Provider: {finding['provider']}
Resource: {finding['resource_id']} ({finding['resource_type']})
Issue: {finding['issue_type']}
Severity: {finding['severity']}
Owner: {finding['owner_team']}
Environment: {finding['environment']}
Details: {finding['details']}
Recommended Action: {finding['recommended_action']}
""")

if __name__ == "__main__":
    main()
