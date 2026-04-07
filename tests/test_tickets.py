"""
Ticket generation tests.
"""

import json
from datetime import datetime

from secpipe.schema import Finding, Severity
from secpipe.tickets import TicketGenerator


class TestTicketGenerator:
    """Tests for remediation ticket generation."""

    def test_build_ticket_from_cloud_triage_finding(self):
        """Should convert a triaged finding into a ticket."""
        finding = Finding(
            detection_name="cloud_security_triage",
            title="[AWS] Public storage bucket on arn:aws:s3:::customer-export-prod",
            description="Public storage bucket detected on a production resource.",
            severity=Severity.CRITICAL,
            first_seen=datetime.now(),
            recommendations=["Block public access immediately."],
            extra={
                "provider": "AWS",
                "resource_id": "arn:aws:s3:::customer-export-prod",
                "issue_type": "Public storage bucket",
                "priority": "P1",
                "owner_team": "data-platform",
                "environment": "production",
            },
        )

        ticket = TicketGenerator().build_ticket(finding)

        assert ticket.provider == "AWS"
        assert ticket.resource_id == "arn:aws:s3:::customer-export-prod"
        assert ticket.issue_type == "Public storage bucket"
        assert ticket.severity == "critical"
        assert ticket.priority == "P1"
        assert ticket.owner_team == "data-platform"
        assert ticket.status == "Open"
        assert "Block public access immediately." == ticket.recommended_action

    def test_build_tickets(self):
        """Should build multiple tickets."""
        findings = [
            Finding(
                detection_name="cloud_security_triage",
                title="Finding 1",
                description="Description 1",
                severity=Severity.HIGH,
                extra={
                    "provider": "Azure",
                    "resource_id": "nsg-prod-01",
                    "issue_type": "SSH open to the internet",
                    "priority": "P2",
                    "owner_team": "network-security",
                    "environment": "production",
                },
            ),
            Finding(
                detection_name="cloud_security_triage",
                title="Finding 2",
                description="Description 2",
                severity=Severity.MEDIUM,
                extra={
                    "provider": "GCP",
                    "resource_id": "svc-build-automation",
                    "issue_type": "Overly broad service account permissions",
                    "priority": "P3",
                    "owner_team": "devops",
                    "environment": "development",
                },
            ),
        ]

        tickets = TicketGenerator().build_tickets(findings)

        assert len(tickets) == 2
        assert tickets[0].priority == "P2"
        assert tickets[1].priority == "P3"

    def test_ticket_to_dict(self):
        """Should serialize tickets cleanly."""
        finding = Finding(
            detection_name="cloud_security_triage",
            title="Finding 1",
            description="Description 1",
            severity=Severity.HIGH,
            extra={
                "provider": "OCI",
                "resource_id": "ocid1.securitylist.oc1.iad.example",
                "issue_type": "RDP exposed publicly",
                "priority": "P2",
                "owner_team": "infrastructure-operations",
                "environment": "production",
            },
        )

        ticket = TicketGenerator().build_ticket(finding)
        data = ticket.to_dict()

        assert data["provider"] == "OCI"
        assert data["issue_type"] == "RDP exposed publicly"
        assert data["status"] == "Open"
        json.dumps(data)
