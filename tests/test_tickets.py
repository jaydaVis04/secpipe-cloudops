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
                "resource_type": "S3 Bucket",
                "issue_type": "Public storage bucket",
                "priority": "P1",
                "owner_team": "data-platform",
                "owner_queue": "data-platform-aws",
                "environment": "production",
                "classification": "storage_exposure",
                "service_category": "storage",
            },
        )

        ticket = TicketGenerator().build_ticket(finding)

        assert ticket.provider == "AWS"
        assert ticket.resource_id == "arn:aws:s3:::customer-export-prod"
        assert ticket.resource_type == "S3 Bucket"
        assert ticket.issue_type == "Public storage bucket"
        assert ticket.severity == "critical"
        assert ticket.priority == "P1"
        assert ticket.owner_team == "data-platform"
        assert ticket.owner_queue == "data-platform-aws"
        assert ticket.classification == "storage_exposure"
        assert ticket.service_category == "storage"
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
                    "resource_type": "Network Security Group",
                    "issue_type": "SSH open to the internet",
                    "priority": "P2",
                    "owner_team": "network-security",
                    "owner_queue": "network-security-azure",
                    "environment": "production",
                    "classification": "network_exposure",
                    "service_category": "network",
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
                    "resource_type": "Service Account",
                    "issue_type": "Overly broad service account permissions",
                    "priority": "P3",
                    "owner_team": "devops",
                    "owner_queue": "devops-gcp",
                    "environment": "development",
                    "classification": "identity_exposure",
                    "service_category": "identity",
                },
            ),
        ]

        tickets = TicketGenerator().build_tickets(findings)

        assert len(tickets) == 2
        assert tickets[0].priority == "P2"
        assert tickets[1].priority == "P3"
        assert tickets[0].resource_type == "Network Security Group"
        assert tickets[1].owner_queue == "devops-gcp"

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
                "resource_type": "Security List",
                "issue_type": "RDP exposed publicly",
                "priority": "P2",
                "owner_team": "infrastructure-operations",
                "owner_queue": "infrastructure-operations-oci",
                "environment": "production",
                "classification": "network_exposure",
                "service_category": "network",
            },
        )

        ticket = TicketGenerator().build_ticket(finding)
        data = ticket.to_dict()

        assert data["provider"] == "OCI"
        assert data["resource_type"] == "Security List"
        assert data["issue_type"] == "RDP exposed publicly"
        assert data["owner_queue"] == "infrastructure-operations-oci"
        assert data["classification"] == "network_exposure"
        assert data["service_category"] == "network"
        assert data["status"] == "Open"
        json.dumps(data)
