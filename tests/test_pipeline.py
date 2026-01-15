"""
Pipeline Integration Tests

End-to-end tests for the full pipeline.
"""

import pytest
from pathlib import Path

from secpipe import Pipeline, Event, Finding, Severity
from secpipe.parsers import ParserRegistry
from secpipe.detections import DetectionRegistry


class TestPipeline:
    """Integration tests for Pipeline class."""
    
    def test_ingest_file(self, temp_log_file):
        """Should ingest log file and create events."""
        pipeline = Pipeline()
        count = pipeline.ingest("auth", temp_log_file)
        
        assert count == 8
        assert len(pipeline.events) == 8
    
    def test_ingest_lines(self, sample_auth_log_lines):
        """Should ingest log lines."""
        pipeline = Pipeline()
        count = pipeline.ingest_lines("auth", sample_auth_log_lines)
        
        assert count == 8
    
    def test_detect_after_ingest(self, temp_log_file):
        """Should run detections after ingesting."""
        pipeline = Pipeline()
        pipeline.ingest("auth", temp_log_file)
        
        findings = pipeline.detect()
        
        assert isinstance(findings, list)
        # Should detect the brute force in sample data
        assert len(findings) >= 1
    
    def test_from_config_file(self, temp_config_file, tmp_path):
        """Should load pipeline from config file."""
        pipeline = Pipeline.from_config_file(temp_config_file)
        findings = pipeline.run()
        
        assert isinstance(findings, list)
        
        # Check outputs were created
        assert (tmp_path / "findings.jsonl").exists()
        assert (tmp_path / "findings.md").exists()
    
    def test_get_summary(self, temp_log_file):
        """Should generate execution summary."""
        pipeline = Pipeline()
        pipeline.ingest("auth", temp_log_file)
        pipeline.detect()
        
        summary = pipeline.get_summary()
        
        assert "events_ingested" in summary
        assert "findings_count" in summary
        assert summary["events_ingested"] == 8
    
    def test_clear_state(self, temp_log_file):
        """Should clear events and findings."""
        pipeline = Pipeline()
        pipeline.ingest("auth", temp_log_file)
        pipeline.detect()
        
        assert len(pipeline.events) > 0
        assert len(pipeline.findings) >= 0
        
        pipeline.clear()
        
        assert len(pipeline.events) == 0
        assert len(pipeline.findings) == 0
    
    def test_multiple_sources(self, tmp_path, sample_auth_log_lines, sample_nginx_log_lines):
        """Should ingest from multiple sources."""
        # Create log files
        auth_log = tmp_path / "auth.log"
        auth_log.write_text("\n".join(sample_auth_log_lines))
        
        nginx_log = tmp_path / "access.log"
        nginx_log.write_text("\n".join(sample_nginx_log_lines))
        
        pipeline = Pipeline()
        count1 = pipeline.ingest("auth", auth_log)
        count2 = pipeline.ingest("nginx", nginx_log)
        
        assert count1 == 8
        assert count2 == 12
        assert len(pipeline.events) == 20
    
    def test_detection_configuration(self, temp_log_file):
        """Should respect detection configuration."""
        config = {
            "detections": {
                "enabled": ["brute_force_ssh"],  # Only this detection
                "min_severity": "high",
            }
        }
        
        pipeline = Pipeline(config)
        pipeline.ingest("auth", temp_log_file)
        findings = pipeline.detect()
        
        # Should only have brute_force_ssh findings
        for finding in findings:
            assert finding.detection_name == "brute_force_ssh"
            assert finding.severity >= Severity.HIGH


class TestEndToEnd:
    """Full end-to-end scenario tests."""
    
    def test_brute_force_scenario(self, tmp_path):
        """Test detection of SSH brute force attack."""
        # Create realistic brute force log
        log_lines = []
        for i in range(20):
            user = ["admin", "root", "test", "ubuntu"][i % 4]
            log_lines.append(
                f"Jan 15 10:00:{i:02d} server sshd[1234]: "
                f"Failed password for invalid user {user} "
                f"from 192.168.1.100 port {50000 + i} ssh2"
            )
        
        log_file = tmp_path / "auth.log"
        log_file.write_text("\n".join(log_lines))
        
        # Run pipeline
        pipeline = Pipeline()
        pipeline.ingest("auth", log_file)
        findings = pipeline.detect()
        
        # Should detect brute force
        brute_force_findings = [
            f for f in findings 
            if f.detection_name == "brute_force_ssh"
        ]
        assert len(brute_force_findings) >= 1
        
        finding = brute_force_findings[0]
        assert finding.source_ip == "192.168.1.100"
        assert finding.severity == Severity.HIGH
        assert finding.mitre_attack_id == "T1110.001"
    
    def test_persistence_scenario(self, tmp_path):
        """Test detection of persistence mechanism."""
        log_lines = [
            "Jan 15 10:00:00 server crontab[1234]: (attacker) BEGIN EDIT",
            "Jan 15 10:00:01 server crontab[1234]: (attacker) REPLACE",
            "Jan 15 10:00:02 server crontab[1234]: (attacker) END EDIT",
        ]
        
        log_file = tmp_path / "auth.log"
        log_file.write_text("\n".join(log_lines))
        
        pipeline = Pipeline()
        pipeline.ingest("auth", log_file)
        findings = pipeline.detect()
        
        # Should detect cron persistence
        cron_findings = [
            f for f in findings
            if f.detection_name == "cron_persistence"
        ]
        assert len(cron_findings) >= 1
    
    def test_full_export_pipeline(self, tmp_path, sample_auth_log_lines):
        """Test full pipeline with all export formats."""
        # Setup
        log_file = tmp_path / "auth.log"
        log_file.write_text("\n".join(sample_auth_log_lines))
        
        config = {
            "sources": [
                {"type": "auth", "path": str(log_file)},
            ],
            "outputs": [
                {"type": "jsonl", "path": str(tmp_path / "findings.jsonl")},
                {"type": "sqlite", "path": str(tmp_path / "findings.db")},
                {"type": "markdown", "path": str(tmp_path / "report.md")},
            ],
        }
        
        pipeline = Pipeline(config)
        findings = pipeline.run()
        
        # Verify all outputs created
        assert (tmp_path / "findings.jsonl").exists()
        assert (tmp_path / "findings.db").exists()
        assert (tmp_path / "report.md").exists()
        
        # Verify markdown report content
        report_content = (tmp_path / "report.md").read_text()
        assert "Security Findings Report" in report_content
