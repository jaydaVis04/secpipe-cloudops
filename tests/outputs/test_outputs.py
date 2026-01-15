"""
Output Tests

Tests for output/export functionality.
"""

import pytest
import json
import sqlite3
from pathlib import Path

from secpipe.outputs import (
    OutputRegistry,
    JSONLOutput,
    SQLiteOutput,
    MarkdownOutput,
)
from secpipe.schema import Finding, Severity


class TestOutputRegistry:
    """Tests for output registry."""
    
    def test_list_outputs(self):
        """Should list all registered outputs."""
        outputs = OutputRegistry.list_outputs()
        assert "jsonl" in outputs
        assert "sqlite" in outputs
        assert "markdown" in outputs
        assert "webhook" in outputs
    
    def test_create_output(self):
        """Should create output by name."""
        output = OutputRegistry.create("jsonl", {"path": "test.jsonl"})
        assert isinstance(output, JSONLOutput)


class TestJSONLOutput:
    """Tests for JSONL output."""
    
    def test_write_findings(self, tmp_path, sample_findings):
        """Should write findings to JSONL file."""
        output_path = tmp_path / "findings.jsonl"
        output = JSONLOutput({"path": str(output_path)})
        
        output.write(sample_findings)
        
        assert output_path.exists()
        
        # Verify content
        lines = output_path.read_text().strip().split("\n")
        assert len(lines) == 2
        
        data = json.loads(lines[0])
        assert data["detection_name"] == "brute_force_ssh"
        assert data["severity"] == "high"
        assert "_exported_at" in data
    
    def test_append_mode(self, tmp_path, sample_findings):
        """Should append to existing file in append mode."""
        output_path = tmp_path / "findings.jsonl"
        
        # First write
        output = JSONLOutput({"path": str(output_path), "append": False})
        output.write(sample_findings[:1])
        
        # Second write in append mode
        output = JSONLOutput({"path": str(output_path), "append": True})
        output.write(sample_findings[1:])
        
        lines = output_path.read_text().strip().split("\n")
        assert len(lines) == 2


class TestSQLiteOutput:
    """Tests for SQLite output."""
    
    def test_write_findings(self, tmp_path, sample_findings):
        """Should write findings to SQLite database."""
        output_path = tmp_path / "findings.db"
        output = SQLiteOutput({"path": str(output_path)})
        
        output.write(sample_findings)
        
        assert output_path.exists()
        
        # Verify content
        conn = sqlite3.connect(str(output_path))
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM findings")
        count = cursor.fetchone()[0]
        conn.close()
        
        assert count == 2
    
    def test_query_findings(self, tmp_path, sample_findings):
        """Should support querying findings."""
        output_path = tmp_path / "findings.db"
        output = SQLiteOutput({"path": str(output_path)})
        output.write(sample_findings)
        
        results = output.query(
            "SELECT * FROM findings WHERE severity = ?",
            ("high",)
        )
        
        assert len(results) == 1
        assert results[0]["detection_name"] == "brute_force_ssh"
    
    def test_get_summary(self, tmp_path, sample_findings):
        """Should generate summary statistics."""
        output_path = tmp_path / "findings.db"
        output = SQLiteOutput({"path": str(output_path)})
        output.write(sample_findings)
        
        summary = output.get_summary()
        
        assert summary["total_findings"] == 2
        assert "high" in summary["by_severity"]
        assert summary["by_severity"]["high"] == 1
    
    def test_upsert_findings(self, tmp_path, sample_findings):
        """Should update existing findings on re-write."""
        output_path = tmp_path / "findings.db"
        output = SQLiteOutput({"path": str(output_path)})
        
        # Write twice
        output.write(sample_findings)
        output.write(sample_findings)
        
        # Should still have only 2 findings (not 4)
        summary = output.get_summary()
        assert summary["total_findings"] == 2


class TestMarkdownOutput:
    """Tests for Markdown report output."""
    
    def test_write_report(self, tmp_path, sample_findings):
        """Should write Markdown report."""
        output_path = tmp_path / "findings.md"
        output = MarkdownOutput({"path": str(output_path)})
        
        output.write(sample_findings)
        
        assert output_path.exists()
        
        content = output_path.read_text()
        assert "# Security Findings Report" in content
        assert "Executive Summary" in content
        assert "HIGH" in content
        assert "brute_force_ssh" in content
    
    def test_severity_sections(self, tmp_path, sample_findings):
        """Should organize findings by severity."""
        output_path = tmp_path / "findings.md"
        output = MarkdownOutput({"path": str(output_path)})
        
        output.write(sample_findings)
        
        content = output_path.read_text()
        assert "HIGH Severity" in content
        assert "MEDIUM Severity" in content
    
    def test_mitre_attack_links(self, tmp_path, sample_findings):
        """Should include MITRE ATT&CK links."""
        output_path = tmp_path / "findings.md"
        output = MarkdownOutput({"path": str(output_path)})
        
        output.write(sample_findings)
        
        content = output_path.read_text()
        assert "attack.mitre.org" in content
        assert "T1110" in content
    
    def test_empty_findings(self, tmp_path):
        """Should handle empty findings list."""
        output_path = tmp_path / "findings.md"
        output = MarkdownOutput({"path": str(output_path)})
        
        output.write([])
        
        content = output_path.read_text()
        assert "No security findings detected" in content
    
    def test_evidence_samples(self, tmp_path):
        """Should include evidence samples when enabled."""
        finding = Finding(
            detection_name="test",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            raw_samples=["raw log line 1", "raw log line 2"],
        )
        
        output_path = tmp_path / "findings.md"
        output = MarkdownOutput({
            "path": str(output_path),
            "include_evidence": True,
        })
        
        output.write([finding])
        
        content = output_path.read_text()
        assert "Evidence Samples" in content
        assert "raw log line 1" in content


class TestWebhookOutput:
    """Tests for webhook output."""
    
    def test_requires_url(self, sample_findings):
        """Should require URL configuration."""
        from secpipe.outputs.webhook import WebhookOutput
        
        output = WebhookOutput({})  # No URL
        
        with pytest.raises(ValueError, match="Webhook URL not configured"):
            output.write(sample_findings)
    
    def test_format_slack_batch(self, sample_findings):
        """Should format Slack-style payload."""
        from secpipe.outputs.webhook import WebhookOutput
        
        output = WebhookOutput({"format": "slack"})
        payload = output._format_slack_batch(sample_findings)
        
        assert "blocks" in payload
        assert any("SecPipe" in str(b) for b in payload["blocks"])
    
    def test_format_generic_batch(self, sample_findings):
        """Should format generic JSON payload."""
        from secpipe.outputs.webhook import WebhookOutput
        
        output = WebhookOutput({"format": "generic"})
        payload = output._format_generic_batch(sample_findings)
        
        assert payload["source"] == "secpipe"
        assert payload["finding_count"] == 2
        assert len(payload["findings"]) == 2
