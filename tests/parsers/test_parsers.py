"""
Parser Tests

Tests for log parsing functionality.
"""

import pytest
from datetime import datetime

from secpipe.parsers import (
    ParserRegistry,
    AuthLogParser,
    CloudFindingsParser,
    JSONEventsParser,
    NginxParser,
)
from secpipe.schema import EventType


class TestParserRegistry:
    """Tests for parser registry."""
    
    def test_list_parsers(self):
        """Should list all registered parsers."""
        parsers = ParserRegistry.list_parsers()
        assert "auth" in parsers
        assert "nginx" in parsers
        assert "json" in parsers
        assert "syslog" in parsers
        assert "cloud" in parsers
    
    def test_create_parser(self):
        """Should create parser by name."""
        parser = ParserRegistry.create("auth")
        assert isinstance(parser, AuthLogParser)
    
    def test_create_unknown_parser(self):
        """Should raise error for unknown parser."""
        with pytest.raises(ValueError, match="Unknown parser"):
            ParserRegistry.create("nonexistent")


class TestAuthLogParser:
    """Tests for auth.log parser."""
    
    def test_parse_ssh_failed(self):
        """Should parse SSH failed password line."""
        parser = AuthLogParser({"year": 2024})
        line = "Jan 15 10:00:01 webserver sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2"
        
        event = parser.parse_line(line)
        
        assert event is not None
        assert event.event_type == EventType.AUTH_FAILURE
        assert event.source_ip == "192.168.1.100"
        assert event.username == "admin"
        assert event.source_port == 54321
        assert event.hostname == "webserver"
        assert event.process_name == "sshd"
        assert event.pid == 12345
    
    def test_parse_ssh_accepted(self):
        """Should parse SSH accepted login line."""
        parser = AuthLogParser({"year": 2024})
        line = "Jan 15 10:05:00 webserver sshd[12346]: Accepted publickey for deploy from 10.0.0.5 port 22222 ssh2"
        
        event = parser.parse_line(line)
        
        assert event is not None
        assert event.event_type == EventType.AUTH_SUCCESS
        assert event.source_ip == "10.0.0.5"
        assert event.username == "deploy"
        assert event.extra.get("method") == "publickey"
    
    def test_parse_sudo_command(self):
        """Should parse sudo command line."""
        parser = AuthLogParser({"year": 2024})
        line = "Jan 15 10:10:00 webserver sudo[12347]:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"
        
        event = parser.parse_line(line)
        
        assert event is not None
        assert event.event_type == EventType.SUDO_COMMAND
        assert event.username == "deploy"
        assert event.command == "/usr/bin/systemctl restart nginx"
        assert event.extra.get("target_user") == "root"
    
    def test_parse_file(self, temp_log_file):
        """Should parse entire log file."""
        parser = AuthLogParser({"year": 2024})
        events = list(parser.parse_file(temp_log_file))
        
        assert len(events) == 8
        
        # Check event types
        failures = [e for e in events if e.event_type == EventType.AUTH_FAILURE]
        successes = [e for e in events if e.event_type == EventType.AUTH_SUCCESS]
        sudo_events = [e for e in events if e.event_type == EventType.SUDO_COMMAND]
        
        assert len(failures) == 6
        assert len(successes) == 1
        assert len(sudo_events) == 1
    
    def test_parse_invalid_line(self):
        """Should return None for invalid line."""
        parser = AuthLogParser()
        event = parser.parse_line("this is not a valid log line")
        assert event is None


class TestNginxParser:
    """Tests for nginx access log parser."""
    
    def test_parse_combined_format(self):
        """Should parse nginx combined log format."""
        parser = NginxParser()
        line = '192.168.1.50 - - [15/Jan/2024:10:00:00 +0000] "GET /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"'
        
        event = parser.parse_line(line)
        
        assert event is not None
        assert event.source_ip == "192.168.1.50"
        assert event.http_method == "GET"
        assert event.http_path == "/login"
        assert event.http_status == 401
        assert event.http_user_agent == "Mozilla/5.0"
    
    def test_parse_auth_failure(self):
        """Should identify 401 as auth failure."""
        parser = NginxParser()
        line = '192.168.1.50 - - [15/Jan/2024:10:00:00 +0000] "POST /api/login HTTP/1.1" 401 0 "-" "curl/7.68.0"'
        
        event = parser.parse_line(line)
        
        assert event is not None
        assert event.event_type == EventType.AUTH_FAILURE
    
    def test_parse_successful_request(self):
        """Should parse successful HTTP request."""
        parser = NginxParser()
        line = '10.0.0.1 - admin [15/Jan/2024:10:05:00 +0000] "GET /dashboard HTTP/1.1" 200 5432 "-" "Mozilla/5.0"'
        
        event = parser.parse_line(line)
        
        assert event is not None
        assert event.event_type == EventType.HTTP_REQUEST
        assert event.username == "admin"
        assert event.http_status == 200
        assert event.http_bytes == 5432
    
    def test_is_suspicious_path(self):
        """Should identify suspicious request paths."""
        parser = NginxParser()
        
        assert parser.is_suspicious_path("/../../../etc/passwd")
        assert parser.is_suspicious_path("/admin/.env")
        assert parser.is_suspicious_path("/path?id=1 UNION SELECT *")
        assert not parser.is_suspicious_path("/api/users/123")
    
    def test_is_scanner_user_agent(self):
        """Should identify scanner user agents."""
        parser = NginxParser()
        
        assert parser.is_scanner_user_agent("Nikto/2.1.5")
        assert parser.is_scanner_user_agent("sqlmap/1.0")
        assert not parser.is_scanner_user_agent("Mozilla/5.0 Chrome/91.0")


class TestJSONEventsParser:
    """Tests for JSON events parser."""
    
    def test_parse_basic_event(self):
        """Should parse basic JSON event."""
        parser = JSONEventsParser()
        line = '{"timestamp": "2024-01-15T10:00:00Z", "event_type": "login_failure", "username": "admin", "source_ip": "192.168.1.100"}'
        
        event = parser.parse_line(line)
        
        assert event is not None
        assert event.event_type == EventType.AUTH_FAILURE
        assert event.username == "admin"
        assert event.source_ip == "192.168.1.100"
    
    def test_parse_unix_timestamp(self):
        """Should parse Unix timestamp."""
        parser = JSONEventsParser()
        line = '{"timestamp": 1705316400, "event_type": "login_success"}'
        
        event = parser.parse_line(line)
        
        assert event is not None
        assert event.timestamp.year == 2024
    
    def test_parse_millisecond_timestamp(self):
        """Should parse millisecond Unix timestamp."""
        parser = JSONEventsParser()
        line = '{"timestamp": 1705316400000, "event_type": "login_success"}'
        
        event = parser.parse_line(line)
        
        assert event is not None
    
    def test_custom_field_mapping(self):
        """Should support custom field mappings."""
        options = {
            "field_map": {
                "timestamp_fields": ["ts", "time"],
                "username_fields": ["user_id", "actor"],
            }
        }
        parser = JSONEventsParser(options)
        line = '{"ts": "2024-01-15T10:00:00Z", "actor": "alice"}'
        
        event = parser.parse_line(line)
        
        assert event is not None
        assert event.username == "alice"
    
    def test_parse_invalid_json(self):
        """Should return None for invalid JSON."""
        parser = JSONEventsParser()
        event = parser.parse_line("not json")
        assert event is None
    
    def test_parse_extra_fields(self):
        """Should preserve extra fields."""
        parser = JSONEventsParser()
        line = '{"timestamp": "2024-01-15T10:00:00Z", "event_type": "login_success", "custom_field": "custom_value"}'
        
        event = parser.parse_line(line)
        
        assert event is not None
        assert event.extra.get("custom_field") == "custom_value"


class TestCloudFindingsParser:
    """Tests for cloud findings parser."""

    def test_parse_single_cloud_finding(self):
        """Should convert a cloud finding into a normalized event."""
        parser = CloudFindingsParser({"default_timestamp": "2026-04-06T12:00:00"})
        line = """
        {
          "provider": "AWS",
          "resource_id": "arn:aws:s3:::customer-export-prod",
          "resource_type": "S3 Bucket",
          "issue_type": "Public storage bucket",
          "severity": "critical",
          "owner_team": "data-platform",
          "environment": "production",
          "details": "Bucket is public.",
          "recommended_action": "Block public access."
        }
        """

        event = parser.parse_line(line)

        assert event is not None
        assert event.event_type == EventType.CONFIG_CHANGE
        assert event.source_parser == "cloud"
        assert event.hostname == "aws"
        assert event.file_path == "arn:aws:s3:::customer-export-prod"
        assert event.extra["provider"] == "AWS"
        assert event.extra["owner_team"] == "data-platform"
        assert event.extra["severity"] == "critical"

    def test_parse_network_finding_as_network_event(self, tmp_path):
        """Should map exposed remote access issues to network events."""
        parser = CloudFindingsParser({"default_timestamp": "2026-04-06T12:00:00"})
        findings_file = tmp_path / "cloud_findings.json"
        findings_file.write_text(
            """
            [
              {
                "provider": "Azure",
                "resource_id": "nsg-prod-01",
                "resource_type": "Network Security Group",
                "issue_type": "SSH open to the internet",
                "severity": "high",
                "owner_team": "network-security",
                "environment": "production",
                "details": "TCP/22 open to all sources.",
                "recommended_action": "Restrict SSH."
              }
            ]
            """.strip()
        )

        events = list(parser.parse_file(findings_file))

        assert len(events) == 1
        assert events[0].event_type == EventType.NETWORK_CONNECTION
        assert events[0].extra["issue_type"] == "SSH open to the internet"
