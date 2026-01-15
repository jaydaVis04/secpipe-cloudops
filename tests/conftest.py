"""
Pytest Configuration and Fixtures

Provides shared fixtures for testing SecPipe components.
"""

import pytest
from datetime import datetime, timedelta
from pathlib import Path

from secpipe.schema import Event, EventType, Finding, Severity


@pytest.fixture
def sample_auth_log_lines():
    """Sample auth.log lines for testing."""
    base_time = datetime(2024, 1, 15, 10, 0, 0)
    
    return [
        f"Jan 15 10:00:01 webserver sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2",
        f"Jan 15 10:00:02 webserver sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54322 ssh2",
        f"Jan 15 10:00:03 webserver sshd[12345]: Failed password for invalid user root from 192.168.1.100 port 54323 ssh2",
        f"Jan 15 10:00:04 webserver sshd[12345]: Failed password for invalid user test from 192.168.1.100 port 54324 ssh2",
        f"Jan 15 10:00:05 webserver sshd[12345]: Failed password for invalid user user from 192.168.1.100 port 54325 ssh2",
        f"Jan 15 10:00:06 webserver sshd[12345]: Failed password for invalid user guest from 192.168.1.100 port 54326 ssh2",
        f"Jan 15 10:05:00 webserver sshd[12346]: Accepted publickey for deploy from 10.0.0.5 port 22222 ssh2",
        f"Jan 15 10:10:00 webserver sudo[12347]:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
    ]


@pytest.fixture
def sample_nginx_log_lines():
    """Sample nginx access log lines for testing."""
    return [
        '192.168.1.50 - - [15/Jan/2024:10:00:00 +0000] "GET /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
        '192.168.1.50 - - [15/Jan/2024:10:00:01 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
        '192.168.1.50 - - [15/Jan/2024:10:00:02 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
        '192.168.1.50 - - [15/Jan/2024:10:00:03 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
        '192.168.1.50 - - [15/Jan/2024:10:00:04 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
        '192.168.1.50 - - [15/Jan/2024:10:00:05 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
        '192.168.1.50 - - [15/Jan/2024:10:00:06 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
        '192.168.1.50 - - [15/Jan/2024:10:00:07 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
        '192.168.1.50 - - [15/Jan/2024:10:00:08 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
        '192.168.1.50 - - [15/Jan/2024:10:00:09 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
        '192.168.1.50 - - [15/Jan/2024:10:00:10 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
        '10.0.0.1 - admin [15/Jan/2024:10:05:00 +0000] "GET /dashboard HTTP/1.1" 200 5432 "-" "Mozilla/5.0"',
    ]


@pytest.fixture
def sample_json_events():
    """Sample JSON event lines for testing."""
    return [
        '{"timestamp": "2024-01-15T10:00:00Z", "event_type": "login_failure", "username": "admin", "source_ip": "192.168.1.100"}',
        '{"timestamp": "2024-01-15T10:00:01Z", "event_type": "login_failure", "username": "root", "source_ip": "192.168.1.100"}',
        '{"timestamp": "2024-01-15T10:00:02Z", "event_type": "login_success", "username": "deploy", "source_ip": "10.0.0.5"}',
    ]


@pytest.fixture
def sample_events():
    """Pre-parsed sample events for detection testing."""
    base_time = datetime(2024, 1, 15, 10, 0, 0)
    events = []
    
    # SSH brute force events
    for i in range(10):
        events.append(Event(
            timestamp=base_time + timedelta(seconds=i),
            event_type=EventType.AUTH_FAILURE,
            source_parser="auth",
            raw_line=f"sshd: Failed password from 192.168.1.100",
            hostname="webserver",
            username=["admin", "root", "test", "user"][i % 4],
            source_ip="192.168.1.100",
            source_port=54320 + i,
            process_name="sshd",
            extra={"pattern": "ssh_failed", "method": "password"},
        ))
    
    # Successful login
    events.append(Event(
        timestamp=base_time + timedelta(minutes=5),
        event_type=EventType.AUTH_SUCCESS,
        source_parser="auth",
        raw_line="sshd: Accepted publickey for deploy",
        hostname="webserver",
        username="deploy",
        source_ip="10.0.0.5",
        process_name="sshd",
        extra={"pattern": "ssh_accepted", "method": "publickey"},
    ))
    
    # Sudo command
    events.append(Event(
        timestamp=base_time + timedelta(minutes=10),
        event_type=EventType.SUDO_COMMAND,
        source_parser="auth",
        raw_line="sudo: deploy executed command",
        hostname="webserver",
        username="deploy",
        command="/usr/bin/systemctl restart nginx",
        extra={"pattern": "sudo_command", "target_user": "root"},
    ))
    
    return events


@pytest.fixture
def sample_findings():
    """Sample findings for output testing."""
    return [
        Finding(
            detection_name="brute_force_ssh",
            title="SSH brute force from 192.168.1.100",
            description="Detected 10 failed SSH login attempts",
            severity=Severity.HIGH,
            mitre_attack_id="T1110.001",
            mitre_attack_technique="Brute Force: Password Guessing",
            first_seen=datetime(2024, 1, 15, 10, 0, 0),
            last_seen=datetime(2024, 1, 15, 10, 0, 9),
            source_ip="192.168.1.100",
            event_count=10,
            recommendations=[
                "Block IP at firewall",
                "Review SSH configuration",
            ],
        ),
        Finding(
            detection_name="unusual_sudo",
            title="High-risk sudo commands by deploy",
            description="User deploy executed systemctl commands",
            severity=Severity.MEDIUM,
            mitre_attack_id="T1548.003",
            first_seen=datetime(2024, 1, 15, 10, 10, 0),
            username="deploy",
            event_count=1,
        ),
    ]


@pytest.fixture
def temp_log_file(tmp_path, sample_auth_log_lines):
    """Create a temporary log file for testing."""
    log_file = tmp_path / "auth.log"
    log_file.write_text("\n".join(sample_auth_log_lines))
    return log_file


@pytest.fixture
def temp_config_file(tmp_path, temp_log_file):
    """Create a temporary config file for testing."""
    config = f"""
pipeline:
  name: test-pipeline

sources:
  - type: auth
    path: {temp_log_file}

detections:
  min_severity: low

outputs:
  - type: jsonl
    path: {tmp_path}/findings.jsonl
  - type: markdown
    path: {tmp_path}/findings.md
"""
    config_file = tmp_path / "config.yaml"
    config_file.write_text(config)
    return config_file
