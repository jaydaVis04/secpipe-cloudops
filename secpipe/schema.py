from __future__ import annotations

"""
SecPipe Event and Finding Schema

Defines the common data structures used throughout the pipeline.
All parsers normalize events to the Event schema, and all detections
produce Finding objects.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any
import json
import hashlib


class Severity(Enum):
    """Finding severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    def __lt__(self, other: "Severity") -> bool:
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)
    
    def __le__(self, other: "Severity") -> bool:
        return self == other or self < other


class EventType(Enum):
    """Normalized event types."""
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    AUTH_LOGOUT = "auth_logout"
    PROCESS_START = "process_start"
    PROCESS_STOP = "process_stop"
    FILE_CREATE = "file_create"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    NETWORK_CONNECTION = "network_connection"
    HTTP_REQUEST = "http_request"
    SUDO_COMMAND = "sudo_command"
    CRON_EDIT = "cron_edit"
    SERVICE_ACTION = "service_action"
    USER_MODIFY = "user_modify"
    CONFIG_CHANGE = "config_change"
    LOG_ACTION = "log_action"
    UNKNOWN = "unknown"


@dataclass
class Event:
    """
    Normalized event schema.
    
    All parsers convert their source-specific formats into this common
    schema to enable consistent detection logic.
    """
    timestamp: datetime
    event_type: EventType
    source_parser: str
    raw_line: str
    
    # Identity fields
    hostname: str | None = None
    username: str | None = None
    process_name: str | None = None
    pid: int | None = None
    
    # Network fields
    source_ip: str | None = None
    source_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    
    # HTTP fields (for web logs)
    http_method: str | None = None
    http_path: str | None = None
    http_status: int | None = None
    http_user_agent: str | None = None
    http_bytes: int | None = None
    
    # File fields
    file_path: str | None = None
    file_action: str | None = None
    
    # Command fields
    command: str | None = None
    
    # Additional context
    message: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate and normalize fields after initialization."""
        if isinstance(self.timestamp, str):
            self.timestamp = datetime.fromisoformat(self.timestamp)
        if isinstance(self.event_type, str):
            self.event_type = EventType(self.event_type)
    
    @property
    def event_id(self) -> str:
        """Generate a unique ID for this event based on content."""
        content = f"{self.timestamp.isoformat()}{self.event_type.value}{self.raw_line}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["event_type"] = self.event_type.value
        data["event_id"] = self.event_id
        return data
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        """Create Event from dictionary."""
        data = data.copy()
        data.pop("event_id", None)  # Remove computed field
        if "timestamp" in data and isinstance(data["timestamp"], str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        if "event_type" in data and isinstance(data["event_type"], str):
            data["event_type"] = EventType(data["event_type"])
        return cls(**data)


@dataclass
class Finding:
    """
    Security finding produced by a detection.
    
    Findings represent potential security issues identified by analyzing
    events. Each finding includes context, severity, and MITRE ATT&CK mapping.
    """
    detection_name: str
    title: str
    description: str
    severity: Severity
    mitre_attack_id: str | None = None
    mitre_attack_technique: str | None = None
    
    # Timing
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    
    # Context
    source_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    
    # Evidence
    event_count: int = 1
    evidence_events: list[str] = field(default_factory=list)  # Event IDs
    raw_samples: list[str] = field(default_factory=list)  # Sample raw lines
    
    # Additional context
    recommendations: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate fields after initialization."""
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
    
    @property
    def finding_id(self) -> str:
        """Generate unique ID for this finding."""
        content = f"{self.detection_name}{self.title}{self.first_seen}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data["severity"] = self.severity.value
        data["finding_id"] = self.finding_id
        if self.first_seen:
            data["first_seen"] = self.first_seen.isoformat()
        if self.last_seen:
            data["last_seen"] = self.last_seen.isoformat()
        return data
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Create Finding from dictionary."""
        data = data.copy()
        data.pop("finding_id", None)
        if "severity" in data and isinstance(data["severity"], str):
            data["severity"] = Severity(data["severity"])
        for field_name in ["first_seen", "last_seen"]:
            if field_name in data and isinstance(data[field_name], str):
                data[field_name] = datetime.fromisoformat(data[field_name])
        return cls(**data)


# MITRE ATT&CK technique mapping for reference
MITRE_TECHNIQUES = {
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "T1098.004": "Account Manipulation: SSH Authorized Keys",
    "T1543.002": "Create or Modify System Process: Systemd Service",
    "T1070.002": "Indicator Removal: Clear Linux or Mac System Logs",
    "T1078.003": "Valid Accounts: Local Accounts",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1021.004": "Remote Services: SSH",
}
