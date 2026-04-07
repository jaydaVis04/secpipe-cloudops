from __future__ import annotations

"""
Cloud Findings Parser

Converts modeled cloud security findings into normalized SecPipe events.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from secpipe.parsers.base import Parser, ParserRegistry
from secpipe.schema import Event, EventType


@ParserRegistry.register
class CloudFindingsParser(Parser):
    """
    Parser for modeled cloud posture findings.

    The cloud findings input is a JSON array rather than line-oriented logs,
    so parse_file loads the full document and converts each finding into one
    normalized event.
    """

    name = "cloud"
    description = "Cloud security findings parser"
    supported_extensions = [".json"]

    ISSUE_TYPE_MAP = {
        "public storage bucket": EventType.CONFIG_CHANGE,
        "excessive iam permissions": EventType.USER_MODIFY,
        "overly broad service account permissions": EventType.USER_MODIFY,
        "ssh open to the internet": EventType.NETWORK_CONNECTION,
        "rdp exposed publicly": EventType.NETWORK_CONNECTION,
        "insecure network path": EventType.NETWORK_CONNECTION,
    }

    def parse_file(self, path: Path | str) -> Iterator[Event]:
        """Parse a JSON findings file containing either a list or one object."""
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            raise ValueError("Cloud findings file must contain a JSON object or array")

        for finding in data:
            if not isinstance(finding, dict):
                if self.options.get("strict", False):
                    raise ValueError("Each cloud finding must be a JSON object")
                continue

            try:
                yield self._parse_finding(finding)
            except Exception:
                if self.options.get("strict", False):
                    raise
                continue

    def parse_line(self, line: str) -> Event | None:
        """Parse a single JSON finding object."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        if not isinstance(data, dict):
            return None

        return self._parse_finding(data)

    def _parse_finding(self, finding: dict[str, Any]) -> Event:
        """Convert one cloud finding into a normalized Event."""
        issue_type = self._normalize_text(finding.get("issue_type"), "unknown")
        provider = self._normalize_text(finding.get("provider"), "unknown")
        resource_id = self._normalize_text(finding.get("resource_id"), "unknown")
        resource_type = self._normalize_text(finding.get("resource_type"), "unknown")
        owner_team = self._normalize_text(finding.get("owner_team"), "unassigned")
        environment = self._normalize_text(finding.get("environment"), "unknown")
        severity = self._normalize_text(finding.get("severity"), "low").lower()
        details = self._normalize_text(finding.get("details"), "")
        recommended_action = self._normalize_text(
            finding.get("recommended_action"),
            "",
        )

        raw_line = json.dumps(finding, sort_keys=True)
        timestamp = self._extract_timestamp(finding)
        event_type = self.ISSUE_TYPE_MAP.get(issue_type.lower(), EventType.CONFIG_CHANGE)

        message = f"{provider} {issue_type} on {resource_type} {resource_id}"

        return Event(
            timestamp=timestamp,
            event_type=event_type,
            source_parser=self.name,
            raw_line=raw_line,
            hostname=provider.lower(),
            message=message,
            file_path=resource_id,
            extra={
                "provider": provider,
                "resource_id": resource_id,
                "resource_type": resource_type,
                "issue_type": issue_type,
                "severity": severity,
                "owner_team": owner_team,
                "environment": environment,
                "details": details,
                "recommended_action": recommended_action,
            },
        )

    def _normalize_text(self, value: Any, default: str) -> str:
        """Normalize JSON values into predictable strings for Event fields."""
        if value is None:
            return default

        text = str(value).strip()
        if not text:
            return default

        return text

    def _extract_timestamp(self, finding: dict[str, Any]) -> datetime:
        """Use a finding timestamp when present, otherwise use ingest time."""
        timestamp = finding.get("timestamp")
        if isinstance(timestamp, str):
            try:
                return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                pass

        configured_timestamp = self.options.get("default_timestamp")
        if isinstance(configured_timestamp, datetime):
            return configured_timestamp
        if isinstance(configured_timestamp, str):
            try:
                return datetime.fromisoformat(configured_timestamp)
            except ValueError:
                pass

        return datetime.now()
