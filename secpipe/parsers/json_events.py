from __future__ import annotations

"""
JSON Events Parser

Parses JSON-formatted log events from various sources.
Supports flexible field mapping for different JSON schemas.
"""

import json
from datetime import datetime
from typing import Any

from secpipe.parsers.base import Parser, ParserRegistry
from secpipe.schema import Event, EventType


@ParserRegistry.register
class JSONEventsParser(Parser):
    """
    Parser for JSON-formatted log events.
    
    Supports flexible field mapping to handle different JSON schemas
    from various logging systems (e.g., structured logging libraries,
    cloud provider logs, application logs).
    """
    
    name = "json"
    description = "JSON-formatted event parser"
    supported_extensions = [".json", ".jsonl", ".ndjson"]
    
    # Default field mappings (source field -> Event field)
    DEFAULT_FIELD_MAP = {
        # Timestamp fields to check
        "timestamp_fields": [
            "timestamp", "@timestamp", "time", "datetime", "date",
            "eventTime", "event_time", "created_at", "ts"
        ],
        # Event type fields
        "event_type_fields": [
            "event_type", "eventType", "type", "action", "event"
        ],
        # Username fields
        "username_fields": [
            "username", "user", "userName", "user_name", "actor",
            "principal", "identity"
        ],
        # Source IP fields
        "source_ip_fields": [
            "source_ip", "sourceIP", "src_ip", "clientIP", "client_ip",
            "remote_addr", "ip", "ipAddress"
        ],
        # Hostname fields
        "hostname_fields": [
            "hostname", "host", "server", "instance", "node"
        ],
        # Message fields
        "message_fields": [
            "message", "msg", "description", "detail", "text"
        ],
    }
    
    # Event type value mappings
    EVENT_TYPE_MAP = {
        # Authentication
        "login": EventType.AUTH_SUCCESS,
        "login_success": EventType.AUTH_SUCCESS,
        "auth_success": EventType.AUTH_SUCCESS,
        "authentication_success": EventType.AUTH_SUCCESS,
        "login_failure": EventType.AUTH_FAILURE,
        "login_failed": EventType.AUTH_FAILURE,
        "auth_failure": EventType.AUTH_FAILURE,
        "authentication_failure": EventType.AUTH_FAILURE,
        "logout": EventType.AUTH_LOGOUT,
        "session_end": EventType.AUTH_LOGOUT,
        
        # Process events
        "process_start": EventType.PROCESS_START,
        "process_create": EventType.PROCESS_START,
        "exec": EventType.PROCESS_START,
        "process_stop": EventType.PROCESS_STOP,
        "process_terminate": EventType.PROCESS_STOP,
        
        # File events
        "file_create": EventType.FILE_CREATE,
        "file_write": EventType.FILE_MODIFY,
        "file_modify": EventType.FILE_MODIFY,
        "file_delete": EventType.FILE_DELETE,
        
        # Network events
        "network_connection": EventType.NETWORK_CONNECTION,
        "connection": EventType.NETWORK_CONNECTION,
        "connect": EventType.NETWORK_CONNECTION,
        
        # HTTP events
        "http_request": EventType.HTTP_REQUEST,
        "request": EventType.HTTP_REQUEST,
        "api_call": EventType.HTTP_REQUEST,
        
        # Admin events
        "sudo": EventType.SUDO_COMMAND,
        "privilege_escalation": EventType.SUDO_COMMAND,
        "cron": EventType.CRON_EDIT,
        "scheduled_task": EventType.CRON_EDIT,
        "service": EventType.SERVICE_ACTION,
        "user_change": EventType.USER_MODIFY,
        "config_change": EventType.CONFIG_CHANGE,
    }
    
    def __init__(self, options: dict | None = None):
        super().__init__(options)
        # Allow custom field mappings
        self.field_map = self.DEFAULT_FIELD_MAP.copy()
        if options and "field_map" in options:
            self.field_map.update(options["field_map"])
    
    def parse_line(self, line: str) -> Event | None:
        """Parse a single JSON log line."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None
        
        if not isinstance(data, dict):
            return None
        
        return self._parse_json_object(data, line)
    
    def _parse_json_object(self, data: dict[str, Any], raw_line: str) -> Event:
        """Convert a JSON object to an Event."""
        # Extract timestamp
        timestamp = self._extract_timestamp(data)
        
        # Extract event type
        event_type = self._extract_event_type(data)
        
        # Extract other fields
        username = self._extract_field(data, "username_fields")
        source_ip = self._extract_field(data, "source_ip_fields")
        hostname = self._extract_field(data, "hostname_fields")
        message = self._extract_field(data, "message_fields")
        
        # Build extra dict with remaining fields
        extra = {
            k: v for k, v in data.items()
            if k not in self._get_all_mapped_fields()
        }
        
        return Event(
            timestamp=timestamp,
            event_type=event_type,
            source_parser=self.name,
            raw_line=raw_line,
            hostname=hostname,
            username=username,
            source_ip=source_ip,
            message=message,
            dest_ip=data.get("dest_ip") or data.get("destination_ip"),
            dest_port=data.get("dest_port") or data.get("destination_port"),
            process_name=data.get("process") or data.get("program"),
            pid=data.get("pid") or data.get("process_id"),
            command=data.get("command") or data.get("cmd"),
            file_path=data.get("file_path") or data.get("path"),
            http_method=data.get("method") or data.get("http_method"),
            http_path=data.get("url") or data.get("uri") or data.get("path"),
            http_status=data.get("status") or data.get("status_code"),
            extra=extra,
        )
    
    def _extract_timestamp(self, data: dict[str, Any]) -> datetime:
        """Extract and parse timestamp from JSON data."""
        for field in self.field_map["timestamp_fields"]:
            if field in data:
                ts_value = data[field]
                return self._parse_timestamp(ts_value)
        
        # No timestamp found, use current time
        return datetime.now()
    
    def _parse_timestamp(self, value: Any) -> datetime:
        """Parse a timestamp value in various formats."""
        if isinstance(value, datetime):
            return value
        
        if isinstance(value, (int, float)):
            # Unix timestamp (seconds or milliseconds)
            if value > 1e12:  # Milliseconds
                return datetime.fromtimestamp(value / 1000)
            return datetime.fromtimestamp(value)
        
        if isinstance(value, str):
            # Try various formats
            formats = [
                "%Y-%m-%dT%H:%M:%S.%fZ",      # ISO with microseconds
                "%Y-%m-%dT%H:%M:%SZ",          # ISO
                "%Y-%m-%dT%H:%M:%S.%f%z",      # ISO with timezone
                "%Y-%m-%dT%H:%M:%S%z",         # ISO with timezone
                "%Y-%m-%d %H:%M:%S.%f",        # Space separated
                "%Y-%m-%d %H:%M:%S",           # Space separated
                "%Y/%m/%d %H:%M:%S",           # Slash separated
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue
            
            # Try fromisoformat as last resort
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass
        
        return datetime.now()
    
    def _extract_event_type(self, data: dict[str, Any]) -> EventType:
        """Extract and map event type from JSON data."""
        for field in self.field_map["event_type_fields"]:
            if field in data:
                value = str(data[field]).lower()
                if value in self.EVENT_TYPE_MAP:
                    return self.EVENT_TYPE_MAP[value]
        
        return EventType.UNKNOWN
    
    def _extract_field(
        self, data: dict[str, Any], field_list_key: str
    ) -> str | None:
        """Extract a field value using multiple possible field names."""
        for field in self.field_map[field_list_key]:
            if field in data and data[field]:
                return str(data[field])
        return None
    
    def _get_all_mapped_fields(self) -> set[str]:
        """Get set of all fields used in mapping."""
        fields = set()
        for field_list in self.field_map.values():
            fields.update(field_list)
        return fields
