from __future__ import annotations

"""
Base Detection Interface

All security detections inherit from this base class and implement
the analyze method to identify suspicious patterns in events.
"""

from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterator

from secpipe.schema import Event, EventType, Finding, Severity


class Detection(ABC):
    """
    Abstract base class for security detections.
    
    Detections analyze normalized events and produce findings when
    suspicious patterns are identified.
    """
    
    # Subclasses must define these
    name: str = "base"
    description: str = "Base detection interface"
    severity: Severity = Severity.MEDIUM
    mitre_attack_id: str | None = None
    mitre_attack_technique: str | None = None
    
    # Detection categories for filtering
    categories: list[str] = []
    
    # Whether this detection is enabled by default
    enabled_by_default: bool = True
    
    def __init__(self, options: dict | None = None):
        """
        Initialize detection with optional configuration.
        
        Args:
            options: Detection-specific configuration options
        """
        self.options = options or {}
    
    @abstractmethod
    def analyze(self, events: list[Event]) -> list[Finding]:
        """
        Analyze events and produce findings.
        
        Args:
            events: List of normalized events to analyze
            
        Returns:
            List of findings (may be empty)
        """
        pass
    
    def create_finding(
        self,
        title: str,
        description: str,
        events: list[Event],
        severity: Severity | None = None,
        **extra_fields,
    ) -> Finding:
        """
        Helper to create a Finding with common fields populated.
        
        Args:
            title: Short finding title
            description: Detailed description
            events: Events that triggered this finding
            severity: Override default severity
            **extra_fields: Additional Finding fields
            
        Returns:
            Finding object
        """
        severity = severity or self.severity
        
        # Extract timing from events
        timestamps = [e.timestamp for e in events]
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None
        
        # Extract common context from events
        source_ips = set(e.source_ip for e in events if e.source_ip)
        usernames = set(e.username for e in events if e.username)
        hostnames = set(e.hostname for e in events if e.hostname)
        
        # Sample raw lines for evidence
        raw_samples = [e.raw_line for e in events[:5]]
        event_ids = [e.event_id for e in events[:20]]
        
        return Finding(
            detection_name=self.name,
            title=title,
            description=description,
            severity=severity,
            mitre_attack_id=self.mitre_attack_id,
            mitre_attack_technique=self.mitre_attack_technique,
            first_seen=first_seen,
            last_seen=last_seen,
            source_ip=list(source_ips)[0] if len(source_ips) == 1 else None,
            username=list(usernames)[0] if len(usernames) == 1 else None,
            hostname=list(hostnames)[0] if len(hostnames) == 1 else None,
            event_count=len(events),
            evidence_events=event_ids,
            raw_samples=raw_samples,
            extra={
                "all_source_ips": list(source_ips),
                "all_usernames": list(usernames),
                "all_hostnames": list(hostnames),
                **extra_fields,
            },
        )
    
    def group_events_by(
        self,
        events: list[Event],
        key_func,
    ) -> dict[str, list[Event]]:
        """
        Group events by a key function.
        
        Args:
            events: Events to group
            key_func: Function that takes an event and returns a grouping key
            
        Returns:
            Dictionary mapping keys to event lists
        """
        groups = defaultdict(list)
        for event in events:
            key = key_func(event)
            if key is not None:
                groups[key].append(event)
        return dict(groups)
    
    def filter_events_by_type(
        self,
        events: list[Event],
        event_types: list[EventType],
    ) -> list[Event]:
        """Filter events to only those matching specified types."""
        return [e for e in events if e.event_type in event_types]
    
    def filter_events_by_window(
        self,
        events: list[Event],
        window_seconds: int,
        reference_time: datetime | None = None,
    ) -> list[Event]:
        """Filter events to those within a time window."""
        if not events:
            return []
        
        if reference_time is None:
            reference_time = max(e.timestamp for e in events)
        
        window_start = reference_time - timedelta(seconds=window_seconds)
        return [e for e in events if e.timestamp >= window_start]


class DetectionRegistry:
    """Registry of available detections."""
    
    _detections: dict[str, type[Detection]] = {}
    
    @classmethod
    def register(cls, detection_class: type[Detection]) -> type[Detection]:
        """
        Register a detection class.
        
        Can be used as a decorator:
            @DetectionRegistry.register
            class MyDetection(Detection):
                ...
        """
        cls._detections[detection_class.name] = detection_class
        return detection_class
    
    @classmethod
    def get(cls, name: str) -> type[Detection] | None:
        """Get a detection class by name."""
        return cls._detections.get(name)
    
    @classmethod
    def list_detections(cls) -> list[str]:
        """List all registered detection names."""
        return list(cls._detections.keys())
    
    @classmethod
    def list_by_category(cls, category: str) -> list[str]:
        """List detections matching a category."""
        return [
            name for name, det_class in cls._detections.items()
            if category in det_class.categories
        ]
    
    @classmethod
    def create(cls, name: str, options: dict | None = None) -> Detection:
        """
        Create a detection instance by name.
        
        Args:
            name: Detection name
            options: Detection configuration options
            
        Returns:
            Detection instance
            
        Raises:
            ValueError: If detection name is not registered
        """
        detection_class = cls.get(name)
        if detection_class is None:
            available = ", ".join(cls.list_detections())
            raise ValueError(
                f"Unknown detection: {name}. Available: {available}"
            )
        return detection_class(options)
    
    @classmethod
    def create_all(
        cls,
        enabled_only: bool = True,
        categories: list[str] | None = None,
        options: dict | None = None,
    ) -> list[Detection]:
        """
        Create instances of all registered detections.
        
        Args:
            enabled_only: Only create detections enabled by default
            categories: Filter to specific categories
            options: Options passed to all detections
            
        Returns:
            List of detection instances
        """
        detections = []
        for name, det_class in cls._detections.items():
            if enabled_only and not det_class.enabled_by_default:
                continue
            if categories and not any(c in det_class.categories for c in categories):
                continue
            detections.append(det_class(options))
        return detections


class DetectionEngine:
    """
    Orchestrates running multiple detections on events.
    """
    
    def __init__(
        self,
        detections: list[Detection] | None = None,
        min_severity: Severity = Severity.LOW,
    ):
        """
        Initialize detection engine.
        
        Args:
            detections: List of detection instances to run
            min_severity: Minimum severity for reported findings
        """
        self.detections = detections or DetectionRegistry.create_all()
        self.min_severity = min_severity
    
    def run(self, events: list[Event]) -> list[Finding]:
        """
        Run all detections on events.
        
        Args:
            events: Events to analyze
            
        Returns:
            List of findings from all detections
        """
        all_findings = []
        
        for detection in self.detections:
            try:
                findings = detection.analyze(events)
                # Filter by minimum severity
                findings = [
                    f for f in findings
                    if f.severity >= self.min_severity
                ]
                all_findings.extend(findings)
            except Exception as e:
                # Log error but continue with other detections
                print(f"Error in detection {detection.name}: {e}")
        
        # Sort by severity (highest first) then by time
        def sort_key(f):
            severity_order = -[Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL].index(f.severity)
            # Handle timezone-aware vs naive datetimes
            ts = f.first_seen
            if ts is None:
                ts = datetime.min
            elif ts.tzinfo is not None:
                ts = ts.replace(tzinfo=None)
            return (severity_order, ts)
        
        all_findings.sort(key=sort_key)
        
        return all_findings
    
    def run_streaming(self, events: Iterator[Event]) -> Iterator[Finding]:
        """
        Run detections on a stream of events.
        
        This buffers events and runs detections periodically.
        Useful for real-time processing.
        
        Args:
            events: Iterator of events
            
        Yields:
            Findings as they are detected
        """
        buffer = []
        buffer_size = self.options.get("buffer_size", 1000) if hasattr(self, 'options') else 1000
        
        for event in events:
            buffer.append(event)
            
            if len(buffer) >= buffer_size:
                findings = self.run(buffer)
                for finding in findings:
                    yield finding
                buffer = []
        
        # Process remaining events
        if buffer:
            findings = self.run(buffer)
            for finding in findings:
                yield finding
