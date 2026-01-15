"""
SecPipe - Security Telemetry Pipeline

A security telemetry pipeline that ingests logs from multiple sources,
normalizes events to a common schema, runs rule-based detections,
and exports structured findings.

Usage:
    from secpipe import Pipeline
    
    # Quick analysis
    pipeline = Pipeline()
    pipeline.ingest("auth", "/var/log/auth.log")
    findings = pipeline.detect()
    
    # From configuration
    pipeline = Pipeline.from_config_file("config.yaml")
    findings = pipeline.run()
"""

__version__ = "0.1.0"

from secpipe.schema import Event, EventType, Finding, Severity
from secpipe.pipeline import Pipeline
from secpipe.parsers import ParserRegistry
from secpipe.detections import DetectionRegistry, DetectionEngine
from secpipe.outputs import OutputRegistry

__all__ = [
    "Event",
    "EventType",
    "Finding",
    "Severity",
    "Pipeline",
    "ParserRegistry",
    "DetectionRegistry",
    "DetectionEngine",
    "OutputRegistry",
]
