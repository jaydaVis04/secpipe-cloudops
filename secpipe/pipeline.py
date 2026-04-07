from __future__ import annotations

"""
SecPipe Pipeline Orchestration

Provides the main Pipeline class that coordinates ingestion,
detection, and output.
"""

import yaml
from pathlib import Path
from typing import Any

from secpipe.schema import Event, Finding, Severity
from secpipe.parsers import ParserRegistry
from secpipe.detections import DetectionRegistry, DetectionEngine
from secpipe.outputs import OutputRegistry


class Pipeline:
    """
    Main pipeline orchestrator.
    
    Coordinates log ingestion, detection execution, and output
    generation based on configuration.
    """
    
    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize pipeline with configuration.
        
        Args:
            config: Pipeline configuration dictionary
        """
        self.config = config or {}
        self.events: list[Event] = []
        self.findings: list[Finding] = []
        
        # Initialize components
        self._init_parsers()
        self._init_detections()
        self._init_outputs()
    
    def _init_parsers(self) -> None:
        """Initialize parsers from configuration."""
        self.parsers = {}
        sources = self.config.get("sources", [])
        
        for source in sources:
            parser_type = source.get("type")
            options = source.get("options", {})
            
            if parser_type:
                self.parsers[parser_type] = ParserRegistry.create(
                    parser_type, options
                )
    
    def _init_detections(self) -> None:
        """Initialize detection engine from configuration."""
        detection_config = self.config.get("detections", {})
        enabled = detection_config.get("enabled")
        min_severity_str = detection_config.get("min_severity", "low")
        min_severity = Severity(min_severity_str)
        
        if enabled:
            # Create only specified detections
            detections = [
                DetectionRegistry.create(name)
                for name in enabled
                if DetectionRegistry.get(name)
            ]
        else:
            # Create all detections
            detections = DetectionRegistry.create_all()
        
        self.detection_engine = DetectionEngine(
            detections=detections,
            min_severity=min_severity,
        )
    
    def _init_outputs(self) -> None:
        """Initialize outputs from configuration."""
        self.outputs = []
        output_configs = self.config.get("outputs", [])
        
        for output_config in output_configs:
            output_type = output_config.get("type")
            if output_type:
                output = OutputRegistry.create(output_type, output_config)
                self.outputs.append(output)
    
    @classmethod
    def from_config_file(cls, path: Path | str) -> "Pipeline":
        """
        Create pipeline from a YAML configuration file.
        
        Args:
            path: Path to YAML config file
            
        Returns:
            Pipeline instance
        """
        path = Path(path)
        with open(path, "r") as f:
            config = yaml.safe_load(f)
        return cls(config.get("pipeline", config))
    
    def ingest(
        self,
        source_type: str,
        path: Path | str,
        options: dict[str, Any] | None = None,
    ) -> int:
        """
        Ingest logs from a file.
        
        Args:
            source_type: Parser type to use
            path: Path to log file
            options: Parser options
            
        Returns:
            Number of events ingested
        """
        parser = ParserRegistry.create(source_type, options)
        
        count = 0
        for event in parser.parse_file(path):
            self.events.append(event)
            count += 1
        
        return count
    
    def ingest_lines(
        self,
        source_type: str,
        lines: list[str],
        options: dict[str, Any] | None = None,
    ) -> int:
        """
        Ingest logs from a list of lines.
        
        Args:
            source_type: Parser type to use
            lines: Log lines to parse
            options: Parser options
            
        Returns:
            Number of events ingested
        """
        parser = ParserRegistry.create(source_type, options)
        
        count = 0
        for event in parser.parse_lines(lines):
            self.events.append(event)
            count += 1
        
        return count
    
    def detect(self) -> list[Finding]:
        """
        Run detections on ingested events.
        
        Returns:
            List of findings
        """
        self.findings = self.detection_engine.run(self.events)
        return self.findings
    
    def export(self, output_type: str | None = None) -> None:
        """
        Export findings to configured outputs.
        
        Args:
            output_type: Specific output type to use (or all if None)
        """
        if output_type:
            for output in self.outputs:
                if output.name == output_type:
                    output.write(self.findings)
                    return
            
            # Output type not in config, create ad-hoc
            output = OutputRegistry.create(output_type)
            output.write(self.findings)
        else:
            # Write to all configured outputs
            for output in self.outputs:
                output.write(self.findings)
    
    def run(self) -> list[Finding]:
        """
        Run the full pipeline.
        
        Ingests from configured sources, runs detections, and exports
        to configured outputs.
        
        Returns:
            List of findings
        """
        # Ingest from configured sources
        for source in self.config.get("sources", []):
            source_type = source.get("type")
            path = source.get("path")
            options = source.get("options", {})
            
            if source_type and path:
                self.ingest(source_type, path, options)
        
        # Run detections
        self.detect()
        
        # Export
        self.export()
        
        return self.findings
    
    def get_summary(self) -> dict[str, Any]:
        """Get pipeline execution summary."""
        severity_counts = {}
        for finding in self.findings:
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        detection_counts = {}
        for finding in self.findings:
            det = finding.detection_name
            detection_counts[det] = detection_counts.get(det, 0) + 1
        
        return {
            "events_ingested": len(self.events),
            "findings_count": len(self.findings),
            "by_severity": severity_counts,
            "by_detection": detection_counts,
        }
    
    def clear(self) -> None:
        """Clear ingested events and findings."""
        self.events = []
        self.findings = []
