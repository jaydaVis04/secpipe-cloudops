"""
JSONL Output

Exports findings as newline-delimited JSON (JSONL/NDJSON format).
Suitable for streaming processing and log aggregation systems.
"""

import json
from pathlib import Path
from datetime import datetime

from secpipe.outputs.base import Output, OutputRegistry
from secpipe.schema import Finding


@OutputRegistry.register
class JSONLOutput(Output):
    """
    Export findings to JSONL format.
    
    Each finding is written as a single JSON line, making the output
    suitable for streaming processing and ingestion by log systems.
    """
    
    name = "jsonl"
    description = "Newline-delimited JSON output"
    
    def __init__(self, options: dict | None = None):
        super().__init__(options)
        self.path = Path(options.get("path", "findings.jsonl")) if options else Path("findings.jsonl")
        self.append = options.get("append", False) if options else False
        self._file = None
    
    def write(self, findings: list[Finding]) -> None:
        """Write findings to JSONL file."""
        mode = "a" if self.append else "w"
        
        # Ensure parent directory exists
        self.path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.path, mode, encoding="utf-8") as f:
            for finding in findings:
                data = finding.to_dict()
                # Add export metadata
                data["_exported_at"] = datetime.now().isoformat()
                f.write(json.dumps(data, default=str) + "\n")
    
    def write_streaming(self, finding: Finding) -> None:
        """Write a single finding in streaming mode."""
        if self._file is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._file = open(self.path, "a" if self.append else "w", encoding="utf-8")
        
        data = finding.to_dict()
        data["_exported_at"] = datetime.now().isoformat()
        self._file.write(json.dumps(data, default=str) + "\n")
        self._file.flush()
    
    def close(self) -> None:
        """Close streaming file handle."""
        if self._file:
            self._file.close()
            self._file = None
