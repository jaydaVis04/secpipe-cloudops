from __future__ import annotations

"""
Base Output Interface

All output sinks inherit from this base class and implement
the write method to export findings to various formats.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from secpipe.schema import Finding


class Output(ABC):
    """
    Abstract base class for output sinks.
    
    Outputs are responsible for exporting findings to various formats
    and destinations (files, databases, webhooks, etc.).
    """
    
    name: str = "base"
    description: str = "Base output interface"
    
    def __init__(self, options: dict | None = None):
        """
        Initialize output with configuration.
        
        Args:
            options: Output-specific configuration
        """
        self.options = options or {}
    
    @abstractmethod
    def write(self, findings: list[Finding]) -> None:
        """
        Write findings to the output destination.
        
        Args:
            findings: List of findings to export
        """
        pass
    
    def write_single(self, finding: Finding) -> None:
        """Write a single finding."""
        self.write([finding])
    
    def close(self) -> None:
        """Close output resources (override if needed)."""
        pass
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class OutputRegistry:
    """Registry of available outputs."""
    
    _outputs: dict[str, type[Output]] = {}
    
    @classmethod
    def register(cls, output_class: type[Output]) -> type[Output]:
        """Register an output class."""
        cls._outputs[output_class.name] = output_class
        return output_class
    
    @classmethod
    def get(cls, name: str) -> type[Output] | None:
        """Get an output class by name."""
        return cls._outputs.get(name)
    
    @classmethod
    def list_outputs(cls) -> list[str]:
        """List all registered output names."""
        return list(cls._outputs.keys())
    
    @classmethod
    def create(cls, name: str, options: dict | None = None) -> Output:
        """Create an output instance by name."""
        output_class = cls.get(name)
        if output_class is None:
            available = ", ".join(cls.list_outputs())
            raise ValueError(
                f"Unknown output: {name}. Available: {available}"
            )
        return output_class(options)
