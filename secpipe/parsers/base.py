from __future__ import annotations

"""
Base Parser Interface

All log parsers inherit from this base class and implement the
parse_line method to convert source-specific formats into Events.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

from secpipe.schema import Event


class Parser(ABC):
    """
    Abstract base class for log parsers.
    
    Parsers are responsible for converting source-specific log formats
    into normalized Event objects that can be processed by detections.
    """
    
    # Subclasses must define these
    name: str = "base"
    description: str = "Base parser interface"
    supported_extensions: list[str] = []
    
    def __init__(self, options: dict | None = None):
        """
        Initialize parser with optional configuration.
        
        Args:
            options: Parser-specific configuration options
        """
        self.options = options or {}
    
    @abstractmethod
    def parse_line(self, line: str) -> Event | None:
        """
        Parse a single log line into an Event.
        
        Args:
            line: Raw log line to parse
            
        Returns:
            Event if parsing succeeds, None if line should be skipped
        """
        pass
    
    def parse_file(self, path: Path | str) -> Iterator[Event]:
        """
        Parse all lines from a file.
        
        Args:
            path: Path to log file
            
        Yields:
            Event objects for each successfully parsed line
        """
        path = Path(path)
        
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")
        
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    event = self.parse_line(line)
                    if event:
                        yield event
                except Exception as e:
                    # Log parsing errors but continue
                    if self.options.get("strict", False):
                        raise
                    # In non-strict mode, skip unparseable lines
                    continue
    
    def parse_lines(self, lines: list[str]) -> Iterator[Event]:
        """
        Parse a list of log lines.
        
        Args:
            lines: List of raw log lines
            
        Yields:
            Event objects for each successfully parsed line
        """
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            event = self.parse_line(line)
            if event:
                yield event
    
    def validate_event(self, event: Event) -> bool:
        """
        Validate an event has required fields.
        
        Override in subclasses for parser-specific validation.
        
        Args:
            event: Event to validate
            
        Returns:
            True if event is valid
        """
        return (
            event.timestamp is not None
            and event.event_type is not None
            and event.source_parser == self.name
        )


class ParserRegistry:
    """Registry of available parsers."""
    
    _parsers: dict[str, type[Parser]] = {}
    
    @classmethod
    def register(cls, parser_class: type[Parser]) -> type[Parser]:
        """
        Register a parser class.
        
        Can be used as a decorator:
            @ParserRegistry.register
            class MyParser(Parser):
                ...
        """
        cls._parsers[parser_class.name] = parser_class
        return parser_class
    
    @classmethod
    def get(cls, name: str) -> type[Parser] | None:
        """Get a parser class by name."""
        return cls._parsers.get(name)
    
    @classmethod
    def list_parsers(cls) -> list[str]:
        """List all registered parser names."""
        return list(cls._parsers.keys())
    
    @classmethod
    def create(cls, name: str, options: dict | None = None) -> Parser:
        """
        Create a parser instance by name.
        
        Args:
            name: Parser name
            options: Parser configuration options
            
        Returns:
            Parser instance
            
        Raises:
            ValueError: If parser name is not registered
        """
        parser_class = cls.get(name)
        if parser_class is None:
            available = ", ".join(cls.list_parsers())
            raise ValueError(
                f"Unknown parser: {name}. Available parsers: {available}"
            )
        return parser_class(options)
