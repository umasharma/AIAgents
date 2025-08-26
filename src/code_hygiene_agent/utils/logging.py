"""
Logging configuration and utilities for the Code Hygiene Agent.

This module provides structured logging using structlog with support for
both JSON and text output formats.
"""

import logging
import sys
from typing import Any

import structlog
from structlog.stdlib import LoggerFactory

from ..config.settings import LogFormat, LogLevel, settings


def configure_logging(
    level: LogLevel | None = None,
    format_type: LogFormat | None = None,
    logger_name: str = "code_hygiene_agent",
) -> structlog.stdlib.BoundLogger:
    """
    Configure structured logging for the application.

    Args:
        level: Logging level override
        format_type: Log format override
        logger_name: Name for the logger

    Returns:
        Configured structlog logger
    """
    # Use settings defaults if not overridden
    log_level = level or settings.log_level
    log_format = format_type or settings.log_format

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.value),
    )

    # Set up processors based on format
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.CallsiteParameterAdder(
            [
                structlog.processors.CallsiteParameter.FUNC_NAME,
                structlog.processors.CallsiteParameter.FILENAME,
                structlog.processors.CallsiteParameter.LINENO,
            ]
        ),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
    ]

    if log_format == LogFormat.JSON:
        processors.extend(
            [structlog.processors.format_exc_info, structlog.processors.JSONRenderer()]
        )
    else:
        processors.extend(
            [
                structlog.processors.format_exc_info,
                structlog.dev.ConsoleRenderer(colors=True),
            ]
        )

    # Configure structlog
    structlog.configure(
        processors=processors,
        logger_factory=LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    return structlog.get_logger(logger_name)


def get_logger(name: str = "code_hygiene_agent") -> structlog.stdlib.BoundLogger:
    """Get a configured logger instance."""
    return structlog.get_logger(name)


class LogContext:
    """Context manager for adding structured context to logs."""

    def __init__(self, **context: Any) -> None:
        self.context = context
        self.token: object | None = None

    def __enter__(self) -> "LogContext":
        self.token = structlog.contextvars.bind_contextvars(**self.context)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.token:
            structlog.contextvars.unbind_contextvars(*self.context.keys())


def log_analysis_start(
    logger: structlog.stdlib.BoundLogger,
    analyzer_name: str,
    project_path: str,
    **kwargs: Any,
) -> None:
    """Log the start of an analysis operation."""
    logger.info(
        "Starting code analysis",
        analyzer=analyzer_name,
        project_path=project_path,
        **kwargs,
    )


def log_analysis_complete(
    logger: structlog.stdlib.BoundLogger,
    analyzer_name: str,
    duration: float,
    issues_found: int,
    **kwargs: Any,
) -> None:
    """Log the completion of an analysis operation."""
    logger.info(
        "Analysis completed",
        analyzer=analyzer_name,
        duration_seconds=duration,
        issues_found=issues_found,
        **kwargs,
    )


def log_analysis_error(
    logger: structlog.stdlib.BoundLogger,
    analyzer_name: str,
    error: Exception,
    **kwargs: Any,
) -> None:
    """Log an error during analysis."""
    logger.error(
        "Analysis failed",
        analyzer=analyzer_name,
        error=str(error),
        error_type=type(error).__name__,
        **kwargs,
    )


def log_github_operation(
    logger: structlog.stdlib.BoundLogger, operation: str, repo: str, **kwargs: Any
) -> None:
    """Log a GitHub API operation."""
    logger.info("GitHub operation", operation=operation, repository=repo, **kwargs)


def log_mcp_request(
    logger: structlog.stdlib.BoundLogger,
    tool_name: str,
    parameters: dict[str, Any],
    **kwargs: Any,
) -> None:
    """Log an MCP tool request."""
    logger.info("MCP tool request", tool=tool_name, parameters=parameters, **kwargs)


# Initialize default logger
logger = configure_logging()
