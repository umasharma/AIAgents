"""
Custom exceptions for the Code Hygiene Agent.

This module defines the exception hierarchy used throughout the application
for better error handling and debugging.
"""

from typing import Any


class CodeHygieneError(Exception):
    """Base exception for all Code Hygiene Agent errors."""

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.cause = cause


class ConfigurationError(CodeHygieneError):
    """Raised when there's an issue with configuration."""

    pass


class AnalysisError(CodeHygieneError):
    """Base exception for analysis-related errors."""

    pass


class VulnerabilityScannError(AnalysisError):
    """Raised when vulnerability scanning fails."""

    pass


class DeadCodeAnalysisError(AnalysisError):
    """Raised when dead code analysis fails."""

    pass


class ReportGenerationError(CodeHygieneError):
    """Raised when report generation fails."""

    pass


class GitHubIntegrationError(CodeHygieneError):
    """Raised when GitHub API operations fail."""

    pass


class RepositoryError(CodeHygieneError):
    """Raised when repository operations (clone, checkout, etc.) fail."""

    pass


class MCPServerError(CodeHygieneError):
    """Raised when MCP server operations fail."""

    pass


class AnalyzerNotFoundError(CodeHygieneError):
    """Raised when a requested analyzer is not registered."""

    pass


class InvalidProjectStructureError(AnalysisError):
    """Raised when project structure is invalid for analysis."""

    pass


class TimeoutError(CodeHygieneError):
    """Raised when operations timeout."""

    pass
