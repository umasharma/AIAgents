"""
Base analyzer framework for the Code Hygiene Agent.

This module provides the abstract base class and common functionality
for all code analyzers.
"""

import asyncio
import subprocess
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from ..config.settings import settings
from ..utils.exceptions import AnalysisError, TimeoutError
from ..utils.logging import get_logger

logger = get_logger(__name__)


class AnalysisIssue(BaseModel):
    """Represents a single analysis issue found during scanning."""

    id: str
    title: str
    description: str
    file_path: str | None = None
    line_number: int | None = None
    column_number: int | None = None
    severity: str  # "critical", "high", "medium", "low", "info"
    category: str  # "security", "quality", "performance", "maintainability"
    analyzer: str
    rule_id: str | None = None
    suggestion: str | None = None
    references: list[str] = []

    class Config:
        schema_extra = {
            "example": {
                "id": "bandit_B101_001",
                "title": "Use of assert detected",
                "description": "Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.",
                "file_path": "src/main.py",
                "line_number": 42,
                "column_number": 4,
                "severity": "low",
                "category": "quality",
                "analyzer": "bandit",
                "rule_id": "B101",
                "suggestion": "Consider using proper exception handling instead of assert statements.",
                "references": [
                    "https://bandit.readthedocs.io/en/latest/plugins/b101_assert_used.html"
                ],
            }
        }


class AnalysisResult(BaseModel):
    """Contains the complete results from an analyzer."""

    analyzer_name: str
    project_path: str
    execution_time: float
    success: bool
    issues: list[AnalysisIssue] = []
    metadata: dict[str, Any] = {}
    error_message: str | None = None

    @property
    def issue_count_by_severity(self) -> dict[str, int]:
        """Get count of issues by severity level."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for issue in self.issues:
            counts[issue.severity] = counts.get(issue.severity, 0) + 1
        return counts

    @property
    def total_issues(self) -> int:
        """Get total number of issues found."""
        return len(self.issues)


class BaseAnalyzer(ABC):
    """Abstract base class for all code analyzers."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.logger = get_logger(f"{__name__}.{name}")

    @property
    @abstractmethod
    def required_tools(self) -> list[str]:
        """List of external tools required by this analyzer."""
        pass

    @property
    @abstractmethod
    def supported_file_types(self) -> list[str]:
        """List of file extensions this analyzer can process."""
        pass

    @abstractmethod
    async def analyze(self, project_path: Path) -> AnalysisResult:
        """
        Perform analysis on the given project path.

        Args:
            project_path: Path to the project root

        Returns:
            AnalysisResult containing findings

        Raises:
            AnalysisError: If analysis fails
        """
        pass

    async def check_tool_availability(self) -> dict[str, bool]:
        """
        Check if required external tools are available.

        Returns:
            Dict mapping tool names to availability status
        """
        availability = {}

        for tool in self.required_tools:
            try:
                result = await self._run_command([tool, "--version"], timeout=10)
                availability[tool] = result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                availability[tool] = False

        return availability

    async def _run_command(
        self,
        command: list[str],
        cwd: Path | None = None,
        timeout: int | None = None,
        capture_output: bool = True,
        check: bool = False,
    ) -> subprocess.CompletedProcess:
        """
        Run a subprocess command asynchronously.

        Args:
            command: Command and arguments to run
            cwd: Working directory for the command
            timeout: Timeout in seconds (defaults to analysis timeout from settings)
            capture_output: Whether to capture stdout/stderr
            check: Whether to raise exception on non-zero exit code

        Returns:
            CompletedProcess result

        Raises:
            TimeoutError: If command times out
            AnalysisError: If command fails and check=True
        """
        if timeout is None:
            timeout = settings.analysis.analysis_timeout

        self.logger.debug(
            "Running command",
            command=" ".join(command),
            cwd=str(cwd) if cwd else None,
            timeout=timeout,
        )

        try:
            if capture_output:
                result = await asyncio.create_subprocess_exec(
                    *command,
                    cwd=cwd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    result.communicate(), timeout=timeout
                )

                completed_process = subprocess.CompletedProcess(
                    args=command,
                    returncode=result.returncode,
                    stdout=stdout,
                    stderr=stderr,
                )
            else:
                result = await asyncio.create_subprocess_exec(*command, cwd=cwd)
                await asyncio.wait_for(result.wait(), timeout=timeout)

                completed_process = subprocess.CompletedProcess(
                    args=command, returncode=result.returncode
                )

            if check and completed_process.returncode != 0:
                error_msg = (
                    completed_process.stderr.decode("utf-8")
                    if completed_process.stderr
                    else "Command failed"
                )
                raise AnalysisError(
                    f"Command failed: {' '.join(command)}",
                    details={
                        "error_output": error_msg,
                        "return_code": completed_process.returncode,
                    },
                )

            return completed_process

        except asyncio.TimeoutError as e:
            raise TimeoutError(
                f"Command timed out after {timeout} seconds: {' '.join(command)}"
            ) from e
        except Exception as e:
            raise AnalysisError(
                f"Failed to run command: {' '.join(command)}", cause=e
            ) from e

    def _filter_files(self, project_path: Path) -> list[Path]:
        """
        Filter files in the project based on supported file types and patterns.

        Args:
            project_path: Root path of the project

        Returns:
            List of files to analyze
        """
        files = []

        for pattern in settings.analysis.include_patterns:
            files.extend(project_path.glob(pattern))

        # Filter out excluded patterns
        filtered_files = []
        for file_path in files:
            should_exclude = False
            for exclude_pattern in settings.analysis.exclude_patterns:
                if file_path.match(exclude_pattern):
                    should_exclude = True
                    break

            if not should_exclude and file_path.suffix in self.supported_file_types:
                filtered_files.append(file_path)

        return filtered_files

    def _create_base_result(
        self, project_path: Path, start_time: float
    ) -> AnalysisResult:
        """Create a base AnalysisResult with common metadata."""
        return AnalysisResult(
            analyzer_name=self.name,
            project_path=str(project_path),
            execution_time=time.time() - start_time,
            success=False,
        )
