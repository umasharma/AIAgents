"""
Analyzer registry for managing and coordinating different code analyzers.

This module provides a centralized registry for all analyzers and
coordinates their execution.
"""

import asyncio
from pathlib import Path

from ..config.settings import settings
from ..utils.exceptions import AnalysisError, AnalyzerNotFoundError
from ..utils.logging import get_logger
from .base import AnalysisResult, BaseAnalyzer
from .dead_code import DeadCodeAnalyzer
from .vulnerability import VulnerabilityAnalyzer

logger = get_logger(__name__)


class AnalyzerRegistry:
    """Registry for managing code analyzers."""

    def __init__(self) -> None:
        self._analyzers: dict[str, BaseAnalyzer] = {}
        self._register_default_analyzers()

    def register(self, analyzer: BaseAnalyzer) -> None:
        """
        Register an analyzer in the registry.

        Args:
            analyzer: Analyzer instance to register
        """
        self._analyzers[analyzer.name] = analyzer
        logger.info("Registered analyzer", analyzer=analyzer.name)

    def unregister(self, name: str) -> None:
        """
        Unregister an analyzer from the registry.

        Args:
            name: Name of the analyzer to unregister
        """
        if name in self._analyzers:
            del self._analyzers[name]
            logger.info("Unregistered analyzer", analyzer=name)

    def get_analyzer(self, name: str) -> BaseAnalyzer:
        """
        Get an analyzer by name.

        Args:
            name: Name of the analyzer

        Returns:
            The requested analyzer

        Raises:
            AnalyzerNotFoundError: If analyzer is not found
        """
        if name not in self._analyzers:
            raise AnalyzerNotFoundError(f"Analyzer '{name}' not found")
        return self._analyzers[name]

    def list_analyzers(self) -> list[str]:
        """Get list of registered analyzer names."""
        return list(self._analyzers.keys())

    def get_enabled_analyzers(self) -> list[BaseAnalyzer]:
        """Get list of enabled analyzers based on configuration."""
        enabled = []
        enabled_names = settings.get_enabled_analyzers()

        for name in enabled_names:
            if name in self._analyzers:
                enabled.append(self._analyzers[name])
            else:
                logger.warning("Enabled analyzer not found in registry", analyzer=name)

        return enabled

    async def check_analyzer_availability(self, name: str) -> dict[str, bool]:
        """
        Check tool availability for a specific analyzer.

        Args:
            name: Name of the analyzer

        Returns:
            Dict mapping tool names to availability status
        """
        analyzer = self.get_analyzer(name)
        return await analyzer.check_tool_availability()

    async def check_all_availability(self) -> dict[str, dict[str, bool]]:
        """Check tool availability for all registered analyzers."""
        availability = {}

        for name, analyzer in self._analyzers.items():
            try:
                availability[name] = await analyzer.check_tool_availability()
            except Exception as e:
                logger.error(
                    "Failed to check analyzer availability", analyzer=name, error=str(e)
                )
                availability[name] = dict.fromkeys(analyzer.required_tools, False)

        return availability

    async def analyze_project(
        self,
        project_path: Path,
        analyzer_names: list[str] | None = None,
        max_concurrent: int | None = None,
    ) -> dict[str, AnalysisResult]:
        """
        Run multiple analyzers on a project.

        Args:
            project_path: Path to project root
            analyzer_names: Specific analyzers to run (defaults to enabled analyzers)
            max_concurrent: Maximum concurrent analyzers (defaults to settings)

        Returns:
            Dict mapping analyzer names to their results
        """
        if analyzer_names is None:
            analyzers = self.get_enabled_analyzers()
        else:
            analyzers = [self.get_analyzer(name) for name in analyzer_names]

        if not analyzers:
            logger.warning("No analyzers to run")
            return {}

        if max_concurrent is None:
            max_concurrent = settings.analysis.max_concurrent_scans

        logger.info(
            "Starting project analysis",
            project_path=str(project_path),
            analyzers=[a.name for a in analyzers],
            max_concurrent=max_concurrent,
        )

        # Create semaphore to limit concurrent analyzers
        semaphore = asyncio.Semaphore(max_concurrent)

        async def run_analyzer(analyzer: BaseAnalyzer) -> tuple[str, AnalysisResult]:
            """Run a single analyzer with semaphore protection."""
            async with semaphore:
                try:
                    result = await analyzer.analyze(project_path)
                    return analyzer.name, result
                except Exception as e:
                    logger.error(
                        "Analyzer failed",
                        analyzer=analyzer.name,
                        error=str(e),
                        error_type=type(e).__name__,
                    )
                    # Create a failed result
                    failed_result = AnalysisResult(
                        analyzer_name=analyzer.name,
                        project_path=str(project_path),
                        execution_time=0.0,
                        success=False,
                        error_message=str(e),
                    )
                    return analyzer.name, failed_result

        # Run analyzers concurrently
        tasks = [run_analyzer(analyzer) for analyzer in analyzers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        analysis_results = {}
        for result in results:
            if isinstance(result, Exception):
                logger.error("Task failed with exception", error=str(result))
                continue

            analyzer_name, analysis_result = result
            analysis_results[analyzer_name] = analysis_result

        logger.info(
            "Project analysis completed",
            project_path=str(project_path),
            results_count=len(analysis_results),
            successful_analyzers=[
                name for name, result in analysis_results.items() if result.success
            ],
            failed_analyzers=[
                name for name, result in analysis_results.items() if not result.success
            ],
        )

        return analysis_results

    def _register_default_analyzers(self) -> None:
        """Register the default set of analyzers."""
        try:
            # Register vulnerability analyzer
            vulnerability_analyzer = VulnerabilityAnalyzer()
            self.register(vulnerability_analyzer)

            # Register dead code analyzer
            dead_code_analyzer = DeadCodeAnalyzer()
            self.register(dead_code_analyzer)

        except Exception as e:
            logger.error("Failed to register default analyzers", error=str(e))
            raise AnalysisError(
                "Failed to initialize analyzer registry", cause=e
            ) from e


# Global registry instance
registry = AnalyzerRegistry()
