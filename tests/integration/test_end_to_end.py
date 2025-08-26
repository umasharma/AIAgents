"""
Integration tests for end-to-end workflows.

This module tests complete workflows from analysis to reporting
with real external tools where possible.
"""

import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from code_hygiene_agent.config.settings import ReportFormat
from code_hygiene_agent.mcp_server.server import CodeHygieneAgent


class TestEndToEndWorkflows:
    """Test complete end-to-end workflows."""

    @pytest.fixture
    def sample_project(self):
        """Create a sample Python project for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)

            # Create requirements.txt with potentially vulnerable packages
            requirements_file = project_path / "requirements.txt"
            requirements_file.write_text(
                """
# This is for testing purposes only
requests==2.25.0
flask==1.1.0
numpy==1.19.0
            """.strip()
            )

            # Create Python files with dead code
            src_dir = project_path / "src"
            src_dir.mkdir()

            # Main file with unused imports
            main_file = src_dir / "main.py"
            main_file.write_text("""
import os
import sys
import unused_module
import json

def used_function():
    \"\"\"This function is used.\"\"\"
    return json.dumps({"message": "hello"})

def unused_function():
    \"\"\"This function is never called.\"\"\"
    return "unused"

class UsedClass:
    def __init__(self):
        self.data = used_function()

class UnusedClass:
    \"\"\"This class is never instantiated.\"\"\"

    def method(self):
        return "unused"

if __name__ == "__main__":
    obj = UsedClass()
    print(obj.data)
            """)

            # Utils file with more dead code
            utils_file = src_dir / "utils.py"
            utils_file.write_text("""
import datetime
import math

def helper_function(x):
    \"\"\"This is used by main.py (simulated).\"\"\"
    return math.sqrt(x)

def unused_helper():
    \"\"\"This helper is never used.\"\"\"
    return datetime.now()

UNUSED_CONSTANT = "this is not used"
USED_CONSTANT = "this might be used"
            """)

            # Test file (should be excluded from dead code analysis)
            test_dir = project_path / "tests"
            test_dir.mkdir()
            test_file = test_dir / "test_main.py"
            test_file.write_text("""
import unittest
from src.main import used_function

class TestMain(unittest.TestCase):
    def test_used_function(self):
        result = used_function()
        self.assertIn("hello", result)
            """)

            # Project metadata files
            pyproject_file = project_path / "pyproject.toml"
            pyproject_file.write_text("""
[project]
name = "sample-project"
version = "0.1.0"
dependencies = [
    "click>=8.0.0",
    "pydantic>=1.8.0"
]
            """)

            yield project_path

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.slow
    async def test_complete_analysis_workflow(self, sample_project):
        """Test complete analysis workflow without external dependencies."""
        agent = CodeHygieneAgent()

        # Mock external tool calls to avoid requiring actual installations
        with patch(
            "code_hygiene_agent.analyzers.vulnerability.VulnerabilityAnalyzer._run_command"
        ) as mock_vuln_cmd:
            with patch(
                "code_hygiene_agent.analyzers.vulnerability.VulnerabilityAnalyzer._tool_available",
                return_value=True,
            ):
                with patch(
                    "code_hygiene_agent.analyzers.dead_code.DeadCodeAnalyzer._run_command"
                ) as mock_dead_cmd:
                    # Mock pip-audit returning vulnerabilities
                    mock_vuln_output = {
                        "vulnerabilities": [
                            {
                                "package": "requests",
                                "installed_version": "2.25.0",
                                "specs": [
                                    {
                                        "id": "PYSEC-2021-135",
                                        "details": "requests before 2.26.0 vulnerable to dependency confusion",
                                        "fix_versions": ["2.26.0"],
                                    }
                                ],
                            }
                        ]
                    }

                    mock_vuln_cmd.return_value.returncode = 1
                    mock_vuln_cmd.return_value.stdout = json.dumps(
                        mock_vuln_output
                    ).encode()
                    mock_vuln_cmd.return_value.stderr = b""

                    # Mock vulture output
                    mock_dead_output = """
src/main.py:3: unused import 'unused_module' (90% confidence)
src/main.py:11: unused function 'unused_function' (95% confidence)
src/main.py:19: unused class 'UnusedClass' (85% confidence)
src/utils.py:2: unused import 'datetime' (80% confidence)
src/utils.py:9: unused function 'unused_helper' (90% confidence)
                    """.strip()

                    mock_dead_cmd.return_value.returncode = 0
                    mock_dead_cmd.return_value.stdout = mock_dead_output.encode()
                    mock_dead_cmd.return_value.stderr = b""

                    # Run the analysis
                    result = await agent.analyze_project(
                        str(sample_project),
                        analyzers=["vulnerability", "dead_code"],
                        create_pr=False,
                    )

                    # Verify results
                    assert result["success"] is True
                    assert result["total_issues"] > 0
                    assert "vulnerability" in result["analysis_results"]
                    assert "dead_code" in result["analysis_results"]

                    # Check vulnerability results
                    vuln_result = result["analysis_results"]["vulnerability"]
                    assert vuln_result["success"] is True
                    assert vuln_result["issues_count"] >= 1

                    # Check dead code results
                    dead_result = result["analysis_results"]["dead_code"]
                    assert dead_result["success"] is True
                    assert (
                        dead_result["issues_count"] >= 5
                    )  # At least the mocked vulture results

                    # Verify report was generated
                    assert "report" in result
                    assert len(result["report"]) > 100  # Non-trivial report content
                    assert "Code Hygiene Analysis Report" in result["report"]

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_tool_availability_check(self):
        """Test checking availability of external tools."""
        agent = CodeHygieneAgent()

        availability = await agent.check_tool_availability()

        # Should check all registered analyzers
        assert "vulnerability" in availability
        assert "dead_code" in availability

        # Each analyzer should report tool availability
        for _analyzer_name, tools in availability.items():
            assert isinstance(tools, dict)
            for _tool_name, is_available in tools.items():
                assert isinstance(is_available, bool)

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_analyzer_registry_operations(self):
        """Test analyzer registry functionality."""
        agent = CodeHygieneAgent()
        registry = agent.analyzer_registry

        # Check default analyzers are registered
        analyzers = registry.list_analyzers()
        assert "vulnerability" in analyzers
        assert "dead_code" in analyzers

        # Test getting analyzer info
        info = agent.get_analyzer_info()
        assert "vulnerability" in info
        assert "dead_code" in info

        for _name, analyzer_info in info.items():
            assert "name" in analyzer_info
            assert "required_tools" in analyzer_info
            assert "supported_file_types" in analyzer_info
            assert "enabled" in analyzer_info

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_error_handling_and_recovery(self, sample_project):
        """Test error handling when tools are unavailable."""
        agent = CodeHygieneAgent()

        # Mock one analyzer failing and one succeeding
        with patch(
            "code_hygiene_agent.analyzers.vulnerability.VulnerabilityAnalyzer.analyze"
        ) as mock_vuln:
            with patch(
                "code_hygiene_agent.analyzers.dead_code.DeadCodeAnalyzer.analyze"
            ) as mock_dead:
                # Mock vulnerability analyzer failure
                mock_vuln.side_effect = Exception("Tool not found: pip-audit")

                # Mock dead code analyzer success
                from code_hygiene_agent.analyzers.base import AnalysisResult

                mock_dead.return_value = AnalysisResult(
                    analyzer_name="dead_code",
                    project_path=str(sample_project),
                    execution_time=1.0,
                    success=True,
                    issues=[],
                )

                # Should handle partial failure gracefully
                result = await agent.analyze_project(
                    str(sample_project),
                    analyzers=["vulnerability", "dead_code"],
                    create_pr=False,
                )

                # Analysis should still succeed overall
                assert result["success"] is True
                assert len(result["analyzers"]["failed"]) == 1
                assert len(result["analyzers"]["successful"]) == 1
                assert "vulnerability" in result["analyzers"]["failed"]
                assert "dead_code" in result["analyzers"]["successful"]

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_report_generation_formats(self, sample_project):
        """Test generating reports in different formats."""
        agent = CodeHygieneAgent()

        # Create sample analysis results
        from code_hygiene_agent.analyzers.base import AnalysisIssue, AnalysisResult

        sample_issues = [
            AnalysisIssue(
                id="test_001",
                title="Test vulnerability",
                description="A test security issue",
                severity="high",
                category="security",
                analyzer="test",
            )
        ]

        analysis_results = {
            "test": AnalysisResult(
                analyzer_name="test",
                project_path=str(sample_project),
                execution_time=1.0,
                success=True,
                issues=sample_issues,
            )
        }

        # Test Markdown format
        markdown_report = await agent.report_generator.generate_report(
            analysis_results,
            sample_project,
            format_type=ReportFormat.MARKDOWN,
            include_ai_suggestions=False,
        )

        assert "# Code Hygiene Analysis Report" in markdown_report
        assert "Test vulnerability" in markdown_report
        assert "## Analysis Results" in markdown_report

        # Test JSON format
        json_report = await agent.report_generator.generate_report(
            analysis_results,
            sample_project,
            format_type=ReportFormat.JSON,
            include_ai_suggestions=False,
        )

        import json

        report_data = json.loads(json_report)
        assert "metadata" in report_data
        assert "analysis_results" in report_data
        assert report_data["metadata"]["total_issues"] == 1

        # Test HTML format
        html_report = await agent.report_generator.generate_report(
            analysis_results,
            sample_project,
            format_type=ReportFormat.HTML,
            include_ai_suggestions=False,
        )

        assert "<!DOCTYPE html>" in html_report
        assert "<title>Code Hygiene Analysis Report</title>" in html_report
        assert "Test vulnerability" in html_report

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.slow
    async def test_concurrent_analysis_execution(self, sample_project):
        """Test that multiple analyzers can run concurrently."""
        import time

        agent = CodeHygieneAgent()

        # Mock both analyzers with delays to test concurrency
        async def mock_slow_analyze(self, project_path):
            await asyncio.sleep(0.5)  # Simulate work
            from code_hygiene_agent.analyzers.base import AnalysisResult

            return AnalysisResult(
                analyzer_name=self.name,
                project_path=str(project_path),
                execution_time=0.5,
                success=True,
                issues=[],
            )

        with patch(
            "code_hygiene_agent.analyzers.vulnerability.VulnerabilityAnalyzer.analyze",
            mock_slow_analyze,
        ):
            with patch(
                "code_hygiene_agent.analyzers.dead_code.DeadCodeAnalyzer.analyze",
                mock_slow_analyze,
            ):
                start_time = time.time()

                result = await agent.analyze_project(
                    str(sample_project),
                    analyzers=["vulnerability", "dead_code"],
                    create_pr=False,
                )

                end_time = time.time()

                # Should complete in less time than sequential execution
                # (2 analyzers × 0.5s each = 1s sequential, but concurrent should be ~0.5s)
                assert (end_time - start_time) < 0.8  # Allow some overhead

                assert result["success"] is True
                assert len(result["analyzers"]["successful"]) == 2


# Mark this module for integration testing
pytest.mark.integration(TestEndToEndWorkflows)
