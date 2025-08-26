"""
Unit tests for the reporting system.

This module tests report generation functionality including multiple formats
and AI-powered insights.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from code_hygiene_agent.analyzers.base import AnalysisIssue, AnalysisResult
from code_hygiene_agent.config.settings import ReportFormat
from code_hygiene_agent.reporting.generator import ReportGenerator
from code_hygiene_agent.utils.exceptions import ReportGenerationError


class TestReportGenerator:
    """Test the ReportGenerator class."""

    @pytest.fixture
    def mock_openai_client(self):
        """Create a mock OpenAI client."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content="AI generated summary"))
        ]
        mock_client.chat.completions.create.return_value = mock_response
        return mock_client

    @pytest.fixture
    def generator(self, mock_openai_client):
        """Create a ReportGenerator with mocked OpenAI client."""
        return ReportGenerator(openai_client=mock_openai_client)

    @pytest.fixture
    def sample_analysis_results(self):
        """Create comprehensive sample analysis results."""
        vulnerability_issues = [
            AnalysisIssue(
                id="vuln_001",
                title="Vulnerable dependency: requests",
                description="requests 2.25.0 has known security vulnerabilities",
                file_path="requirements.txt",
                line_number=1,
                severity="critical",
                category="security",
                analyzer="pip-audit",
                rule_id="PYSEC-2021-135",
                suggestion="Update requests to version 2.28.0 or later",
                references=["https://pypi.org/project/requests/2.28.0/"],
            ),
            AnalysisIssue(
                id="vuln_002",
                title="Vulnerable dependency: flask",
                description="flask 1.0.0 has medium severity vulnerability",
                file_path="requirements.txt",
                line_number=2,
                severity="medium",
                category="security",
                analyzer="safety",
                suggestion="Update flask to version 2.0.0 or later",
            ),
        ]

        dead_code_issues = [
            AnalysisIssue(
                id="dead_001",
                title="Unused function: old_helper",
                description="The function 'old_helper' appears to be unused (95% confidence)",
                file_path="src/utils.py",
                line_number=42,
                severity="medium",
                category="dead_code",
                analyzer="vulture",
                suggestion="Consider removing the unused function 'old_helper'",
            ),
            AnalysisIssue(
                id="dead_002",
                title="Unused import: datetime",
                description="The import 'datetime' is not used in this file",
                file_path="src/main.py",
                line_number=3,
                severity="low",
                category="unused_import",
                analyzer="ast",
                suggestion="Remove the unused import: datetime",
            ),
        ]

        return {
            "vulnerability": AnalysisResult(
                analyzer_name="vulnerability",
                project_path="/test/project",
                execution_time=2.5,
                success=True,
                issues=vulnerability_issues,
                metadata={
                    "dependency_files": ["requirements.txt"],
                    "tools_used": ["pip-audit", "safety"],
                },
            ),
            "dead_code": AnalysisResult(
                analyzer_name="dead_code",
                project_path="/test/project",
                execution_time=1.8,
                success=True,
                issues=dead_code_issues,
                metadata={"files_analyzed": 15, "tools_used": ["vulture", "ast"]},
            ),
        }

    def test_report_generator_initialization(self, generator):
        """Test report generator initialization."""
        assert generator.openai_client is not None
        assert generator.env is not None

    @pytest.mark.asyncio
    async def test_generate_markdown_report(self, generator, sample_analysis_results):
        """Test generating a markdown report."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)

            report = await generator.generate_report(
                sample_analysis_results,
                project_path,
                format_type=ReportFormat.MARKDOWN,
                include_ai_suggestions=False,
            )

            # Check report structure
            assert "# Code Hygiene Analysis Report" in report
            assert "## Executive Summary" in report
            assert "### Issues by Severity" in report
            assert "### Issues by Category" in report
            assert "## Analysis Results" in report

            # Check content
            assert "Total Issues:** 4" in report
            assert "Vulnerability Analysis" in report
            assert "Dead_Code Analysis" in report

            # Check issue details
            assert "Vulnerable dependency: requests" in report
            assert "Unused function: old_helper" in report
            assert "requirements.txt" in report
            assert "src/utils.py" in report

    @pytest.mark.asyncio
    async def test_generate_json_report(self, generator, sample_analysis_results):
        """Test generating a JSON report."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)

            report = await generator.generate_report(
                sample_analysis_results,
                project_path,
                format_type=ReportFormat.JSON,
                include_ai_suggestions=False,
            )

            # Parse JSON to verify structure
            report_data = json.loads(report)

            assert "metadata" in report_data
            assert "summary" in report_data
            assert "analysis_results" in report_data
            assert "ai_insights" in report_data

            # Check metadata
            metadata = report_data["metadata"]
            assert metadata["total_issues"] == 4
            assert len(metadata["successful_analyzers"]) == 2
            assert len(metadata["failed_analyzers"]) == 0

            # Check summary
            summary = report_data["summary"]
            assert summary["issues_by_severity"]["critical"] == 1
            assert summary["issues_by_severity"]["medium"] == 2
            assert summary["issues_by_severity"]["low"] == 1
            assert summary["issues_by_category"]["security"] == 2
            assert summary["issues_by_category"]["dead_code"] == 1
            assert summary["issues_by_category"]["unused_import"] == 1

            # Check analysis results
            assert "vulnerability" in report_data["analysis_results"]
            assert "dead_code" in report_data["analysis_results"]

            vulnerability_result = report_data["analysis_results"]["vulnerability"]
            assert vulnerability_result["success"] is True
            assert len(vulnerability_result["issues"]) == 2

    @pytest.mark.asyncio
    async def test_generate_html_report(self, generator, sample_analysis_results):
        """Test generating an HTML report."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)

            report = await generator.generate_report(
                sample_analysis_results,
                project_path,
                format_type=ReportFormat.HTML,
                include_ai_suggestions=False,
            )

            # Check HTML structure
            assert "<!DOCTYPE html>" in report
            assert '<html lang="en">' in report
            assert "<title>Code Hygiene Analysis Report</title>" in report
            assert "<h1>🧹 Code Hygiene Analysis Report</h1>" in report

            # Check content
            assert "Total Issues: <strong>4</strong>" in report
            assert "Vulnerability Analysis" in report
            assert "Dead_Code Analysis" in report

            # Check CSS styling
            assert "<style>" in report
            assert "body { font-family:" in report
            assert ".issue.critical" in report

    @pytest.mark.asyncio
    async def test_generate_report_with_ai_suggestions(
        self, generator, sample_analysis_results, mock_openai_client
    ):
        """Test generating a report with AI-powered suggestions."""
        # Mock AI responses
        mock_openai_client.chat.completions.create.side_effect = [
            # First call for summary
            MagicMock(
                choices=[
                    MagicMock(
                        message=MagicMock(
                            content="The project has critical security vulnerabilities that need immediate attention."
                        )
                    )
                ]
            ),
            # Second call for recommendations
            MagicMock(
                choices=[
                    MagicMock(
                        message=MagicMock(
                            content=json.dumps(
                                [
                                    {
                                        "title": "Update vulnerable dependencies",
                                        "priority": "critical",
                                        "description": "Several dependencies have known security vulnerabilities.",
                                        "steps": [
                                            "Update requests to 2.28.0+",
                                            "Update flask to 2.0.0+",
                                            "Run security scan again",
                                        ],
                                    }
                                ]
                            )
                        )
                    )
                ]
            ),
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)

            report = await generator.generate_report(
                sample_analysis_results, project_path, include_ai_suggestions=True
            )

            # Check AI content is included
            assert "critical security vulnerabilities" in report
            assert "🤖 AI-Powered Recommendations" in report
            assert "Update vulnerable dependencies" in report

            # Verify OpenAI was called twice (summary + recommendations)
            assert mock_openai_client.chat.completions.create.call_count == 2

    @pytest.mark.asyncio
    async def test_ai_summary_generation_failure(
        self, generator, sample_analysis_results, mock_openai_client
    ):
        """Test handling of AI summary generation failure."""
        mock_openai_client.chat.completions.create.side_effect = Exception("API error")

        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)

            # Should not raise exception, but continue without AI insights
            report = await generator.generate_report(
                sample_analysis_results, project_path, include_ai_suggestions=True
            )

            # Should have basic summary instead of AI summary
            assert "This analysis found **4** issues" in report
            assert "🤖 AI-Powered Recommendations" not in report

    def test_calculate_risk_score(self, generator):
        """Test risk score calculation."""
        # Test with various issue severities
        issues_by_severity = {
            "critical": 2,
            "high": 1,
            "medium": 3,
            "low": 5,
            "info": 2,
        }

        risk_score = generator._calculate_risk_score(issues_by_severity)

        # Expected: 2*20 + 1*10 + 3*5 + 5*2 + 2*1 = 40 + 10 + 15 + 10 + 2 = 77
        assert risk_score == 77

        # Test with no issues
        empty_issues = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        assert generator._calculate_risk_score(empty_issues) == 0

        # Test capping at 100
        high_severity_issues = {
            "critical": 10,
            "high": 10,
            "medium": 10,
            "low": 10,
            "info": 10,
        }
        assert generator._calculate_risk_score(high_severity_issues) == 100

    def test_prepare_ai_context(self, generator, sample_analysis_results):
        """Test preparing analysis context for AI processing."""
        context = generator._prepare_ai_context(sample_analysis_results)

        expected_parts = [
            "vulnerability: 2 issues",
            "Severities: critical: 1, medium: 1",
            "dead_code: 2 issues",
            "Severities: medium: 1, low: 1",
        ]

        for part in expected_parts:
            assert part in context

    @pytest.mark.asyncio
    async def test_prepare_report_data(self, generator, sample_analysis_results):
        """Test report data preparation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)

            report_data = await generator._prepare_report_data(
                sample_analysis_results, project_path, include_ai_suggestions=False
            )

            # Check metadata
            metadata = report_data["metadata"]
            assert metadata["total_issues"] == 4
            assert len(metadata["successful_analyzers"]) == 2
            assert metadata["project_path"] == str(project_path)

            # Check summary
            summary = report_data["summary"]
            assert summary["issues_by_severity"]["critical"] == 1
            assert summary["issues_by_severity"]["medium"] == 2
            assert summary["issues_by_category"]["security"] == 2
            assert summary["risk_score"] > 0

            # Check issues are collected
            assert len(report_data["issues"]) == 4

            # Check AI insights structure
            ai_insights = report_data["ai_insights"]
            assert ai_insights["enabled"] is False
            assert ai_insights["summary"] == ""
            assert ai_insights["recommendations"] == []

    @pytest.mark.asyncio
    async def test_unsupported_format_error(self, generator, sample_analysis_results):
        """Test error handling for unsupported report formats."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)

            # Test with None format_type to trigger default path and ensure error handling works
            with patch.object(
                generator,
                "_generate_markdown_report",
                side_effect=Exception("Test error"),
            ):
                with pytest.raises(ReportGenerationError):
                    await generator.generate_report(
                        sample_analysis_results,
                        project_path,
                        format_type=ReportFormat.MARKDOWN,
                    )

    @pytest.mark.asyncio
    async def test_failed_analysis_results(self, generator):
        """Test report generation with failed analysis results."""
        failed_results = {
            "vulnerability": AnalysisResult(
                analyzer_name="vulnerability",
                project_path="/test/project",
                execution_time=0.5,
                success=False,
                issues=[],
                error_message="Tool not found: pip-audit",
            ),
            "dead_code": AnalysisResult(
                analyzer_name="dead_code",
                project_path="/test/project",
                execution_time=1.0,
                success=True,
                issues=[],
            ),
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)

            report = await generator.generate_report(
                failed_results, project_path, include_ai_suggestions=False
            )

            # Should still generate report with error information
            assert "❌ Failed" in report
            assert "Tool not found: pip-audit" in report
            assert "✅ Success" in report  # dead_code succeeded


if __name__ == "__main__":
    pytest.main([__file__])
