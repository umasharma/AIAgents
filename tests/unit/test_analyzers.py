"""
Unit tests for analyzer modules.

This module tests the core analyzer functionality including vulnerability
scanning and dead code detection.
"""

import asyncio
import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from code_hygiene_agent.analyzers.base import (
    AnalysisIssue,
    AnalysisResult,
    BaseAnalyzer,
)
from code_hygiene_agent.analyzers.dead_code import DeadCodeAnalyzer
from code_hygiene_agent.analyzers.registry import AnalyzerRegistry
from code_hygiene_agent.analyzers.vulnerability import VulnerabilityAnalyzer
from code_hygiene_agent.utils.exceptions import (
    AnalysisError,
    VulnerabilityScannError,
)


class TestAnalysisIssue:
    """Test the AnalysisIssue model."""

    def test_analysis_issue_creation(self):
        """Test creating an AnalysisIssue with all fields."""
        issue = AnalysisIssue(
            id="test_001",
            title="Test Issue",
            description="A test issue description",
            file_path="test.py",
            line_number=42,
            column_number=10,
            severity="high",
            category="security",
            analyzer="test_analyzer",
            rule_id="TEST001",
            suggestion="Fix this issue",
            references=["https://example.com"],
        )

        assert issue.id == "test_001"
        assert issue.title == "Test Issue"
        assert issue.severity == "high"
        assert issue.category == "security"
        assert issue.analyzer == "test_analyzer"
        assert issue.line_number == 42
        assert len(issue.references) == 1

    def test_analysis_issue_minimal(self):
        """Test creating an AnalysisIssue with minimal required fields."""
        issue = AnalysisIssue(
            id="minimal_001",
            title="Minimal Issue",
            description="Minimal test issue",
            severity="low",
            category="quality",
            analyzer="test_analyzer",
        )

        assert issue.id == "minimal_001"
        assert issue.file_path is None
        assert issue.line_number is None
        assert issue.suggestion is None
        assert issue.references == []


class TestAnalysisResult:
    """Test the AnalysisResult model."""

    def test_analysis_result_creation(self):
        """Test creating an AnalysisResult."""
        issues = [
            AnalysisIssue(
                id="issue1",
                title="Issue 1",
                description="First issue",
                severity="critical",
                category="security",
                analyzer="test",
            ),
            AnalysisIssue(
                id="issue2",
                title="Issue 2",
                description="Second issue",
                severity="medium",
                category="quality",
                analyzer="test",
            ),
        ]

        result = AnalysisResult(
            analyzer_name="test_analyzer",
            project_path="/test/path",
            execution_time=1.5,
            success=True,
            issues=issues,
        )

        assert result.analyzer_name == "test_analyzer"
        assert result.success is True
        assert len(result.issues) == 2
        assert result.total_issues == 2

        severity_counts = result.issue_count_by_severity
        assert severity_counts["critical"] == 1
        assert severity_counts["medium"] == 1
        assert severity_counts["high"] == 0


class TestBaseAnalyzer:
    """Test the BaseAnalyzer base class."""

    def test_base_analyzer_instantiation(self):
        """Test that BaseAnalyzer cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseAnalyzer("test")

    @patch("asyncio.create_subprocess_exec")
    def test_run_command_success(self, mock_create_subprocess):
        """Test successful command execution."""

        # Create a concrete analyzer for testing
        class TestAnalyzer(BaseAnalyzer):
            @property
            def required_tools(self):
                return ["test-tool"]

            @property
            def supported_file_types(self):
                return [".py"]

            async def analyze(self, project_path):
                pass

        analyzer = TestAnalyzer("test")

        # Mock the subprocess
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"success output", b"")
        mock_process.returncode = 0
        mock_create_subprocess.return_value = mock_process

        async def test_run():
            result = await analyzer._run_command(["test", "command"])
            assert result.returncode == 0
            assert result.stdout == b"success output"

        asyncio.run(test_run())


class TestVulnerabilityAnalyzer:
    """Test the VulnerabilityAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        """Create a VulnerabilityAnalyzer instance for testing."""
        return VulnerabilityAnalyzer()

    @pytest.fixture
    def temp_project(self):
        """Create a temporary project directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)

            # Create requirements.txt
            requirements_file = project_path / "requirements.txt"
            requirements_file.write_text(
                "requests==2.25.0\nflask==1.1.0\ndjango==3.0.0\n"
            )

            # Create pyproject.toml
            pyproject_file = project_path / "pyproject.toml"
            pyproject_file.write_text("""
[project]
dependencies = [
    "numpy==1.21.0",
    "pandas==1.3.0"
]
            """)

            yield project_path

    def test_analyzer_properties(self, analyzer):
        """Test analyzer properties."""
        assert analyzer.name == "vulnerability"
        assert "pip-audit" in analyzer.required_tools
        assert ".txt" in analyzer.supported_file_types
        assert ".toml" in analyzer.supported_file_types

    def test_find_dependency_files(self, analyzer, temp_project):
        """Test finding dependency files in a project."""
        dependency_files = analyzer._find_dependency_files(temp_project)

        file_names = [f.name for f in dependency_files]
        assert "requirements.txt" in file_names
        assert "pyproject.toml" in file_names

    @pytest.mark.asyncio
    @patch.object(VulnerabilityAnalyzer, "_run_command")
    @patch.object(VulnerabilityAnalyzer, "_tool_available")
    async def test_analyze_success(
        self, mock_tool_available, mock_run_command, analyzer, temp_project
    ):
        """Test successful vulnerability analysis."""
        # Mock tool availability
        mock_tool_available.return_value = True

        # Mock pip-audit returning vulnerabilities
        mock_vulnerability_output = {
            "vulnerabilities": [
                {
                    "package": "flask",
                    "installed_version": "1.1.0",
                    "specs": [
                        {
                            "id": "PYSEC-2021-135",
                            "details": "Flask before 2.0.0 has a vulnerability",
                            "fix_versions": ["2.0.0"],
                        }
                    ],
                }
            ]
        }

        mock_run_command.return_value = subprocess.CompletedProcess(
            args=["pip-audit"],
            returncode=1,  # pip-audit returns 1 when vulnerabilities found
            stdout=json.dumps(mock_vulnerability_output).encode(),
            stderr=b"",
        )

        result = await analyzer.analyze(temp_project)

        assert result.success is True
        assert len(result.issues) >= 1

        # Check the vulnerability issue
        flask_issue = next(
            (issue for issue in result.issues if "flask" in issue.title.lower()), None
        )
        assert flask_issue is not None
        assert flask_issue.severity in ["critical", "high", "medium", "low"]
        assert flask_issue.category == "security"
        assert flask_issue.analyzer == "pip-audit"

    @pytest.mark.asyncio
    @patch.object(VulnerabilityAnalyzer, "_run_command")
    @patch.object(VulnerabilityAnalyzer, "_tool_available")
    async def test_analyze_no_vulnerabilities(
        self, mock_tool_available, mock_run_command, analyzer, temp_project
    ):
        """Test analysis when no vulnerabilities are found."""
        mock_tool_available.return_value = True
        mock_run_command.return_value = subprocess.CompletedProcess(
            args=["pip-audit"],
            returncode=0,  # No vulnerabilities
            stdout=b'{"vulnerabilities": []}',
            stderr=b"",
        )

        result = await analyzer.analyze(temp_project)

        assert result.success is True
        assert len(result.issues) == 0

    def test_determine_severity(self, analyzer):
        """Test severity determination logic."""
        # Test critical severity
        spec_critical = {"details": "remote code execution vulnerability"}
        assert analyzer._determine_severity(spec_critical) == "critical"

        # Test high severity
        spec_high = {"details": "arbitrary code execution possible"}
        assert analyzer._determine_severity(spec_high) == "high"

        # Test medium severity (default)
        spec_unknown = {"details": "some other vulnerability"}
        assert analyzer._determine_severity(spec_unknown) == "medium"

    @pytest.mark.asyncio
    async def test_analyze_no_dependency_files(self, analyzer):
        """Test analysis with no dependency files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            empty_project = Path(temp_dir)

            result = await analyzer.analyze(empty_project)

            assert result.success is True
            assert len(result.issues) == 0

    @pytest.mark.asyncio
    @patch.object(VulnerabilityAnalyzer, "_run_command")
    async def test_analyze_command_failure(
        self, mock_run_command, analyzer, temp_project
    ):
        """Test handling of command failures."""
        mock_run_command.side_effect = AnalysisError("pip-audit command failed")

        with pytest.raises(VulnerabilityScannError):
            await analyzer.analyze(temp_project)


class TestDeadCodeAnalyzer:
    """Test the DeadCodeAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        """Create a DeadCodeAnalyzer instance for testing."""
        return DeadCodeAnalyzer()

    @pytest.fixture
    def temp_project(self):
        """Create a temporary Python project for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)

            # Create a Python file with unused imports and functions
            python_file = project_path / "test_module.py"
            python_file.write_text("""
import os
import sys
import unused_module

def used_function():
    return "used"

def unused_function():
    return "unused"

class UsedClass:
    def method(self):
        return used_function()

class UnusedClass:
    def unused_method(self):
        pass

# Use some imports
print(os.getcwd())
            """)

            yield project_path

    def test_analyzer_properties(self, analyzer):
        """Test analyzer properties."""
        assert analyzer.name == "dead_code"
        assert "vulture" in analyzer.required_tools
        assert ".py" in analyzer.supported_file_types

    @pytest.mark.asyncio
    @patch.object(DeadCodeAnalyzer, "_run_command")
    async def test_analyze_with_vulture_output(
        self, mock_run_command, analyzer, temp_project
    ):
        """Test analysis with vulture output."""
        vulture_output = """
test_module.py:3: unused import 'unused_module' (90% confidence)
test_module.py:8: unused function 'unused_function' (95% confidence)
test_module.py:14: unused class 'UnusedClass' (85% confidence)
        """.strip()

        mock_run_command.return_value = subprocess.CompletedProcess(
            args=["vulture"], returncode=0, stdout=vulture_output.encode(), stderr=b""
        )

        result = await analyzer.analyze(temp_project)

        assert result.success is True
        assert len(result.issues) >= 3  # At least the vulture issues

        # Check for unused function issue
        unused_func_issues = [
            issue for issue in result.issues if "unused_function" in issue.title
        ]
        assert len(unused_func_issues) == 1
        assert unused_func_issues[0].category == "dead_code"
        assert unused_func_issues[0].analyzer == "vulture"

    def test_find_unused_imports(self, analyzer):
        """Test finding unused imports with AST."""
        code = """
import os
import sys
import unused_module

def main():
    print(os.getcwd())
    # sys is not used
        """

        import ast

        tree = ast.parse(code)
        unused_imports = analyzer._find_unused_imports(tree, code)

        # Should find sys and unused_module as unused
        unused_names = [imp["name"] for imp in unused_imports]
        assert "sys" in unused_names
        assert "unused_module" in unused_names
        assert "os" not in unused_names  # os is used

    def test_determine_dead_code_severity(self, analyzer):
        """Test dead code severity determination."""
        # High confidence function should be medium
        assert analyzer._determine_dead_code_severity("function", 95) == "medium"

        # High confidence variable should be low
        assert analyzer._determine_dead_code_severity("variable", 95) == "low"

        # Medium confidence should be low
        assert analyzer._determine_dead_code_severity("function", 85) == "low"

        # Low confidence should be info
        assert analyzer._determine_dead_code_severity("function", 75) == "info"

    @pytest.mark.asyncio
    async def test_analyze_no_python_files(self, analyzer):
        """Test analysis with no Python files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            empty_project = Path(temp_dir)

            # Create a non-Python file
            text_file = empty_project / "readme.txt"
            text_file.write_text("This is not Python")

            result = await analyzer.analyze(empty_project)

            assert result.success is True
            assert len(result.issues) == 0


class TestAnalyzerRegistry:
    """Test the AnalyzerRegistry class."""

    @pytest.fixture
    def registry(self):
        """Create a fresh registry for testing."""
        return AnalyzerRegistry()

    def test_registry_initialization(self, registry):
        """Test that registry initializes with default analyzers."""
        analyzers = registry.list_analyzers()
        assert "vulnerability" in analyzers
        assert "dead_code" in analyzers

    def test_register_analyzer(self, registry):
        """Test registering a custom analyzer."""

        class CustomAnalyzer(BaseAnalyzer):
            @property
            def required_tools(self):
                return ["custom-tool"]

            @property
            def supported_file_types(self):
                return [".custom"]

            async def analyze(self, project_path):
                pass

        custom_analyzer = CustomAnalyzer("custom")
        registry.register(custom_analyzer)

        assert "custom" in registry.list_analyzers()
        assert registry.get_analyzer("custom") == custom_analyzer

    def test_unregister_analyzer(self, registry):
        """Test unregistering an analyzer."""
        original_count = len(registry.list_analyzers())

        registry.unregister("vulnerability")

        assert len(registry.list_analyzers()) == original_count - 1
        assert "vulnerability" not in registry.list_analyzers()

    def test_get_nonexistent_analyzer(self, registry):
        """Test getting a non-existent analyzer raises error."""
        from code_hygiene_agent.utils.exceptions import AnalyzerNotFoundError

        with pytest.raises(AnalyzerNotFoundError):
            registry.get_analyzer("nonexistent")

    @patch("code_hygiene_agent.analyzers.registry.settings")
    def test_get_enabled_analyzers(self, mock_settings, registry):
        """Test getting enabled analyzers based on configuration."""
        mock_settings.get_enabled_analyzers.return_value = {"vulnerability"}

        enabled = registry.get_enabled_analyzers()

        assert len(enabled) == 1
        assert enabled[0].name == "vulnerability"


if __name__ == "__main__":
    pytest.main([__file__])
