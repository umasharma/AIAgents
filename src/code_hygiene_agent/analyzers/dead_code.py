"""
Dead code analyzer for Python projects.

This module provides dead code detection using Vulture to identify
unused functions, classes, variables, and imports.
"""

import ast
import re
import time
from pathlib import Path

from ..utils.exceptions import DeadCodeAnalysisError
from .base import AnalysisIssue, AnalysisResult, BaseAnalyzer


class DeadCodeAnalyzer(BaseAnalyzer):
    """Analyzes Python projects for dead code and unused imports."""

    def __init__(self) -> None:
        super().__init__("dead_code")

    @property
    def required_tools(self) -> list[str]:
        """External tools required for dead code analysis."""
        return ["vulture"]

    @property
    def supported_file_types(self) -> list[str]:
        """File types this analyzer can process."""
        return [".py"]

    async def analyze(self, project_path: Path) -> AnalysisResult:
        """
        Analyze project for dead code and unused imports.

        Args:
            project_path: Path to project root

        Returns:
            AnalysisResult with dead code findings
        """
        start_time = time.time()
        result = self._create_base_result(project_path, start_time)

        try:
            self.logger.info(
                "Starting dead code analysis", project_path=str(project_path)
            )

            # Find Python files to analyze
            python_files = self._filter_files(project_path)
            if not python_files:
                self.logger.warning(
                    "No Python files found", project_path=str(project_path)
                )
                result.success = True
                result.execution_time = time.time() - start_time
                return result

            # Run Vulture analysis
            vulture_issues = await self._run_vulture(project_path)
            result.issues.extend(vulture_issues)

            # Run custom AST-based analysis for unused imports
            import_issues = await self._analyze_unused_imports(python_files)
            result.issues.extend(import_issues)

            result.success = True
            result.metadata = {
                "files_analyzed": len(python_files),
                "tools_used": ["vulture", "ast"],
                "dead_code_items": len(
                    [i for i in result.issues if i.category == "dead_code"]
                ),
                "unused_imports": len(
                    [i for i in result.issues if i.category == "unused_import"]
                ),
            }

            self.logger.info(
                "Dead code analysis completed",
                project_path=str(project_path),
                issues_found=len(result.issues),
                execution_time=time.time() - start_time,
            )

        except Exception as e:
            result.error_message = str(e)
            result.success = False
            self.logger.error(
                "Dead code analysis failed",
                project_path=str(project_path),
                error=str(e),
                error_type=type(e).__name__,
            )
            raise DeadCodeAnalysisError(
                f"Dead code analysis failed for {project_path}", cause=e
            ) from e

        result.execution_time = time.time() - start_time
        return result

    async def _run_vulture(self, project_path: Path) -> list[AnalysisIssue]:
        """Run Vulture on the project to find dead code."""
        issues = []

        try:
            # Run vulture with specific options
            command = [
                "vulture",
                str(project_path),
                "--min-confidence",
                "80",  # Only high-confidence results
                "--sort-by-size",  # Sort by size to prioritize larger issues
            ]

            result = await self._run_command(command, cwd=project_path)

            if result.stdout:
                vulture_output = result.stdout.decode("utf-8")
                issues.extend(self._parse_vulture_output(vulture_output))

            if result.stderr:
                error_output = result.stderr.decode("utf-8")
                if error_output and not error_output.strip().startswith("WARNING"):
                    self.logger.warning("Vulture stderr output", output=error_output)

        except Exception as e:
            self.logger.warning("Failed to run vulture", error=str(e))

        return issues

    def _parse_vulture_output(self, output: str) -> list[AnalysisIssue]:
        """Parse Vulture output into AnalysisIssue objects."""
        issues = []

        # Vulture output format: file:line: unused {type} '{name}' ({confidence}% confidence)
        pattern = r"(.+):(\d+): unused (\w+) \'([^\']+)\' \((\d+)% confidence\)"

        for line in output.strip().split("\n"):
            if not line.strip():
                continue

            match = re.match(pattern, line)
            if match:
                file_path, line_num, item_type, item_name, confidence = match.groups()

                # Skip very low confidence items
                if int(confidence) < 80:
                    continue

                issue_id = f"vulture_{item_type}_{file_path}_{line_num}"

                # Determine severity based on item type and confidence
                severity = self._determine_dead_code_severity(
                    item_type, int(confidence)
                )

                # Create suggestion based on item type
                suggestion = self._generate_dead_code_suggestion(item_type, item_name)

                issue = AnalysisIssue(
                    id=issue_id,
                    title=f"Unused {item_type}: {item_name}",
                    description=f"The {item_type} '{item_name}' appears to be unused ({confidence}% confidence)",
                    file_path=file_path,
                    line_number=int(line_num),
                    severity=severity,
                    category="dead_code",
                    analyzer="vulture",
                    suggestion=suggestion,
                    references=["https://github.com/jendrikseipp/vulture"],
                )

                issues.append(issue)

        return issues

    async def _analyze_unused_imports(
        self, python_files: list[Path]
    ) -> list[AnalysisIssue]:
        """Analyze Python files for unused imports using AST."""
        issues = []

        for file_path in python_files:
            try:
                with open(file_path, encoding="utf-8") as f:
                    content = f.read()

                tree = ast.parse(content, filename=str(file_path))
                unused_imports = self._find_unused_imports(tree, content)

                for import_info in unused_imports:
                    issue_id = f"unused_import_{file_path.name}_{import_info['line']}"

                    issue = AnalysisIssue(
                        id=issue_id,
                        title=f"Unused import: {import_info['name']}",
                        description=f"The import '{import_info['name']}' is not used in this file",
                        file_path=str(file_path),
                        line_number=import_info["line"],
                        severity="low",
                        category="unused_import",
                        analyzer="ast",
                        suggestion=f"Remove the unused import: {import_info['name']}",
                        references=[],
                    )

                    issues.append(issue)

            except Exception as e:
                self.logger.warning(
                    "Failed to analyze imports in file",
                    file=str(file_path),
                    error=str(e),
                )

        return issues

    def _find_unused_imports(self, tree: ast.AST, content: str) -> list[dict]:
        """Find unused imports in an AST."""
        imports = []
        names_used = set()

        # Collect all imports
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(
                        {
                            "name": alias.asname or alias.name,
                            "full_name": alias.name,
                            "line": node.lineno,
                            "type": "import",
                        }
                    )
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name != "*":  # Skip wildcard imports
                        imports.append(
                            {
                                "name": alias.asname or alias.name,
                                "full_name": f"{node.module}.{alias.name}"
                                if node.module
                                else alias.name,
                                "line": node.lineno,
                                "type": "from_import",
                            }
                        )

        # Collect all name references
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                names_used.add(node.id)
            elif isinstance(node, ast.Attribute):
                # For attribute access like 'module.function', add 'module'
                if isinstance(node.value, ast.Name):
                    names_used.add(node.value.id)

        # Find unused imports
        unused_imports = []
        for import_info in imports:
            if import_info["name"] not in names_used:
                # Additional check: see if it's used as a module prefix
                if not self._is_used_as_prefix(import_info["name"], content):
                    unused_imports.append(import_info)

        return unused_imports

    def _is_used_as_prefix(self, name: str, content: str) -> bool:
        """Check if an import name is used as a prefix (e.g., module.function)."""
        import_pattern = rf"\b{re.escape(name)}\."
        return bool(re.search(import_pattern, content))

    def _determine_dead_code_severity(self, item_type: str, confidence: int) -> str:
        """Determine severity based on dead code type and confidence."""
        if confidence >= 95:
            if item_type in ["class", "function"]:
                return "medium"
            else:
                return "low"
        elif confidence >= 85:
            return "low"
        else:
            return "info"

    def _generate_dead_code_suggestion(self, item_type: str, item_name: str) -> str:
        """Generate appropriate suggestion for dead code item."""
        suggestions = {
            "function": f"Consider removing the unused function '{item_name}' or verify if it's actually needed",
            "class": f"Consider removing the unused class '{item_name}' or verify if it's actually needed",
            "method": f"Consider removing the unused method '{item_name}' or verify if it's actually needed",
            "property": f"Consider removing the unused property '{item_name}' or verify if it's actually needed",
            "variable": f"Consider removing the unused variable '{item_name}' or verify if it's actually needed",
            "import": f"Consider removing the unused import '{item_name}'",
            "attribute": f"Consider removing the unused attribute '{item_name}' or verify if it's actually needed",
        }

        return suggestions.get(
            item_type,
            f"Consider removing or reviewing the unused {item_type} '{item_name}'",
        )
