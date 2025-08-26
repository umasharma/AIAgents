"""
Main MCP server implementation for the Code Hygiene Agent.

This module provides the Model Context Protocol server that exposes
code hygiene analysis capabilities to MCP clients.
"""

import asyncio
import json
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import Resource, TextContent, Tool

from ..analyzers.registry import registry
from ..config.settings import settings
from ..integrations.github import GitHubIntegrator
from ..reporting.generator import ReportGenerator
from ..utils.exceptions import CodeHygieneError
from ..utils.logging import get_logger
from .tools import TOOLS

logger = get_logger(__name__)


class CodeHygieneAgent:
    """Main agent class that coordinates all code hygiene operations."""

    def __init__(self) -> None:
        self.analyzer_registry = registry
        self.github_integrator = GitHubIntegrator()
        self.report_generator = ReportGenerator()

    async def analyze_project(
        self,
        project_path: str,
        analyzers: list[str] | None = None,
        create_pr: bool = False,
    ) -> dict[str, Any]:
        """
        Perform comprehensive code hygiene analysis on a project.

        Args:
            project_path: Path to the project to analyze
            analyzers: Specific analyzers to run (defaults to enabled analyzers)
            create_pr: Whether to create a GitHub PR with fixes

        Returns:
            Dictionary containing analysis results and report
        """
        project_path_obj = Path(project_path)

        if not project_path_obj.exists():
            raise CodeHygieneError(f"Project path does not exist: {project_path}")

        logger.info(
            "Starting project analysis",
            project_path=project_path,
            analyzers=analyzers,
            create_pr=create_pr,
        )

        try:
            # Run analysis
            analysis_results = await self.analyzer_registry.analyze_project(
                project_path_obj, analyzer_names=analyzers
            )

            # Generate comprehensive report
            report_content = await self.report_generator.generate_report(
                analysis_results, project_path_obj
            )

            # Optionally create GitHub PR
            pr_url = None
            if create_pr and any(result.issues for result in analysis_results.values()):
                pr_url = await self.github_integrator.create_hygiene_pr(
                    project_path_obj, analysis_results, report_content
                )

            # Compile final results
            total_issues = sum(
                len(result.issues) for result in analysis_results.values()
            )
            successful_analyzers = [
                name for name, result in analysis_results.items() if result.success
            ]
            failed_analyzers = [
                name for name, result in analysis_results.items() if not result.success
            ]

            return {
                "success": True,
                "project_path": project_path,
                "total_issues": total_issues,
                "analyzers": {
                    "successful": successful_analyzers,
                    "failed": failed_analyzers,
                },
                "analysis_results": {
                    name: {
                        "success": result.success,
                        "issues_count": len(result.issues),
                        "execution_time": result.execution_time,
                        "error_message": result.error_message,
                    }
                    for name, result in analysis_results.items()
                },
                "report": report_content,
                "pull_request_url": pr_url,
            }

        except Exception as e:
            logger.error(
                "Project analysis failed",
                project_path=project_path,
                error=str(e),
                error_type=type(e).__name__,
            )
            return {
                "success": False,
                "project_path": project_path,
                "error": str(e),
                "error_type": type(e).__name__,
            }

    async def check_tool_availability(self) -> dict[str, dict[str, bool]]:
        """Check availability of all required external tools."""
        return await self.analyzer_registry.check_all_availability()

    def get_analyzer_info(self) -> dict[str, dict[str, Any]]:
        """Get information about all registered analyzers."""
        info = {}

        for name in self.analyzer_registry.list_analyzers():
            analyzer = self.analyzer_registry.get_analyzer(name)
            info[name] = {
                "name": analyzer.name,
                "required_tools": analyzer.required_tools,
                "supported_file_types": analyzer.supported_file_types,
                "enabled": name in settings.get_enabled_analyzers(),
            }

        return info


class CodeHygieneServer:
    """MCP server for the Code Hygiene Agent."""

    def __init__(self) -> None:
        self.server = Server("code-hygiene-agent")
        self.agent = CodeHygieneAgent()
        self._setup_handlers()

    def _setup_handlers(self) -> None:
        """Set up MCP server request handlers."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """List available tools."""
            return TOOLS

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
            """Handle tool calls."""
            logger.info("Tool called", tool=name, arguments=arguments)

            try:
                if name == "analyze_code_hygiene":
                    result = await self._handle_analyze_project(arguments)
                elif name == "check_analyzer_availability":
                    result = await self._handle_check_availability(arguments)
                elif name == "get_analyzer_info":
                    result = await self._handle_get_analyzer_info(arguments)
                elif name == "create_hygiene_pr":
                    result = await self._handle_create_pr(arguments)
                elif name == "analyze_github_repository":
                    result = await self._handle_analyze_github_repository(arguments)
                else:
                    raise CodeHygieneError(f"Unknown tool: {name}")

                return [
                    TextContent(
                        type="text",
                        text=json.dumps(result, indent=2, ensure_ascii=False),
                    )
                ]

            except Exception as e:
                logger.error(
                    "Tool call failed",
                    tool=name,
                    error=str(e),
                    error_type=type(e).__name__,
                )
                return [
                    TextContent(
                        type="text",
                        text=json.dumps(
                            {
                                "success": False,
                                "error": str(e),
                                "error_type": type(e).__name__,
                            },
                            indent=2,
                        ),
                    )
                ]

        @self.server.list_resources()
        async def list_resources() -> list[Resource]:
            """List available resources."""
            return [
                Resource(
                    uri="config://settings",
                    name="Configuration Settings",
                    description="Current agent configuration settings",
                    mimeType="application/json",
                ),
                Resource(
                    uri="status://analyzers",
                    name="Analyzer Status",
                    description="Status and availability of all analyzers",
                    mimeType="application/json",
                ),
            ]

        @self.server.read_resource()
        async def read_resource(uri: str) -> str:
            """Read resource content."""
            if uri == "config://settings":
                return json.dumps(settings.dict(), indent=2, default=str)
            elif uri == "status://analyzers":
                availability = await self.agent.check_tool_availability()
                analyzer_info = self.agent.get_analyzer_info()

                return json.dumps(
                    {"analyzer_info": analyzer_info, "tool_availability": availability},
                    indent=2,
                )
            else:
                raise CodeHygieneError(f"Unknown resource: {uri}")

    async def _handle_analyze_project(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Handle project analysis requests."""
        project_path = arguments.get("project_path")
        if not project_path:
            raise CodeHygieneError("project_path is required")

        analyzers = arguments.get("analyzers")
        create_pr = arguments.get("create_pr", False)

        return await self.agent.analyze_project(project_path, analyzers, create_pr)

    async def _handle_check_availability(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Handle tool availability checks."""
        availability = await self.agent.check_tool_availability()

        return {"success": True, "tool_availability": availability}

    async def _handle_get_analyzer_info(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Handle analyzer information requests."""
        analyzer_info = self.agent.get_analyzer_info()

        return {"success": True, "analyzers": analyzer_info}

    async def _handle_create_pr(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Handle GitHub PR creation requests."""
        project_path = arguments.get("project_path")
        if not project_path:
            raise CodeHygieneError("project_path is required")

        # First run analysis
        analysis_result = await self.agent.analyze_project(
            project_path, analyzers=arguments.get("analyzers"), create_pr=True
        )

        return analysis_result

    async def _handle_analyze_github_repository(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Handle GitHub repository analysis requests."""
        from ..integrations.github import GitHubIntegrator
        from ..integrations.repo_manager import RepositoryManager
        from ..reporting.generator import ReportFormat, ReportGenerator

        repo_url = arguments.get("repo_url")
        if not repo_url:
            raise CodeHygieneError("repo_url is required")

        branch = arguments.get("branch")
        analyzers = arguments.get("analyzers")
        create_pr = arguments.get("create_pr", True)
        pr_title = arguments.get("pr_title")
        report_format = arguments.get("report_format", "markdown")
        include_ai_suggestions = arguments.get("include_ai_suggestions", True)
        clone_depth = arguments.get("clone_depth", 1)

        repo_manager = RepositoryManager()

        try:
            await logger.ainfo("Starting GitHub repository analysis", repo_url=repo_url)

            # Parse repository URL to get owner and repo name
            owner, repo_name = repo_manager.parse_github_url(repo_url)

            # Clone repository
            repo_path = await repo_manager.clone_repository(
                repo_url=repo_url, branch=branch, depth=clone_depth
            )

            # Get repository information
            repo_info = await repo_manager.get_repository_info(repo_path)

            # Run analysis on cloned repository
            analysis_results = await self.agent.analyzer_registry.analyze_project(
                project_path=repo_path,
                analyzer_names=analyzers or ["vulnerability", "dead_code"],
                max_concurrent=2,  # Limit concurrent analyzers for external repos
            )

            # Generate report
            report_generator = ReportGenerator()
            report_format_enum = ReportFormat(report_format)

            report_content = await report_generator.generate_report(
                analysis_results=analysis_results,
                project_path=repo_path,
                format_type=report_format_enum,
                include_ai_suggestions=include_ai_suggestions,
            )

            result = {
                "success": True,
                "repository": {
                    "url": repo_url,
                    "owner": owner,
                    "name": repo_name,
                    "branch": branch or repo_info.get("active_branch"),
                    "commit_hash": repo_info.get("commit_hash", "")[:8],
                    "total_files": repo_info.get("total_files", 0),
                    "file_types": repo_info.get("file_types", {}),
                },
                "analysis": {
                    "total_issues": sum(
                        len(result.issues) for result in analysis_results.values()
                    ),
                    "analyzers_run": list(analysis_results.keys()),
                    "execution_time": sum(
                        result.execution_time for result in analysis_results.values()
                    ),
                    "issues_by_severity": self._aggregate_issues_by_severity(
                        analysis_results
                    ),
                    "issues_by_category": self._aggregate_issues_by_category(
                        analysis_results
                    ),
                },
                "report": {
                    "format": report_format,
                    "length": len(report_content),
                    "content": report_content,
                },
            }

            # Create PR if requested and GitHub is configured
            if (
                create_pr
                and settings.github.token
                and settings.github.token != "fake_key_for_testing"
            ):
                try:
                    github_integrator = GitHubIntegrator()

                    # Create a new branch for fixes
                    branch_name = f"code-hygiene-improvements-{int(asyncio.get_event_loop().time())}"
                    await repo_manager.create_analysis_branch(repo_path, branch_name)

                    # Apply automated fixes (basic ones)
                    fixes_applied = await self._apply_basic_fixes(
                        repo_path, analysis_results
                    )

                    if fixes_applied > 0:
                        # Commit changes
                        commit_message = f"Code hygiene improvements\n\nApplied {fixes_applied} automated fixes:\n- Removed unused imports\n- Fixed basic formatting issues\n\n🤖 Generated by Code Hygiene Agent"

                        commit_hash = await repo_manager.commit_changes(
                            repo_path,
                            commit_message,
                            "Code Hygiene Agent",
                            "noreply@codehygiene.ai",
                        )

                        # Push changes
                        await repo_manager.push_changes(
                            repo_path, "origin", branch_name
                        )

                        # Create PR
                        pr_url = await github_integrator.create_pr_from_analysis(
                            owner=owner,
                            repo=repo_name,
                            head_branch=branch_name,
                            base_branch=branch or "main",
                            title=pr_title
                            or f"Code hygiene improvements - {fixes_applied} fixes applied",
                            analysis_results=analysis_results,
                            report_content=report_content,
                        )

                        result["pull_request"] = {
                            "created": True,
                            "url": pr_url,
                            "branch": branch_name,
                            "fixes_applied": fixes_applied,
                            "commit_hash": commit_hash[:8],
                        }

                        await logger.ainfo(
                            "PR created successfully",
                            pr_url=pr_url,
                            fixes=fixes_applied,
                        )

                    else:
                        result["pull_request"] = {
                            "created": False,
                            "reason": "No automated fixes available",
                        }

                except Exception as e:
                    await logger.aerror("Failed to create PR", error=str(e))
                    result["pull_request"] = {"created": False, "error": str(e)}
            else:
                result["pull_request"] = {
                    "created": False,
                    "reason": "PR creation disabled or GitHub not configured",
                }

            return result

        except Exception as e:
            await logger.aerror(
                "GitHub repository analysis failed", error=str(e), repo_url=repo_url
            )
            raise CodeHygieneError(f"Repository analysis failed: {e}") from e

        finally:
            # Cleanup cloned repository
            repo_manager.cleanup_temp_directories()

    async def _apply_basic_fixes(self, repo_path, analysis_results) -> int:
        """Apply basic automated fixes to the repository."""
        fixes_applied = 0

        # Apply fixes for dead code issues (remove unused imports)
        if "dead_code" in analysis_results:
            dead_code_issues = analysis_results["dead_code"].issues
            unused_import_issues = [
                issue
                for issue in dead_code_issues
                if "unused import" in issue.title.lower()
            ]

            # Group by file
            files_to_fix = {}
            for issue in unused_import_issues:
                if issue.file_path:
                    file_path = repo_path / issue.file_path
                    if file_path not in files_to_fix:
                        files_to_fix[file_path] = []
                    files_to_fix[file_path].append(issue)

            # Apply fixes file by file
            for file_path, issues in files_to_fix.items():
                try:
                    if file_path.exists() and file_path.suffix == ".py":
                        content = file_path.read_text(encoding="utf-8")

                        # Simple fix: remove unused import lines
                        lines = content.split("\n")
                        lines_to_remove = set()

                        for issue in issues:
                            if issue.line_number and 1 <= issue.line_number <= len(
                                lines
                            ):
                                line = lines[issue.line_number - 1].strip()
                                if line.startswith("import ") or line.startswith(
                                    "from "
                                ):
                                    lines_to_remove.add(issue.line_number - 1)

                        if lines_to_remove:
                            # Remove lines in reverse order to maintain indices
                            for line_idx in sorted(lines_to_remove, reverse=True):
                                del lines[line_idx]

                            # Write back to file
                            file_path.write_text("\n".join(lines), encoding="utf-8")
                            fixes_applied += len(lines_to_remove)

                            await logger.ainfo(
                                "Applied unused import fixes",
                                file=str(file_path),
                                fixes=len(lines_to_remove),
                            )

                except Exception as e:
                    await logger.awarning(
                        "Failed to apply fix", file=str(file_path), error=str(e)
                    )

        return fixes_applied

    def _aggregate_issues_by_severity(self, analysis_results) -> dict[str, int]:
        """Aggregate issues by severity across all analyzers."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for result in analysis_results.values():
            for issue in result.issues:
                severity_counts[issue.severity] = (
                    severity_counts.get(issue.severity, 0) + 1
                )

        return severity_counts

    def _aggregate_issues_by_category(self, analysis_results) -> dict[str, int]:
        """Aggregate issues by category across all analyzers."""
        category_counts = {}

        for result in analysis_results.values():
            for issue in result.issues:
                category_counts[issue.category] = (
                    category_counts.get(issue.category, 0) + 1
                )

        return category_counts

    async def run(self) -> None:
        """Run the MCP server."""
        logger.info("Starting Code Hygiene Agent MCP server")

        try:
            async with stdio_server() as (read_stream, write_stream):
                await self.server.run(
                    read_stream,
                    write_stream,
                    InitializationOptions(
                        server_name="code-hygiene-agent",
                        server_version="1.0.0",
                        capabilities=self.server.get_capabilities(),
                    ),
                )
        except Exception as e:
            logger.error("MCP server failed", error=str(e))
            raise


async def main():
    """Main entry point for the MCP server."""
    try:
        # Validate configuration
        settings.validate_configuration()

        # Initialize and run server
        server = CodeHygieneServer()
        await server.run()

    except Exception as e:
        logger.error("Failed to start server", error=str(e))
        raise


if __name__ == "__main__":
    asyncio.run(main())
