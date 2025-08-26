"""
MCP tool definitions for the Code Hygiene Agent.

This module defines all the tools that are exposed through the MCP interface,
allowing clients to interact with the code hygiene analysis capabilities.
"""

from mcp.types import Tool

# Tool definitions for the MCP server
TOOLS: list[Tool] = [
    Tool(
        name="analyze_code_hygiene",
        description="Perform comprehensive code hygiene analysis on a project, including vulnerability scanning and dead code detection",
        inputSchema={
            "type": "object",
            "properties": {
                "project_path": {
                    "type": "string",
                    "description": "Absolute path to the project directory to analyze",
                },
                "analyzers": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of specific analyzers to run (e.g., ['vulnerability', 'dead_code']). If not provided, all enabled analyzers will run.",
                },
                "create_pr": {
                    "type": "boolean",
                    "description": "Whether to automatically create a GitHub PR with fixes (requires GitHub configuration)",
                    "default": False,
                },
            },
            "required": ["project_path"],
            "additionalProperties": False,
        },
    ),
    Tool(
        name="check_analyzer_availability",
        description="Check the availability of external tools required by all analyzers (pip-audit, vulture, safety, etc.)",
        inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
    ),
    Tool(
        name="get_analyzer_info",
        description="Get detailed information about all registered analyzers, including their capabilities and requirements",
        inputSchema={
            "type": "object",
            "properties": {
                "analyzer_name": {
                    "type": "string",
                    "description": "Optional: Get info for a specific analyzer. If not provided, returns info for all analyzers.",
                }
            },
            "additionalProperties": False,
        },
    ),
    Tool(
        name="create_hygiene_pr",
        description="Analyze a project and create a GitHub pull request with automated code hygiene improvements",
        inputSchema={
            "type": "object",
            "properties": {
                "project_path": {
                    "type": "string",
                    "description": "Absolute path to the project directory to analyze",
                },
                "analyzers": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of specific analyzers to run. If not provided, all enabled analyzers will run.",
                },
                "pr_title": {
                    "type": "string",
                    "description": "Custom title for the pull request. If not provided, a default title will be generated.",
                },
                "pr_description": {
                    "type": "string",
                    "description": "Additional description to include in the pull request body.",
                },
            },
            "required": ["project_path"],
            "additionalProperties": False,
        },
    ),
    Tool(
        name="scan_vulnerabilities",
        description="Specifically scan for vulnerable dependencies using pip-audit and safety",
        inputSchema={
            "type": "object",
            "properties": {
                "project_path": {
                    "type": "string",
                    "description": "Absolute path to the project directory to scan",
                },
                "include_dev_dependencies": {
                    "type": "boolean",
                    "description": "Whether to include development dependencies in the scan",
                    "default": True,
                },
                "severity_threshold": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Minimum severity level to report",
                    "default": "low",
                },
            },
            "required": ["project_path"],
            "additionalProperties": False,
        },
    ),
    Tool(
        name="find_dead_code",
        description="Specifically analyze Python code for dead code, unused functions, and unused imports",
        inputSchema={
            "type": "object",
            "properties": {
                "project_path": {
                    "type": "string",
                    "description": "Absolute path to the project directory to analyze",
                },
                "confidence_threshold": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 100,
                    "description": "Minimum confidence level (0-100) for dead code detection",
                    "default": 80,
                },
                "exclude_test_files": {
                    "type": "boolean",
                    "description": "Whether to exclude test files from dead code analysis",
                    "default": True,
                },
            },
            "required": ["project_path"],
            "additionalProperties": False,
        },
    ),
    Tool(
        name="generate_hygiene_report",
        description="Generate a detailed code hygiene report from previous analysis results",
        inputSchema={
            "type": "object",
            "properties": {
                "project_path": {
                    "type": "string",
                    "description": "Path to the project that was analyzed",
                },
                "format": {
                    "type": "string",
                    "enum": ["markdown", "json", "html"],
                    "description": "Output format for the report",
                    "default": "markdown",
                },
                "include_ai_suggestions": {
                    "type": "boolean",
                    "description": "Whether to include AI-powered suggestions and insights",
                    "default": True,
                },
                "output_file": {
                    "type": "string",
                    "description": "Optional file path to save the report. If not provided, returns the report content.",
                },
            },
            "required": ["project_path"],
            "additionalProperties": False,
        },
    ),
    Tool(
        name="configure_analyzers",
        description="Configure which analyzers are enabled and their settings",
        inputSchema={
            "type": "object",
            "properties": {
                "enable_vulnerability_scanning": {
                    "type": "boolean",
                    "description": "Enable vulnerability scanning with pip-audit and safety",
                },
                "enable_dead_code_analysis": {
                    "type": "boolean",
                    "description": "Enable dead code analysis with vulture",
                },
                "max_concurrent_scans": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10,
                    "description": "Maximum number of analyzers to run concurrently",
                },
                "analysis_timeout": {
                    "type": "integer",
                    "minimum": 30,
                    "maximum": 1800,
                    "description": "Timeout for analysis operations in seconds",
                },
            },
            "additionalProperties": False,
        },
    ),
    Tool(
        name="analyze_github_repository",
        description="Clone and analyze a GitHub repository for code hygiene issues, optionally creating a PR with fixes",
        inputSchema={
            "type": "object",
            "properties": {
                "repo_url": {
                    "type": "string",
                    "description": "GitHub repository URL (e.g., https://github.com/owner/repo)",
                },
                "branch": {
                    "type": "string",
                    "description": "Specific branch to analyze (default: main/master branch)",
                },
                "analyzers": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of analyzers to run (default: all available)",
                },
                "create_pr": {
                    "type": "boolean",
                    "default": True,
                    "description": "Whether to create a GitHub PR with fixes",
                },
                "pr_title": {
                    "type": "string",
                    "description": "Custom title for the PR (optional)",
                },
                "report_format": {
                    "type": "string",
                    "enum": ["markdown", "json", "html"],
                    "default": "markdown",
                    "description": "Format for the generated report",
                },
                "include_ai_suggestions": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include AI-powered suggestions in the report",
                },
                "clone_depth": {
                    "type": "integer",
                    "default": 1,
                    "minimum": 1,
                    "description": "Git clone depth (1 for shallow clone)",
                },
            },
            "required": ["repo_url"],
            "additionalProperties": False,
        },
    ),
]


# Tool descriptions for documentation
TOOL_DESCRIPTIONS = {
    "analyze_code_hygiene": {
        "purpose": "Main analysis tool that runs comprehensive code hygiene checks",
        "use_cases": [
            "Full project health assessment",
            "CI/CD integration for code quality checks",
            "Pre-commit hooks for code validation",
            "Regular maintenance and cleanup",
        ],
        "outputs": [
            "Total issues found by category and severity",
            "Detailed analysis results from each analyzer",
            "Comprehensive report with findings",
            "Optional GitHub PR with automated fixes",
        ],
    },
    "check_analyzer_availability": {
        "purpose": "Verify that required external tools are installed and accessible",
        "use_cases": [
            "Environment setup validation",
            "Troubleshooting analysis failures",
            "CI/CD environment verification",
        ],
        "outputs": [
            "Status of each required tool (pip-audit, vulture, safety, etc.)",
            "Version information where available",
            "Installation recommendations for missing tools",
        ],
    },
    "create_hygiene_pr": {
        "purpose": "Automated GitHub integration for code improvements",
        "use_cases": [
            "Automated maintenance PRs",
            "Scheduled code cleanup",
            "Team code hygiene initiatives",
        ],
        "outputs": [
            "Analysis results",
            "GitHub PR URL with automated fixes",
            "Detailed report attached to PR",
        ],
    },
    "analyze_github_repository": {
        "purpose": "Complete workflow for analyzing external GitHub repositories",
        "use_cases": [
            "Analyzing open source projects for contribution opportunities",
            "Security audits of third-party dependencies",
            "Code quality assessment of external repositories",
            "Automated maintenance PRs to external projects",
        ],
        "outputs": [
            "Repository clone and analysis results",
            "Comprehensive code hygiene report",
            "Optional GitHub PR with automated fixes",
            "Repository metadata and statistics",
        ],
    },
}
