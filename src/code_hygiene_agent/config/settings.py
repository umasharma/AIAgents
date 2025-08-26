"""
Configuration management for the Code Hygiene Agent.

This module provides centralized configuration management using Pydantic
for validation and type safety.
"""

from enum import Enum
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings

from ..utils.exceptions import ConfigurationError


class LogLevel(str, Enum):
    """Available logging levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogFormat(str, Enum):
    """Available log formats."""

    JSON = "json"
    TEXT = "text"


class ReportFormat(str, Enum):
    """Available report formats."""

    MARKDOWN = "markdown"
    JSON = "json"
    HTML = "html"


class GitHubSettings(BaseSettings):
    """GitHub integration settings."""

    token: str = Field(..., description="GitHub Personal Access Token")
    owner: str = Field(..., description="GitHub repository owner")
    repo: str = Field(..., description="GitHub repository name")

    create_pr_automatically: bool = Field(
        default=False, description="Whether to create PRs automatically"
    )
    pr_branch_prefix: str = Field(
        default="code-hygiene-", description="Prefix for PR branches"
    )
    pr_title_prefix: str = Field(
        default="[Code Hygiene]", description="Prefix for PR titles"
    )
    pr_reviewer_teams: list[str] = Field(
        default_factory=list, description="Teams to request reviews from"
    )

    class Config:
        env_prefix = "GITHUB_"


class OpenAISettings(BaseSettings):
    """OpenAI API settings for LLM decision making."""

    api_key: str = Field(..., description="OpenAI API key")
    model: str = Field(default="gpt-4", description="OpenAI model to use")
    max_tokens: int = Field(default=2000, description="Maximum tokens per request")
    temperature: float = Field(default=0.1, description="Temperature for responses")

    class Config:
        env_prefix = "OPENAI_"


class AnalysisSettings(BaseSettings):
    """Code analysis settings."""

    max_concurrent_scans: int = Field(
        default=5, description="Maximum concurrent analysis scans"
    )
    analysis_timeout: int = Field(
        default=300, description="Analysis timeout in seconds"
    )

    # Enable/disable individual analyzers
    enable_bandit: bool = Field(
        default=True, description="Enable Bandit security scanner"
    )
    enable_semgrep: bool = Field(default=True, description="Enable Semgrep analysis")
    enable_safety: bool = Field(
        default=True, description="Enable Safety vulnerability scanner"
    )
    enable_pip_audit: bool = Field(default=True, description="Enable pip-audit")
    enable_vulture: bool = Field(
        default=True, description="Enable Vulture dead code finder"
    )

    # File patterns to include/exclude
    include_patterns: list[str] = Field(
        default_factory=lambda: [
            "**/*.py",
            "requirements*.txt",
            "pyproject.toml",
            "setup.py",
        ],
        description="File patterns to include in analysis",
    )
    exclude_patterns: list[str] = Field(
        default_factory=lambda: [
            "**/node_modules/**",
            "**/.git/**",
            "**/venv/**",
            "**/__pycache__/**",
            "**/dist/**",
            "**/build/**",
        ],
        description="File patterns to exclude from analysis",
    )

    class Config:
        env_prefix = "ANALYSIS_"


class ReportSettings(BaseSettings):
    """Report generation settings."""

    format: ReportFormat = Field(
        default=ReportFormat.MARKDOWN, description="Default report format"
    )
    include_suggestions: bool = Field(
        default=True, description="Include AI-generated suggestions in reports"
    )
    include_severity_scores: bool = Field(
        default=True, description="Include severity scores in reports"
    )
    output_directory: Path = Field(
        default=Path("./reports"), description="Directory for report output"
    )

    class Config:
        env_prefix = "REPORT_"


class MCPServerSettings(BaseSettings):
    """MCP server settings."""

    host: str = Field(default="localhost", description="Server host")
    port: int = Field(default=3000, description="Server port")
    debug: bool = Field(default=False, description="Enable debug mode")

    class Config:
        env_prefix = "MCP_SERVER_"


class Settings(BaseSettings):
    """Main application settings."""

    # Logging configuration
    log_level: LogLevel = Field(default=LogLevel.INFO, description="Logging level")
    log_format: LogFormat = Field(default=LogFormat.JSON, description="Log format")

    # Component settings
    github: GitHubSettings = Field(
        default_factory=lambda: GitHubSettings(token="", owner="", repo="")
    )
    openai: OpenAISettings = Field(default_factory=lambda: OpenAISettings(api_key=""))
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)
    reporting: ReportSettings = Field(default_factory=ReportSettings)
    mcp_server: MCPServerSettings = Field(default_factory=MCPServerSettings)

    # Optional external service tokens
    semgrep_app_token: str | None = Field(
        default=None,
        description="Semgrep App token for enhanced analysis",
    )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        validate_assignment = True

    @field_validator("github", mode="before")
    @classmethod
    def validate_github_config(cls, v):
        """Validate GitHub configuration."""
        if isinstance(v, dict):
            required_fields = ["token", "owner", "repo"]
            missing = [field for field in required_fields if not v.get(field)]
            if missing:
                raise ConfigurationError(
                    f"Missing required GitHub configuration: {', '.join(missing)}"
                )
        return v

    @field_validator("openai", mode="before")
    @classmethod
    def validate_openai_config(cls, v):
        """Validate OpenAI configuration."""
        if isinstance(v, dict) and not v.get("api_key"):
            raise ConfigurationError("OpenAI API key is required")
        return v

    def get_enabled_analyzers(self) -> set[str]:
        """Get the set of enabled analyzers."""
        enabled = set()
        if self.analysis.enable_bandit:
            enabled.add("bandit")
        if self.analysis.enable_semgrep:
            enabled.add("semgrep")
        if self.analysis.enable_safety:
            enabled.add("safety")
        if self.analysis.enable_pip_audit:
            enabled.add("pip_audit")
        if self.analysis.enable_vulture:
            enabled.add("vulture")
        return enabled

    def validate_configuration(self) -> None:
        """Validate the complete configuration."""
        try:
            # Validate that required directories exist
            self.reporting.output_directory.mkdir(parents=True, exist_ok=True)

            # Validate GitHub token format (basic check)
            if not self.github.token.startswith(("ghp_", "github_pat_")):
                raise ConfigurationError(
                    "GitHub token should start with 'ghp_' or 'github_pat_'"
                )

        except Exception as e:
            raise ConfigurationError(f"Configuration validation failed: {e}") from e


# Global settings instance - provide default values for testing
try:
    settings = Settings(
        github=GitHubSettings(
            token="fake_token_for_testing", owner="test_owner", repo="test_repo"
        ),
        openai=OpenAISettings(api_key="fake_key_for_testing"),
    )
except Exception:
    # Fallback for testing
    settings = Settings(
        **{
            "github": {
                "token": "fake_token_for_testing",
                "owner": "test_owner",
                "repo": "test_repo",
            },
            "openai": {"api_key": "fake_key_for_testing"},
        }
    )
