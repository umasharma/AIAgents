"""
Command-line interface for the Code Hygiene Agent.

This module provides a CLI for testing and direct usage of the agent
outside of the MCP server context.
"""

import asyncio
import json
import sys
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config.settings import LogLevel, settings
from .mcp_server.server import CodeHygieneAgent
from .utils.logging import configure_logging

console = Console()


@click.group()
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.option(
    "--config", type=click.Path(exists=True), help="Path to configuration file"
)
def cli(debug: bool, config: str | None) -> None:
    """Code Hygiene Agent - Automated code analysis and improvement."""
    if debug:
        settings.log_level = LogLevel.DEBUG

    configure_logging()


@cli.command()
@click.argument("project_path", type=click.Path(exists=True, file_okay=False))
@click.option("--analyzers", "-a", multiple=True, help="Specific analyzers to run")
@click.option("--create-pr", is_flag=True, help="Create GitHub PR with fixes")
@click.option("--output", "-o", type=click.Path(), help="Output file for report")
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["markdown", "json", "html"]),
    default="markdown",
)
def analyze(
    project_path: str,
    analyzers: tuple[str, ...],
    create_pr: bool,
    output: str | None,
    report_format: str,
) -> None:
    """Analyze a project for code hygiene issues."""
    asyncio.run(
        _run_analysis(project_path, analyzers, create_pr, output, report_format)
    )


async def _run_analysis(
    project_path: str,
    analyzers: tuple[str, ...],
    create_pr: bool,
    output: str | None,
    report_format: str,
) -> None:
    """Run the analysis asynchronously."""
    console.print(f"🔍 Analyzing project: [bold]{project_path}[/bold]")

    try:
        agent = CodeHygieneAgent()

        # Convert format string to settings format
        from .config.settings import ReportFormat

        getattr(ReportFormat, report_format.upper())

        # Run analysis
        result = await agent.analyze_project(
            project_path,
            analyzers=list(analyzers) if analyzers else None,
            create_pr=create_pr,
        )

        if result["success"]:
            # Display summary
            _display_analysis_summary(result)

            # Save or display report
            if output:
                with open(output, "w", encoding="utf-8") as f:
                    f.write(result["report"])
                console.print(f"📄 Report saved to: [bold]{output}[/bold]")
            else:
                console.print("\n" + "=" * 80)
                console.print("📄 DETAILED REPORT")
                console.print("=" * 80)
                console.print(result["report"])

            # Display PR URL if created
            if result.get("pull_request_url"):
                console.print(
                    f"\n🔗 Pull Request: [link]{result['pull_request_url']}[/link]"
                )
        else:
            console.print(
                f"❌ Analysis failed: {result.get('error', 'Unknown error')}",
                style="red",
            )
            sys.exit(1)

    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        sys.exit(1)


def _display_analysis_summary(result: dict[str, Any]) -> None:
    """Display a summary of analysis results."""
    console.print("\n📊 ANALYSIS SUMMARY", style="bold blue")

    # Create summary table
    table = Table(title="Analysis Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Total Issues", str(result["total_issues"]))
    table.add_row("Successful Analyzers", ", ".join(result["analyzers"]["successful"]))

    if result["analyzers"]["failed"]:
        table.add_row(
            "Failed Analyzers", ", ".join(result["analyzers"]["failed"]), style="red"
        )

    console.print(table)

    # Show analyzer details
    console.print("\n🔧 ANALYZER DETAILS", style="bold green")

    for name, details in result["analysis_results"].items():
        status = "✅" if details["success"] else "❌"
        console.print(
            f"{status} {name}: {details['issues_count']} issues "
            f"({details['execution_time']:.2f}s)"
        )


@cli.command()
def check() -> None:
    """Check availability of required tools."""
    asyncio.run(_check_tools())


async def _check_tools() -> None:
    """Check tool availability asynchronously."""
    console.print("Checking tool availability...")

    try:
        agent = CodeHygieneAgent()
        availability = await agent.check_tool_availability()

        # Create availability table
        table = Table(title="Tool Availability")
        table.add_column("Analyzer", style="cyan")
        table.add_column("Tool", style="yellow")
        table.add_column("Status", style="green")

        for analyzer_name, tools in availability.items():
            for tool_name, is_available in tools.items():
                status = "Available" if is_available else "Missing"
                style = "green" if is_available else "red"
                table.add_row(analyzer_name, tool_name, status, style=style)

        console.print(table)

        # Show missing tools
        missing_tools = []
        for _analyzer_name, tools in availability.items():
            for tool_name, is_available in tools.items():
                if not is_available:
                    missing_tools.append(tool_name)

        if missing_tools:
            console.print("\n⚠️  Missing Tools", style="bold red")
            for tool in set(missing_tools):
                console.print(f"   pip install {tool}", style="yellow")
        else:
            console.print("\n✅ All tools are available!", style="bold green")

    except Exception as e:
        console.print(f"❌ Error checking tools: {e}", style="red")
        sys.exit(1)


@cli.command()
def info() -> None:
    """Show information about available analyzers."""
    try:
        agent = CodeHygieneAgent()
        analyzer_info = agent.get_analyzer_info()

        console.print("📋 ANALYZER INFORMATION", style="bold blue")

        for name, info in analyzer_info.items():
            status = "🟢 Enabled" if info["enabled"] else "🔴 Disabled"

            panel_content = f"""
[bold]Status:[/bold] {status}
[bold]Required Tools:[/bold] {", ".join(info["required_tools"])}
[bold]Supported Files:[/bold] {", ".join(info["supported_file_types"])}
            """.strip()

            console.print(Panel(panel_content, title=name.title()))

    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        sys.exit(1)


@cli.command()
def serve() -> None:
    """Start the MCP server."""
    console.print("🚀 Starting Code Hygiene Agent MCP Server...")

    try:
        from .mcp_server.server import main

        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n👋 Shutting down server...")
    except Exception as e:
        console.print(f"❌ Server error: {e}", style="red")
        sys.exit(1)


@cli.command()
@click.option(
    "--format", "output_format", type=click.Choice(["json", "yaml"]), default="json"
)
def config(output_format: str) -> None:
    """Show current configuration."""
    try:
        config_dict = settings.dict()

        if output_format == "json":
            console.print(json.dumps(config_dict, indent=2, default=str))
        else:
            # Simple YAML-like output
            def print_dict(d: dict[str, Any], indent: int = 0) -> None:
                for key, value in d.items():
                    if isinstance(value, dict):
                        console.print("  " * indent + f"{key}:")
                        print_dict(value, indent + 1)
                    else:
                        console.print("  " * indent + f"{key}: {value}")

            print_dict(config_dict)

    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        sys.exit(1)


def main() -> None:
    """Main CLI entry point."""
    cli()


if __name__ == "__main__":
    main()
