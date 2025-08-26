"""
Report generation system for code hygiene analysis results.

This module provides comprehensive reporting capabilities with multiple
output formats and AI-powered suggestions.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import openai
except ImportError:
    openai = None
from jinja2 import Environment, FileSystemLoader, Template

from ..analyzers.base import AnalysisResult
from ..config.settings import ReportFormat, settings
from ..utils.exceptions import ReportGenerationError
from ..utils.logging import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """Generates comprehensive reports from analysis results."""

    def __init__(self, openai_client: Any = None) -> None:
        """
        Initialize report generator.

        Args:
            openai_client: OpenAI client for AI-powered suggestions (optional)
        """
        if openai_client is None and openai is not None:
            self.openai_client = openai.Client(api_key=settings.openai.api_key)
        else:
            self.openai_client = openai_client
        self._templates_dir = Path(__file__).parent / "templates"
        self._setup_templates()

    def _setup_templates(self) -> None:
        """Set up Jinja2 template environment."""
        if self._templates_dir.exists():
            self.env = Environment(
                loader=FileSystemLoader(str(self._templates_dir)), autoescape=True
            )
        else:
            # Use string templates if template directory doesn't exist
            self.env = Environment(loader=None, autoescape=True)

    async def generate_report(
        self,
        analysis_results: dict[str, AnalysisResult],
        project_path: Path,
        format_type: ReportFormat | None = None,
        include_ai_suggestions: bool | None = None,
    ) -> str:
        """
        Generate a comprehensive report from analysis results.

        Args:
            analysis_results: Results from multiple analyzers
            project_path: Path to the analyzed project
            format_type: Output format (defaults to settings)
            include_ai_suggestions: Whether to include AI suggestions

        Returns:
            Generated report content
        """
        format_type = format_type or settings.reporting.format
        include_ai_suggestions = (
            include_ai_suggestions
            if include_ai_suggestions is not None
            else settings.reporting.include_suggestions
        )

        logger.info(
            "Generating report",
            format=format_type.value,
            analyzers=list(analysis_results.keys()),
            include_ai=include_ai_suggestions,
        )

        try:
            # Prepare report data
            report_data = await self._prepare_report_data(
                analysis_results, project_path, include_ai_suggestions
            )

            # Generate report based on format
            if format_type == ReportFormat.MARKDOWN:
                content = await self._generate_markdown_report(report_data)
            elif format_type == ReportFormat.JSON:
                content = await self._generate_json_report(report_data)
            elif format_type == ReportFormat.HTML:
                content = await self._generate_html_report(report_data)
            else:
                raise ReportGenerationError(f"Unsupported report format: {format_type}")

            logger.info("Report generated successfully", format=format_type.value)
            return content

        except Exception as e:
            logger.error(
                "Report generation failed",
                error=str(e),
                error_type=type(e).__name__,
                format=format_type.value,
            )
            raise ReportGenerationError(
                f"Failed to generate report: {e}", cause=e
            ) from e

    async def _prepare_report_data(
        self,
        analysis_results: dict[str, AnalysisResult],
        project_path: Path,
        include_ai_suggestions: bool,
    ) -> dict[str, Any]:
        """Prepare data for report generation."""
        # Calculate summary statistics
        total_issues = sum(len(result.issues) for result in analysis_results.values())
        successful_analyzers = [
            name for name, result in analysis_results.items() if result.success
        ]
        failed_analyzers = [
            name for name, result in analysis_results.items() if not result.success
        ]

        # Group issues by severity and category
        issues_by_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        issues_by_category: dict[str, int] = {}
        all_issues = []

        for result in analysis_results.values():
            for issue in result.issues:
                # Count by severity
                issues_by_severity[issue.severity] += 1

                # Count by category
                issues_by_category[issue.category] = (
                    issues_by_category.get(issue.category, 0) + 1
                )

                # Collect all issues
                all_issues.append(issue)

        # Generate AI-powered executive summary and recommendations
        ai_summary = ""
        ai_recommendations = []

        if include_ai_suggestions and total_issues > 0:
            try:
                ai_summary = await self._generate_ai_summary(
                    analysis_results, project_path
                )
                ai_recommendations = await self._generate_ai_recommendations(
                    analysis_results
                )
            except Exception as e:
                logger.warning("Failed to generate AI suggestions", error=str(e))

        return {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "project_path": str(project_path),
                "total_issues": total_issues,
                "analyzers_run": len(analysis_results),
                "successful_analyzers": successful_analyzers,
                "failed_analyzers": failed_analyzers,
            },
            "summary": {
                "issues_by_severity": issues_by_severity,
                "issues_by_category": issues_by_category,
                "risk_score": self._calculate_risk_score(issues_by_severity),
            },
            "analysis_results": analysis_results,
            "issues": all_issues,
            "ai_insights": {
                "summary": ai_summary,
                "recommendations": ai_recommendations,
                "enabled": include_ai_suggestions,
            },
        }

    async def _generate_markdown_report(self, report_data: dict) -> str:
        """Generate a Markdown report."""
        template_content = """# Code Hygiene Analysis Report

**Generated:** {{ metadata.generated_at }}
**Project:** `{{ metadata.project_path }}`
**Total Issues:** {{ metadata.total_issues }}

## Executive Summary

{% if ai_insights.enabled and ai_insights.summary %}
{{ ai_insights.summary }}
{% else %}
This analysis found **{{ metadata.total_issues }}** issues across **{{ metadata.analyzers_run }}** analyzers.

**Risk Assessment:** {{ summary.risk_score }}/100
{% endif %}

### Issues by Severity
{% for severity, count in summary.issues_by_severity.items() %}
{% if count > 0 %}
- **{{ severity.title() }}:** {{ count }}
{% endif %}
{% endfor %}

### Issues by Category
{% for category, count in summary.issues_by_category.items() %}
- **{{ category.title() }}:** {{ count }}
{% endfor %}

## Analysis Results

{% for analyzer_name, result in analysis_results.items() %}
### {{ analyzer_name.title() }} Analysis

- **Status:** {% if result.success %}✅ Success{% else %}❌ Failed{% endif %}
- **Execution Time:** {{ "%.2f"|format(result.execution_time) }}s
- **Issues Found:** {{ result.issues|length }}

{% if result.error_message %}
**Error:** {{ result.error_message }}
{% endif %}

{% if result.issues %}
#### Issues Found

{% for issue in result.issues %}
**{{ issue.severity.upper() }}** - {{ issue.title }}
- **File:** `{{ issue.file_path }}`{% if issue.line_number %} (line {{ issue.line_number }}){% endif %}
- **Category:** {{ issue.category }}
- **Description:** {{ issue.description }}
{% if issue.suggestion %}
- **Suggestion:** {{ issue.suggestion }}
{% endif %}
{% if issue.references %}
- **References:** {{ issue.references|join(', ') }}
{% endif %}

{% endfor %}
{% endif %}

---
{% endfor %}

{% if ai_insights.enabled and ai_insights.recommendations %}
## 🤖 AI-Powered Recommendations

{% for recommendation in ai_insights.recommendations %}
### {{ recommendation.priority.title() }} Priority: {{ recommendation.title }}

{{ recommendation.description }}

{% if recommendation.steps %}
**Implementation Steps:**
{% for step in recommendation.steps %}
{{ loop.index }}. {{ step }}
{% endfor %}
{% endif %}

{% endfor %}
{% endif %}

## Next Steps

1. **Address Critical Issues:** Focus on {{ summary.issues_by_severity.critical }} critical issues first
2. **Review High Priority:** Examine {{ summary.issues_by_severity.high }} high priority issues
3. **Plan Improvements:** Create tasks for {{ summary.issues_by_severity.medium }} medium priority issues
4. **Consider Automation:** Set up continuous monitoring for code hygiene

---
*Report generated by Code Hygiene Agent*
"""

        template = Template(template_content)
        return template.render(**report_data)

    async def _generate_json_report(self, report_data: dict) -> str:
        """Generate a JSON report."""
        # Convert AnalysisResult objects to dictionaries for JSON serialization
        json_data = {
            "metadata": report_data["metadata"],
            "summary": report_data["summary"],
            "analysis_results": {
                name: {
                    "analyzer_name": result.analyzer_name,
                    "project_path": result.project_path,
                    "execution_time": result.execution_time,
                    "success": result.success,
                    "issues": [issue.model_dump() for issue in result.issues],
                    "metadata": result.metadata,
                    "error_message": result.error_message,
                }
                for name, result in report_data["analysis_results"].items()
            },
            "ai_insights": report_data["ai_insights"],
        }

        return json.dumps(json_data, indent=2, ensure_ascii=False)

    async def _generate_html_report(self, report_data: dict) -> str:
        """Generate an HTML report."""
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Code Hygiene Analysis Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 2rem; }
        .header { border-bottom: 2px solid #eee; padding-bottom: 1rem; margin-bottom: 2rem; }
        .summary { background: #f8f9fa; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
        .issue { border-left: 4px solid #007bff; padding: 0.5rem 1rem; margin: 1rem 0; background: #f8f9fa; }
        .issue.critical { border-left-color: #dc3545; }
        .issue.high { border-left-color: #fd7e14; }
        .issue.medium { border-left-color: #ffc107; }
        .issue.low { border-left-color: #28a745; }
        .analyzer { margin: 2rem 0; }
        .metadata { font-size: 0.9em; color: #666; }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
        th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🧹 Code Hygiene Analysis Report</h1>
        <div class="metadata">
            Generated: {{ metadata.generated_at }}<br>
            Project: <code>{{ metadata.project_path }}</code><br>
            Total Issues: <strong>{{ metadata.total_issues }}</strong>
        </div>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        {% if ai_insights.enabled and ai_insights.summary %}
        <p>{{ ai_insights.summary }}</p>
        {% else %}
        <p>This analysis found <strong>{{ metadata.total_issues }}</strong> issues across <strong>{{ metadata.analyzers_run }}</strong> analyzers.</p>
        <p><strong>Risk Assessment:</strong> {{ summary.risk_score }}/100</p>
        {% endif %}

        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            {% for severity, count in summary.issues_by_severity.items() %}
            {% if count > 0 %}
            <tr><td>{{ severity.title() }}</td><td>{{ count }}</td></tr>
            {% endif %}
            {% endfor %}
        </table>
    </div>

    {% for analyzer_name, result in analysis_results.items() %}
    <div class="analyzer">
        <h2>{{ analyzer_name.title() }} Analysis</h2>
        <p>
            Status: {% if result.success %}✅ Success{% else %}❌ Failed{% endif %} |
            Execution Time: {{ "%.2f"|format(result.execution_time) }}s |
            Issues: {{ result.issues|length }}
        </p>

        {% if result.error_message %}
        <div class="issue critical">
            <strong>Error:</strong> {{ result.error_message }}
        </div>
        {% endif %}

        {% for issue in result.issues %}
        <div class="issue {{ issue.severity }}">
            <h4>{{ issue.title }}</h4>
            <p><strong>File:</strong> <code>{{ issue.file_path }}</code>{% if issue.line_number %} (line {{ issue.line_number }}){% endif %}</p>
            <p><strong>Category:</strong> {{ issue.category }}</p>
            <p>{{ issue.description }}</p>
            {% if issue.suggestion %}
            <p><strong>Suggestion:</strong> {{ issue.suggestion }}</p>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    {% endfor %}

    <footer>
        <hr>
        <p><em>Report generated by Code Hygiene Agent</em></p>
    </footer>
</body>
</html>"""

        template = Template(html_template)
        return template.render(**report_data)

    async def _generate_ai_summary(
        self, analysis_results: dict[str, AnalysisResult], project_path: Path
    ) -> str:
        """Generate AI-powered executive summary."""
        if self.openai_client is None:
            return ""

        # Prepare context for AI
        context = self._prepare_ai_context(analysis_results)

        prompt = f"""
Analyze the following code hygiene analysis results and provide an executive summary.

Project: {project_path}
Analysis Results: {context}

Please provide:
1. A brief assessment of the overall code health
2. The most critical issues that need immediate attention
3. Risk assessment and potential impact
4. Priority recommendations

Keep the summary concise but informative (2-3 paragraphs).
"""

        try:
            response = self.openai_client.chat.completions.create(
                model=settings.openai.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior software engineer reviewing code analysis results. Provide clear, actionable insights.",
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=settings.openai.max_tokens,
                temperature=settings.openai.temperature,
            )

            return response.choices[0].message.content.strip()

        except Exception as e:
            logger.warning("Failed to generate AI summary", error=str(e))
            return ""

    async def _generate_ai_recommendations(
        self, analysis_results: dict[str, AnalysisResult]
    ) -> list[dict]:
        """Generate AI-powered recommendations."""
        if self.openai_client is None:
            return []

        context = self._prepare_ai_context(analysis_results)

        prompt = f"""
Based on these code analysis results, provide 3-5 specific, actionable recommendations for improving code hygiene:

{context}

For each recommendation, provide:
1. Title (brief)
2. Priority (critical/high/medium/low)
3. Description (2-3 sentences)
4. Implementation steps (3-5 bullet points)

Format as JSON array.
"""

        try:
            response = self.openai_client.chat.completions.create(
                model=settings.openai.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior software engineer. Provide practical, specific recommendations in JSON format.",
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=settings.openai.max_tokens,
                temperature=settings.openai.temperature,
            )

            content = response.choices[0].message.content.strip()
            # Try to parse JSON, fallback to empty list if failed
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                logger.warning("Failed to parse AI recommendations as JSON")
                return []

        except Exception as e:
            logger.warning("Failed to generate AI recommendations", error=str(e))
            return []

    def _prepare_ai_context(self, analysis_results: dict[str, AnalysisResult]) -> str:
        """Prepare analysis context for AI processing."""
        context_parts = []

        for analyzer_name, result in analysis_results.items():
            context_parts.append(f"{analyzer_name}: {len(result.issues)} issues")

            # Add severity breakdown
            severity_counts = {}
            for issue in result.issues:
                severity_counts[issue.severity] = (
                    severity_counts.get(issue.severity, 0) + 1
                )

            if severity_counts:
                severity_str = ", ".join(
                    f"{k}: {v}" for k, v in severity_counts.items()
                )
                context_parts.append(f"  Severities: {severity_str}")

        return "\n".join(context_parts)

    def _calculate_risk_score(self, issues_by_severity: dict[str, int]) -> int:
        """Calculate a risk score based on issue severities."""
        weights = {"critical": 20, "high": 10, "medium": 5, "low": 2, "info": 1}

        score = sum(
            issues_by_severity.get(severity, 0) * weight
            for severity, weight in weights.items()
        )

        # Normalize to 0-100 scale (adjust multiplier based on typical project sizes)
        return min(100, score)
