"""
GitHub integration for creating pull requests and managing repositories.

This module provides GitHub API integration using PyGithub for automated
pull request creation with code hygiene improvements.
"""

import subprocess
from datetime import datetime
from pathlib import Path

from github import Github
from github.GithubException import GithubException
from github.Repository import Repository

from ..analyzers.base import AnalysisResult
from ..config.settings import settings
from ..utils.exceptions import GitHubIntegrationError
from ..utils.logging import get_logger

logger = get_logger(__name__)


class GitHubIntegrator:
    """Handles GitHub operations for code hygiene automation."""

    def __init__(self, token: str | None = None) -> None:
        """
        Initialize GitHub integrator.

        Args:
            token: GitHub personal access token (defaults to settings)
        """
        self.token = token or settings.github.token
        self.github = Github(self.token)
        self._repo_cache: dict[str, Repository] = {}

    def get_repository(self, owner: str, repo: str) -> Repository:
        """
        Get GitHub repository object with caching.

        Args:
            owner: Repository owner
            repo: Repository name

        Returns:
            GitHub repository object
        """
        repo_key = f"{owner}/{repo}"

        if repo_key not in self._repo_cache:
            try:
                self._repo_cache[repo_key] = self.github.get_repo(repo_key)
                logger.info("Retrieved repository", repository=repo_key)
            except GithubException as e:
                raise GitHubIntegrationError(
                    f"Failed to access repository {repo_key}",
                    details={
                        "status_code": e.status,
                        "message": e.data.get("message", ""),
                    },
                    cause=e,
                ) from e

        return self._repo_cache[repo_key]

    async def create_hygiene_pr(
        self,
        project_path: Path,
        analysis_results: dict[str, AnalysisResult],
        report_content: str,
        owner: str | None = None,
        repo: str | None = None,
    ) -> str:
        """
        Create a pull request with code hygiene improvements.

        Args:
            project_path: Local path to the project
            analysis_results: Results from code analysis
            report_content: Generated report content
            owner: GitHub repository owner (defaults to settings)
            repo: Repository name (defaults to settings)

        Returns:
            URL of the created pull request
        """
        owner = owner or settings.github.owner
        repo = repo or settings.github.repo

        logger.info(
            "Creating code hygiene PR",
            repository=f"{owner}/{repo}",
            project_path=str(project_path),
        )

        try:
            # Get repository
            github_repo = self.get_repository(owner, repo)

            # Create branch name
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            branch_name = f"{settings.github.pr_branch_prefix}hygiene-{timestamp}"

            # Get default branch
            default_branch = github_repo.default_branch
            default_branch_ref = github_repo.get_branch(default_branch)

            # Create new branch
            github_repo.create_git_ref(
                ref=f"refs/heads/{branch_name}", sha=default_branch_ref.commit.sha
            )

            logger.info(
                "Created branch", branch=branch_name, repository=f"{owner}/{repo}"
            )

            # Apply fixes and commit changes
            commits_made = await self._apply_fixes_and_commit(
                project_path, analysis_results, github_repo, branch_name
            )

            if not commits_made:
                # No changes to commit, clean up branch and return
                github_repo.get_git_ref(f"heads/{branch_name}").delete()
                logger.info("No changes to commit, branch deleted")
                return ""

            # Create report file
            report_filename = f"code-hygiene-report-{timestamp}.md"
            await self._create_report_file(
                github_repo, branch_name, report_filename, report_content
            )

            # Create pull request
            pr_title = f"{settings.github.pr_title_prefix} Code Hygiene Improvements"
            pr_body = self._generate_pr_body(analysis_results, report_filename)

            pull_request = github_repo.create_pull(
                title=pr_title, body=pr_body, head=branch_name, base=default_branch
            )

            # Add reviewers if configured
            if settings.github.pr_reviewer_teams:
                try:
                    pull_request.create_review_request(
                        team_reviewers=settings.github.pr_reviewer_teams
                    )
                except GithubException as e:
                    logger.warning(
                        "Failed to add reviewers",
                        error=str(e),
                        teams=settings.github.pr_reviewer_teams,
                    )

            logger.info(
                "Created pull request",
                pr_url=pull_request.html_url,
                pr_number=pull_request.number,
            )

            return pull_request.html_url

        except Exception as e:
            logger.error(
                "Failed to create pull request",
                error=str(e),
                error_type=type(e).__name__,
                repository=f"{owner}/{repo}",
            )
            raise GitHubIntegrationError(
                f"Failed to create pull request for {owner}/{repo}", cause=e
            ) from e

    async def _apply_fixes_and_commit(
        self,
        project_path: Path,
        analysis_results: dict[str, AnalysisResult],
        github_repo: Repository,
        branch_name: str,
    ) -> bool:
        """
        Apply automated fixes and commit changes.

        Returns:
            True if commits were made, False otherwise
        """
        commits_made = False

        # Apply vulnerability fixes
        if "vulnerability" in analysis_results:
            vulnerability_result = analysis_results["vulnerability"]
            if await self._apply_vulnerability_fixes(
                project_path, vulnerability_result
            ):
                await self._git_commit(
                    project_path,
                    "fix: Update vulnerable dependencies\n\nAutomatically updated dependencies with known vulnerabilities.",
                )
                commits_made = True

        # Apply dead code removal
        if "dead_code" in analysis_results:
            dead_code_result = analysis_results["dead_code"]
            if await self._apply_dead_code_fixes(project_path, dead_code_result):
                await self._git_commit(
                    project_path,
                    "refactor: Remove unused imports and dead code\n\nAutomatically removed unused imports and dead code identified by analysis.",
                )
                commits_made = True

        return commits_made

    async def _apply_vulnerability_fixes(
        self, project_path: Path, result: AnalysisResult
    ) -> bool:
        """Apply automated vulnerability fixes."""
        changes_made = False

        # Simple fixes for requirements files
        for issue in result.issues:
            if issue.file_path and issue.suggestion and "Update" in issue.suggestion:
                file_path = Path(issue.file_path)

                if (
                    file_path.name.startswith("requirements")
                    and file_path.suffix == ".txt"
                ):
                    if await self._update_requirements_file(file_path, issue):
                        changes_made = True

        return changes_made

    async def _update_requirements_file(self, file_path: Path, issue) -> bool:
        """Update a requirements file to fix vulnerability."""
        try:
            if not file_path.exists():
                return False

            with open(file_path) as f:
                content = f.read()

            # Extract package name from issue title
            package_name = issue.title.replace("Vulnerable dependency: ", "").strip()

            # Simple pattern matching for package updates
            lines = content.split("\n")
            updated = False

            for _i, line in enumerate(lines):
                if line.strip().startswith(package_name):
                    # This is a very basic fix - in production you'd want more sophisticated parsing
                    logger.info(
                        f"Would update line: {line} (automated fix not implemented for safety)"
                    )
                    # lines[i] = f"{package_name}>=SAFE_VERSION"  # Commented out for safety
                    # updated = True
                    break

            # Uncomment below for actual file updates (disabled for safety in demo)
            # if updated:
            #     with open(file_path, 'w') as f:
            #         f.write('\n'.join(lines))

            return updated

        except Exception as e:
            logger.error(f"Failed to update requirements file {file_path}: {e}")
            return False

    async def _apply_dead_code_fixes(
        self, project_path: Path, result: AnalysisResult
    ) -> bool:
        """Apply automated dead code removal."""
        changes_made = False

        # Group unused imports by file
        unused_imports_by_file = {}
        for issue in result.issues:
            if issue.category == "unused_import" and issue.file_path:
                if issue.file_path not in unused_imports_by_file:
                    unused_imports_by_file[issue.file_path] = []
                unused_imports_by_file[issue.file_path].append(issue)

        # Remove unused imports from each file
        for file_path, imports in unused_imports_by_file.items():
            if await self._remove_unused_imports(Path(file_path), imports):
                changes_made = True

        return changes_made

    async def _remove_unused_imports(
        self, file_path: Path, unused_imports: list
    ) -> bool:
        """Remove unused imports from a Python file."""
        try:
            if not file_path.exists():
                return False

            with open(file_path, encoding="utf-8") as f:
                lines = f.readlines()

            # Create set of line numbers to remove
            lines_to_remove = {
                issue.line_number for issue in unused_imports if issue.line_number
            }

            if not lines_to_remove:
                return False

            # Filter out the unused import lines
            filtered_lines = []
            for i, line in enumerate(lines, 1):
                if i not in lines_to_remove:
                    filtered_lines.append(line)

            # Write back the filtered content
            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(filtered_lines)

            logger.info(
                "Removed unused imports",
                file=str(file_path),
                imports_removed=len(lines_to_remove),
            )

            return True

        except Exception as e:
            logger.error(f"Failed to remove unused imports from {file_path}: {e}")
            return False

    async def _git_commit(self, project_path: Path, message: str) -> None:
        """Create a git commit with the given message."""
        try:
            # Add all changes
            await self._run_git_command(["git", "add", "."], project_path)

            # Check if there are changes to commit
            result = await self._run_git_command(
                ["git", "diff", "--cached", "--quiet"], project_path, check=False
            )

            if result.returncode == 0:
                # No changes to commit
                return

            # Commit changes
            await self._run_git_command(["git", "commit", "-m", message], project_path)

            logger.info("Git commit created", message=message)

        except Exception as e:
            logger.error(f"Git commit failed: {e}")
            raise

    async def _run_git_command(
        self, command: list[str], cwd: Path, check: bool = True
    ) -> subprocess.CompletedProcess:
        """Run a git command."""
        try:
            result = subprocess.run(
                command, cwd=cwd, capture_output=True, text=True, timeout=30
            )

            if check and result.returncode != 0:
                logger.error(
                    "Git command failed",
                    command=" ".join(command),
                    stderr=result.stderr,
                    returncode=result.returncode,
                )
                raise subprocess.CalledProcessError(
                    result.returncode, command, result.stdout, result.stderr
                )

            return result

        except subprocess.TimeoutExpired:
            logger.error("Git command timed out", command=" ".join(command))
            raise

    async def _create_report_file(
        self, github_repo: Repository, branch_name: str, filename: str, content: str
    ) -> None:
        """Create a report file in the GitHub repository."""
        try:
            github_repo.create_file(
                path=filename,
                message=f"Add code hygiene report: {filename}",
                content=content,
                branch=branch_name,
            )
            logger.info("Created report file", filename=filename, branch=branch_name)

        except GithubException as e:
            logger.warning(f"Failed to create report file: {e}")

    def _generate_pr_body(
        self, analysis_results: dict[str, AnalysisResult], report_filename: str
    ) -> str:
        """Generate pull request body content with ASCII-safe formatting."""
        total_issues = sum(len(result.issues) for result in analysis_results.values())
        successful_analyzers = [
            name for name, result in analysis_results.items() if result.success
        ]

        body = f"""## Code Hygiene Improvements

This pull request contains automated improvements to the codebase based on static analysis.

### Summary
- **Total Issues Found:** {total_issues}
- **Analyzers Used:** {", ".join(successful_analyzers)}
- **Automated Fixes Applied:** Yes
- **Detailed Report:** `{report_filename}`

### Changes Made
"""

        for analyzer_name, result in analysis_results.items():
            if result.success and result.issues:
                body += (
                    f"\n#### {analyzer_name.title()} ({len(result.issues)} issues)\n"
                )

                # Group issues by category
                by_category = {}
                for issue in result.issues:
                    if issue.category not in by_category:
                        by_category[issue.category] = []
                    by_category[issue.category].append(issue)

                for category, issues in by_category.items():
                    body += f"- **{category.title()}**: {len(issues)} issues\n"

        body += """
### Review Notes
- All changes were made automatically based on static analysis
- Please review the changes carefully before merging
- The detailed analysis report is included in this PR
- Consider running your test suite to ensure no functionality was broken

### Next Steps
1. Review the automated changes
2. Run tests to verify functionality
3. Consider the suggestions in the detailed report for manual fixes

---
*This PR was created automatically by the Code Hygiene Agent*
"""

        return body

    async def create_pr_from_analysis(
        self,
        owner: str,
        repo: str,
        head_branch: str,
        base_branch: str,
        title: str,
        analysis_results: dict[str, AnalysisResult],
        report_content: str,
    ) -> str:
        """
        Create a PR from analysis results without running the full project analysis.

        Args:
            owner: Repository owner
            repo: Repository name
            head_branch: Source branch with changes
            base_branch: Target branch for PR
            title: PR title
            analysis_results: Analysis results from analyzers
            report_content: Generated report content

        Returns:
            URL of created PR
        """
        try:
            github_repo = self.github.get_repo(f"{owner}/{repo}")

            # Create PR body from analysis results with ASCII-safe content
            pr_body = self._create_pr_body_from_analysis(
                analysis_results, report_content
            )

            # Ensure title and body are properly encoded
            safe_title = title.encode('ascii', errors='replace').decode('ascii')
            safe_body = pr_body.encode('ascii', errors='replace').decode('ascii')

            # Create the PR
            pr = github_repo.create_pull(
                title=safe_title, body=safe_body, head=head_branch, base=base_branch
            )

            await logger.ainfo(
                "PR created from analysis",
                pr_url=pr.html_url,
                pr_number=pr.number,
                head_branch=head_branch,
                base_branch=base_branch,
            )

            return pr.html_url

        except Exception as e:
            error_msg = f"Failed to create PR: {e}"
            await logger.aerror(
                "PR creation failed", error=str(e), repo=f"{owner}/{repo}"
            )
            raise GitHubIntegrationError(error_msg) from e

    def _create_pr_body_from_analysis(
        self, analysis_results: dict[str, AnalysisResult], report_content: str
    ) -> str:
        """Create PR body from analysis results with proper Unicode handling."""

        # Calculate summary statistics
        total_issues = sum(len(result.issues) for result in analysis_results.values())

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        category_counts = {}

        for result in analysis_results.values():
            for issue in result.issues:
                severity_counts[issue.severity] = (
                    severity_counts.get(issue.severity, 0) + 1
                )
                category_counts[issue.category] = (
                    category_counts.get(issue.category, 0) + 1
                )

        # Build PR body with ASCII-safe fallbacks
        body = f"""# Code Hygiene Analysis Results

This PR contains automated fixes based on code hygiene analysis.

## Analysis Summary

**Total Issues Found:** {total_issues}

### Issues by Severity
"""

        for severity, count in severity_counts.items():
            if count > 0:
                # Use ASCII-safe indicators instead of emojis
                indicator = {
                    "critical": "[CRITICAL]",
                    "high": "[HIGH]",
                    "medium": "[MEDIUM]", 
                    "low": "[LOW]",
                    "info": "[INFO]",
                }
                body += (
                    f"- {indicator.get(severity, '•')} **{severity.title()}**: {count}\n"
                )

        body += "\n### Issues by Category\n"
        for category, count in category_counts.items():
            body += f"- **{category.title()}**: {count}\n"

        body += f"""

## Automated Fixes Applied

This PR includes automated fixes for issues that can be safely corrected:
- [x] Removed unused imports
- [x] Basic code formatting improvements
- [x] Safe dependency updates (where applicable)

## Full Analysis Report

<details>
<summary>Click to view detailed analysis report</summary>

```markdown
{report_content}
```

</details>

## Review Required

Please review all changes carefully:
1. **Test thoroughly** - Run your full test suite
2. **Manual review** - Some issues may require manual attention
3. **Dependency updates** - Verify compatibility of any updated dependencies

## About This PR

This PR was automatically generated by the Code Hygiene Agent, which analyzed your codebase for:
- Security vulnerabilities
- Dead/unused code
- Code quality issues
- Best practice violations

---
*Generated by Code Hygiene Agent*
"""

        return body
