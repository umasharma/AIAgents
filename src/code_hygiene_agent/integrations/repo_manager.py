"""
Repository management for cloning and analyzing GitHub repositories.
"""

import asyncio
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

import git
import structlog

from ..utils.exceptions import RepositoryError

logger = structlog.get_logger()


class RepositoryManager:
    """Manages repository cloning and cleanup for analysis."""

    def __init__(self):
        self._temp_dirs: list[Path] = []

    def parse_github_url(self, url: str) -> tuple[str, str]:
        """
        Parse GitHub URL to extract owner and repository name.

        Args:
            url: GitHub repository URL

        Returns:
            Tuple of (owner, repo_name)

        Raises:
            RepositoryError: If URL is invalid
        """
        # Handle different GitHub URL formats
        patterns = [
            r"github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?/?$",  # Standard format
            r"github\.com/([^/]+)/([^/]+)/tree/([^/]+)",  # With branch
            r"github\.com/([^/]+)/([^/]+)/blob/([^/]+)",  # With file path
        ]

        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                owner = match.group(1)
                repo = match.group(2)
                return owner, repo

        raise RepositoryError(f"Invalid GitHub URL format: {url}")

    async def clone_repository(
        self,
        repo_url: str,
        target_dir: Path | None = None,
        branch: str | None = None,
        depth: int | None = 1,
    ) -> Path:
        """
        Clone a GitHub repository for analysis.

        Args:
            repo_url: GitHub repository URL
            target_dir: Directory to clone into (creates temp if None)
            branch: Specific branch to clone (default branch if None)
            depth: Clone depth (1 for shallow clone)

        Returns:
            Path to cloned repository

        Raises:
            RepositoryError: If cloning fails
        """
        await logger.ainfo(
            "Starting repository clone", repo_url=repo_url, branch=branch
        )

        try:
            # Create target directory
            if target_dir is None:
                target_dir = Path(tempfile.mkdtemp(prefix="code_hygiene_repo_"))
                self._temp_dirs.append(target_dir)
            else:
                target_dir.mkdir(parents=True, exist_ok=True)

            # Clone options
            clone_kwargs = {
                "depth": depth,
                "single_branch": True,
            }

            if branch:
                clone_kwargs["branch"] = branch

            # Perform clone
            await logger.ainfo("Cloning repository", target_dir=str(target_dir))

            # Run git clone in subprocess to avoid blocking
            repo = await asyncio.to_thread(
                git.Repo.clone_from, repo_url, str(target_dir), **clone_kwargs
            )

            await logger.ainfo(
                "Repository cloned successfully",
                repo_path=str(target_dir),
                commit_hash=repo.head.commit.hexsha[:8],
                branch=repo.active_branch.name if repo.active_branch else "detached",
            )

            return target_dir

        except git.exc.GitCommandError as e:
            error_msg = f"Git clone failed: {e}"
            await logger.aerror(
                "Repository clone failed", error=str(e), repo_url=repo_url
            )
            raise RepositoryError(error_msg) from e

        except Exception as e:
            error_msg = f"Unexpected error during clone: {e}"
            await logger.aerror(
                "Unexpected clone error", error=str(e), repo_url=repo_url
            )
            raise RepositoryError(error_msg) from e

    async def get_repository_info(self, repo_path: Path) -> dict[str, Any]:
        """
        Get information about the cloned repository.

        Args:
            repo_path: Path to repository

        Returns:
            Dictionary with repository information
        """
        try:
            repo = git.Repo(str(repo_path))

            # Get basic info
            info = {
                "path": str(repo_path),
                "is_bare": repo.bare,
                "active_branch": repo.active_branch.name
                if repo.active_branch
                else None,
                "commit_hash": repo.head.commit.hexsha,
                "commit_message": repo.head.commit.message.strip(),
                "commit_author": str(repo.head.commit.author),
                "commit_date": repo.head.commit.committed_datetime.isoformat(),
                "remotes": [remote.name for remote in repo.remotes],
                "origin_url": None,
            }

            # Get origin URL if available
            if "origin" in [r.name for r in repo.remotes]:
                try:
                    info["origin_url"] = repo.remotes.origin.url
                except Exception:
                    pass

            # Count files by type
            file_counts = {}
            for file_path in repo_path.rglob("*"):
                if file_path.is_file() and not file_path.name.startswith("."):
                    suffix = file_path.suffix.lower()
                    if suffix:
                        file_counts[suffix] = file_counts.get(suffix, 0) + 1

            info["file_types"] = file_counts
            info["total_files"] = sum(file_counts.values())

            return info

        except Exception as e:
            await logger.awarning("Failed to get repository info", error=str(e))
            return {"path": str(repo_path), "error": str(e)}

    async def create_analysis_branch(self, repo_path: Path, branch_name: str) -> str:
        """
        Create a new branch for applying fixes.

        Args:
            repo_path: Path to repository
            branch_name: Name of new branch

        Returns:
            Name of created branch

        Raises:
            RepositoryError: If branch creation fails
        """
        try:
            repo = git.Repo(str(repo_path))

            # Create new branch from current HEAD
            new_branch = repo.create_head(branch_name)
            new_branch.checkout()

            await logger.ainfo(
                "Created analysis branch", branch=branch_name, repo_path=str(repo_path)
            )
            return branch_name

        except Exception as e:
            error_msg = f"Failed to create branch {branch_name}: {e}"
            await logger.aerror(
                "Branch creation failed", error=str(e), branch=branch_name
            )
            raise RepositoryError(error_msg) from e

    async def commit_changes(
        self,
        repo_path: Path,
        message: str,
        author_name: str | None = None,
        author_email: str | None = None,
    ) -> str:
        """
        Commit changes to the repository.

        Args:
            repo_path: Path to repository
            message: Commit message
            author_name: Author name (defaults to settings)
            author_email: Author email (defaults to settings)

        Returns:
            Commit hash

        Raises:
            RepositoryError: If commit fails
        """
        try:
            repo = git.Repo(str(repo_path))

            # Configure author
            if author_name is None:
                author_name = "Code Hygiene Agent"
            if author_email is None:
                author_email = "noreply@codehygiene.ai"

            # Add all changes
            repo.git.add(A=True)

            # Check if there are changes to commit
            if not repo.index.diff("HEAD"):
                await logger.ainfo("No changes to commit", repo_path=str(repo_path))
                return repo.head.commit.hexsha

            # Create commit
            commit = repo.index.commit(
                message,
                author=git.Actor(author_name, author_email),
                committer=git.Actor(author_name, author_email),
            )

            await logger.ainfo(
                "Changes committed",
                repo_path=str(repo_path),
                commit_hash=commit.hexsha[:8],
                files_changed=len(commit.stats.files),
            )

            return commit.hexsha

        except Exception as e:
            error_msg = f"Failed to commit changes: {e}"
            await logger.aerror("Commit failed", error=str(e), repo_path=str(repo_path))
            raise RepositoryError(error_msg) from e

    async def push_changes(
        self,
        repo_path: Path,
        remote_name: str = "origin",
        branch_name: str | None = None,
    ) -> bool:
        """
        Push changes to remote repository.

        Args:
            repo_path: Path to repository
            remote_name: Name of remote (default: origin)
            branch_name: Branch to push (current if None)

        Returns:
            True if successful

        Raises:
            RepositoryError: If push fails
        """
        try:
            repo = git.Repo(str(repo_path))

            if branch_name is None:
                branch_name = repo.active_branch.name

            # Push to remote
            origin = repo.remote(remote_name)
            origin.push(branch_name)

            await logger.ainfo(
                "Changes pushed successfully",
                repo_path=str(repo_path),
                remote=remote_name,
                branch=branch_name,
            )

            return True

        except Exception as e:
            error_msg = f"Failed to push changes: {e}"
            await logger.aerror(
                "Push failed", error=str(e), remote=remote_name, branch=branch_name
            )
            raise RepositoryError(error_msg) from e

    def cleanup_temp_directories(self) -> None:
        """Clean up temporary directories created during analysis."""
        for temp_dir in self._temp_dirs:
            try:
                if temp_dir.exists():
                    shutil.rmtree(temp_dir)
                    logger.info("Cleaned up temporary directory", path=str(temp_dir))
            except Exception as e:
                logger.warning(
                    "Failed to cleanup directory", path=str(temp_dir), error=str(e)
                )

        self._temp_dirs.clear()

    def __del__(self):
        """Cleanup on destruction."""
        self.cleanup_temp_directories()
