"""
Code Hygiene Agent - MCP Server for automated code analysis and remediation.

A comprehensive Model Context Protocol (MCP) agent that performs:
- Vulnerability and dependency scanning
- Dead code analysis
- Automated report generation
- GitHub integration for PR creation
"""

__version__ = "1.0.0"
__author__ = "Code Hygiene Agent"
__description__ = "MCP Agent for automated code hygiene analysis and remediation"

from .config.settings import Settings
from .utils.exceptions import CodeHygieneError

__all__ = ["Settings", "CodeHygieneError"]
