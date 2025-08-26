"""
Main entry point for the Code Hygiene Agent.

This module provides the main entry point for running the MCP server.
"""

import asyncio
import sys

from .mcp_server.server import main

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down Code Hygiene Agent...")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
