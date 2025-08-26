# TaskTracker Web Application

A sample Python web application for task management with intentional code quality issues for testing the Code Hygiene Agent.

## Overview

This is a Flask-based web application that demonstrates common code quality issues found in real-world projects:

- Outdated dependencies with known vulnerabilities
- Dead code and unused imports
- Security anti-patterns
- Unmaintained legacy code sections

## Setup

```bash
pip install -r requirements.txt
python src/webapp/app.py
```

## Features

- User authentication
- Task creation and management
- File upload functionality
- API endpoints
- Database integration

## Testing

```bash
python -m pytest tests/
```

*Note: This project contains intentional security vulnerabilities and code quality issues for demonstration purposes. Do not use in production.*