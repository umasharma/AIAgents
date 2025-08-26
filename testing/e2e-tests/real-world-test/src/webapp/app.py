"""
Main Flask application with intentional security vulnerabilities and dead code.
This represents a realistic web application with common issues.
"""

import os
import sys
import json
import pickle
import hashlib
import subprocess
import tempfile
import datetime
import sqlite3
import logging
import uuid
import base64

# Unused imports that should be flagged
import math
import random
import time
import collections
from functools import wraps

from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
from werkzeug.utils import secure_filename
import requests
import jwt
from cryptography.fernet import Fernet
import yaml

# Initialize Flask app
app = Flask(__name__)

# Security issues: hardcoded secrets
app.secret_key = "super-secret-key-12345"  # Hardcoded secret
JWT_SECRET = "jwt-secret-key"               # Another hardcoded secret
DATABASE_PASSWORD = "admin123"             # Hardcoded DB password

# Global variables (some unused)
UPLOAD_FOLDER = '/tmp/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 16 * 1024 * 1024

# Unused global variables
UNUSED_CONFIG = {"debug": True, "testing": False}
LEGACY_SETTINGS = {"old_feature": True}
DEPRECATED_CONSTANTS = ["CONST1", "CONST2", "CONST3"]


class UnusedUserClass:
    """This entire class is never used - dead code."""
    
    def __init__(self, username, email):
        self.username = username
        self.email = email
        self.created_at = datetime.datetime.now()
    
    def get_profile(self):
        return {
            "username": self.username,
            "email": self.email,
            "member_since": self.created_at
        }
    
    def update_profile(self, data):
        # This method is never called
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)


class TaskManager:
    """Task management class - partially used."""
    
    def __init__(self):
        self.tasks = []
        self.completed_tasks = []  # Never actually used
        self.task_history = {}     # Never used
    
    def add_task(self, title, description):
        """Used method."""
        task = {
            "id": str(uuid.uuid4()),
            "title": title,
            "description": description,
            "created_at": datetime.datetime.now().isoformat(),
            "completed": False
        }
        self.tasks.append(task)
        return task
    
    def get_task_stats(self):
        """Unused method with complex logic."""
        total_tasks = len(self.tasks)
        completed = len([t for t in self.tasks if t.get("completed", False)])
        pending = total_tasks - completed
        
        avg_completion_time = 0
        if completed > 0:
            # Complex calculation that's never used
            completion_times = []
            for task in self.tasks:
                if task.get("completed"):
                    created = datetime.datetime.fromisoformat(task["created_at"])
                    completed_at = task.get("completed_at", datetime.datetime.now())
                    if isinstance(completed_at, str):
                        completed_at = datetime.datetime.fromisoformat(completed_at)
                    completion_times.append((completed_at - created).total_seconds())
            
            if completion_times:
                avg_completion_time = sum(completion_times) / len(completion_times)
        
        return {
            "total": total_tasks,
            "completed": completed,
            "pending": pending,
            "avg_completion_time": avg_completion_time
        }
    
    def export_tasks_csv(self):
        """Another unused method."""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Title", "Description", "Created", "Completed"])
        
        for task in self.tasks:
            writer.writerow([
                task["id"],
                task["title"], 
                task["description"],
                task["created_at"],
                task.get("completed", False)
            ])
        
        return output.getvalue()


# Global task manager instance
task_manager = TaskManager()


def unused_decorator(f):
    """Unused decorator function."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f"Calling function: {f.__name__}")
        return f(*args, **kwargs)
    return decorated_function


def vulnerable_deserialization(data):
    """Security vulnerability: unsafe deserialization."""
    # Security issue: pickle deserialization of untrusted data
    try:
        return pickle.loads(base64.b64decode(data))
    except Exception:
        return None


def insecure_password_hash(password):
    """Security vulnerability: weak password hashing."""
    # Security issue: using MD5 for password hashing
    salt = "fixed_salt_123"  # Weak fixed salt
    return hashlib.md5((password + salt).encode()).hexdigest()


def command_injection_vulnerability(user_input):
    """Security vulnerability: command injection."""
    # Security issue: direct command execution with user input
    try:
        result = subprocess.run(f"echo {user_input}", shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return str(e)


def path_traversal_vulnerability(filename):
    """Security vulnerability: path traversal."""
    # Security issue: no path validation
    file_path = os.path.join("/tmp/uploads", filename)
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except Exception:
        return "File not found"


@app.route('/')
def index():
    """Main page with template injection vulnerability."""
    name = request.args.get('name', 'World')
    
    # Security issue: template injection
    template = f"""
    <h1>Welcome to TaskTracker, {name}!</h1>
    <p>Manage your tasks efficiently.</p>
    <a href="/tasks">View Tasks</a> | <a href="/upload">Upload File</a>
    """
    return render_template_string(template)


@app.route('/tasks', methods=['GET', 'POST'])
def tasks():
    """Task management endpoint."""
    if request.method == 'POST':
        data = request.get_json()
        task = task_manager.add_task(data.get('title'), data.get('description'))
        return jsonify(task)
    
    return jsonify({"tasks": task_manager.tasks})


@app.route('/upload', methods=['POST'])
def upload_file():
    """File upload with multiple security issues."""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    # Security issue: insufficient file type validation
    filename = file.filename
    
    # Security issue: path traversal possibility
    upload_path = os.path.join(UPLOAD_FOLDER, filename)
    
    # Create directory if it doesn't exist
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    # Security issue: no file size checking
    file.save(upload_path)
    
    # Security issue: file permissions not set properly
    os.chmod(upload_path, 0o777)
    
    return jsonify({
        "message": "File uploaded successfully",
        "filename": filename,
        "path": upload_path
    })


@app.route('/api/user/<user_id>')
def get_user(user_id):
    """API endpoint with SQL injection vulnerability."""
    # Security issue: SQL injection (simulated)
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    # In a real app, this would execute against a database
    return jsonify({
        "query": query,
        "user_id": user_id,
        "warning": "This endpoint is vulnerable to SQL injection"
    })


@app.route('/api/search')
def search():
    """Search endpoint with XSS vulnerability."""
    query = request.args.get('q', '')
    
    # Security issue: no input sanitization
    results_html = f"""
    <h2>Search Results for: {query}</h2>
    <p>Found 0 results for "{query}"</p>
    """
    
    return results_html


@app.route('/admin/config', methods=['GET', 'POST'])
def admin_config():
    """Admin endpoint with YAML deserialization vulnerability."""
    if request.method == 'POST':
        config_data = request.data.decode('utf-8')
        
        # Security issue: unsafe YAML loading
        try:
            config = yaml.load(config_data, Loader=yaml.UnsafeLoader)
            return jsonify({"status": "Config updated", "config": config})
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    
    return jsonify({"current_config": {"debug": True, "testing": False}})


@app.route('/jwt-test')
def jwt_test():
    """JWT endpoint with weak secret."""
    payload = {
        "user_id": 123,
        "username": "testuser",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    
    # Security issue: weak JWT secret
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    
    return jsonify({"token": token})


def unused_utility_function():
    """Unused utility function."""
    return "This function is never called"


def another_unused_function(data):
    """Another unused function with parameters."""
    processed_data = []
    for item in data:
        if isinstance(item, str):
            processed_data.append(item.upper())
        elif isinstance(item, (int, float)):
            processed_data.append(item * 2)
    return processed_data


def legacy_data_processor():
    """Legacy function that's no longer used."""
    # Complex legacy code that's never called
    legacy_config = {
        "version": "1.0",
        "deprecated": True,
        "replacement": "new_data_processor"
    }
    
    # Simulate old data processing logic
    data_cache = {}
    processed_items = 0
    error_count = 0
    
    try:
        # Old processing logic
        for i in range(100):
            key = f"item_{i}"
            value = f"processed_{i}"
            data_cache[key] = value
            processed_items += 1
    except Exception:
        error_count += 1
    
    return {
        "config": legacy_config,
        "processed": processed_items,
        "errors": error_count,
        "cache_size": len(data_cache)
    }


# Unused module-level variables
DEPRECATED_SETTINGS_V1 = {"old": True}
LEGACY_MAPPING = {"a": 1, "b": 2, "c": 3}
UNUSED_CONSTANTS = [
    "CONSTANT_1",
    "CONSTANT_2", 
    "CONSTANT_3"
]

# Actually used settings
CURRENT_VERSION = "2.0"
ACTIVE_FEATURES = ["tasks", "upload", "api"]


if __name__ == '__main__':
    # Security issue: debug mode enabled in production
    # Security issue: binding to all interfaces
    app.run(debug=True, host='0.0.0.0', port=5000)