"""
Utility functions with various code quality issues.
"""

import os
import json
import hashlib
import requests
import subprocess
import tempfile
import logging
import datetime
import re
import base64
import yaml
import xml.etree.ElementTree as ET

# Unused imports
import math
import random
import string
import collections
import itertools


def unused_string_utilities():
    """Collection of unused string utility functions."""
    
    def capitalize_words(text):
        return ' '.join(word.capitalize() for word in text.split())
    
    def reverse_string(text):
        return text[::-1]
    
    def count_vowels(text):
        vowels = 'aeiouAEIOU'
        return sum(1 for char in text if char in vowels)
    
    def remove_special_chars(text):
        return re.sub(r'[^a-zA-Z0-9\s]', '', text)
    
    # These functions are defined but never used
    return {
        "capitalize": capitalize_words,
        "reverse": reverse_string,
        "vowels": count_vowels,
        "clean": remove_special_chars
    }


def insecure_file_operations(filename, content):
    """Security vulnerability: unsafe file operations."""
    # Security issue: no path validation
    file_path = f"/tmp/{filename}"
    
    # Security issue: arbitrary file write
    with open(file_path, 'w') as f:
        f.write(content)
    
    # Security issue: overly permissive file permissions
    os.chmod(file_path, 0o777)
    
    return file_path


def command_injection_helper(user_command):
    """Security vulnerability: command injection."""
    # Security issue: shell injection vulnerability
    try:
        result = subprocess.run(
            f"ls -la {user_command}",
            shell=True,
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        return f"Error: {str(e)}"


def weak_encryption_example(data):
    """Security issue: weak encryption implementation."""
    # Security issue: weak encryption key
    key = "simple_key_123"
    
    # Security issue: basic XOR "encryption"
    encrypted = []
    for i, char in enumerate(data):
        key_char = key[i % len(key)]
        encrypted.append(chr(ord(char) ^ ord(key_char)))
    
    return ''.join(encrypted)


def unsafe_xml_parser(xml_string):
    """Security vulnerability: XML External Entity (XXE) attack."""
    # Security issue: XML parsing without disabling external entities
    try:
        root = ET.fromstring(xml_string)
        return {"tag": root.tag, "text": root.text}
    except ET.ParseError:
        return {"error": "Invalid XML"}


def unsafe_yaml_loader(yaml_content):
    """Security vulnerability: unsafe YAML loading."""
    # Security issue: using unsafe YAML loader
    try:
        return yaml.load(yaml_content, Loader=yaml.UnsafeLoader)
    except yaml.YAMLError:
        return None


def hardcoded_credentials_example():
    """Security issue: hardcoded credentials."""
    # Security issues: hardcoded secrets
    database_config = {
        "host": "localhost",
        "user": "admin",
        "password": "admin123",      # Hardcoded password
        "api_key": "abc123xyz789",   # Hardcoded API key
        "secret_token": "secret123"  # Hardcoded token
    }
    return database_config


def unused_data_processing_functions():
    """Collection of unused data processing functions."""
    
    def process_csv_data(csv_string):
        """Unused CSV processor."""
        lines = csv_string.strip().split('\n')
        headers = lines[0].split(',')
        data = []
        
        for line in lines[1:]:
            values = line.split(',')
            row_data = dict(zip(headers, values))
            data.append(row_data)
        
        return data
    
    def aggregate_numeric_data(data_list):
        """Unused aggregation function."""
        if not data_list:
            return {}
        
        numeric_data = [x for x in data_list if isinstance(x, (int, float))]
        
        if not numeric_data:
            return {}
        
        return {
            "sum": sum(numeric_data),
            "avg": sum(numeric_data) / len(numeric_data),
            "min": min(numeric_data),
            "max": max(numeric_data),
            "count": len(numeric_data)
        }
    
    def filter_data_by_criteria(data_list, criteria):
        """Unused filtering function."""
        filtered = []
        for item in data_list:
            include_item = True
            for key, expected_value in criteria.items():
                if isinstance(item, dict) and item.get(key) != expected_value:
                    include_item = False
                    break
            if include_item:
                filtered.append(item)
        return filtered
    
    # Return functions but they're never actually used
    return {
        "csv": process_csv_data,
        "aggregate": aggregate_numeric_data,
        "filter": filter_data_by_criteria
    }


def validate_user_input(user_input):
    """Used function - input validation."""
    if not user_input or not isinstance(user_input, str):
        return False
    
    # Basic validation
    if len(user_input.strip()) == 0:
        return False
    
    if len(user_input) > 1000:  # Reasonable length limit
        return False
    
    # Check for suspicious patterns
    suspicious_patterns = [
        r'<script.*?>',     # Script tags
        r'javascript:',     # JavaScript URLs
        r'eval\(',         # Eval calls
        r'exec\(',         # Exec calls
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            return False
    
    return True


def format_datetime(dt):
    """Used function - datetime formatting."""
    if isinstance(dt, datetime.datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return str(dt)


class UnusedCacheManager:
    """Unused caching class."""
    
    def __init__(self, max_size=1000, ttl=3600):
        self.cache = {}
        self.timestamps = {}
        self.max_size = max_size
        self.ttl = ttl  # Time to live in seconds
    
    def get(self, key):
        """Unused get method."""
        if key not in self.cache:
            return None
        
        # Check if expired
        now = datetime.datetime.now()
        if key in self.timestamps:
            age = (now - self.timestamps[key]).total_seconds()
            if age > self.ttl:
                del self.cache[key]
                del self.timestamps[key]
                return None
        
        return self.cache[key]
    
    def set(self, key, value):
        """Unused set method."""
        # Cleanup if cache is full
        if len(self.cache) >= self.max_size:
            oldest_key = min(self.timestamps.keys(), 
                           key=lambda k: self.timestamps[k])
            del self.cache[oldest_key]
            del self.timestamps[oldest_key]
        
        self.cache[key] = value
        self.timestamps[key] = datetime.datetime.now()
    
    def clear_expired(self):
        """Unused cleanup method."""
        now = datetime.datetime.now()
        expired_keys = []
        
        for key, timestamp in self.timestamps.items():
            age = (now - timestamp).total_seconds()
            if age > self.ttl:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.cache[key]
            del self.timestamps[key]
        
        return len(expired_keys)


class UnusedApiClient:
    """Unused API client class."""
    
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.api_key = api_key
        self.session = requests.Session()
    
    def make_request(self, endpoint, method='GET', data=None):
        """Unused request method."""
        url = f"{self.base_url}/{endpoint}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                json=data
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
    
    def get_user(self, user_id):
        """Unused method."""
        return self.make_request(f"users/{user_id}")
    
    def create_task(self, task_data):
        """Unused method."""
        return self.make_request("tasks", method="POST", data=task_data)


def legacy_password_validation(password):
    """Unused legacy function with weak validation."""
    # Weak password validation (unused)
    if len(password) < 4:  # Very weak minimum
        return False
    
    if password.lower() in ['password', '123456', 'admin']:
        return False
    
    return True


def generate_weak_token():
    """Security issue: weak token generation."""
    # Security issue: predictable token generation
    import time
    timestamp = int(time.time())
    user_id = 123  # Hardcoded
    
    # Weak token generation
    token_data = f"{user_id}:{timestamp}"
    return base64.b64encode(token_data.encode()).decode()


# Unused module-level variables
UNUSED_CONFIG_SETTINGS = {
    "debug_mode": True,
    "log_level": "DEBUG",
    "cache_enabled": False
}

DEPRECATED_ERROR_CODES = {
    1001: "Legacy error 1",
    1002: "Legacy error 2", 
    1003: "Legacy error 3"
}

UNUSED_REGEX_PATTERNS = [
    r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',  # Email
    r'^\+?1?-?\.?\s?\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}$',  # Phone
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$'  # Password
]

# Used constants
CURRENT_API_VERSION = "v2"
SUPPORTED_FILE_TYPES = ["txt", "json", "csv"]