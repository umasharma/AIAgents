"""
Test file with dead code and security testing issues.
"""

import unittest
import json
import tempfile
import os
import sys
import datetime
import subprocess

# Unused imports
import math
import random
import string
import collections
import itertools
import hashlib

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from webapp.app import app, task_manager
from webapp.models import User, Task


class UnusedTestUtilities:
    """Unused test utility class."""
    
    def __init__(self):
        self.test_data = {}
        self.mock_responses = []
        self.setup_complete = False
    
    def generate_test_user(self):
        """Unused method."""
        return {
            "username": "testuser",
            "email": "test@example.com",
            "password": "password123"
        }
    
    def create_mock_tasks(self, count=5):
        """Unused method."""
        tasks = []
        for i in range(count):
            task = {
                "title": f"Test Task {i+1}",
                "description": f"Description for test task {i+1}",
                "completed": i % 2 == 0
            }
            tasks.append(task)
        return tasks
    
    def cleanup_test_data(self):
        """Unused cleanup method."""
        self.test_data.clear()
        self.mock_responses.clear()
        self.setup_complete = False


class TaskTrackerTestCase(unittest.TestCase):
    """Main test class."""
    
    def setUp(self):
        """Test setup."""
        self.app = app.test_client()
        self.app.testing = True
        
        # Clear any existing tasks
        task_manager.tasks.clear()
        
        # Unused setup variables
        self.unused_test_config = {"debug": True}
        self.legacy_settings = {"old_feature": False}
    
    def test_index_page(self):
        """Test the main index page."""
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome to TaskTracker', response.data)
    
    def test_index_with_name_parameter(self):
        """Test index page with name parameter - vulnerable to template injection."""
        response = self.app.get('/?name=TestUser')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome to TaskTracker, TestUser!', response.data)
    
    def test_tasks_get(self):
        """Test getting tasks."""
        response = self.app.get('/tasks')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('tasks', data)
    
    def test_tasks_post(self):
        """Test creating a new task."""
        task_data = {
            "title": "Test Task",
            "description": "This is a test task"
        }
        response = self.app.post('/tasks',
                               data=json.dumps(task_data),
                               content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['title'], task_data['title'])
    
    def test_upload_file(self):
        """Test file upload functionality."""
        # Create a temporary test file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Test file content")
            temp_file_path = f.name
        
        try:
            with open(temp_file_path, 'rb') as test_file:
                data = {'file': (test_file, 'test.txt')}
                response = self.app.post('/upload', data=data)
                self.assertEqual(response.status_code, 200)
                response_data = json.loads(response.data)
                self.assertEqual(response_data['filename'], 'test.txt')
        finally:
            # Cleanup
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
    
    def test_sql_injection_endpoint(self):
        """Test SQL injection vulnerability."""
        response = self.app.get('/api/user/1')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('query', data)
        self.assertIn('SELECT * FROM users WHERE id = 1', data['query'])
        
        # Test with injection payload
        response = self.app.get('/api/user/1 OR 1=1')
        self.assertEqual(response.status_code, 200)
    
    def test_xss_vulnerability(self):
        """Test XSS vulnerability in search."""
        xss_payload = "<script>alert('xss')</script>"
        response = self.app.get(f'/api/search?q={xss_payload}')
        self.assertEqual(response.status_code, 200)
        # The payload should be reflected (vulnerability)
        self.assertIn(xss_payload.encode(), response.data)
    
    def test_jwt_endpoint(self):
        """Test JWT token generation."""
        response = self.app.get('/jwt-test')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('token', data)
    
    def unused_test_method_1(self):
        """This test method is never called."""
        result = self.app.get('/nonexistent-endpoint')
        self.assertEqual(result.status_code, 404)
    
    def unused_test_method_2(self):
        """Another unused test method."""
        test_data = {"key": "value"}
        serialized = json.dumps(test_data)
        deserialized = json.loads(serialized)
        self.assertEqual(test_data, deserialized)
    
    def unused_complex_test_method(self):
        """Complex unused test with multiple operations."""
        # Complex test logic that's never executed
        test_users = []
        for i in range(10):
            user_data = {
                "id": i + 1,
                "username": f"user_{i+1}",
                "email": f"user{i+1}@example.com",
                "created_at": datetime.datetime.now().isoformat()
            }
            test_users.append(user_data)
        
        # Simulate database operations
        saved_users = []
        for user in test_users:
            # Mock save operation
            user["saved"] = True
            saved_users.append(user)
        
        # Assertions that never run
        self.assertEqual(len(saved_users), 10)
        self.assertTrue(all(user["saved"] for user in saved_users))
    
    def tearDown(self):
        """Test cleanup."""
        # Clear tasks
        task_manager.tasks.clear()
        
        # Unused cleanup variables
        self.unused_cleanup_flag = True
        self.legacy_cleanup_data = {}


class UnusedModelTestCase(unittest.TestCase):
    """Unused test case for model testing."""
    
    def setUp(self):
        self.test_db = ":memory:"
        self.test_users = []
        self.test_tasks = []
    
    def test_user_creation(self):
        """Unused user creation test."""
        user = User("testuser", "test@example.com", "password123")
        self.assertEqual(user.username, "testuser")
        self.assertEqual(user.email, "test@example.com")
    
    def test_task_creation(self):
        """Unused task creation test."""
        task = Task("Test Task", "Test Description", 1)
        self.assertEqual(task.title, "Test Task")
        self.assertEqual(task.user_id, 1)
    
    def test_password_hashing(self):
        """Test password hashing (shows vulnerability)."""
        user = User("testuser", "test@example.com", "password123")
        # This test would reveal the MD5 vulnerability
        self.assertTrue(len(user.password_hash) == 32)  # MD5 length


class UnusedIntegrationTestCase(unittest.TestCase):
    """Completely unused integration test class."""
    
    def setUp(self):
        self.client = app.test_client()
        self.test_data_created = False
        self.integration_setup_complete = False
    
    def test_full_user_workflow(self):
        """Unused integration test."""
        # Create user
        user_data = {
            "username": "integrationuser",
            "email": "integration@test.com",
            "password": "testpass123"
        }
        
        # Create task
        task_data = {
            "title": "Integration Test Task",
            "description": "Task created during integration testing"
        }
        
        # Test workflow (never executed)
        user_response = self.client.post('/api/users', data=json.dumps(user_data))
        task_response = self.client.post('/tasks', data=json.dumps(task_data))
        
        # Assertions that never run
        self.assertEqual(user_response.status_code, 201)
        self.assertEqual(task_response.status_code, 200)


def unused_test_helper_function():
    """Unused test helper function."""
    return {
        "test_data": True,
        "helper_function": "unused",
        "created_at": datetime.datetime.now()
    }


def another_unused_helper(data_list):
    """Another unused helper function."""
    processed = []
    for item in data_list:
        if isinstance(item, dict):
            processed.append(item.copy())
        else:
            processed.append({"value": item})
    return processed


# Unused test configuration
UNUSED_TEST_CONFIG = {
    "database_url": "sqlite:///:memory:",
    "testing": True,
    "debug": False
}

LEGACY_TEST_SETTINGS = {
    "old_test_runner": "nose",
    "deprecated_assertions": True,
    "legacy_fixtures": ["fixture1", "fixture2"]
}

# Used test configuration
CURRENT_TEST_SETTINGS = {
    "test_runner": "unittest",
    "coverage_enabled": True
}


if __name__ == '__main__':
    unittest.main()