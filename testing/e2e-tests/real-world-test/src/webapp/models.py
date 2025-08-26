"""
Database models with dead code and security issues.
Represents a typical model file in a web application.
"""

import hashlib
import datetime
import uuid
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
import json
import pickle

# Unused imports

Base = declarative_base()


class UnusedBaseModel:
    """Unused base model class."""
    
    def __init__(self):
        self.created_at = datetime.datetime.utcnow()
        self.updated_at = datetime.datetime.utcnow()
    
    def save(self):
        """Unused save method."""
        self.updated_at = datetime.datetime.utcnow()
        # Database save logic would go here
        pass
    
    def delete(self):
        """Unused delete method."""
        # Database delete logic would go here
        pass


class User(Base):
    """User model - partially used."""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_login = Column(DateTime)  # Never actually used
    profile_data = Column(Text)    # Never used
    
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password_hash = self.hash_password(password)
    
    def hash_password(self, password):
        """Security issue: weak password hashing."""
        # Using MD5 - security vulnerability
        return hashlib.md5(password.encode()).hexdigest()
    
    def check_password(self, password):
        """Used method."""
        return self.hash_password(password) == self.password_hash
    
    def get_profile(self):
        """Unused method."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
    
    def update_last_login(self):
        """Unused method."""
        self.last_login = datetime.datetime.utcnow()
    
    def serialize_profile(self):
        """Security issue: unsafe serialization."""
        # Using pickle for serialization - security risk
        profile_data = {
            "username": self.username,
            "email": self.email,
            "preferences": {"theme": "dark", "notifications": True}
        }
        return pickle.dumps(profile_data)
    
    def deserialize_profile(self, data):
        """Security issue: unsafe deserialization."""
        # Pickle deserialization - very dangerous
        try:
            return pickle.loads(data)
        except Exception:
            return None


class Task(Base):
    """Task model - mostly used."""
    __tablename__ = 'tasks'
    
    id = Column(Integer, primary_key=True)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    user_id = Column(Integer, nullable=False)  # Should be foreign key
    completed = Column(Boolean, default=False)
    priority = Column(Integer, default=1)      # Never used
    category = Column(String(50))              # Never used
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime)            # Never used
    
    def __init__(self, title, description, user_id):
        self.title = title
        self.description = description
        self.user_id = user_id
    
    def to_dict(self):
        """Used method."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "completed": self.completed,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
    
    def mark_completed(self):
        """Unused method."""
        self.completed = True
        self.completed_at = datetime.datetime.utcnow()
    
    def set_priority(self, priority):
        """Unused method."""
        if priority in [1, 2, 3, 4, 5]:
            self.priority = priority
    
    def update_category(self, category):
        """Unused method."""
        allowed_categories = ["work", "personal", "urgent", "later"]
        if category in allowed_categories:
            self.category = category
    
    def get_age_in_days(self):
        """Unused method with calculation."""
        if self.created_at:
            delta = datetime.datetime.utcnow() - self.created_at
            return delta.days
        return 0
    
    def export_to_json(self):
        """Unused method."""
        return json.dumps(self.to_dict(), indent=2)


class UnusedProjectModel(Base):
    """Completely unused model."""
    __tablename__ = 'projects'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    owner_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    is_archived = Column(Boolean, default=False)
    
    def __init__(self, name, description, owner_id):
        self.name = name
        self.description = description
        self.owner_id = owner_id
    
    def archive(self):
        """Unused method."""
        self.is_archived = True
    
    def get_task_count(self):
        """Unused method."""
        # Would query related tasks
        return 0


class SessionManager:
    """Unused session management class."""
    
    def __init__(self):
        self.active_sessions = {}
        self.session_timeout = 3600  # 1 hour
    
    def create_session(self, user_id):
        """Unused method."""
        session_id = str(uuid.uuid4())
        self.active_sessions[session_id] = {
            "user_id": user_id,
            "created_at": datetime.datetime.utcnow(),
            "last_activity": datetime.datetime.utcnow()
        }
        return session_id
    
    def validate_session(self, session_id):
        """Unused method."""
        if session_id not in self.active_sessions:
            return False
        
        session = self.active_sessions[session_id]
        now = datetime.datetime.utcnow()
        time_since_activity = (now - session["last_activity"]).total_seconds()
        
        if time_since_activity > self.session_timeout:
            del self.active_sessions[session_id]
            return False
        
        # Update last activity
        session["last_activity"] = now
        return True
    
    def cleanup_expired_sessions(self):
        """Unused cleanup method."""
        now = datetime.datetime.utcnow()
        expired_sessions = []
        
        for session_id, session_data in self.active_sessions.items():
            time_since_activity = (now - session_data["last_activity"]).total_seconds()
            if time_since_activity > self.session_timeout:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.active_sessions[session_id]
        
        return len(expired_sessions)


def unused_database_helper():
    """Unused database utility function."""
    return "This function helps with database operations but is never called"


def create_database_connection():
    """Unused connection function."""
    # Would create database connection
    connection_string = "postgresql://user:password@localhost/tasktracker"
    return connection_string


def migrate_legacy_data():
    """Unused migration function."""
    # Complex migration logic that's never used
    migration_steps = [
        "backup_current_data",
        "create_new_tables", 
        "migrate_users",
        "migrate_tasks",
        "verify_data_integrity",
        "cleanup_old_tables"
    ]
    
    results = {}
    for step in migration_steps:
        # Simulate migration step
        results[step] = {"status": "completed", "records_processed": 0}
    
    return results


# Unused constants and configurations
DATABASE_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "database": "tasktracker",
    "user": "app_user",
    "password": "secret123"  # Hardcoded password
}

LEGACY_TABLE_MAPPING = {
    "old_users": "users",
    "old_tasks": "tasks", 
    "old_projects": "projects"
}

UNUSED_QUERY_TEMPLATES = [
    "SELECT * FROM users WHERE active = 1",
    "SELECT * FROM tasks WHERE completed = 0",
    "SELECT * FROM projects WHERE archived = 0"
]

# Used configuration
CURRENT_DB_VERSION = "2.1"
SUPPORTED_FEATURES = ["users", "tasks"]