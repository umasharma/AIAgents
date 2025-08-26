"""
Configuration file with hardcoded secrets and insecure settings.
"""


class Config:
    """Base configuration class."""
    
    # Security issues: hardcoded secrets
    SECRET_KEY = "hardcoded-secret-key-12345"
    DATABASE_URI = "sqlite:///tasktracker.db"
    
    # More hardcoded credentials
    ADMIN_PASSWORD = "admin123"
    API_KEY = "sk-1234567890abcdef"
    JWT_SECRET_KEY = "jwt-super-secret"
    ENCRYPTION_KEY = "simple-encryption-key"
    
    # Security issue: insecure configurations
    DEBUG = True
    TESTING = True
    WTF_CSRF_ENABLED = False  # CSRF protection disabled
    
    # File upload settings (insecure)
    UPLOAD_FOLDER = '/tmp/uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'exe', 'bat'}
    
    # Email configuration (insecure)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = False  # Insecure email
    MAIL_USERNAME = 'admin@example.com'
    MAIL_PASSWORD = 'email_password_123'  # Hardcoded email password
    
    # Third-party API configurations (hardcoded)
    GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    SLACK_WEBHOOK = "https://hooks.slack.com/services/xxx/yyy/zzz"
    STRIPE_SECRET_KEY = "sk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"


class DevelopmentConfig(Config):
    """Development configuration - even more insecure."""
    
    DEBUG = True
    TESTING = True
    
    # Development database (insecure connection)
    DATABASE_URI = "postgresql://admin:password123@localhost:5432/tasktracker_dev"
    
    # Logging configuration (problematic)
    LOG_LEVEL = "DEBUG"
    LOG_TO_STDOUT = True
    LOG_SENSITIVE_DATA = True  # Bad practice
    
    # Cache configuration
    REDIS_URL = "redis://localhost:6379/0"
    CACHE_TYPE = "simple"
    
    # Session configuration (insecure)
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours
    SESSION_COOKIE_SECURE = False  # Insecure cookies
    SESSION_COOKIE_HTTPONLY = False  # XSS vulnerable


class ProductionConfig(Config):
    """Production configuration - still has issues."""
    
    DEBUG = False  # Good
    TESTING = False  # Good
    
    # But still has hardcoded secrets
    DATABASE_URI = "postgresql://prod_user:prod_pass_123@prod-db:5432/tasktracker"
    REDIS_URL = "redis://prod-redis:6379/0"
    
    # Security headers not properly configured
    SECURITY_HEADERS = {
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '0',  # Disabled XSS protection
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
    }


class TestingConfig(Config):
    """Testing configuration."""
    
    TESTING = True
    DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    
    # Test-specific hardcoded values
    TEST_USER_PASSWORD = "test123"
    TEST_API_TOKEN = "test-token-123"


# Unused configuration classes
class LegacyConfig:
    """Old configuration class that's no longer used."""
    
    OLD_DATABASE_URL = "mysql://root:root@localhost/old_tasktracker"
    LEGACY_API_ENDPOINT = "https://api-v1.example.com"
    DEPRECATED_FEATURE_FLAGS = {
        "old_feature_1": True,
        "old_feature_2": False,
        "removed_feature": True
    }


class UnusedStagingConfig:
    """Staging configuration that's never used."""
    
    STAGING_DATABASE = "postgresql://staging:staging123@staging-db/tasktracker"
    STAGING_REDIS = "redis://staging-redis:6379/0"
    STAGING_S3_BUCKET = "tasktracker-staging"
    STAGING_API_KEY = "staging-api-key-456"


# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

# Unused configuration constants
LEGACY_SETTINGS = {
    "version": "1.0",
    "deprecated": True,
    "migration_needed": True
}

OLD_API_ENDPOINTS = [
    "https://api-v1.example.com/users",
    "https://api-v1.example.com/tasks",
    "https://api-v1.example.com/projects"
]

# Used configuration
CURRENT_CONFIG_VERSION = "2.0"
SUPPORTED_ENVIRONMENTS = ["development", "production", "testing"]