"""Configuration settings for Keeper application."""

import os


class Config:
    """Base configuration class."""

    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret-key-change-in-production"

    # Database Configuration
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True

    # AWS Configuration
    AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
    AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")

    # AWS KMS Configuration
    KMS_KEY_ID = os.environ.get("KMS_KEY_ID")  # ARN or Key ID
    KMS_KEY_ALIAS = os.environ.get("KMS_KEY_ALIAS")  # alias/name
    KMS_REGION = os.environ.get(
        "KMS_REGION", AWS_REGION
    )  # Can differ from general AWS region
    KMS_ENCRYPTION_CONTEXT = os.environ.get(
        "KMS_ENCRYPTION_CONTEXT", '{"application":"keeper"}'
    )
    ENABLE_KMS_KEY_ROTATION = (
        os.environ.get("ENABLE_KMS_KEY_ROTATION", "true").lower() == "true"
    )
    KMS_DEK_CACHE_TTL = int(os.environ.get("KMS_DEK_CACHE_TTL", 3600))  # 1 hour cache
    KMS_MAX_RETRIES = int(os.environ.get("KMS_MAX_RETRIES", 3))

    # Vault Configuration
    VAULT_URL = os.environ.get("VAULT_URL", "http://localhost:8200")
    VAULT_TOKEN = os.environ.get("VAULT_TOKEN")
    VAULT_MOUNT_POINT = os.environ.get("VAULT_MOUNT_POINT", "secret")

    # Okta SAML Configuration
    OKTA_ISSUER = os.environ.get("OKTA_ISSUER")
    OKTA_CLIENT_ID = os.environ.get("OKTA_CLIENT_ID")
    OKTA_CLIENT_SECRET = os.environ.get("OKTA_CLIENT_SECRET")
    OKTA_METADATA_URL = os.environ.get("OKTA_METADATA_URL")

    # Pagination
    SECRETS_PER_PAGE = int(os.environ.get("SECRETS_PER_PAGE", 20))

    # Security
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None

    # Authentication Configuration
    REQUIRE_EMAIL_VERIFICATION = (
        os.environ.get("REQUIRE_EMAIL_VERIFICATION", "true").lower() == "true"
    )
    EMAIL_VERIFICATION_TOKEN_EXPIRY = int(
        os.environ.get("EMAIL_VERIFICATION_TOKEN_EXPIRY", 86400)
    )  # 24 hours
    CREATE_DEFAULT_ADMIN = (
        os.environ.get("CREATE_DEFAULT_ADMIN", "true").lower() == "true"
    )
    DEFAULT_ADMIN_USERNAME = os.environ.get("DEFAULT_ADMIN_USERNAME", "admin")
    DEFAULT_ADMIN_PASSWORD = os.environ.get("DEFAULT_ADMIN_PASSWORD", "admin")
    DEFAULT_ADMIN_EMAIL = os.environ.get("DEFAULT_ADMIN_EMAIL", "admin@localhost")

    # Key Management Strategy
    KEY_MANAGEMENT_BACKEND = os.environ.get(
        "KEY_MANAGEMENT_BACKEND", "local"
    )  # 'kms' or 'local'

    # Logging Configuration
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    LOG_DIR = os.environ.get("LOG_DIR", "logs")
    LOG_FILE = os.environ.get("LOG_FILE", "keeper.log")
    LOG_MAX_BYTES = int(os.environ.get("LOG_MAX_BYTES", 10485760))  # 10MB
    LOG_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", 10))
    LOG_FORMAT = os.environ.get(
        "LOG_FORMAT",
        "%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s",
    )

    # Structured Logging Options
    ENABLE_JSON_LOGGING = (
        os.environ.get("ENABLE_JSON_LOGGING", "false").lower() == "true"
    )
    ENABLE_REQUEST_LOGGING = (
        os.environ.get("ENABLE_REQUEST_LOGGING", "true").lower() == "true"
    )

    # Separate Log Files
    AUDIT_LOG_FILE = os.environ.get("AUDIT_LOG_FILE", "audit.log")
    SYNC_LOG_FILE = os.environ.get("SYNC_LOG_FILE", "sync.log")
    ERROR_LOG_FILE = os.environ.get("ERROR_LOG_FILE", "error.log")

    @property
    def kms_encryption_context(self) -> dict:
        """Parse KMS encryption context from JSON string."""
        import json

        try:
            return json.loads(self.KMS_ENCRYPTION_CONTEXT)
        except (json.JSONDecodeError, TypeError):
            return {"application": "keeper"}

    @property
    def kms_key_spec(self) -> str:
        """Get the KMS key specification to use."""
        return self.KMS_KEY_ID or self.KMS_KEY_ALIAS or "alias/keeper-default"


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get("DATABASE_URL") or "sqlite:///keeper_dev.db"
    )
    WTF_CSRF_ENABLED = False  # Disable CSRF for easier development

    # Enhanced logging for development
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "DEBUG")
    ENABLE_REQUEST_LOGGING = True


class ProductionConfig(Config):
    """Production configuration."""

    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:///keeper.db"

    # Production logging settings
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "WARNING")
    ENABLE_JSON_LOGGING = (
        os.environ.get("ENABLE_JSON_LOGGING", "true").lower() == "true"
    )

    @classmethod
    def init_app(cls, app):
        Config.init_app(app)


class TestingConfig(Config):
    """Testing configuration."""

    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
