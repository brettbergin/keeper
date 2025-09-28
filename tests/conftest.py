"""Test configuration and fixtures for Keeper test suite."""

import os
import tempfile
from datetime import datetime, timezone

import pytest

from keeper.app import create_app
from keeper.models import db
from keeper.models.environment import Environment
from keeper.models.secret import SecrecyLevel, Secret, SecretType
from keeper.models.secret_version import SecretVersion
from keeper.models.user import AuthMethod, User, UserRole


@pytest.fixture(scope="session")
def app():
    """Create application for testing."""
    # Create temporary database
    db_fd, db_path = tempfile.mkstemp()

    # Override config for testing
    test_config = {
        "TESTING": True,
        "SECRET_KEY": "test-secret-key-for-testing",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "WTF_CSRF_ENABLED": False,
        "KEY_MANAGEMENT_BACKEND": "local",
        "REQUIRE_EMAIL_VERIFICATION": False,
        "CREATE_DEFAULT_ADMIN": False,
        "LOG_LEVEL": "ERROR",  # Reduce log noise during testing
    }

    app = create_app("testing")
    app.config.update(test_config)

    with app.app_context():
        db.create_all()
        # Create default environments for testing
        Environment.create_default_environments()
        yield app
        db.drop_all()

    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Create test CLI runner."""
    return app.test_cli_runner()


@pytest.fixture
def db_session(app):
    """Create clean database session for each test."""
    with app.app_context():
        # Clear all data
        db.session.query(SecretVersion).delete()
        db.session.query(Secret).delete()
        db.session.query(User).delete()
        # Keep environments as they are needed
        db.session.commit()
        yield db.session


@pytest.fixture
def test_environments(db_session):
    """Provide test environments."""
    envs = Environment.query.all()
    return {env.name: env for env in envs}


@pytest.fixture
def admin_user(db_session):
    """Create admin user for testing."""
    user = User(
        username="test_admin",
        email="admin@test.com",
        full_name="Test Administrator",
        role=UserRole.ADMIN,
        auth_method=AuthMethod.DATABASE,
        is_active=True,
        email_verified=True,
        created_at=datetime.now(timezone.utc),
    )
    user.set_password("admin123")
    user.save()
    return user


@pytest.fixture
def manager_user(db_session, test_environments):
    """Create manager user for testing."""
    user = User(
        username="test_manager",
        email="manager@test.com",
        full_name="Test Manager",
        role=UserRole.MANAGER,
        auth_method=AuthMethod.DATABASE,
        is_active=True,
        email_verified=True,
        created_at=datetime.now(timezone.utc),
    )
    user.set_password("manager123")
    # Set managed environments
    user.set_managed_environments(["development", "staging"])
    user.save()
    return user


@pytest.fixture
def regular_user(db_session):
    """Create regular user for testing."""
    user = User(
        username="test_user",
        email="user@test.com",
        full_name="Test User",
        role=UserRole.USER,
        auth_method=AuthMethod.DATABASE,
        is_active=True,
        email_verified=True,
        created_at=datetime.now(timezone.utc),
    )
    user.set_password("user123")
    user.save()
    return user


@pytest.fixture
def demo_user(db_session):
    """Create demo user for testing."""
    user = User(
        username="demo_user",
        email="demo@test.com",
        full_name="Demo User",
        role=UserRole.USER,
        auth_method=AuthMethod.DEMO,
        is_active=True,
        email_verified=True,
        created_at=datetime.now(timezone.utc),
    )
    user.save()
    return user


@pytest.fixture
def test_secret(db_session, test_environments, admin_user):
    """Create test secret with version."""
    secret = Secret.create(
        name="test-secret",
        display_name="Test Secret",
        description="A test secret for testing",
        secret_type=SecretType.PASSWORD,
        secrecy_level=SecrecyLevel.MEDIUM,
        environment_id=test_environments["development"].id,
        service_name="test-service",
        creator_id=admin_user.id,
    )

    # Create a version
    version = SecretVersion.create_version(
        secret_id=secret.id,
        value="test-secret-value",
        created_by_id=admin_user.id,
        generation_method="manual",
    )

    return secret


@pytest.fixture
def authenticated_client(client, admin_user):
    """Create authenticated client session."""
    from datetime import datetime, timedelta

    from keeper.auth.session import generate_session_token
    from keeper.models import db

    with client.application.app_context():
        # Generate session token and set it on the user
        session_token = generate_session_token()
        expires_at = datetime.utcnow() + timedelta(hours=8)

        # Refresh the user from the current session to avoid conflicts
        user = db.session.merge(admin_user)
        user.session_token = session_token
        user.session_expires_at = expires_at
        user.last_login = datetime.utcnow()
        db.session.commit()

    # Set Flask session
    with client.session_transaction() as sess:
        sess["user_id"] = admin_user.id
        sess["username"] = admin_user.username
        sess["user_role"] = admin_user.role.value
        sess["is_admin"] = admin_user.is_admin
        sess["session_token"] = session_token
    return client


@pytest.fixture
def manager_authenticated_client(client, manager_user):
    """Create manager authenticated client session."""
    from datetime import datetime, timedelta

    from keeper.auth.session import generate_session_token
    from keeper.models import db

    with client.application.app_context():
        session_token = generate_session_token()
        expires_at = datetime.utcnow() + timedelta(hours=8)

        user = db.session.merge(manager_user)
        user.session_token = session_token
        user.session_expires_at = expires_at
        user.last_login = datetime.utcnow()
        db.session.commit()

    with client.session_transaction() as sess:
        sess["user_id"] = manager_user.id
        sess["username"] = manager_user.username
        sess["user_role"] = manager_user.role.value
        sess["is_admin"] = manager_user.is_admin
        sess["session_token"] = session_token
    return client


@pytest.fixture
def user_authenticated_client(client, regular_user):
    """Create user authenticated client session."""
    from datetime import datetime, timedelta

    from keeper.auth.session import generate_session_token
    from keeper.models import db

    with client.application.app_context():
        session_token = generate_session_token()
        expires_at = datetime.utcnow() + timedelta(hours=8)

        user = db.session.merge(regular_user)
        user.session_token = session_token
        user.session_expires_at = expires_at
        user.last_login = datetime.utcnow()
        db.session.commit()

    with client.session_transaction() as sess:
        sess["user_id"] = regular_user.id
        sess["username"] = regular_user.username
        sess["user_role"] = regular_user.role.value
        sess["is_admin"] = regular_user.is_admin
        sess["session_token"] = session_token
    return client


# Utility functions for tests
def login_user(client, username, password):
    """Helper function to login user via form."""
    return client.post(
        "/auth/database/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def create_test_secret_with_version(
    environment_id, creator_id, name="test-secret", value="test-value"
):
    """Helper to create secret with version for testing."""
    secret = Secret.create(
        name=name,
        display_name=f"Test {name}",
        description=f"Test secret {name}",
        secret_type=SecretType.STRING,
        secrecy_level=SecrecyLevel.LOW,
        environment_id=environment_id,
        service_name="test",
        creator_id=creator_id,
    )

    SecretVersion.create_version(
        secret_id=secret.id,
        value=value,
        created_by_id=creator_id,
        generation_method="manual",
    )

    return secret
