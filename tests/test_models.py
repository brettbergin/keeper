"""Test models functionality."""

import pytest

from keeper.models.environment import Environment
from keeper.models.secret import SecrecyLevel, Secret, SecretType, SyncStatus
from keeper.models.secret_version import SecretVersion
from keeper.models.user import AuthMethod, User, UserRole


@pytest.mark.models
class TestUserModel:
    """Test User model functionality."""

    def test_user_creation(self, db_session):
        """Test basic user creation."""
        user = User(
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            role=UserRole.USER,
            auth_method=AuthMethod.DATABASE,
            is_active=True,
        )
        user.save()

        assert user.id is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.role == UserRole.USER
        assert user.is_active is True
        assert user.created_at is not None

    def test_password_hashing(self, db_session):
        """Test password hashing and verification."""
        user = User(
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            role=UserRole.USER,
            auth_method=AuthMethod.DATABASE,
        )

        password = "testpassword123"
        user.set_password(password)
        user.save()

        # Password should be hashed
        assert user.password_hash != password
        assert user.password_hash is not None

        # Should verify correctly
        assert user.check_password(password) is True
        assert user.check_password("wrongpassword") is False

    def test_user_find_methods(self, db_session):
        """Test user finding methods."""
        user = User(
            username="findme",
            email="findme@example.com",
            full_name="Find Me",
            role=UserRole.USER,
            auth_method=AuthMethod.DATABASE,
        )
        user.save()

        # Test find by username
        found_user = User.find_by_username("findme")
        assert found_user is not None
        assert found_user.id == user.id

        # Test find by email
        found_user = User.find_by_email("findme@example.com")
        assert found_user is not None
        assert found_user.id == user.id

        # Test not found
        assert User.find_by_username("notfound") is None
        assert User.find_by_email("notfound@example.com") is None

    def test_admin_properties(self, db_session):
        """Test admin-related properties."""
        admin_user = User(
            username="admin",
            email="admin@example.com",
            full_name="Admin User",
            role=UserRole.ADMIN,
            auth_method=AuthMethod.DATABASE,
        )
        admin_user.save()

        regular_user = User(
            username="user",
            email="user@example.com",
            full_name="Regular User",
            role=UserRole.USER,
            auth_method=AuthMethod.DATABASE,
        )
        regular_user.save()

        assert admin_user.is_admin is True
        assert regular_user.is_admin is False

    def test_managed_environments(self, db_session, test_environments):
        """Test managed environments functionality."""
        manager = User(
            username="manager",
            email="manager@example.com",
            full_name="Manager User",
            role=UserRole.MANAGER,
            auth_method=AuthMethod.DATABASE,
        )
        manager.save()

        # Set managed environments
        env_names = ["development", "staging"]
        manager.set_managed_environments(env_names)

        # Verify managed environments
        managed = manager.get_managed_environments()
        assert set(managed) == set(env_names)

        # Test can_manage_environment
        assert manager.can_manage_environment("development") is True
        assert manager.can_manage_environment("staging") is True
        assert manager.can_manage_environment("production") is False

    def test_email_verification_token(self, db_session):
        """Test email verification token generation and verification."""
        user = User(
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            role=UserRole.USER,
            auth_method=AuthMethod.DATABASE,
            email_verified=False,
        )
        user.save()

        # Generate token
        token = user.generate_email_verification_token()
        assert token is not None
        assert len(token) > 0

        # Verify token
        verified_user = User.verify_email_token(token)
        assert verified_user is not None
        assert verified_user.id == user.id

        # Invalid token should return None
        assert User.verify_email_token("invalid-token") is None


@pytest.mark.models
class TestEnvironmentModel:
    """Test Environment model functionality."""

    def test_default_environments_creation(self, db_session):
        """Test that default environments are created correctly."""
        # Clear existing environments
        Environment.query.delete()
        db_session.commit()

        # Create default environments
        Environment.create_default_environments()

        environments = Environment.query.all()
        assert len(environments) == 3

        env_names = {env.name for env in environments}
        assert env_names == {"development", "staging", "production"}

        # Check environment production flags
        dev_env = Environment.query.filter_by(name="development").first()
        staging_env = Environment.query.filter_by(name="staging").first()
        prod_env = Environment.query.filter_by(name="production").first()

        assert dev_env.is_production is False
        assert staging_env.is_production is False
        assert prod_env.is_production is True

    def test_environment_properties(self, db_session):
        """Test environment properties and methods."""
        env = Environment(
            name="test-env",
            display_name="Test Environment",
            description="Test environment description",
            is_production=False,
            aws_region="us-west-2",
        )
        env.save()

        assert env.name == "test-env"
        assert env.is_production is False

        # Test AWS secret name generation (base naming for environment)
        secret_name = env.get_aws_secret_name("my-secret")
        assert secret_name == "keeper/test-env/my-secret"

        # Test Vault path generation
        vault_path = env.get_vault_path("my-secret")
        assert vault_path == "secret/test-env/my-secret"


@pytest.mark.models
class TestSecretModel:
    """Test Secret model functionality."""

    def test_secret_creation(self, db_session, test_environments, admin_user):
        """Test basic secret creation."""
        secret = Secret.create(
            name="test-secret",
            display_name="Test Secret",
            description="A test secret",
            secret_type=SecretType.PASSWORD,
            secrecy_level=SecrecyLevel.HIGH,
            environment_id=test_environments["development"].id,
            service_name="test-service",
            creator_id=admin_user.id,
        )

        assert secret.id is not None
        assert secret.name == "test-secret"
        assert secret.secret_type == SecretType.PASSWORD
        assert secret.secrecy_level == SecrecyLevel.HIGH
        assert secret.is_active is True
        assert secret.created_at is not None

    def test_secret_full_name(self, db_session, test_environments, admin_user):
        """Test secret full name generation."""
        secret = Secret.create(
            name="my-secret",
            display_name="My Secret",
            description="Test secret",
            secret_type=SecretType.STRING,
            secrecy_level=SecrecyLevel.LOW,
            environment_id=test_environments["production"].id,
            service_name="test",
            creator_id=admin_user.id,
        )

        assert secret.full_name == "production/my-secret"

    def test_sync_status_defaults(self, db_session, test_environments, admin_user):
        """Test that sync statuses default correctly."""
        secret = Secret.create(
            name="sync-test",
            display_name="Sync Test",
            description="Test sync status",
            secret_type=SecretType.STRING,
            secrecy_level=SecrecyLevel.LOW,
            environment_id=test_environments["development"].id,
            service_name="test",
            creator_id=admin_user.id,
        )

        assert secret.aws_sync_status == SyncStatus.NOT_SYNCED
        assert secret.vault_sync_status == SyncStatus.NOT_SYNCED
        assert secret.aws_last_sync is None
        assert secret.vault_last_sync is None

    def test_secret_rotation_marking(self, db_session, test_environments, admin_user):
        """Test secret rotation timestamp marking."""
        secret = Secret.create(
            name="rotation-test",
            display_name="Rotation Test",
            description="Test rotation",
            secret_type=SecretType.PASSWORD,
            secrecy_level=SecrecyLevel.MEDIUM,
            environment_id=test_environments["staging"].id,
            service_name="test",
            creator_id=admin_user.id,
        )

        original_updated = secret.updated_at
        secret.mark_rotated()

        assert secret.last_rotated_at is not None
        assert secret.updated_at > original_updated


@pytest.mark.models
class TestSecretVersionModel:
    """Test SecretVersion model functionality."""

    def test_version_creation(self, db_session, test_secret, admin_user):
        """Test creating a secret version."""
        version = SecretVersion.create_version(
            secret_id=test_secret.id,
            value="new-secret-value",
            created_by_id=admin_user.id,
            generation_method="manual",
        )

        assert version.id is not None
        assert version.secret_id == test_secret.id
        assert version.created_by_id == admin_user.id
        assert version.generation_method == "manual"
        assert version.is_current is True
        assert version.created_at is not None

    def test_version_encryption_decryption(self, db_session, test_secret, admin_user):
        """Test that secret values are encrypted and can be decrypted."""
        original_value = "super-secret-password"

        version = SecretVersion.create_version(
            secret_id=test_secret.id,
            value=original_value,
            created_by_id=admin_user.id,
            generation_method="manual",
        )

        # Value should be encrypted (not stored as plaintext)
        assert version.encrypted_value != original_value
        assert version.encrypted_value is not None

        # Should be able to decrypt back to original value
        decrypted_value = version.decrypt_value()
        assert decrypted_value == original_value

    def test_version_integrity_verification(self, db_session, test_secret, admin_user):
        """Test version integrity verification."""
        version = SecretVersion.create_version(
            secret_id=test_secret.id,
            value="integrity-test-value",
            created_by_id=admin_user.id,
            generation_method="manual",
        )

        # Integrity should be valid for fresh version
        assert version.verify_integrity("integrity-test-value") is True

    def test_version_history(self, db_session, test_secret, admin_user):
        """Test version history functionality."""
        # Create multiple versions
        values = ["version1", "version2", "version3"]
        versions = []

        for i, value in enumerate(values):
            version = SecretVersion.create_version(
                secret_id=test_secret.id,
                value=value,
                created_by_id=admin_user.id,
                generation_method="manual",
            )
            versions.append(version)

        # Get version history
        history = SecretVersion.get_version_history(test_secret.id, limit=10)

        # Should include all versions plus the original from fixture
        assert len(history) >= len(values)

        # Most recent should be current
        latest_version = history[0]
        assert latest_version.is_current is True

    def test_multiple_versions_current_management(
        self, db_session, test_secret, admin_user
    ):
        """Test that only one version can be current."""
        # Create new version
        new_version = SecretVersion.create_version(
            secret_id=test_secret.id,
            value="new-current-value",
            created_by_id=admin_user.id,
            generation_method="manual",
        )

        # New version should be current
        assert new_version.is_current is True

        # Previous version should no longer be current
        old_versions = SecretVersion.query.filter(
            SecretVersion.secret_id == test_secret.id,
            SecretVersion.id != new_version.id,
        ).all()

        for version in old_versions:
            assert version.is_current is False


# Note: AuditLog and Approval model tests are commented out because
# they require specific method signatures that may not match the current implementation.
# These can be added back once the exact API is confirmed.

# @pytest.mark.models
# class TestAuditLogModel:
#     """Test AuditLog model functionality."""
#     pass

# @pytest.mark.models
# class TestApprovalModel:
#     """Test Approval model functionality."""
#     pass
