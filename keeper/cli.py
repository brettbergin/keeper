"""Command line interface for Keeper application."""

import json

import click


@click.group()
def cli():
    """Keeper secret management CLI."""
    pass


@cli.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", default=8989, help="Port to bind to")
@click.option("--debug", is_flag=True, help="Enable debug mode")
def run(host, port, debug):
    """Run the Keeper Flask application."""
    from keeper.app import create_app

    app = create_app()
    app.run(host=host, port=port, debug=debug)


@cli.command()
def init_db():
    """Initialize the database."""
    from keeper.app import create_app
    from keeper.models.database import db
    from keeper.models.environment import Environment

    app = create_app()
    with app.app_context():
        db.create_all()
        Environment.create_default_environments()
        click.echo("Database initialized with default environments.")


@cli.command()
def reset_db():
    """Reset the database (WARNING: destroys all data)."""
    if click.confirm("This will destroy all data. Are you sure?"):
        from keeper.app import create_app
        from keeper.models.database import db
        from keeper.models.environment import Environment

        app = create_app()
        with app.app_context():
            db.drop_all()
            db.create_all()
            Environment.create_default_environments()
            click.echo("Database reset complete.")
    else:
        click.echo("Database reset cancelled.")


@cli.command()
def migrate_db():
    """Run database migrations."""
    import os
    import sqlite3

    from flask import Flask

    # Create minimal app without triggering model initialization
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///keeper_dev.db"
    )

    with app.app_context():
        # Get database URI
        db_uri = app.config["SQLALCHEMY_DATABASE_URI"]

        if db_uri.startswith("sqlite:///"):
            db_path = db_uri.replace("sqlite:///", "")

            click.echo("Running database migrations...")
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            try:
                # Migrate secret_versions table for KMS envelope encryption
                cursor.execute("PRAGMA table_info(secret_versions)")
                sv_columns = [column[1] for column in cursor.fetchall()]

                migrations_applied = []

                if "nonce" not in sv_columns:
                    click.echo("Adding nonce column to secret_versions...")
                    cursor.execute("ALTER TABLE secret_versions ADD COLUMN nonce BLOB")
                    migrations_applied.append("secret_versions.nonce")

                if "auth_tag" not in sv_columns:
                    click.echo("Adding auth_tag column to secret_versions...")
                    cursor.execute(
                        "ALTER TABLE secret_versions ADD COLUMN auth_tag BLOB"
                    )
                    migrations_applied.append("secret_versions.auth_tag")

                if "encrypted_dek" not in sv_columns:
                    click.echo("Adding encrypted_dek column to secret_versions...")
                    cursor.execute(
                        "ALTER TABLE secret_versions ADD COLUMN encrypted_dek BLOB"
                    )
                    migrations_applied.append("secret_versions.encrypted_dek")

                if "kms_key_id" not in sv_columns:
                    click.echo("Adding kms_key_id column to secret_versions...")
                    cursor.execute(
                        "ALTER TABLE secret_versions ADD COLUMN kms_key_id TEXT"
                    )
                    migrations_applied.append("secret_versions.kms_key_id")

                if "encryption_context" not in sv_columns:
                    click.echo("Adding encryption_context column to secret_versions...")
                    cursor.execute(
                        "ALTER TABLE secret_versions ADD COLUMN encryption_context TEXT"
                    )
                    migrations_applied.append("secret_versions.encryption_context")

                # Migrate environments table for KMS configuration
                cursor.execute("PRAGMA table_info(environments)")
                env_columns = [column[1] for column in cursor.fetchall()]

                if "kms_key_id" not in env_columns:
                    click.echo("Adding kms_key_id column to environments...")
                    cursor.execute(
                        "ALTER TABLE environments ADD COLUMN kms_key_id TEXT"
                    )
                    migrations_applied.append("environments.kms_key_id")

                if "kms_key_alias" not in env_columns:
                    click.echo("Adding kms_key_alias column to environments...")
                    cursor.execute(
                        "ALTER TABLE environments ADD COLUMN kms_key_alias TEXT"
                    )
                    migrations_applied.append("environments.kms_key_alias")

                if "key_rotation_enabled" not in env_columns:
                    click.echo("Adding key_rotation_enabled column to environments...")
                    cursor.execute(
                        "ALTER TABLE environments ADD COLUMN key_rotation_enabled BOOLEAN DEFAULT 1"
                    )
                    migrations_applied.append("environments.key_rotation_enabled")

                if "last_key_rotation" not in env_columns:
                    click.echo("Adding last_key_rotation column to environments...")
                    cursor.execute(
                        "ALTER TABLE environments ADD COLUMN last_key_rotation TIMESTAMP"
                    )
                    migrations_applied.append("environments.last_key_rotation")

                if "aws_sync_enabled" not in env_columns:
                    click.echo("Adding aws_sync_enabled column to environments...")
                    cursor.execute(
                        "ALTER TABLE environments ADD COLUMN aws_sync_enabled BOOLEAN DEFAULT 1"
                    )
                    migrations_applied.append("environments.aws_sync_enabled")

                if "vault_sync_enabled" not in env_columns:
                    click.echo("Adding vault_sync_enabled column to environments...")
                    cursor.execute(
                        "ALTER TABLE environments ADD COLUMN vault_sync_enabled BOOLEAN DEFAULT 1"
                    )
                    migrations_applied.append("environments.vault_sync_enabled")

                # Update existing records with default values
                if migrations_applied:
                    click.echo("Updating existing records with default values...")

                    # Update secret_versions with empty values for new columns
                    if any("secret_versions" in m for m in migrations_applied):
                        cursor.execute(
                            """
                            UPDATE secret_versions 
                            SET nonce = COALESCE(nonce, ?), 
                                auth_tag = COALESCE(auth_tag, ?),
                                encrypted_dek = COALESCE(encrypted_dek, ?),
                                kms_key_id = COALESCE(kms_key_id, 'local-development-key'),
                                encryption_context = COALESCE(encryption_context, '{}')
                            WHERE nonce IS NULL OR auth_tag IS NULL OR encrypted_dek IS NULL OR kms_key_id IS NULL OR encryption_context IS NULL
                        """,
                            (b"", b"", b""),
                        )

                    # Update environments with default values
                    if any("environments" in m for m in migrations_applied):
                        cursor.execute(
                            """
                            UPDATE environments 
                            SET key_rotation_enabled = COALESCE(key_rotation_enabled, 1),
                                aws_sync_enabled = COALESCE(aws_sync_enabled, 1),
                                vault_sync_enabled = COALESCE(vault_sync_enabled, 1)
                            WHERE key_rotation_enabled IS NULL OR aws_sync_enabled IS NULL OR vault_sync_enabled IS NULL
                        """
                        )

                conn.commit()

                if migrations_applied:
                    click.echo(f"✓ Applied {len(migrations_applied)} migrations:")
                    for migration in migrations_applied:
                        click.echo(f"  - {migration}")
                else:
                    click.echo("✓ No migrations needed - database is up to date")

                click.echo("Database migration completed successfully!")

            except Exception as e:
                conn.rollback()
                click.echo(f"Migration failed: {str(e)}", err=True)
                raise
            finally:
                conn.close()

        else:
            click.echo("Migration currently supports SQLite databases only.")
            click.echo("For other databases, use SQLAlchemy migrations or run:")
            click.echo("  keeper reset-db  # WARNING: This will destroy all data")


@cli.command()
def shell():
    """Start an interactive shell with app context."""
    from keeper.app import create_app
    from keeper.models import (
        AuditAction,
        AuditLog,
        AuditResult,
        Environment,
        SecrecyLevel,
        Secret,
        SecretType,
        SecretVersion,
        SyncStatus,
        User,
        db,
    )

    app = create_app()
    with app.app_context():
        import code

        namespace = {
            "app": app,
            "db": db,
            "User": User,
            "Environment": Environment,
            "Secret": Secret,
            "SecretVersion": SecretVersion,
            "AuditLog": AuditLog,
            "SecretType": SecretType,
            "SecrecyLevel": SecrecyLevel,
            "SyncStatus": SyncStatus,
            "AuditAction": AuditAction,
            "AuditResult": AuditResult,
        }
        code.interact(local=namespace)


# Key Management Commands
@cli.group()
def kms():
    """Key Management Service commands."""
    pass


@kms.command()
@click.option("--key-id", help="Specific KMS key ID to get info for")
def key_info(key_id):
    """Get information about KMS keys."""
    from keeper.app import create_app
    from keeper.services.key_management import get_key_management_service

    app = create_app()
    with app.app_context():
        try:
            km_service = get_key_management_service()
            key_info = km_service.get_key_info(key_id)

            click.echo(json.dumps(key_info, indent=2, default=str))

        except Exception as e:
            click.echo(f"Error getting key info: {str(e)}", err=True)
            return 1


@kms.command()
@click.option("--key-id", help="Specific KMS key ID to rotate")
@click.option("--environment", help="Rotate key for specific environment")
@click.confirmation_option(prompt="Are you sure you want to rotate the encryption key?")
def rotate(key_id, environment):
    """Rotate KMS encryption keys."""
    from keeper.app import create_app
    from keeper.models.environment import Environment
    from keeper.services.key_management import get_key_management_service

    app = create_app()
    with app.app_context():
        try:
            if environment:
                env = Environment.find_by_name(environment)
                if not env:
                    click.echo(f"Environment '{environment}' not found", err=True)
                    return 1

                result = env.initiate_key_rotation()
                click.echo(f"Key rotation for environment '{environment}':")
                click.echo(json.dumps(result, indent=2, default=str))
            else:
                km_service = get_key_management_service()
                result = km_service.rotate_keys(key_id)
                click.echo("Key rotation result:")
                click.echo(json.dumps(result, indent=2, default=str))

        except Exception as e:
            click.echo(f"Error rotating key: {str(e)}", err=True)
            return 1


@kms.command()
def test_connection():
    """Test KMS connectivity and configuration."""
    from keeper.app import create_app
    from keeper.services.key_management import (
        KeyManagementError,
        get_key_management_service,
    )

    app = create_app()
    with app.app_context():
        try:
            click.echo("Testing KMS connection...")

            km_service = get_key_management_service()

            # Test encryption/decryption
            test_value = "test-secret-for-kms-connectivity"
            encrypted_data = km_service.encrypt_secret(test_value)
            decrypted_value = km_service.decrypt_secret(encrypted_data)

            if decrypted_value == test_value:
                click.echo("✓ KMS connection test successful")
                click.echo(f"✓ Encryption algorithm: {encrypted_data['algorithm']}")
                click.echo(f"✓ KMS key: {encrypted_data['kms_key_id']}")
            else:
                click.echo(
                    "✗ KMS connection test failed: decryption mismatch", err=True
                )
                return 1

        except KeyManagementError as e:
            click.echo(f"✗ KMS connection test failed: {str(e)}", err=True)
            return 1
        except Exception as e:
            click.echo(f"✗ Unexpected error during KMS test: {str(e)}", err=True)
            return 1


# Migration Commands
@cli.group()
def migrate():
    """Database migration commands."""
    pass


@migrate.command()
@click.option("--environment", help="Migrate only secrets in specific environment")
@click.option(
    "--dry-run", is_flag=True, default=True, help="Run migration without making changes"
)
@click.option(
    "--batch-size", default=100, help="Number of secrets to process per batch"
)
def to_kms(environment, dry_run, batch_size):
    """Migrate existing secrets to KMS envelope encryption."""
    from keeper.app import create_app
    from keeper.migrations.kms_migration import run_kms_migration
    from keeper.models.environment import Environment

    app = create_app()
    with app.app_context():
        try:
            environment_id = None
            if environment:
                env = Environment.find_by_name(environment)
                if not env:
                    click.echo(f"Environment '{environment}' not found", err=True)
                    return 1
                environment_id = env.id
                click.echo(f"Migrating secrets in environment: {environment}")

            if dry_run:
                click.echo(
                    "Running migration in DRY RUN mode (no changes will be made)"
                )
            else:
                click.echo("Running migration in LIVE mode (changes will be made)")
                if not click.confirm("Continue with live migration?"):
                    click.echo("Migration cancelled")
                    return 0

            click.echo("Starting KMS migration...")

            result = run_kms_migration(
                environment_id=environment_id, dry_run=dry_run, batch_size=batch_size
            )

            # Display results
            click.echo("\nMigration Results:")
            click.echo("=" * 50)
            click.echo(f"Success: {result['success']}")
            click.echo(f"Dry Run: {result['dry_run']}")
            click.echo(f"Total Secrets: {result['summary']['total_secrets']}")
            click.echo(f"Migrated: {result['summary']['migrated_secrets']}")
            click.echo(f"Failed: {result['summary']['failed_secrets']}")
            click.echo(f"Skipped: {result['summary']['skipped_secrets']}")
            click.echo(f"Success Rate: {result['summary']['success_rate']:.1f}%")

            if result["statistics"]["migration_errors"]:
                click.echo(
                    f"\nErrors ({len(result['statistics']['migration_errors'])}):"
                )
                for error in result["statistics"]["migration_errors"][:5]:
                    click.echo(f"  - {error}")
                if len(result["statistics"]["migration_errors"]) > 5:
                    click.echo(
                        f"  ... and {len(result['statistics']['migration_errors']) - 5} more"
                    )

            if not result["success"]:
                return 1

        except Exception as e:
            click.echo(f"Migration failed: {str(e)}", err=True)
            return 1


@migrate.command()
@click.argument("backup_file")
def rollback_kms(backup_file):
    """Rollback KMS migration using backup file."""
    from keeper.app import create_app
    from keeper.migrations.kms_migration import rollback_kms_migration

    app = create_app()
    with app.app_context():
        try:
            click.echo(f"Rolling back KMS migration using backup: {backup_file}")

            result = rollback_kms_migration(backup_file)

            if result["success"]:
                click.echo("Rollback completed successfully")
            else:
                click.echo(f"Rollback failed: {result['message']}", err=True)
                return 1

        except Exception as e:
            click.echo(f"Rollback failed: {str(e)}", err=True)
            return 1


# Sync Commands
@cli.group()
def sync():
    """Secret synchronization commands."""
    pass


@sync.command()
@click.option("--environment", help="Sync only secrets in specific environment")
@click.option("--backend", multiple=True, help="Backends to sync to (aws, vault)")
@click.option(
    "--dry-run", is_flag=True, help="Show what would be synced without making changes"
)
def pending(environment, backend, dry_run):
    """Process secrets with SYNC_PENDING status."""
    from keeper.app import create_app
    from keeper.models.environment import Environment
    from keeper.models.secret import Secret, SyncStatus
    from keeper.services.sync_service import SyncService

    app = create_app()
    with app.app_context():
        try:
            # Build query for pending secrets
            query = Secret.query.filter(
                (Secret.aws_sync_status == SyncStatus.SYNC_PENDING)
                | (Secret.vault_sync_status == SyncStatus.SYNC_PENDING)
            ).filter_by(is_active=True)

            if environment:
                env = Environment.find_by_name(environment)
                if not env:
                    click.echo(f"Environment '{environment}' not found", err=True)
                    return 1
                query = query.filter_by(environment_id=env.id)
                click.echo(f"Processing pending syncs in environment: {environment}")

            pending_secrets = query.all()

            if not pending_secrets:
                click.echo("No secrets with pending sync status found")
                return 0

            # Process backends
            backends = list(backend) if backend else ["aws", "vault"]

            click.echo(f"Found {len(pending_secrets)} secrets with pending sync status")
            click.echo(f"Target backends: {', '.join(backends)}")

            if dry_run:
                click.echo("\nDRY RUN - No changes will be made:\n")
                for secret in pending_secrets:
                    aws_status = (
                        "✓"
                        if secret.aws_sync_status == SyncStatus.SYNC_PENDING
                        else "-"
                    )
                    vault_status = (
                        "✓"
                        if secret.vault_sync_status == SyncStatus.SYNC_PENDING
                        else "-"
                    )
                    click.echo(
                        f"  {secret.full_name} [AWS: {aws_status}, Vault: {vault_status}]"
                    )
                return 0

            sync_service = SyncService()

            successful = 0
            failed = 0

            for secret in pending_secrets:
                try:
                    click.echo(f"Syncing {secret.full_name}...")

                    # Test if secret can be decrypted (this is where the base64 fix is important)
                    current_version = secret.current_version
                    if not current_version:
                        click.echo("  ✗ No current version found")
                        failed += 1
                        continue

                    # Try to decrypt the value (this will fail if base64 import missing)
                    try:
                        value = current_version.decrypt_value()
                        click.echo("  ✓ Secret decryption successful")
                    except Exception as decrypt_error:
                        click.echo(f"  ✗ Decryption failed: {decrypt_error}")
                        failed += 1
                        continue

                    # Perform actual sync
                    result = sync_service.sync_secret_to_backends(
                        secret, None, backends
                    )

                    if result["overall_success"]:
                        click.echo("  ✓ Sync successful")
                        successful += 1
                    else:
                        click.echo(f"  ✗ Sync failed: {result}")
                        failed += 1

                except Exception as e:
                    click.echo(f"  ✗ Error syncing secret: {e}")
                    failed += 1

            click.echo(f"\nSync completed: {successful} successful, {failed} failed")

            if failed > 0:
                return 1

        except Exception as e:
            click.echo(f"Sync processing failed: {str(e)}", err=True)
            return 1


@sync.command()
@click.option("--backend", multiple=True, help="Test specific backends (aws, vault)")
def test_backends(backend):
    """Test connectivity to sync backends."""
    from keeper.app import create_app
    from keeper.services.sync_service import SyncService

    app = create_app()
    with app.app_context():
        try:
            sync_service = SyncService()
            results = sync_service.test_backends()

            click.echo("Backend Connectivity Test Results:")
            click.echo("=" * 40)

            for backend_name, result in results.items():
                if backend_name == "overall_status":
                    continue

                if backend and backend_name not in backend:
                    continue

                status = result["status"]
                icon = "✓" if status == "success" else "✗"
                click.echo(f"{backend_name.upper()}: {icon} {status}")

                if "message" in result:
                    click.echo(f"  Message: {result['message']}")
                if "config" in result:
                    click.echo(f"  Config: {result['config']}")

            overall = results.get("overall_status", "unknown")
            click.echo(f"\nOverall Status: {overall}")

            if overall == "error":
                return 1

        except Exception as e:
            click.echo(f"Backend test failed: {str(e)}", err=True)
            return 1


if __name__ == "__main__":
    cli()
