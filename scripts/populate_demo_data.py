#!/usr/bin/env python3
"""
Demo data population script for Keeper.

This script creates demo users and secrets to showcase the RBAC system and
provide realistic test data for development and demonstrations.
"""

import os
import sys
import random
from datetime import datetime, timedelta

# Add the parent directory to the path so we can import keeper modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from keeper.app import create_app
from keeper.models import (
    db, User, Secret, SecretVersion, Environment, AuditLog,
    UserRole, AuthMethod, SecretType, SecrecyLevel, SyncStatus,
    AuditAction, AuditResult
)


class DemoDataPopulator:
    """Handles creation of demo data."""
    
    def __init__(self, app):
        self.app = app
        self.users = {}
        self.environments = {}
        self.secrets = []
        self.summary_data = {}
        
    def populate_all(self):
        """Populate all demo data."""
        print("🚀 Starting demo data population...")
        
        with self.app.app_context():
            self.create_demo_users()
            self.get_environments()
            self.create_demo_secrets()
            self.create_audit_entries()
            self.collect_summary_data()
            
        print("✅ Demo data population completed!")
        self.print_summary()
    
    def create_demo_users(self):
        """Create demo users with different roles."""
        print("\n👥 Creating demo users...")
        
        demo_users = [
            {
                'username': 'admin',
                'email': 'admin@company.com',
                'full_name': 'System Administrator',
                'role': UserRole.ADMIN,
                'managed_envs': []
            },
            {
                'username': 'alice.manager',
                'email': 'alice@company.com', 
                'full_name': 'Alice Production Manager',
                'role': UserRole.MANAGER,
                'managed_envs': ['production']
            },
            {
                'username': 'bob.staging',
                'email': 'bob@company.com',
                'full_name': 'Bob Staging Manager', 
                'role': UserRole.MANAGER,
                'managed_envs': ['staging']
            },
            {
                'username': 'charlie.ops',
                'email': 'charlie@company.com',
                'full_name': 'Charlie Operations Manager',
                'role': UserRole.MANAGER,
                'managed_envs': ['staging', 'production']
            },
            {
                'username': 'diana.dev',
                'email': 'diana@company.com',
                'full_name': 'Diana Developer',
                'role': UserRole.USER,
                'managed_envs': []
            },
            {
                'username': 'eve.dev',
                'email': 'eve@company.com',
                'full_name': 'Eve Frontend Developer',
                'role': UserRole.USER,
                'managed_envs': []
            },
            {
                'username': 'frank.backend',
                'email': 'frank@company.com',
                'full_name': 'Frank Backend Developer',
                'role': UserRole.USER,
                'managed_envs': []
            }
        ]
        
        for user_data in demo_users:
            username = user_data['username']
            
            # Check if user already exists
            existing_user = User.find_by_username(username)
            if existing_user:
                print(f"  ⚠️  User {username} already exists, skipping...")
                self.users[username] = existing_user
                continue
                
            # Create new user
            user = User(
                username=username,
                email=user_data['email'],
                full_name=user_data['full_name'],
                role=user_data['role'],
                auth_method=AuthMethod.DEMO,
                is_active=True,
                email_verified=True,
                last_login=datetime.utcnow() - timedelta(days=random.randint(1, 30))
            )
            
            # Set managed environments for managers
            if user_data['managed_envs']:
                user.set_managed_environments(user_data['managed_envs'])
            
            user.save()
            self.users[username] = user
            print(f"  ✅ Created {user_data['role'].value}: {user_data['full_name']} ({username})")
    
    def get_environments(self):
        """Get existing environments."""
        print("\n🌍 Getting environments...")
        
        environments = Environment.get_active_environments()
        for env in environments:
            self.environments[env.name] = env
            print(f"  📍 Found environment: {env.name}")
    
    def create_demo_secrets(self):
        """Create a variety of demo secrets."""
        print("\n🔐 Creating demo secrets...")
        
        # Define secret templates
        secret_templates = [
            # Development secrets (created by developers)
            {
                'name': 'database-dev-password',
                'display_name': 'Development Database Password',
                'description': 'PostgreSQL password for development environment',
                'secret_type': SecretType.PASSWORD,
                'secrecy_level': SecrecyLevel.MEDIUM,
                'environment': 'development',
                'service_name': 'postgresql',
                'value': 'dev_pg_pass_2024!',
                'creator': 'diana.dev'
            },
            {
                'name': 'redis-dev-url',
                'display_name': 'Development Redis Connection',
                'description': 'Redis connection string for caching',
                'secret_type': SecretType.STRING,
                'secrecy_level': SecrecyLevel.LOW,
                'environment': 'development', 
                'service_name': 'redis',
                'value': 'redis://localhost:6379/0',
                'creator': 'eve.dev'
            },
            {
                'name': 'stripe-test-keys',
                'display_name': 'Stripe Test API Keys',
                'description': 'Test API keys for payment processing',
                'secret_type': SecretType.JSON,
                'secrecy_level': SecrecyLevel.MEDIUM,
                'environment': 'development',
                'service_name': 'stripe',
                'value': '{"publishable_key": "pk_test_123456", "secret_key": "sk_test_789012"}',
                'creator': 'frank.backend'
            },
            
            # Staging secrets (created by developers and managers)
            {
                'name': 'database-staging-password', 
                'display_name': 'Staging Database Password',
                'description': 'PostgreSQL password for staging environment',
                'secret_type': SecretType.PASSWORD,
                'secrecy_level': SecrecyLevel.HIGH,
                'environment': 'staging',
                'service_name': 'postgresql',
                'value': 'staging_secure_password_2024$',
                'creator': 'bob.staging'
            },
            {
                'name': 'jwt-signing-key-staging',
                'display_name': 'JWT Signing Key (Staging)',
                'description': 'Secret key for signing JWT tokens in staging',
                'secret_type': SecretType.STRING,
                'secrecy_level': SecrecyLevel.HIGH,
                'environment': 'staging',
                'service_name': 'auth-service',
                'value': 'staging-jwt-secret-key-very-long-and-secure-2024',
                'creator': 'diana.dev'
            },
            {
                'name': 'aws-staging-credentials',
                'display_name': 'AWS Staging Credentials',
                'description': 'AWS access credentials for staging environment',
                'secret_type': SecretType.JSON,
                'secrecy_level': SecrecyLevel.HIGH,
                'environment': 'staging',
                'service_name': 'aws',
                'value': '{"access_key_id": "AKIA123STAGING", "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "region": "us-west-2"}',
                'creator': 'charlie.ops'
            },
            
            # Production secrets (created by managers and admin)
            {
                'name': 'database-prod-password',
                'display_name': 'Production Database Password', 
                'description': 'PostgreSQL master password for production',
                'secret_type': SecretType.PASSWORD,
                'secrecy_level': SecrecyLevel.CRITICAL,
                'environment': 'production',
                'service_name': 'postgresql',
                'value': 'prod_ultra_secure_password_2024!@#$%',
                'creator': 'admin'
            },
            {
                'name': 'stripe-live-keys',
                'display_name': 'Stripe Live API Keys',
                'description': 'Live API keys for payment processing',
                'secret_type': SecretType.JSON,
                'secrecy_level': SecrecyLevel.CRITICAL,
                'environment': 'production',
                'service_name': 'stripe',
                'value': '{"publishable_key": "pk_live_REALKEY123", "secret_key": "sk_live_REALSECRET456"}',
                'creator': 'alice.manager'
            },
            {
                'name': 'ssl-certificate',
                'display_name': 'SSL Certificate',
                'description': 'SSL certificate for production domain',
                'secret_type': SecretType.CERTIFICATE,
                'secrecy_level': SecrecyLevel.HIGH,
                'environment': 'production',
                'service_name': 'nginx',
                'value': '-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV\n...(demo certificate)...\n-----END CERTIFICATE-----',
                'creator': 'charlie.ops'
            },
            {
                'name': 'api-gateway-key',
                'display_name': 'API Gateway Master Key',
                'description': 'Master key for API gateway authentication',
                'secret_type': SecretType.API_KEY,
                'secrecy_level': SecrecyLevel.CRITICAL,
                'environment': 'production',
                'service_name': 'api-gateway',
                'value': 'agw_prod_master_key_2024_ultra_secure_do_not_share',
                'creator': 'admin'
            },
            
            # SSH Keys
            {
                'name': 'deployment-ssh-key',
                'display_name': 'Deployment SSH Key',
                'description': 'SSH private key for automated deployments',
                'secret_type': SecretType.SSH_KEY,
                'secrecy_level': SecrecyLevel.HIGH,
                'environment': 'production',
                'service_name': 'deployment',
                'value': '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAFwAAAAdzc2gtcn\n...(demo SSH key)...\n-----END OPENSSH PRIVATE KEY-----',
                'creator': 'alice.manager'
            }
        ]
        
        for secret_data in secret_templates:
            try:
                # Get environment and creator
                environment = self.environments.get(secret_data['environment'])
                creator = self.users.get(secret_data['creator'])
                
                if not environment:
                    print(f"  ❌ Environment {secret_data['environment']} not found, skipping secret {secret_data['name']}")
                    continue
                    
                if not creator:
                    print(f"  ❌ Creator {secret_data['creator']} not found, skipping secret {secret_data['name']}")
                    continue
                
                # Check if secret already exists
                existing_secret = Secret.query.filter_by(
                    name=secret_data['name'],
                    environment_id=environment.id
                ).first()
                
                if existing_secret:
                    print(f"  ⚠️  Secret {secret_data['name']} already exists, skipping...")
                    continue
                
                # Create secret
                secret = Secret.create(
                    name=secret_data['name'],
                    display_name=secret_data['display_name'],
                    description=secret_data['description'],
                    secret_type=secret_data['secret_type'],
                    secrecy_level=secret_data['secrecy_level'],
                    environment_id=environment.id,
                    service_name=secret_data['service_name'],
                    creator_id=creator.id
                )
                
                # Create the first version
                SecretVersion.create_version(
                    secret_id=secret.id,
                    value=secret_data['value'],
                    created_by_id=creator.id,
                    generation_method='manual'
                )
                
                # Add some random sync status
                secret.aws_sync_status = random.choice([SyncStatus.SYNCED, SyncStatus.OUT_OF_SYNC, SyncStatus.NOT_SYNCED])
                secret.vault_sync_status = random.choice([SyncStatus.SYNCED, SyncStatus.OUT_OF_SYNC, SyncStatus.NOT_SYNCED])
                
                if secret.aws_sync_status == SyncStatus.SYNCED:
                    secret.aws_last_sync = datetime.utcnow() - timedelta(hours=random.randint(1, 48))
                    secret.aws_secret_arn = f"arn:aws:secretsmanager:us-west-2:123456789012:secret:{secret.name}-{random.randint(100000, 999999)}"
                
                if secret.vault_sync_status == SyncStatus.SYNCED:
                    secret.vault_last_sync = datetime.utcnow() - timedelta(hours=random.randint(1, 48))
                    secret.vault_path = f"secret/data/{secret_data['environment']}/{secret.name}"
                
                secret.save()
                self.secrets.append(secret)
                
                print(f"  ✅ Created secret: {secret_data['display_name']} ({secret_data['environment']}) by {creator.full_name}")
                
            except Exception as e:
                print(f"  ❌ Failed to create secret {secret_data['name']}: {str(e)}")
    
    def create_audit_entries(self):
        """Create some historical audit log entries."""
        print("\n📋 Creating audit log entries...")
        
        # Create some recent activity
        audit_actions = [
            (AuditAction.READ, "Secret accessed during deployment"),
            (AuditAction.UPDATE, "Secret rotated as part of security policy"),
            (AuditAction.READ, "Secret retrieved for application configuration"),
            (AuditAction.CREATE, "New secret created for microservice"),
        ]
        
        for i in range(20):
            try:
                action, description = random.choice(audit_actions)
                secret = random.choice(self.secrets) if self.secrets else None
                user = random.choice(list(self.users.values()))
                
                if secret:
                    AuditLog.log_secret_action(
                        action=action,
                        result=AuditResult.SUCCESS,
                        secret=secret,
                        user_id=user.id,
                        username=user.username,
                        ip_address=f"192.168.1.{random.randint(10, 254)}",
                        details={'description': description}
                    )
                
            except Exception as e:
                print(f"  ❌ Failed to create audit entry: {str(e)}")
        
        print(f"  ✅ Created sample audit log entries")
    
    def collect_summary_data(self):
        """Collect summary data while the database session is active."""
        print("\n📊 Collecting summary data...")
        
        # Collect user data
        user_data = []
        for username, user in self.users.items():
            managed_envs = user.get_managed_environments() if user.role == UserRole.MANAGER else []
            user_data.append({
                'full_name': user.full_name,
                'role': user.role.value,
                'managed_envs': managed_envs
            })
        
        # Collect secrets data
        secrets_by_env = {}
        for secret in self.secrets:
            env_name = secret.environment.name
            if env_name not in secrets_by_env:
                secrets_by_env[env_name] = []
            secrets_by_env[env_name].append({
                'display_name': secret.display_name,
                'secrecy_level': secret.secrecy_level.value
            })
        
        self.summary_data = {
            'users': user_data,
            'secrets_by_env': secrets_by_env,
            'total_users': len(self.users),
            'total_secrets': len(self.secrets)
        }
    
    def print_summary(self):
        """Print a summary of created data."""
        print("\n" + "="*60)
        print("📊 DEMO DATA SUMMARY")
        print("="*60)
        
        print(f"\n👥 Users created: {self.summary_data['total_users']}")
        for user_data in self.summary_data['users']:
            env_info = f" (manages: {', '.join(user_data['managed_envs'])})" if user_data['managed_envs'] else ""
            print(f"  • {user_data['full_name']} - {user_data['role']}{env_info}")
        
        print(f"\n🔐 Secrets created: {self.summary_data['total_secrets']}")
        for env_name, secrets in self.summary_data['secrets_by_env'].items():
            print(f"  📍 {env_name.title()}: {len(secrets)} secrets")
            for secret_data in secrets:
                print(f"    • {secret_data['display_name']} ({secret_data['secrecy_level']})")
        
        print("\n🎯 Next steps:")
        print("  1. Start the application: make run")
        print("  2. Visit: http://localhost:5000")
        print("  3. Try the demo login with different users:")
        print("     • admin@company.com (Administrator)")
        print("     • alice@company.com (Production Manager)")
        print("     • diana@company.com (Developer)")
        print("  4. Explore the secrets and try different role permissions!")
        print("="*60)


def main():
    """Main function to populate demo data."""
    # Create Flask app
    app = create_app('development')
    
    # Create populator and run
    populator = DemoDataPopulator(app)
    populator.populate_all()


if __name__ == '__main__':
    main()