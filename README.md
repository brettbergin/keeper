# Keeper - Enterprise Secret Management 🔐

**Keeper** is a comprehensive Flask-based web service for managing and synchronizing secrets across multiple backends including AWS Secrets Manager and HashiCorp Vault. Built with enterprise security in mind, Keeper provides advanced encryption, audit logging, and multi-environment support.

## ✨ Features

### 🔒 **Advanced Encryption**
- **AWS KMS Envelope Encryption** - Industry-standard encryption with hardware-backed keys
- **AES-256-GCM** - Strong symmetric encryption with authentication
- **Per-Environment Keys** - Separate encryption keys for dev/staging/production
- **Automatic Key Rotation** - Support for AWS KMS automatic key rotation
- **Legacy Migration** - Seamless migration from older encryption methods

### 🔄 **Multi-Backend Synchronization**
- **AWS Secrets Manager** - Native integration with AWS cloud secrets
- **HashiCorp Vault** - Support for Vault KV v2 secrets engine
- **Cross-Backend Sync** - Keep secrets synchronized across multiple backends
- **Sync Status Tracking** - Real-time monitoring of synchronization status

### 🌍 **Multi-Environment Support**
- **Environment Isolation** - Separate environments for development, staging, production
- **Per-Environment Configuration** - Custom KMS keys, sync settings per environment
- **Environment-Specific Access** - Role-based access control per environment

### 🔑 **Secret Types & Management**
- **Multiple Secret Types** - Support for passwords, API keys, SSH keys, certificates, JSON, YAML
- **Secret Rotation** - AB rotation pattern for zero-downtime secret updates
- **Version History** - Complete audit trail of secret changes
- **Secret Generation** - Built-in secure secret generation utilities

### 👥 **Enterprise Authentication**
- **Okta SAML Integration** - Enterprise single sign-on support
- **Role-Based Access Control** - Admin and user roles with appropriate permissions
- **Session Management** - Secure session handling with timeout controls

### 📊 **Advanced UI & UX**
- **Bootstrap 5 Interface** - Modern, responsive web interface
- **Advanced Search & Filtering** - Powerful search capabilities across all secrets
- **Pagination** - Efficient handling of large secret databases
- **Real-time Status** - Live sync status and health monitoring

### 🔍 **Audit & Compliance**
- **Comprehensive Audit Logging** - Track all secret operations with detailed logs
- **Activity Dashboard** - Visual overview of recent secret activities
- **Compliance Reports** - Generate reports for security compliance
- **Integrity Verification** - Cryptographic verification of secret integrity

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- Docker & Docker Compose (optional)
- AWS Account with KMS access (for production)
- HashiCorp Vault instance (optional)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/keeper.git
   cd keeper
   ```

2. **Set up Python environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Initialize database**
   ```bash
   keeper init-db
   ```

5. **Run the application**
   ```bash
   keeper run
   ```

Access the application at `http://localhost:8989`

### Docker Quick Start

1. **Using Docker Compose**
   ```bash
   docker-compose up -d
   ```

2. **Initialize database in container**
   ```bash
   docker-compose exec keeper keeper init-db
   ```

## 📖 Configuration

### Environment Variables

Keeper uses environment variables for configuration. Copy `.env.example` to `.env` and customize:

#### **Core Configuration**
```bash
SECRET_KEY=your-secret-key-here
FLASK_ENV=production
DATABASE_URL=sqlite:///keeper.db
```

#### **AWS KMS Configuration (Production)**
```bash
# Key Management Backend
KEY_MANAGEMENT_BACKEND=kms

# AWS Credentials
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key

# KMS Settings
KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
# OR use alias:
KMS_KEY_ALIAS=alias/keeper-production
KMS_ENCRYPTION_CONTEXT={"application":"keeper","environment":"production"}
ENABLE_KMS_KEY_ROTATION=true
```

#### **Development Configuration**
```bash
# Use local encryption for development
KEY_MANAGEMENT_BACKEND=local
DATABASE_URL=sqlite:///keeper_dev.db
```

#### **HashiCorp Vault**
```bash
VAULT_URL=http://localhost:8200
VAULT_TOKEN=your-vault-token
VAULT_MOUNT_POINT=secret
```

#### **Okta SAML (Optional)**
```bash
OKTA_ISSUER=https://your-org.okta.com
OKTA_CLIENT_ID=your-client-id
OKTA_CLIENT_SECRET=your-client-secret
```

### Database Configuration

#### **SQLite (Development)**
```bash
DATABASE_URL=sqlite:///keeper_dev.db
```

#### **MySQL (Production)**
```bash
DATABASE_URL=mysql+pymysql://keeper:password@localhost/keeper
```

## 🔧 CLI Commands

Keeper provides a comprehensive CLI for management operations:

### **Application Management**
```bash
# Run the application
keeper run --host 0.0.0.0 --port 8989

# Initialize database
keeper init-db

# Reset database (WARNING: destroys all data)
keeper reset-db

# Interactive shell
keeper shell
```

### **Key Management Service**
```bash
# Test KMS connectivity
keeper kms test-connection

# Get key information
keeper kms key-info

# Rotate encryption keys
keeper kms rotate --environment production

# Rotate specific key
keeper kms rotate --key-id arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
```

### **Migration Commands**
```bash
# Migrate to KMS encryption (dry run)
keeper migrate to-kms --dry-run

# Migrate specific environment
keeper migrate to-kms --environment production --no-dry-run

# Rollback migration
keeper migrate rollback-kms backup_file.json
```

## 🏗️ Architecture

### **Security Architecture**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Browser   │    │   Keeper App    │    │   AWS KMS       │
│                 │    │                 │    │                 │
│ User Interface  │◄──►│ Flask Service   │◄──►│ Customer Master │
│ Bootstrap UI    │    │ Key Management  │    │ Key (CMK)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                               │
                               ▼
                       ┌─────────────────┐
                       │   Database      │
                       │                 │
                       │ • Encrypted     │
                       │   Secret Data   │
                       │ • Encrypted DEKs│
                       │ • Metadata      │
                       └─────────────────┘
```

### **Envelope Encryption Flow**

1. **Encryption Process:**
   - Generate Data Encryption Key (DEK) via KMS
   - Encrypt secret with DEK using AES-256-GCM
   - Store encrypted secret + encrypted DEK in database
   - DEK never stored in plaintext

2. **Decryption Process:**
   - Retrieve encrypted DEK from database
   - Decrypt DEK using KMS
   - Use plaintext DEK to decrypt secret
   - Cache DEK temporarily for performance

### **Component Overview**

- **Web Interface** - Bootstrap 5 responsive UI
- **API Layer** - Flask blueprints with validation
- **Service Layer** - Business logic and integrations
- **Model Layer** - SQLAlchemy ORM with encryption
- **Security Layer** - KMS integration and auth
- **Storage Layer** - SQLite/MySQL with encrypted data

## 🔒 Security Features

### **Encryption at Rest**
- All secrets encrypted using AES-256-GCM
- Envelope encryption with AWS KMS
- Per-environment encryption keys
- No plaintext keys stored in database

### **Encryption in Transit**
- HTTPS/TLS for all web traffic
- Encrypted API communications
- Secure KMS API calls

### **Access Control**
- Role-based permissions (Admin/User)
- Environment-based access restrictions
- Session timeout controls
- SAML integration for enterprise SSO

### **Audit & Monitoring**
- Complete audit trail of all operations
- Real-time activity monitoring
- Compliance reporting capabilities
- Integrity verification

## 📊 User Interface

### **Dashboard**
- System overview with statistics
- Recent activity feed
- Quick action buttons
- Health status indicators

### **Secret Management**
- Create, read, update, delete secrets
- Support for multiple secret types
- Version history and rollback
- Bulk operations support

### **Environment Management**
- Configure multiple environments
- Per-environment KMS keys
- Sync status monitoring
- Environment-specific settings

### **Admin Panel**
- User management
- System configuration
- Audit log viewing
- Backup and restore operations

## 🔄 Synchronization

### **AWS Secrets Manager**
- Native AWS API integration
- Automatic secret synchronization
- Configurable sync intervals
- Error handling and retry logic

### **HashiCorp Vault**
- Vault KV v2 API support
- Path-based organization
- Authentication token management
- Conflict resolution strategies

### **Sync Status Tracking**
- Real-time sync status
- Error reporting and alerts
- Manual sync triggers
- Sync history and logs

## 📈 Monitoring & Observability

### **Health Checks**
- Application health endpoints
- Database connectivity checks
- KMS availability monitoring
- External service status

### **Logging**
- Structured JSON logging
- Configurable log levels
- Audit trail maintenance
- Performance metrics

### **Metrics**
- Secret creation/modification rates
- Sync success/failure rates
- Authentication events
- Performance benchmarks

## 🧪 Development

### **Development Setup**
```bash
# Clone and setup
git clone https://github.com/your-org/keeper.git
cd keeper
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Development configuration
cp .env.example .env
# Set KEY_MANAGEMENT_BACKEND=local for development

# Initialize database
keeper init-db

# Run in development mode
keeper run --debug
```

### **Code Quality Tools**
```bash
# Format code
make format

# Lint code
make lint

# Type checking
make typecheck

# Run tests
make test

# Coverage report
make coverage
```

### **Testing**
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=keeper

# Run specific test file
pytest tests/test_kms_service.py
```

## 🚀 Deployment

### **Production Deployment**

1. **Set up AWS KMS**
   ```bash
   # Create KMS key
   aws kms create-key --description "Keeper production encryption key"
   
   # Create alias
   aws kms create-alias --alias-name alias/keeper-production --target-key-id KEY_ID
   ```

2. **Configure environment**
   ```bash
   export KEY_MANAGEMENT_BACKEND=kms
   export KMS_KEY_ALIAS=alias/keeper-production
   export DATABASE_URL=mysql+pymysql://keeper:password@localhost/keeper
   ```

3. **Deploy with Docker**
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

### **Docker Production Setup**
```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  keeper:
    build: .
    environment:
      - KEY_MANAGEMENT_BACKEND=kms
      - KMS_KEY_ALIAS=alias/keeper-production
      - DATABASE_URL=mysql+pymysql://keeper:${MYSQL_PASSWORD}@mysql/keeper
    depends_on:
      - mysql
      
  mysql:
    image: mysql:8.0
    environment:
      - MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD}
      - MYSQL_DATABASE=keeper
      - MYSQL_USER=keeper
      - MYSQL_PASSWORD=${MYSQL_PASSWORD}
```

### **Migration to Production**
```bash
# Test migration first
keeper migrate to-kms --dry-run

# Perform migration
keeper migrate to-kms --no-dry-run

# Verify migration
keeper kms test-connection
```

## 📋 API Reference

### **Secret Operations**
```bash
# Create secret
POST /api/secrets
{
  "name": "api-key",
  "secret_type": "API_KEY",
  "value": "secret-value",
  "environment_id": 1
}

# Get secret
GET /api/secrets/{id}

# Update secret
PUT /api/secrets/{id}

# Delete secret
DELETE /api/secrets/{id}
```

### **Environment Operations**
```bash
# List environments
GET /api/environments

# Create environment
POST /api/environments
{
  "name": "production",
  "display_name": "Production",
  "kms_key_alias": "alias/keeper-prod"
}
```

## 🔧 Troubleshooting

### **Common Issues**

#### **KMS Access Denied**
```bash
# Check AWS credentials
aws sts get-caller-identity

# Verify KMS permissions
aws kms describe-key --key-id alias/keeper-production

# Test KMS connectivity
keeper kms test-connection
```

#### **Database Connection Issues**
```bash
# Check database URL
echo $DATABASE_URL

# Test database connectivity
keeper shell
>>> db.session.execute("SELECT 1").fetchone()
```

#### **Migration Issues**
```bash
# Run migration in dry-run mode first
keeper migrate to-kms --dry-run

# Check migration logs
tail -f logs/keeper.log
```

### **Performance Tuning**

#### **KMS Performance**
```bash
# Increase DEK cache TTL
export KMS_DEK_CACHE_TTL=7200

# Adjust batch size for migrations
keeper migrate to-kms --batch-size 50
```

#### **Database Performance**
```bash
# Use connection pooling for MySQL
DATABASE_URL=mysql+pymysql://keeper:pass@localhost/keeper?pool_size=10&max_overflow=20
```

## 🤝 Contributing

### **Development Workflow**
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### **Code Standards**
- Follow PEP 8 for Python code
- Use type hints for all functions
- Add docstrings for all public methods
- Maintain test coverage above 80%

### **Commit Messages**
```
feat: add KMS envelope encryption support
fix: resolve secret decryption error in production
docs: update API documentation for v2.0
test: add integration tests for migration
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Flask and SQLAlchemy communities for excellent frameworks
- AWS for robust KMS service
- HashiCorp for Vault integration capabilities
- Bootstrap team for UI components
- Contributors and maintainers

## 📞 Support

- **Documentation**: [Wiki](https://github.com/your-org/keeper/wiki)
- **Issues**: [GitHub Issues](https://github.com/your-org/keeper/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/keeper/discussions)
- **Security**: Report security issues to security@your-org.com

---

**Made with ❤️ for enterprise security teams**
