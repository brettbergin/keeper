# Data Handling Architecture Specification

**Project**: Keeper - Enterprise Secret Management
**Version**: 0.1.0
**Last Updated**: 2025-09-20
**Components**: SQLAlchemy ORM + Pydantic Validation

## Overview

This document specifies the data handling architecture for the Keeper application, which uses a dual-layer approach combining SQLAlchemy as the Object-Relational Mapping (ORM) layer with Pydantic for data validation and serialization. This architecture ensures data integrity, type safety, and clean separation between database operations and API interactions.

## Architecture Components

### 1. SQLAlchemy ORM Layer

**Purpose**: Database abstraction and persistence layer
**Location**: `keeper/models/`
**Database**: SQLite (development), supports MySQL/PostgreSQL (production)

#### Core ORM Configuration

```python
# keeper/models/database.py
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def init_db(app):
    """Initialize database with Flask app."""
    db.init_app(app)
    with app.app_context():
        db.create_all()
```

#### Base Model Pattern

**File**: `keeper/models/base.py`

All models inherit from `BaseModel` which provides:

**Standard Fields**:
- `id` (Integer, Primary Key)
- `created_at` (DateTime, auto-generated)
- `updated_at` (DateTime, auto-updated)

**Standard Methods**:
- `to_dict()` - Convert to dictionary
- `save()` - Persist to database
- `delete()` - Remove from database
- `save_safely()` - Transaction-safe save with error handling
- `delete_safely()` - Transaction-safe delete with error handling
- `safe_transaction()` - Context manager for transactions

**Benefits**:
- Consistent timestamps across all models
- Standardized CRUD operations
- Built-in error handling and rollback
- Simplified model creation patterns

### 2. Core Data Models

#### Secret Model (`keeper/models/secret.py`)

**Primary Entity**: Represents secrets with multi-backend synchronization

**Key Features**:
- **Enumerations**: `SecretType`, `SecrecyLevel`, `SyncStatus`
- **Relationships**: Environment, User (creator), SecretVersions, AuditLogs
- **Computed Properties**: `sync_status`, `is_expired`, `needs_rotation`
- **Backend Integration**: AWS Secrets Manager and HashiCorp Vault tracking

**Schema Structure**:
```sql
secrets (
    id: INTEGER PRIMARY KEY,
    name: VARCHAR(255) NOT NULL,
    display_name: VARCHAR(255) NOT NULL,
    description: TEXT,
    secret_type: ENUM(SecretType),
    secrecy_level: ENUM(SecrecyLevel),
    service_name: VARCHAR(255),
    environment_id: INTEGER FK,
    creator_id: INTEGER FK,
    aws_sync_status: ENUM(SyncStatus),
    vault_sync_status: ENUM(SyncStatus),
    aws_secret_arn: VARCHAR(512),
    vault_path: VARCHAR(512),
    expires_at: DATETIME,
    auto_rotate: BOOLEAN,
    rotation_interval_days: INTEGER,
    last_rotated_at: DATETIME,
    tags: TEXT (JSON),
    is_active: BOOLEAN,
    created_at: DATETIME,
    updated_at: DATETIME
)
```

#### User Model (`keeper/models/user.py`)

**Authentication Entity**: Multi-method authentication support

**Key Features**:
- **Authentication Methods**: SAML, Database, Demo
- **Role-Based Access**: USER, MANAGER, ADMIN
- **Security**: BCrypt password hashing
- **SAML Integration**: Subject ID and session tracking

#### Environment Model (`keeper/models/environment.py`)

**Environment Isolation**: Separate development, staging, production

**Key Features**:
- Environment-specific backend configurations
- Production flags and access controls
- Backend path generation for secrets

### 3. Pydantic Validation Layer

**Purpose**: Data validation, serialization, and API contract enforcement
**Location**: `keeper/schemas/`
**Version**: Pydantic v2.5.0+

#### Schema Architecture Pattern

**File Structure**:
```
keeper/schemas/
├── __init__.py          # Centralized exports
├── secret.py           # Secret-related schemas
├── user.py             # User management schemas
├── environment.py      # Environment schemas
└── audit.py            # Audit log schemas
```

#### Secret Schemas (`keeper/schemas/secret.py`)

**Schema Hierarchy**:
1. **`SecretBase`** - Common validation rules
2. **`SecretCreate`** - Creation with required fields
3. **`SecretUpdate`** - Partial updates
4. **`SecretResponse`** - API responses with computed fields
5. **`SecretRotateRequest`** - Rotation operations

**Validation Features**:
- **Custom Validators**: Name format validation, rotation interval checks
- **Field Constraints**: Length limits, required fields, enum validation
- **Cross-field Validation**: Auto-rotate requires rotation interval
- **Type Coercion**: Automatic lowercase conversion for names

**Example Schema**:
```python
class SecretCreate(SecretBase):
    environment_id: int = Field(..., gt=0, description="Environment ID")
    value: str = Field(..., min_length=1, description="Secret value")

    @validator("name")
    def validate_name(cls, v):
        if not v.replace("-", "").replace("_", "").replace(".", "").isalnum():
            raise ValueError("Invalid name format")
        return v.lower()
```

### 4. Data Flow Architecture

#### Request → Validation → Persistence Flow

1. **API Request** → Pydantic schema validation
2. **Validated Data** → SQLAlchemy model creation
3. **Model Instance** → Database persistence
4. **Response** → Pydantic serialization

#### Example Implementation:
```python
# API endpoint
@app.route('/secrets', methods=['POST'])
def create_secret():
    # 1. Pydantic validation
    secret_data = SecretCreate(**request.json)

    # 2. SQLAlchemy model creation
    secret = Secret(
        name=secret_data.name,
        display_name=secret_data.display_name,
        # ... other fields
    )

    # 3. Database persistence
    secret.save()

    # 4. Pydantic response serialization
    return SecretResponse.from_orm(secret).dict()
```

## Database Configuration

### Development Configuration
- **Engine**: SQLite
- **Location**: `keeper_dev.db`
- **Connection**: Flask-SQLAlchemy managed

### Production Configuration
- **Supported Engines**: MySQL, PostgreSQL
- **Connection Pooling**: SQLAlchemy engine configuration
- **Migrations**: Flask-Migrate (planned)

## Data Validation Standards

### Pydantic Validation Rules

**String Fields**:
- Length constraints using `Field(min_length=1, max_length=255)`
- Format validation with custom validators
- Automatic type coercion (lowercase, strip)

**Numeric Fields**:
- Range validation using `Field(ge=1, le=365)`
- Required field dependencies
- Cross-field validation

**Enum Fields**:
- Type safety with Python Enums
- Automatic validation against allowed values
- Consistent representation across API and database

**DateTime Fields**:
- Automatic UTC handling
- Expiration date validation
- Rotation scheduling

## Security Considerations

### Data Protection
- **Password Hashing**: BCrypt with salt
- **Secret Values**: Encrypted at rest (via external KMS)
- **Sensitive Data**: Not logged in plain text
- **Database Access**: Connection string encryption

### Validation Security
- **Input Sanitization**: Pydantic automatic escaping
- **Length Limits**: Prevent buffer overflow attacks
- **Type Safety**: Runtime type checking
- **Injection Prevention**: Parameterized queries via SQLAlchemy

## Performance Optimizations

### SQLAlchemy Optimizations
- **Lazy Loading**: Relationships loaded on demand
- **Query Optimization**: Indexed foreign keys
- **Connection Pooling**: Reused database connections
- **Bulk Operations**: Batch inserts/updates

### Pydantic Optimizations
- **ORM Mode**: Direct SQLAlchemy model serialization
- **Field Exclusion**: Only serialize needed fields
- **Computed Fields**: Cached property calculations
- **Validation Caching**: Reused validation rules

## Integration Patterns

### ORM to Schema Conversion
```python
# SQLAlchemy model to Pydantic response
secret_model = Secret.query.get(secret_id)
response = SecretResponse.from_orm(secret_model)
```

### Schema to ORM Creation
```python
# Pydantic validation to SQLAlchemy creation
validated_data = SecretCreate(**request_data)
secret_model = Secret(**validated_data.dict(exclude={'value'}))
```

### Bulk Operations
```python
# Efficient bulk operations with validation
validated_secrets = [SecretCreate(**item) for item in bulk_data]
secret_models = [Secret(**item.dict()) for item in validated_secrets]
db.session.bulk_save_objects(secret_models)
```

## Error Handling

### SQLAlchemy Error Management
- **Transaction Rollback**: Automatic on exceptions
- **Connection Recovery**: Retry logic for transient failures
- **Constraint Violations**: Meaningful error messages
- **Logging**: Structured error logging with context

### Pydantic Validation Errors
- **Field-Level Errors**: Specific field validation messages
- **Cross-Field Validation**: Dependency validation errors
- **Type Conversion**: Clear type mismatch messages
- **Custom Validators**: Domain-specific error messages

## Testing Strategy

### Model Testing
- **Unit Tests**: Individual model methods and properties
- **Integration Tests**: Database operations and relationships
- **Constraint Testing**: Foreign key and unique constraints
- **Transaction Testing**: Rollback and error scenarios

### Schema Testing
- **Validation Testing**: Valid and invalid input scenarios
- **Serialization Testing**: ORM to schema conversion
- **Performance Testing**: Large payload validation
- **Edge Case Testing**: Boundary conditions and limits

## Migration Strategy

### Database Migrations
- **Schema Changes**: Versioned migration scripts
- **Data Migrations**: Safe data transformation scripts
- **Rollback Plans**: Backward compatibility maintenance
- **Production Deployment**: Zero-downtime migration patterns

### Schema Evolution
- **Backward Compatibility**: API versioning strategy
- **Field Addition**: Optional fields with defaults
- **Field Removal**: Deprecation and sunset process
- **Type Changes**: Safe type migration patterns

## Dependencies

### Required Packages
```toml
dependencies = [
    "flask-sqlalchemy>=3.1.1",  # ORM integration
    "sqlalchemy>=2.0.23",       # Database toolkit
    "pydantic>=2.5.0",          # Data validation
    "pymysql>=1.1.0",           # MySQL driver
    "bcrypt>=4.3.0",            # Password hashing
]
```

### Development Dependencies
```toml
dev = [
    "pytest>=8.4.2",           # Testing framework
    "pytest-flask>=1.3.0",     # Flask testing utilities
    "mypy>=1.18.2",             # Type checking
]
```

## Best Practices

### Model Design
1. **Inheritance**: Use BaseModel for common functionality
2. **Relationships**: Define clear bidirectional relationships
3. **Constraints**: Implement database-level constraints
4. **Indexes**: Add indexes for frequently queried fields

### Schema Design
1. **Validation**: Implement comprehensive validation rules
2. **Documentation**: Use Field descriptions for API docs
3. **Examples**: Provide schema examples for documentation
4. **Separation**: Separate create, update, and response schemas

### Performance
1. **Query Optimization**: Use select_related for relationships
2. **Pagination**: Implement pagination for large datasets
3. **Caching**: Cache frequently accessed computed properties
4. **Bulk Operations**: Use bulk operations for large datasets

---

**Document Status**: Complete
**Review Required**: Technical review for production deployment
**Next Update**: Upon major architectural changes or dependency updates