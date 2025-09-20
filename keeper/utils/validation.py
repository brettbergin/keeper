"""Validation utilities for secret and user operations."""

import re
from typing import Any, Dict, Optional

from ..models.environment import Environment
from ..models.secret import SecretType
from ..models.user import User


def validate_secret_value(value: str, secret_type: SecretType) -> Dict[str, Any]:
    """
    Validate a secret value based on its type.

    Returns a dict with validation result and any warnings/suggestions.
    """
    result = {"valid": True, "warnings": [], "suggestions": [], "strength": "unknown"}

    if not value or len(value.strip()) == 0:
        result["valid"] = False
        result["warnings"].append("Secret value cannot be empty")
        return result

    if secret_type == SecretType.PASSWORD:
        return _validate_password(value)
    elif secret_type == SecretType.API_KEY:
        return _validate_api_key(value)
    elif secret_type == SecretType.SSH_KEY:
        return _validate_ssh_key(value)
    elif secret_type == SecretType.RSA_KEY:
        return _validate_rsa_key(value)
    elif secret_type == SecretType.CERTIFICATE:
        return _validate_certificate(value)
    elif secret_type in [SecretType.JSON, SecretType.YAML]:
        return _validate_structured_data(value, secret_type)
    else:
        # Basic validation for string types
        return _validate_generic_string(value)


def _validate_password(password: str) -> Dict[str, Any]:
    """Validate password strength and provide recommendations."""
    result = {"valid": True, "warnings": [], "suggestions": [], "strength": "weak"}

    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

    # Length checks
    if length < 8:
        result["valid"] = False
        result["warnings"].append("Password must be at least 8 characters long")
    elif length < 12:
        result["suggestions"].append(
            "Consider using a password of at least 12 characters"
        )

    # Character type checks
    char_types = sum([has_upper, has_lower, has_digit, has_symbol])
    if char_types < 3:
        result["suggestions"].append(
            "Use a mix of uppercase, lowercase, numbers, and symbols"
        )

    # Common patterns
    if password.lower() in ["password", "123456", "qwerty", "admin", "letmein"]:
        result["valid"] = False
        result["warnings"].append("Password is too common and easily guessable")

    # Sequential patterns
    if re.search(r"(012|123|234|345|456|567|678|789|890)", password):
        result["suggestions"].append("Avoid sequential numbers")

    if re.search(
        r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)",
        password.lower(),
    ):
        result["suggestions"].append("Avoid sequential letters")

    # Repeated characters
    if re.search(r"(.)\1{2,}", password):
        result["suggestions"].append(
            "Avoid repeating the same character multiple times"
        )

    # Determine strength
    if length >= 12 and char_types >= 3 and not result["warnings"]:
        if length >= 16 and char_types == 4:
            result["strength"] = "very_strong"
        elif length >= 14 and char_types >= 3:
            result["strength"] = "strong"
        else:
            result["strength"] = "medium"
    elif length >= 8 and char_types >= 2:
        result["strength"] = "weak"
    else:
        result["strength"] = "very_weak"

    return result


def _validate_api_key(api_key: str) -> Dict[str, Any]:
    """Validate API key format and characteristics."""
    result = {"valid": True, "warnings": [], "suggestions": [], "strength": "unknown"}

    # Length check
    if len(api_key) < 32:
        result["warnings"].append("API key should be at least 32 characters long")

    # Character set check
    if not re.match(r"^[A-Za-z0-9_-]+$", api_key):
        result["suggestions"].append(
            "API key should only contain letters, numbers, underscores, and hyphens"
        )

    # Entropy check (basic)
    unique_chars = len(set(api_key))
    if unique_chars < len(api_key) * 0.5:
        result["suggestions"].append("API key has low character diversity")

    # Determine strength
    if len(api_key) >= 64 and unique_chars >= len(api_key) * 0.7:
        result["strength"] = "strong"
    elif len(api_key) >= 32 and unique_chars >= len(api_key) * 0.5:
        result["strength"] = "medium"
    else:
        result["strength"] = "weak"

    return result


def _validate_ssh_key(ssh_key: str) -> Dict[str, Any]:
    """Validate SSH key format."""
    result = {"valid": True, "warnings": [], "suggestions": [], "strength": "unknown"}

    ssh_key = ssh_key.strip()

    # Check for SSH key headers
    if ssh_key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----"):
        result["strength"] = "strong"
    elif ssh_key.startswith("-----BEGIN RSA PRIVATE KEY-----"):
        result["strength"] = "medium"
        result["suggestions"].append("Consider using Ed25519 keys for better security")
    elif ssh_key.startswith(("ssh-rsa ", "ssh-ed25519 ", "ssh-dss ")):
        result["warnings"].append("This appears to be a public key, not a private key")
    else:
        result["valid"] = False
        result["warnings"].append("Invalid SSH key format")

    return result


def _validate_rsa_key(rsa_key: str) -> Dict[str, Any]:
    """Validate RSA key format."""
    result = {"valid": True, "warnings": [], "suggestions": [], "strength": "unknown"}

    rsa_key = rsa_key.strip()

    if rsa_key.startswith("-----BEGIN RSA PRIVATE KEY-----"):
        result["strength"] = "medium"
    elif rsa_key.startswith("-----BEGIN PRIVATE KEY-----"):
        result["strength"] = "medium"
    elif rsa_key.startswith("-----BEGIN PUBLIC KEY-----"):
        result["warnings"].append("This appears to be a public key, not a private key")
    else:
        result["valid"] = False
        result["warnings"].append("Invalid RSA key format")

    # Check key size (basic heuristic)
    if len(rsa_key) < 1000:
        result["suggestions"].append(
            "Key appears short, consider using at least 2048-bit RSA keys"
        )
    elif len(rsa_key) > 3000:
        result["strength"] = "strong"

    return result


def _validate_certificate(cert: str) -> Dict[str, Any]:
    """Validate certificate format."""
    result = {"valid": True, "warnings": [], "suggestions": [], "strength": "unknown"}

    cert = cert.strip()

    if cert.startswith("-----BEGIN CERTIFICATE-----"):
        result["strength"] = "medium"
    elif cert.startswith("-----BEGIN PRIVATE KEY-----"):
        result["warnings"].append("This appears to be a private key, not a certificate")
    else:
        result["valid"] = False
        result["warnings"].append("Invalid certificate format")

    return result


def _validate_structured_data(data: str, data_type: SecretType) -> Dict[str, Any]:
    """Validate JSON or YAML data."""
    result = {"valid": True, "warnings": [], "suggestions": [], "strength": "unknown"}

    try:
        if data_type == SecretType.JSON:
            import json

            json.loads(data)
        elif data_type == SecretType.YAML:
            import yaml

            yaml.safe_load(data)
    except Exception as e:
        result["valid"] = False
        result["warnings"].append(f"Invalid {data_type.value} format: {str(e)}")

    # Check for potential sensitive data exposure
    sensitive_patterns = [
        r'password["\']?\s*[:=]\s*["\']?[^"\']+',
        r'secret["\']?\s*[:=]\s*["\']?[^"\']+',
        r'key["\']?\s*[:=]\s*["\']?[^"\']+',
        r'token["\']?\s*[:=]\s*["\']?[^"\']+',
    ]

    for pattern in sensitive_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            result["suggestions"].append(
                "Consider storing nested secrets separately for better security"
            )
            break

    return result


def _validate_generic_string(value: str) -> Dict[str, Any]:
    """Basic validation for generic string secrets."""
    result = {"valid": True, "warnings": [], "suggestions": [], "strength": "unknown"}

    # Basic length check
    if len(value) < 8:
        result["suggestions"].append(
            "Consider using a longer value for better security"
        )

    # Check for obvious patterns
    if value.lower() in ["test", "demo", "example", "changeme", "default"]:
        result["warnings"].append("Value appears to be a placeholder or test value")

    return result


def validate_environment_access(user: User, environment: Environment) -> bool:
    """Check if a user can access a specific environment."""
    if not user.is_active:
        return False

    if user.is_admin:
        return True

    # Production environments require special permission
    if environment.is_production and not user.is_admin:
        return False

    # Check user's preferred environment
    if environment.name == user.preferred_environment:
        return True

    # Allow access to development and staging for all users
    if environment.name in ["development", "staging"]:
        return True

    return False


def validate_user_permissions(
    user: User,
    action: str,
    resource_type: str,
    environment: Optional[Environment] = None,
) -> Dict[str, Any]:
    """Validate if a user has permission to perform an action."""
    result = {"allowed": False, "reason": None}

    if not user.is_active:
        result["reason"] = "User account is not active"
        return result

    # Admin users can do everything
    if user.is_admin:
        result["allowed"] = True
        return result

    # Environment-specific checks
    if environment:
        if not validate_environment_access(user, environment):
            result["reason"] = f"No access to {environment.name} environment"
            return result

        # Production environment restrictions
        if environment.is_production:
            restricted_actions = ["delete", "rotate"]
            if action in restricted_actions:
                result["reason"] = (
                    f"Action '{action}' not allowed in production environment"
                )
                return result

    # Resource-specific permissions
    if resource_type == "secret":
        if action in ["create", "read", "update"]:
            result["allowed"] = True
        elif action == "delete":
            result["reason"] = "Delete permission requires admin privileges"
        elif action == "rotate":
            result["allowed"] = True
    elif resource_type == "environment":
        if action == "read":
            result["allowed"] = True
        else:
            result["reason"] = "Environment management requires admin privileges"
    elif resource_type == "user":
        result["reason"] = "User management requires admin privileges"

    return result


def get_password_requirements() -> Dict[str, Any]:
    """Get password requirements for display in UI."""
    return {
        "min_length": 8,
        "recommended_length": 12,
        "require_uppercase": False,
        "require_lowercase": False,
        "require_numbers": False,
        "require_symbols": False,
        "recommended_char_types": 3,
        "forbidden_patterns": ["password", "123456", "qwerty", "admin", "letmein"],
        "strength_levels": {
            "very_weak": {"score": 1, "color": "#dc3545"},
            "weak": {"score": 2, "color": "#fd7e14"},
            "medium": {"score": 3, "color": "#ffc107"},
            "strong": {"score": 4, "color": "#28a745"},
            "very_strong": {"score": 5, "color": "#20c997"},
        },
    }
