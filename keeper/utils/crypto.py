"""Cryptographically secure secret generation utilities."""

import base64
import secrets
import string
from dataclasses import dataclass
from typing import Dict, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa


@dataclass
class PasswordConfig:
    """Configuration for password generation."""

    length: int = 32
    include_uppercase: bool = True
    include_lowercase: bool = True
    include_numbers: bool = True
    include_symbols: bool = True
    exclude_ambiguous: bool = True
    custom_symbols: Optional[str] = None

    def __post_init__(self):
        """Validate configuration."""
        if self.length < 8:
            raise ValueError("Password length must be at least 8 characters")
        if self.length > 512:
            raise ValueError("Password length cannot exceed 512 characters")
        if not any(
            [
                self.include_uppercase,
                self.include_lowercase,
                self.include_numbers,
                self.include_symbols,
            ]
        ):
            raise ValueError("At least one character type must be included")


@dataclass
class KeyConfig:
    """Configuration for key generation."""

    key_type: str = "rsa"  # rsa, ed25519
    key_size: int = 4096  # for RSA keys
    format: str = "pem"  # pem, openssh
    include_public: bool = True

    def __post_init__(self):
        """Validate configuration."""
        if self.key_type not in ["rsa", "ed25519"]:
            raise ValueError("Key type must be 'rsa' or 'ed25519'")
        if self.key_type == "rsa" and self.key_size not in [2048, 3072, 4096]:
            raise ValueError("RSA key size must be 2048, 3072, or 4096")
        if self.format not in ["pem", "openssh"]:
            raise ValueError("Format must be 'pem' or 'openssh'")


class SecretGenerator:
    """Main class for generating cryptographically secure secrets."""

    @staticmethod
    def generate_password(config: Optional[PasswordConfig] = None) -> str:
        """Generate a cryptographically secure password."""
        if config is None:
            config = PasswordConfig()

        # Build character set
        chars = ""

        if config.include_lowercase:
            chars += string.ascii_lowercase

        if config.include_uppercase:
            chars += string.ascii_uppercase

        if config.include_numbers:
            chars += string.digits

        if config.include_symbols:
            if config.custom_symbols:
                chars += config.custom_symbols
            else:
                symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
                if config.exclude_ambiguous:
                    # Remove ambiguous characters
                    symbols = (
                        symbols.replace("0", "")
                        .replace("O", "")
                        .replace("l", "")
                        .replace("1", "")
                    )
                chars += symbols

        if config.exclude_ambiguous:
            # Remove ambiguous characters from all sets
            ambiguous = "0O1l"
            for char in ambiguous:
                chars = chars.replace(char, "")

        if not chars:
            raise ValueError("No valid characters available for password generation")

        # Generate password with guaranteed character type inclusion
        password = []

        # Ensure at least one character from each enabled type
        if config.include_lowercase:
            password.append(secrets.choice(string.ascii_lowercase))
        if config.include_uppercase:
            password.append(secrets.choice(string.ascii_uppercase))
        if config.include_numbers:
            password.append(secrets.choice(string.digits))
        if config.include_symbols:
            symbols = config.custom_symbols or "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if config.exclude_ambiguous:
                symbols = (
                    symbols.replace("0", "")
                    .replace("O", "")
                    .replace("l", "")
                    .replace("1", "")
                )
            password.append(secrets.choice(symbols))

        # Fill remaining length with random characters from full set
        for _ in range(config.length - len(password)):
            password.append(secrets.choice(chars))

        # Shuffle the password to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)

        return "".join(password)

    @staticmethod
    def generate_api_key(length: int = 64, prefix: Optional[str] = None) -> str:
        """Generate a cryptographically secure API key."""
        if length < 32:
            raise ValueError("API key length must be at least 32 characters")
        if length > 256:
            raise ValueError("API key length cannot exceed 256 characters")

        # Use URL-safe base64 alphabet for API keys
        alphabet = string.ascii_letters + string.digits + "-_"
        key = "".join(secrets.choice(alphabet) for _ in range(length))

        if prefix:
            return f"{prefix}_{key}"
        return key

    @staticmethod
    def generate_hex_key(length: int = 32) -> str:
        """Generate a cryptographically secure hex key."""
        if length < 16:
            raise ValueError("Hex key length must be at least 16 characters")
        if length > 128:
            raise ValueError("Hex key length cannot exceed 128 characters")

        return secrets.token_hex(length // 2)

    @staticmethod
    def generate_base64_secret(byte_length: int = 32) -> str:
        """Generate a cryptographically secure base64-encoded secret."""
        if byte_length < 16:
            raise ValueError("Byte length must be at least 16")
        if byte_length > 256:
            raise ValueError("Byte length cannot exceed 256")

        return base64.urlsafe_b64encode(secrets.token_bytes(byte_length)).decode(
            "utf-8"
        )

    @staticmethod
    def generate_ssh_key(config: Optional[KeyConfig] = None) -> Dict[str, str]:
        """Generate an SSH key pair."""
        if config is None:
            config = KeyConfig(key_type="ed25519", format="openssh")

        if config.key_type == "rsa":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=config.key_size,
                backend=default_backend(),
            )
        elif config.key_type == "ed25519":
            private_key = ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError(f"Unsupported key type: {config.key_type}")

        # Get public key
        public_key = private_key.public_key()

        # Serialize private key
        if config.format == "pem":
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")

            result = {"private_key": private_pem}
            if config.include_public:
                result["public_key"] = public_pem

        elif config.format == "openssh":
            private_openssh = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

            public_openssh = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            ).decode("utf-8")

            result = {"private_key": private_openssh}
            if config.include_public:
                result["public_key"] = public_openssh

        return result

    @staticmethod
    def generate_rsa_key(config: Optional[KeyConfig] = None) -> Dict[str, str]:
        """Generate an RSA key pair."""
        if config is None:
            config = KeyConfig(key_type="rsa", key_size=4096)

        config.key_type = "rsa"  # Force RSA
        return SecretGenerator.generate_ssh_key(config)

    @staticmethod
    def generate_certificate_key() -> Dict[str, str]:
        """Generate a key pair suitable for certificates."""
        config = KeyConfig(key_type="rsa", key_size=4096, format="pem")
        return SecretGenerator.generate_rsa_key(config)

    @classmethod
    def generate_secret_by_type(cls, secret_type: str, **kwargs) -> str:
        """Generate a secret based on type with optional parameters."""
        generators = {
            "password": cls._generate_password_with_params,
            "api_key": cls._generate_api_key_with_params,
            "hex_key": cls._generate_hex_key_with_params,
            "base64_secret": cls._generate_base64_with_params,
            "ssh_key": cls._generate_ssh_key_with_params,
            "rsa_key": cls._generate_rsa_key_with_params,
            "certificate": cls._generate_certificate_with_params,
        }

        generator = generators.get(secret_type)
        if not generator:
            raise ValueError(f"Unsupported secret type: {secret_type}")

        return generator(**kwargs)

    @classmethod
    def _generate_password_with_params(cls, length: int = 32, **kwargs) -> str:
        """Generate password with parameters."""
        config = PasswordConfig(length=length, **kwargs)
        return cls.generate_password(config)

    @classmethod
    def _generate_api_key_with_params(
        cls, length: int = 64, prefix: Optional[str] = None, **kwargs
    ) -> str:
        """Generate API key with parameters."""
        return cls.generate_api_key(length=length, prefix=prefix)

    @classmethod
    def _generate_hex_key_with_params(cls, length: int = 32, **kwargs) -> str:
        """Generate hex key with parameters."""
        return cls.generate_hex_key(length=length)

    @classmethod
    def _generate_base64_with_params(cls, byte_length: int = 32, **kwargs) -> str:
        """Generate base64 secret with parameters."""
        return cls.generate_base64_secret(byte_length=byte_length)

    @classmethod
    def _generate_ssh_key_with_params(
        cls, key_type: str = "ed25519", key_size: int = 4096, **kwargs
    ) -> str:
        """Generate SSH key with parameters."""
        config = KeyConfig(key_type=key_type, key_size=key_size, format="openssh")
        result = cls.generate_ssh_key(config)
        # Return private key as primary value
        return result["private_key"]

    @classmethod
    def _generate_rsa_key_with_params(cls, key_size: int = 4096, **kwargs) -> str:
        """Generate RSA key with parameters."""
        config = KeyConfig(key_type="rsa", key_size=key_size, format="pem")
        result = cls.generate_rsa_key(config)
        return result["private_key"]

    @classmethod
    def _generate_certificate_with_params(cls, **kwargs) -> str:
        """Generate certificate key with parameters."""
        result = cls.generate_certificate_key()
        return result["private_key"]


# Convenience functions for common use cases
def generate_password(length: int = 32, **kwargs) -> str:
    """Generate a secure password."""
    config = PasswordConfig(length=length, **kwargs)
    return SecretGenerator.generate_password(config)


def generate_api_key(length: int = 64, prefix: Optional[str] = None) -> str:
    """Generate a secure API key."""
    return SecretGenerator.generate_api_key(length=length, prefix=prefix)


def generate_ssh_key(key_type: str = "ed25519", key_size: int = 4096) -> Dict[str, str]:
    """Generate an SSH key pair."""
    config = KeyConfig(key_type=key_type, key_size=key_size, format="openssh")
    return SecretGenerator.generate_ssh_key(config)


def generate_rsa_key(key_size: int = 4096) -> Dict[str, str]:
    """Generate an RSA key pair."""
    config = KeyConfig(key_type="rsa", key_size=key_size, format="pem")
    return SecretGenerator.generate_rsa_key(config)
