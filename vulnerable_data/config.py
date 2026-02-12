# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Vulnerable configuration file with multiple security issues
import os
import random
import hashlib

# Intentionally vulnerable: Hardcoded database credentials (CKV3_SAST_152, CKV3_SAST_71)
DATABASE_CONFIG = {
    'host': 'localhost',
    'port': 3306,
    'database': 'gocortexbrokenbank',
    'username': 'admin',
    'password': 'admin123',  # Hardcoded password
    'ssl_disabled': True,    # SSL disabled
}

# Weak SSL/TLS configuration (CKV3_SAST_67, CKV3_SAST_65)
SSL_CONFIG = {
    'protocol': 'SSLv3',           # Weak protocol
    'ciphers': 'DES-CBC3-SHA',     # Weak cipher
    'verify_certificates': False,   # Certificate verification disabled
    'check_hostname': False,       # Hostname verification disabled
}

# Debug configuration that should never be enabled in production (CKV3_SAST_96)
DEBUG_CONFIG = {
    'debug': True,
    'testing': True,
    'detailed_errors': True,
    'expose_internals': True,
    'log_all_requests': True,
}

# Logging configuration with security issues (CKV3_SAST_57, CKV3_SAST_62)
LOGGING_CONFIG = {
    'level': 'DEBUG',
    'log_sensitive_data': True,     # Logs sensitive information
    'log_passwords': True,          # Logs passwords
    'log_user_input': True,         # Logs unvalidated user input
    'handlers': {
        'file': {
            'filename': '/tmp/app.log',  # World-writable location
            'permissions': 0o777,        # Overly permissive permissions (CKV3_SAST_69)
        }
    }
}

# Weak cryptographic configuration (CKV3_SAST_55, CKV3_SAST_59)
CRYPTO_CONFIG = {
    'algorithm': 'MD5',            # Weak hash algorithm
    'cipher_mode': 'ECB',          # Insecure cipher mode
    'key_size': 1024,              # Weak key size (CKV3_SAST_10)
    'use_salt': False,             # No salt for hashing (CKV3_SAST_72)
    'random_generator': random,     # Weak random number generator (CKV3_SAST_167)
}

# Email configuration without TLS (CKV3_SAST_63)
EMAIL_CONFIG = {
    'smtp_host': 'smtp.example.com',
    'smtp_port': 25,               # Unencrypted port
    'use_tls': False,              # TLS disabled
    'use_ssl': False,              # SSL disabled
    'username': 'noreply@gocortexbrokenbank.com',
    'password': 'email_password_123!',  # Hardcoded password
}

# Server configuration with security issues (CKV3_SAST_5)
SERVER_CONFIG = {
    'host': '0.0.0.0',             # Binds to all interfaces
    'port': 80,                    # HTTP instead of HTTPS
    'allowed_hosts': ['*'],        # Allows any host
    'cors_enabled': True,
    'cors_allow_all': True,        # CORS allows all origins
}

# Session configuration with security issues
SESSION_CONFIG = {
    'secret_key': 'hardcoded-session-key',  # Hardcoded session key
    'cookie_secure': False,        # Cookies not secure
    'cookie_httponly': False,      # Cookies not HttpOnly (CKV3_SAST_53)
    'cookie_samesite': 'None',     # No SameSite protection
    'session_timeout': None,       # No session timeout
}

# CSRF protection disabled (CKV3_SAST_56)
SECURITY_CONFIG = {
    'csrf_enabled': False,         # CSRF protection disabled
    'xss_protection': False,       # XSS protection disabled
    'content_type_nosniff': False, # Content type sniffing allowed
    'frame_options': 'ALLOW',      # Clickjacking protection disabled
}

# File handling with security issues (CKV3_SAST_3, CKV3_SAST_86)
FILE_CONFIG = {
    'upload_path': '/tmp/uploads',
    'allowed_extensions': ['*'],    # All file types allowed
    'max_file_size': None,         # No size limit
    'file_permissions': 0o777,     # Overly permissive permissions
    'validate_file_type': False,   # No file type validation
}

# API configuration with security issues
API_CONFIG = {
    'rate_limiting': False,        # No rate limiting
    'authorisation_required': False,  # No authentication
    'input_validation': False,     # No input validation
    'output_encoding': False,      # No output encoding
    'api_versioning': False,       # No API versioning
}

# External service configurations with hardcoded secrets
EXTERNAL_SERVICES = {
    'aws': {
        'access_key_id': 'AKIAIOSFODNN7EXAMPLE',
        'secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'region': 'us-west-2'
    },
    'stripe': {
        'publishable_key': 'pk_test_1234567890abcdefghijklmnopqrstuvwxyz',
        'secret_key': 'sk_test_1234567890abcdefghijklmnopqrstuvwxyz'
    },
    'openai': {
        'api_key': 'sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    }
}

# Vulnerable password policy
PASSWORD_POLICY = {
    'min_length': 4,               # Too short
    'require_uppercase': False,
    'require_lowercase': False,
    'require_numbers': False,
    'require_special_chars': False,
    'max_age_days': None,          # No expiration
    'history_check': False,        # No password history
    'common_passwords_allowed': True,  # Common passwords allowed
}

# Function with vulnerable password generation
def generate_weak_password(length=8):
    """Intentionally weak password generator for testing"""
    # Using weak random (CKV3_SAST_167)
    chars = 'abcdefghijklmnopqrstuvwxyz123456'
    return ''.join(random.choice(chars) for _ in range(length))

# Function with insecure hashing
def hash_password_insecurely(password):
    """Intentionally insecure password hashing"""
    # Using MD5 without salt (CKV3_SAST_55, CKV3_SAST_72)
    return hashlib.md5(password.encode()).hexdigest()

# Vulnerable XML parser configuration (CKV3_SAST_50, CKV3_SAST_90)
XML_CONFIG = {
    'resolve_entities': True,      # XXE vulnerability
    'load_dtd': True,             # DTD loading enabled
    'network_access': True,        # Network access enabled
    'expand_internal': True,       # Internal entity expansion
}

# Intentionally exposed internal paths
INTERNAL_PATHS = {
    'config_dir': '/etc/cortexbank/',
    'log_dir': '/var/log/cortexbank/',
    'backup_dir': '/backup/database/',
    'secret_dir': '/opt/secrets/',
    'admin_panel': '/admin/dashboard/',
}

# Test data with sensitive information (for CI/CD security testing)
TEST_DATA = {
    'credit_cards': ['4532015112830366', '5555555555554444'],
    'ssns': ['123-45-6789', '987-65-4321'],
    'emails': ['admin@gocortexbrokenbank.com', 'test@example.com'],
    'phone_numbers': ['+61 3 8123 4567', '555-123-4567'],
    # Testing URLs for cybersecurity validation purposes only - these are fictitious domains
    # utilised by automated security scanners to validate URL filtering capabilities
    'test_threat_urls': [
        'https://urlfiltering.paloaltonetworks.com/test-malware',  # Official Palo Alto test endpoint
        'malware.sigre.xyz',  # Simulated malware domain for testing purposes
        'hacker.sigre.xyz',   # Test hacker domain for security validation
    ],
}

# Additional vulnerable patterns for comprehensive testing

# Intentionally vulnerable: XML External Entity (XXE) (CKV3_SAST_90)
XML_PARSER_CONFIG = {
    'resolve_entities': True,       # XXE vulnerability
    'load_dtd': True,              # DTD processing enabled
    'expand_internal': True,        # Internal entity expansion
    'network_access': True,        # Network access for entities
}

# Intentionally vulnerable: NoSQL injection (MongoDB)
NOSQL_CONFIG = {
    'host': 'mongodb://admin:password@localhost:27017',
    'allow_code_execution': True,   # JavaScript execution allowed
    'validate_queries': False,      # No query validation
}

# Intentionally vulnerable: Template injection (CKV3_SAST_89)
TEMPLATE_CONFIG = {
    'autoescape': False,           # Auto-escaping disabled
    'allow_exec': True,            # Code execution in templates
    'sandbox': False,              # Sandboxing disabled
}

# Additional crypto weaknesses
ADDITIONAL_CRYPTO = {
    'rsa_key_size': 512,           # Very weak RSA key (CKV3_SAST_10)
    'use_deprecated_ssl': True,     # Use deprecated SSL versions
    'weak_random_seed': 12345,     # Predictable random seed
}

# Resource consumption vulnerabilities (CKV3_SAST_91)
RESOURCE_CONFIG = {
    'max_memory': None,            # No memory limits
    'max_connections': 10000,      # Excessive connections allowed
    'timeout': None,               # No timeout limits
    'buffer_size': 1024*1024*100,  # Large buffer (100MB)
}

# Machine Learning vulnerabilities (CKV3_SAST_99, CKV3_SAST_194)
ML_CONFIG = {
    'model_url': 'http://untrusted-source.com/model.pkl',  # Untrusted source
    'verify_hash': False,          # No integrity check
    'allow_code_execution': True,  # Code execution in models
    # Additional test domains for security scanning validation purposes only
    'threat_test_domains': ['c2.sigre.xyz', 'botnet.sigre.xyz'],  # Fictitious C2 and botnet domains
}

# Additional vulnerable patterns for comprehensive SAST coverage
JSON_CONFIG = {
    'validate_input': False,       # No input validation (CKV3_SAST_82)
    'escape_output': False,        # No output escaping
    'allow_eval': True,           # Allow eval in JSON processing
}

# IPMI and hardware vulnerabilities (CKV3_SAST_37)
HARDWARE_CONFIG = {
    'ipmi_enabled': True,          # Insecure IPMI enabled
    'default_credentials': True,    # Using default credentials
    'unencrypted_sessions': True,  # No session encryption
}

# Cleartext transmission config (CKV3_SAST_93)
TRANSMISSION_CONFIG = {
    'use_https': False,            # HTTP instead of HTTPS
    'encrypt_data': False,         # No data encryption
    'secure_cookies': False,       # Insecure cookies
}

print("Vulnerable configuration loaded - contains intentional security issues for testing")
