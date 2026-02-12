# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Intentionally vulnerable secrets file for CI/CD security testing
# This file contains various hardcoded credentials and API keys for automated security validation

# AWS Credentials (CKV_SECRET_2)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_DEFAULT_REGION = "us-west-2"

# OpenAI API Key (CKV_SECRET_107)
OPENAI_API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
OPENAI_ORG_ID = "org-1234567890abcdefghijklmnop"

# GitHub Token (CKV_SECRET_43)
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDEF"
GITHUB_PERSONAL_ACCESS_TOKEN = "github_pat_11ABCDEFGH_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Stripe Keys (CKV_SECRET_17)
STRIPE_PUBLISHABLE_KEY = "pk_test_1234567890abcdefghijklmnopqrstuvwxyz"
STRIPE_SECRET_KEY = "sk_test_1234567890abcdefghijklmnopqrstuvwxyz"
STRIPE_WEBHOOK_SECRET = "whsec_1234567890abcdefghijklmnopqrstuvwxyz"

# Slack Token (CKV_SECRET_14)
SLACK_BOT_TOKEN = "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx"
SLACK_USER_TOKEN = "xoxp-1234567890-1234567890-1234567890-abcdefghijklmnopqrstuvwxyzabcdef"

# Private Key (CKV_SECRET_13)
PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
wXK7SwjCADm9EKCRT1HJP9o8pxFfRWgFO1KJlDBTU+OJJXejNhvY3EXAMPLE
KEY CONTENT HERE - THIS IS INTENTIONALLY VULNERABLE
-----END PRIVATE KEY-----"""

# Google Cloud Keys (CKV_SECRET_45)
GOOGLE_API_KEY = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLan_Zt2YtBSoY"
GOOGLE_CLIENT_ID = "1234567890-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "GOCSPX-1234567890abcdefghijklmnop"

# Azure Storage Account Keys (CKV_SECRET_3)
AZURE_STORAGE_ACCOUNT = "cortexbankstorage"
AZURE_STORAGE_KEY = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890+/EXAMPLE=="

# DigitalOcean Token (CKV_SECRET_34)
DIGITALOCEAN_TOKEN = "dop_v1_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Anthropic API Key (CKV_SECRET_109)
ANTHROPIC_API_KEY = "sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-ABCDEF"

# Hugging Face Token (CKV_SECRET_110)
HUGGINGFACE_TOKEN = "hf_1234567890abcdefghijklmnopqrstuvwxyzABCDEF"

# Database Credentials
DATABASE_PASSWORD = "super_secret_password_123!"
MYSQL_ROOT_PASSWORD = "root123"
POSTGRES_PASSWORD = "postgres_secret_2023"

# Additional secrets for comprehensive coverage

# Airtable API Key (CKV_SECRET_21)
AIRTABLE_API_KEY = "keyABCDEFGHIJKLMN12345"

# Algolia Key (CKV_SECRET_22)
ALGOLIA_API_KEY = "abc123def456ghi789jklmnopqrstuvwxyz"

# Asana Key (CKV_SECRET_24)
ASANA_ACCESS_TOKEN = "1/1234567890:abcdefghijklmnopqrstuvwxyz"

# Auth0 Keys (CKV_SECRET_26)
AUTH0_CLIENT_ID = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
AUTH0_CLIENT_SECRET = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"

# Bitbucket Keys (CKV_SECRET_27)
BITBUCKET_APP_PASSWORD = "ATBB1234567890abcdefghijklmnop"

# CircleCI Token (CKV_SECRET_29)
CIRCLECI_TOKEN = "ccipat_1234567890abcdefghijklmnopqrstuvwxyzABCDEF"

# Cloudflare API (CKV_SECRET_73)
CLOUDFLARE_API_KEY = "1234567890abcdef1234567890abcdef12345678"

# Discord Token (CKV_SECRET_35)
DISCORD_BOT_TOKEN = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA.ABCDEF.1234567890abcdefghijklmnopqrstuvwxyz"

# Docker Swarm Token (CKV_SECRET_89)
DOCKER_SWARM_TOKEN = "SWMTKN-1-1234567890abcdefghijklmnopqrstuvwxyz-abcdefghijklmnopqrstuvwxyz1234567890"

# Elastic Email (CKV_SECRET_40)
ELASTIC_EMAIL_API_KEY = "1234567890ABCDEF1234567890ABCDEF12345678"

# Frame IO Token (CKV_SECRET_105)
FRAMEIO_TOKEN = "fio-1234567890abcdefghijklmnopqrstuvwxyz"

# HubSpot API (CKV_SECRET_49)
HUBSPOT_API_KEY = "1234567890abcdef-1234-5678-9012-abcdefghijkl"

# Intercom Token (CKV_SECRET_50)
INTERCOM_ACCESS_TOKEN = "dG9rOjEyMzQ1Njc4OTA6QUJDREVGRw=="

# Terraform Cloud (CKV_SECRET_47)
TERRAFORM_CLOUD_TOKEN = "1234567890abcdefghijklmnopqrstuvwxyz.atlasv1.ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz"

# Square Keys (CKV_SECRET_101, CKV_SECRET_102)
SQUARE_ACCESS_TOKEN = "EAAAEMzHT1234567890abcdefghijklmnopqrstuvwxyz"
SQUARE_APPLICATION_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"

# Additional high-entropy strings for detection
BASE64_SECRET = "VGhpcyBpcyBhIHNlY3JldCBrZXkgZm9yIHRlc3Rpbmcgb25seSAtIGRvIG5vdCB1c2UgaW4gcHJvZHVjdGlvbiEhIQ=="  # CKV_SECRET_6
HEX_SECRET = "deadbeef1234567890abcdef1234567890abcdef"  # CKV_SECRET_19

# IBM Cloud credentials (CKV_SECRET_7, CKV_SECRET_8)
IBM_CLOUD_API_KEY = "1234567890abcdefghijklmnopqrstuvwxyz-_ABCDEFGHIJKLMNOP"
IBM_COS_HMAC_ACCESS_KEY = "1234567890abcdef1234567890abcdef12345678"
IBM_COS_HMAC_SECRET_KEY = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH"

# JSON Web Token (CKV_SECRET_9)
JWT_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Cloudant Credentials (CKV_SECRET_5)
CLOUDANT_USERNAME = "1234567890abcdef-1234-5678-9012-abcdefghijkl-bluemix"
CLOUDANT_PASSWORD = "1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz"

# Artifactory (CKV_SECRET_1)
ARTIFACTORY_API_KEY = "AKCp1234567890abcdefghijklmnopqrstuvwxyz1234567890"

# Basic Auth (CKV_SECRET_4)
BASIC_AUTH_CREDENTIALS = "admin:password123"

print("Additional secrets loaded for comprehensive vulnerability detection")

# JWT Secret
JWT_SECRET = "your-super-secret-jwt-key-that-should-never-be-hardcoded"

# API Keys for various services
MAILGUN_API_KEY = "key-1234567890abcdefghijklmnopqrstuvwx"
TWILIO_ACCOUNT_SID = "AC1234567890abcdefghijklmnopqrstuvwx"
TWILIO_AUTH_TOKEN = "1234567890abcdefghijklmnopqrstuvwx"

# Base64 encoded secrets (CKV_SECRET_6)
BASE64_SECRET = "dGhpc19pc19hX3NlY3JldF9rZXlfaW5fYmFzZTY0"  # "this_is_a_secret_key_in_base64"

# Connection strings with embedded credentials
MONGODB_CONNECTION = "mongodb://admin:secret123@localhost:27017/cortexbank"
REDIS_URL = "redis://:supersecret@localhost:6379/0"

# Credit card test data (for testing purposes)
TEST_CREDIT_CARD = "4532015112830366"  # Test Visa number
TEST_CVV = "123"

# Social Security Numbers (test data)
TEST_SSN = "123-45-6789"
TEST_SSN_2 = "987-65-4321"

# Additional secrets that might be found in real applications
ENCRYPTION_KEY = "1234567890abcdef1234567890abcdef"  # 32-byte hex key
HMAC_SECRET = "hmac_signing_secret_key_2023"
SESSION_SECRET = "flask_session_secret_key_never_use_in_production"

# Testing URLs for cybersecurity validation purposes only - these are fictitious endpoints
# employed by automated security scanners to validate threat detection and URL filtering
TEST_THREAT_ENDPOINTS = {
    'malware_test': 'https://urlfiltering.paloaltonetworks.com/test-malware',  # Official test URL
    'simulated_c2': 'c2.sigre.xyz',      # Command and control test domain
    'botnet_test': 'botnet.sigre.xyz',   # Botnet simulation domain
    'malware_domain': 'malware.sigre.xyz',  # Malware test domain
    'hacker_domain': 'hacker.sigre.xyz',    # Hacker simulation domain
}

# Email configuration with password
SMTP_PASSWORD = "email_password_123!"
EMAIL_HOST_USER = "noreply@cortexbank.com"
EMAIL_HOST_PASSWORD = "smtp_secret_password"

# Third-party service keys
PAYPAL_CLIENT_ID = "AeA1QIZXOaXgCi3btgsxZadxbx2eZNFz1HSgNyOJzq_4a_k-8EXAMPLE"
PAYPAL_CLIENT_SECRET = "EGnHDxD_qRPdaLdHqTlr8k_4a_k-8EXAMPLE"

# Webhook secrets
GITHUB_WEBHOOK_SECRET = "webhook_secret_for_github_integration"
STRIPE_WEBHOOK_SECRET = "whsec_webhook_secret_for_stripe_events"

print("This file contains intentionally vulnerable secrets for CI/CD security testing.")
print("These credentials are fake and should never be used in production.")
