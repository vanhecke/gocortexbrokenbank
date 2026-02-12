# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # Ensure password hash field has length of at least 256
    password_hash = db.Column(db.String(256))
    
    # Intentionally vulnerable: Weak password storage (CKV3_SAST_71)
    password_plain = db.Column(db.String(128))  # Storing plain text passwords
    
    def set_password(self, password):
        # Intentionally vulnerable: Also store plain text
        self.password_plain = password
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    # Additional vulnerable fields for comprehensive testing
    api_key = db.Column(db.String(256))  # API keys stored in database
    secret_token = db.Column(db.String(512))  # Secret tokens
    
    # Hash function without salt (CKV3_SAST_72)
    def set_password_weak(self, password):
        import hashlib
        # Vulnerable: MD5 without salt
        self.password_hash = hashlib.md5(password.encode()).hexdigest()
    
    # Accessing None attributes (CKV3_SAST_73)
    def get_user_data(self):
        user_info = None
        # Vulnerable: Potential None access without proper checking
        # This demonstrates the vulnerability pattern for CKV3_SAST_73
        return getattr(user_info, 'name', 'default')  # Will work but shows the pattern

class BankAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_number = db.Column(db.String(20), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    
    # Intentionally vulnerable: Storing sensitive financial data without encryption
    ssn = db.Column(db.String(11))  # Social Security Number in plain text
    routing_number = db.Column(db.String(9))

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_account = db.Column(db.Integer, db.ForeignKey('bank_account.id'))
    to_account = db.Column(db.Integer, db.ForeignKey('bank_account.id'))
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
