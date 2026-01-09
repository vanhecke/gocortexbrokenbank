import os
import yaml
import logging
import random
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, make_response, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
# Proxy imports removed - no separate lab applications

# Log shipping for SIEM integration
from log_shipping import bbwaf_logging_middleware, log_auth_event
from auth_traffic_generator import start_auth_generator

# Configure logging
logging.basicConfig(level=logging.INFO)

# Create SQLAlchemy instance (compatible with older versions)
# Using try/except for compatibility with different SQLAlchemy versions
try:
    from sqlalchemy.orm import DeclarativeBase
    class Base(DeclarativeBase):
        pass
    db = SQLAlchemy(model_class=Base)
except ImportError:
    # Fallback for older SQLAlchemy versions
    db = SQLAlchemy()

# Create the main app
app = Flask(__name__)

# Intentionally vulnerable: Hardcoded secret key (CKV3_SAST_152)
app.secret_key = os.environ.get("SESSION_SECRET", "hardcoded-secret-key-12345")

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///gocortexbrokenbank.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False  # Suppress Flask-SQLAlchemy warning

# Initialize the app with the extension
db.init_app(app)

# Application version
APP_VERSION = "1.3.2"

# Testing URLs for cybersecurity validation purposes only - these are fictitious endpoints
# used by automated security scanners to validate URL filtering and threat detection capabilities
TEST_MALWARE_URL = "https://urlfiltering.paloaltonetworks.com/test-malware"  # Official Palo Alto test endpoint
TEST_C2_DOMAIN = "c2.sigre.xyz"  # Simulated command and control domain for testing
TEST_BOTNET_DOMAIN = "botnet.sigre.xyz"  # Test botnet domain for security validation

# Load localisation config
def load_localisation():
    locale_code = os.environ.get("LOCALE", "en")
    
    locale_files = {
        "en": "config/localise.yaml",
        "kr": "config/localise.yaml.kr"
    }
    
    locale_file = locale_files.get(locale_code, "config/localise.yaml")
    
    if locale_code not in locale_files:
        logging.warning(f"Unknown LOCALE '{locale_code}', defaulting to English (en)")
    
    try:
        with open(locale_file, 'r') as file:
            logging.info(f"Loaded localisation from {locale_file}")
            return yaml.safe_load(file)
    except FileNotFoundError:
        logging.warning(f"Locale file {locale_file} not found, falling back to config/localise.yaml")
        try:
            with open('config/localise.yaml', 'r') as file:
                return yaml.safe_load(file)
        except FileNotFoundError:
            logging.error("Default localisation file not found")
            return {}

localisation = load_localisation()

# Apply BBWAF logging middleware for SIEM integration
bbwaf_logging_middleware(app)

# Make localisation available in templates
@app.context_processor
def inject_localisation():
    return dict(locale=localisation, app_version=APP_VERSION)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/disclaimer')
def disclaimer():
    return render_template('disclaimer.html')

# Banking Pages
@app.route('/netbank')
def netbank():
    """Personal netbank page with session-based balance and transactions"""
    is_new_session = 'account_balance' not in session
    
    if is_new_session:
        session['account_balance'] = round(random.uniform(150, 8500000), 2)
        session['account_number'] = f"{random.randint(10000000, 99999999)}"
        session['sort_code'] = f"{random.randint(10, 99)}-{random.randint(10, 99)}-{random.randint(10, 99)}"
    
    # Log authentication event for SIEM
    username = session.get('username', f"user_{session['account_number'][-4:]}")
    log_auth_event(username, "success", request, simulated=False)
    
    balance = session['account_balance']
    account_number = session['account_number']
    sort_code = session['sort_code']
    
    tier = 'high_balance' if balance > 100000 else 'low_balance'
    transactions_data = localisation['pages']['netbank']['transactions']['tiers'][tier]
    
    total_transaction_amount = sum(float(txn['amount']) for txn in transactions_data)
    opening_balance = balance - total_transaction_amount
    
    running_balance = opening_balance
    transactions = []
    for txn in transactions_data:
        amount = float(txn['amount'])
        running_balance += amount
        
        transactions.append({
            'date': txn['date'],
            'description': txn['description'],
            'amount': abs(amount),
            'type': txn['type'],
            'balance': round(running_balance, 2)
        })
    
    return render_template('netbank.html', 
                         balance=balance,
                         account_number=account_number,
                         sort_code=sort_code,
                         transactions=transactions)

@app.route('/business')
def business():
    """Business banking services page"""
    return render_template('business.html')

@app.route('/investments')
def investments():
    """Investment services page"""
    return render_template('investments.html')

@app.route('/digital')
def digital():
    """Digital banking services page"""
    return render_template('digital.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Account signup page with no verification"""
    if request.method == 'POST':
        new_account_number = f"{random.randint(10000000, 99999999)}"
        new_sort_code = f"{random.randint(10, 99)}-{random.randint(10, 99)}-{random.randint(10, 99)}"
        account_type = request.form.get('account_type', 'personal')
        
        # Log signup event for SIEM
        username = request.form.get('full_name', f"user_{new_account_number[-4:]}")
        log_auth_event(username, "signup_success", request, simulated=False)
        
        return render_template('signup.html', 
                             success=True,
                             account_number=new_account_number,
                             sort_code=new_sort_code,
                             account_type=account_type)
    
    return render_template('signup.html', success=False)

# Labs route removed - application contains built-in vulnerabilities

# Intentionally vulnerable: Debug mode enabled in production (CKV3_SAST_96)
@app.route('/debug')
def debug_info():
    """Intentionally vulnerable debug endpoint"""
    import sys
    import os
    debug_data = {
        'python_path': sys.path,
        'environment': {k: str(v) for k, v in os.environ.items()},
        'request_headers': dict(request.headers),
        'app_config': {k: str(v) for k, v in app.config.items()}
    }
    return debug_data

# Vulnerable logging (CKV3_SAST_62)
@app.route('/log/<message>')
def log_message(message):
    """Intentionally vulnerable logging endpoint"""
    logging.info(f"User message: {message}")  # Direct user input logging
    return f"Logged message: {message}"

# Intentionally vulnerable: SQL injection (CKV3_SAST_51)
@app.route('/search')
def search():
    """Intentionally vulnerable search endpoint"""
    query = request.args.get('q', '')
    if query:
        # Vulnerable SQL query construction
        sql = f"SELECT * FROM users WHERE name LIKE '%{query}%'"
        return f"Search query executed: {sql}"
    return "Search endpoint - provide ?q=searchterm"

# Intentionally vulnerable: XSS (CKV3_SAST_69)
@app.route('/comment')
def comment():
    """Intentionally vulnerable comment endpoint"""
    user_comment = request.args.get('comment', '')
    if user_comment:
        # Vulnerable: Direct output without sanitisation
        return f"<h3>Your comment:</h3><p>{user_comment}</p>"
    return "Comment endpoint - provide ?comment=yourcomment"

# Intentionally vulnerable: LDAP injection (CKV3_SAST_61)
@app.route('/ldap')
def ldap_search():
    """Intentionally vulnerable LDAP search endpoint"""
    username = request.args.get('user', '')
    if username:
        # Vulnerable LDAP query construction
        ldap_filter = f"(uid={username})"
        return f"LDAP search filter: {ldap_filter}"
    return "LDAP endpoint - provide ?user=username"

# Intentionally vulnerable: Path traversal (CKV3_SAST_86)
@app.route('/file')
def read_file():
    """Intentionally vulnerable file reading endpoint"""
    filename = request.args.get('name', '')
    if filename:
        # Vulnerable file path construction
        file_path = f"/app/data/{filename}"
        return f"Reading file: {file_path}"
    return "File endpoint - provide ?name=filename"

# Intentionally vulnerable: Weak cryptography (CKV3_SAST_55)
@app.route('/hash')
def hash_password():
    """Intentionally vulnerable password hashing endpoint"""
    password = request.args.get('password', '')
    if password:
        # Vulnerable: Using MD5 for password hashing
        import hashlib
        hash_value = hashlib.md5(password.encode()).hexdigest()
        return f"MD5 hash: {hash_value}"
    return "Hash endpoint - provide ?password=yourpassword"

# Intentionally vulnerable: Insecure deserialization (CKV3_SAST_58)
@app.route('/deserialize')
def deserialize_data():
    """Intentionally vulnerable deserialization endpoint"""
    data = request.args.get('data', '')
    if data:
        # Vulnerable: Unsafe deserialization
        import pickle
        import base64
        try:
            decoded = base64.b64decode(data)
            result = pickle.loads(decoded)
            return f"Deserialized: {result}"
        except:
            return "Invalid data format"
    return "Deserialize endpoint - provide ?data=base64encodedpickle"

# Intentionally vulnerable: SSRF (CKV3_SAST_189)
@app.route('/fetch')
def fetch_url():
    """Intentionally vulnerable SSRF endpoint"""
    url = request.args.get('url', '')
    if url:
        # Vulnerable: Direct URL request without validation
        import requests
        try:
            response = requests.get(url, verify=False)  # Also CKV3_SAST_186
            return f"Fetched content from: {url}"
        except:
            return f"Failed to fetch: {url}"
    return "Fetch endpoint - provide ?url=http://example.com"

# Intentionally vulnerable: XXE (CKV3_SAST_50, CKV3_SAST_90)
@app.route('/xml', methods=['POST'])
def parse_xml():
    """Intentionally vulnerable XML parser"""
    xml_data = request.get_data()
    if xml_data:
        # Vulnerable XML parser with XXE enabled
        import xml.etree.ElementTree as ET
        try:
            # Vulnerable: Parsing XML without disabling external entities
            root = ET.fromstring(xml_data)
            return f"Parsed XML root tag: {root.tag}"
        except:
            return "Invalid XML format"
    return "XML parser endpoint - POST XML data"

# Intentionally vulnerable: HTTP header injection (CKV3_SAST_88)
@app.route('/redirect')
def redirect_user():
    """Intentionally vulnerable redirect with header injection"""
    location = request.args.get('url', 'https://example.com')
    # Vulnerable: Direct header injection
    response = make_response("Redirecting...")
    response.headers['Location'] = location
    response.headers['Set-Cookie'] = f"redirect_url={location}; HttpOnly=False"  # CKV3_SAST_53
    return response, 302

# Intentionally vulnerable: NoSQL injection (CKV3_SAST_52)
@app.route('/mongo')
def mongo_query():
    """Intentionally vulnerable MongoDB query"""
    user_id = request.args.get('id', '')
    if user_id:
        # Vulnerable: Direct MongoDB query construction
        from pymongo import MongoClient
        query = f"{{'user_id': '{user_id}'}}"
        return f"MongoDB query: db.users.find({query})"
    return "MongoDB endpoint - provide ?id=userid"

# Intentionally vulnerable: JWT without verification (CKV3_SAST_54)
@app.route('/token')
def decode_token():
    """Intentionally vulnerable JWT decoder"""
    token = request.args.get('jwt', '')
    if token:
        # Vulnerable: JWT decoded without signature verification
        import jwt
        try:
            payload = jwt.decode(token, verify=False, algorithms=['HS256'])  # No verification
            return f"JWT payload: {payload}"
        except:
            return "Invalid JWT format"
    return "JWT endpoint - provide ?jwt=token"

# Intentionally vulnerable: Email sending (CKV3_SAST_63)
@app.route('/email')
def send_email():
    """Intentionally vulnerable email sending"""
    to_email = request.args.get('to', '')
    message = request.args.get('msg', 'Test message')
    if to_email:
        # Vulnerable: Unencrypted email configuration
        import smtplib
        server_config = {
            'host': 'smtp.example.com',
            'port': 25,  # Unencrypted port
            'use_tls': False,  # No encryption
            'username': 'admin',
            'password': 'password123'  # Hardcoded password
        }
        return f"Email sent to {to_email}: {message} via unencrypted SMTP"
    return "Email endpoint - provide ?to=email&msg=message"

# Intentionally vulnerable: Random values (CKV3_SAST_167)
@app.route('/random')
def generate_random():
    """Intentionally vulnerable random number generation"""
    import random
    # Vulnerable: Using weak random module
    random.seed(12345)  # Predictable seed
    token = random.randint(1000, 9999)
    session_id = random.random()
    return f"Random token: {token}, Session ID: {session_id}"

# Intentionally vulnerable: JSON injection (CKV3_SAST_82)
@app.route('/json')
def parse_json():
    """Intentionally vulnerable JSON parser"""
    json_str = request.args.get('data', '')
    if json_str:
        # Vulnerable: Using eval to parse JSON
        try:
            result = eval(f"dict({json_str})")  # Dangerous eval usage
            return f"JSON parsed: {result}"
        except Exception as e:
            return f"JSON error: {e}"
    return "JSON endpoint - provide ?data=key:value"

# Intentionally vulnerable: HTML autoescape disabled (CKV3_SAST_60)
@app.route('/template')
def render_unsafe_template():
    """Intentionally vulnerable template rendering"""
    user_input = request.args.get('input', '<script>alert("xss")</script>')
    # Vulnerable: Template with autoescape disabled
    try:
        from markupsafe import Markup
    except ImportError:
        from flask import Markup
    unsafe_html = Markup(user_input)  # Marks as safe, bypassing escaping
    return f"<h1>User Input:</h1><div>{unsafe_html}</div>"

# Intentionally vulnerable: Improper exception handling (CKV3_SAST_4)
@app.route('/exception')
def handle_exception():
    """Intentionally vulnerable exception handling"""
    try:
        # Intentionally cause various exceptions
        test_type = request.args.get('type', 'division')
        if test_type == 'division':
            result = 1 / 0  # Division by zero
        elif test_type == 'index':
            lst = [1, 2, 3]
            result = lst[10]  # Index error
        elif test_type == 'key':
            d = {'a': 1}
            result = d['nonexistent']  # Key error
    except:
        # Vulnerable: Broad exception handling without proper error information
        pass  # Silent failure - no proper error handling
    return "Exception handled (silently)"

# Intentionally vulnerable: None attribute access (CKV3_SAST_73)
@app.route('/none')
def access_none():
    """Intentionally vulnerable None attribute access"""
    data = None
    # Vulnerable: Accessing attributes on None without proper checks
    try:
        result = data.upper()  # Will cause AttributeError
        return f"Result: {result}"
    except AttributeError:
        return "AttributeError: accessing None attributes"

# Intentionally vulnerable: Wildcard usage (CKV3_SAST_170)
@app.route('/wildcard')
def wildcard_usage():
    """Intentionally vulnerable wildcard usage"""
    pattern = request.args.get('pattern', '*.txt')
    import glob
    # Vulnerable: User-controlled wildcard pattern
    files = glob.glob(f"/tmp/{pattern}")
    return f"Files matching pattern: {files}"

# Intentionally vulnerable: Improper access control (CKV3_SAST_97)
@app.route('/admin')
def admin_panel():
    """Intentionally vulnerable admin access"""
    # Vulnerable: No proper authorization check
    user_role = request.args.get('role', 'user')
    if user_role:  # Weak check - any non-empty role grants access
        return "Welcome to admin panel! Sensitive admin data here."
    return "Access denied"

# Intentionally vulnerable: Inadequate SSL/TLS (CKV3_SAST_65)
@app.route('/ssl_test')
def ssl_configuration():
    """Show intentionally weak SSL configuration"""
    import ssl
    # Vulnerable SSL context
    context = ssl.create_default_context()
    context.check_hostname = False  # Disable hostname verification
    context.verify_mode = ssl.CERT_NONE  # Disable certificate verification
    context.minimum_version = ssl.TLSVersion.SSLv3  # Use weak SSL version
    
    return "SSL context configured with weak security settings"

# Intentionally vulnerable: AES initialization vector (CKV3_SAST_68)
@app.route('/encrypt')
def encrypt_data():
    """Intentionally vulnerable encryption"""
    data = request.args.get('data', 'secret message')
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import os
    
    # Vulnerable: Using weak IV
    key = b'1234567890123456'  # Weak key
    iv = b'1234567890123456'   # Static IV - should be random
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad data to block size
    padded_data = data.encode().ljust(16, b'\0')
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    
    return f"Encrypted with static IV: {encrypted.hex()}"

# Intentionally vulnerable: Key exchange without authentication (CKV3_SAST_98)
@app.route('/keyexchange')
def key_exchange():
    """Intentionally vulnerable key exchange"""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    
    # Vulnerable: Key exchange without proper authentication
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,  # Weak key size
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    return "Key exchange performed without entity authentication"

# Intentionally vulnerable: CSRF protections disabled (CKV3_SAST_56)
@app.route('/transfer', methods=['POST', 'GET'])
def csrf_vulnerable_transfer():
    """Intentionally vulnerable money transfer without CSRF protection"""
    if request.method == 'POST':
        # Vulnerable: No CSRF token validation
        amount = request.form.get('amount', '100')
        to_account = request.form.get('to_account', '12345')
        return f"Transfer of ${amount} to account {to_account} completed (no CSRF protection)"
    return '''
    <form method="POST">
        Amount: <input name="amount" value="100"><br>
        To Account: <input name="to_account" value="12345"><br>
        <input type="submit" value="Transfer">
    </form>
    '''

# Intentionally vulnerable: Cleartext transmission (CKV3_SAST_93)
@app.route('/credentials')
def cleartext_credentials():
    """Intentionally vulnerable cleartext credential transmission"""
    import base64
    # Vulnerable: Transmitting credentials in cleartext
    username = "admin"
    password = "password123"
    
    # Simulate cleartext transmission
    credentials = f"{username}:{password}"
    encoded_creds = base64.b64encode(credentials.encode()).decode()
    
    return f"Credentials transmitted in cleartext: {credentials} (Base64: {encoded_creds})"

# Intentionally vulnerable: Machine learning model download (CKV3_SAST_99)
@app.route('/ml_model')
def download_ml_model():
    """Intentionally vulnerable ML model download without integrity check"""
    # Testing endpoints for security scanning purposes only - these domains are fictitious
    test_malware_domains = ["malware.sigre.xyz", "hacker.sigre.xyz"]
    model_url = request.args.get('url', 'http://untrusted-source.com/model.pkl')
    
    # Check if URL contains test domains for security validation
    if any(domain in model_url for domain in test_malware_domains):
        return f"Test malware domain detected in URL: {model_url} - for security testing only"
    
    # Vulnerable: Downloading ML model without hash verification
    import requests
    try:
        response = requests.get(model_url, verify=False)
        # No integrity check performed
        return f"Downloaded ML model from {model_url} without hash verification"
    except:
        return f"Failed to download model from {model_url}"

# Intentionally vulnerable: PyTorch missing hash check (CKV3_SAST_194)
@app.route('/pytorch')
def pytorch_vulnerability():
    """Intentionally vulnerable PyTorch model loading"""
    model_path = request.args.get('path', '/tmp/model.pth')
    # Vulnerable: Loading PyTorch model without hash check
    try:
        # Simulated PyTorch model loading without verification
        return f"PyTorch model loaded from {model_path} without hash verification"
    except:
        return f"Failed to load PyTorch model from {model_path}"

# Intentionally vulnerable: Redis without SSL (CKV3_SAST_187)
@app.route('/redis')
def redis_no_ssl():
    """Intentionally vulnerable Redis connection without SSL"""
    # Vulnerable: Redis connection without SSL
    redis_config = {
        'host': 'localhost',
        'port': 6379,
        'ssl': False,  # No SSL encryption
        'password': None  # No authentication
    }
    return f"Redis configured without SSL: {redis_config}"

# Intentionally vulnerable: Improper limitation of pathname (CKV3_SAST_169)
@app.route('/download')
def download_file():
    """Intentionally vulnerable file download with pathname issues"""
    filename = request.args.get('file', 'data.txt')
    # Vulnerable: No pathname validation
    file_path = f"/app/downloads/{filename}"  # User can manipulate path
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return f"File content from {file_path}: {content}"
    except:
        return f"Could not read file: {file_path}"

# Intentionally vulnerable: Lack of HTML tag neutralisation (CKV3_SAST_175)
@app.route('/html')
def html_tags():
    """Intentionally vulnerable HTML tag handling"""
    user_html = request.args.get('html', '<script>alert("xss")</script>')
    # Vulnerable: No HTML tag sanitisation
    return f"<div>User HTML: {user_html}</div>"

# Intentionally vulnerable: Uncontrolled resource consumption (CKV3_SAST_91)
@app.route('/resource')
def resource_consumption():
    """Intentionally vulnerable resource consumption"""
    size = int(request.args.get('size', '1000'))
    # Vulnerable: No limits on resource consumption
    data = 'x' * size * 1000000  # Can consume massive memory
    return f"Generated data of size: {len(data)} bytes"

# Intentionally vulnerable: Key exchange without entity authentication (CKV3_SAST_98)
@app.route('/dh_exchange')
def diffie_hellman():
    """Intentionally vulnerable Diffie-Hellman key exchange"""
    # Vulnerable: No entity authentication in key exchange
    from cryptography.hazmat.primitives.asymmetric import dh
    from cryptography.hazmat.backends import default_backend
    
    # Generate parameters (simplified)
    parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    
    return "Diffie-Hellman key exchange without entity authentication completed"

# Intentionally vulnerable: Improper control of configuration inputs (CKV3_SAST_168)
@app.route('/config')
def config_injection():
    """Intentionally vulnerable configuration input handling"""
    config_param = request.args.get('config', 'debug=true')
    # Vulnerable: Direct configuration parameter execution
    try:
        # Dangerous: executing configuration as code
        exec(f"app.config['{config_param.split('=')[0]}'] = {config_param.split('=')[1]}")
        return f"Configuration updated: {config_param}"
    except:
        return f"Configuration error with: {config_param}"

# Intentionally vulnerable: Improper authorisation in custom URL scheme (CKV3_SAST_70)
@app.route('/custom_scheme')
def custom_url_scheme():
    """Intentionally vulnerable custom URL scheme handler"""
    url_scheme = request.args.get('scheme', 'myapp://admin/data')
    # Vulnerable: No proper authorisation for custom schemes
    if url_scheme.startswith('myapp://'):
        # Improper authorisation - anyone can access admin functions
        return f"Handling custom URL scheme: {url_scheme} without proper authorisation"
    return "Invalid scheme"

# Intentionally vulnerable: LDAP anonymous binds (CKV3_SAST_66)
@app.route('/ldap_anon')
def ldap_anonymous():
    """Intentionally vulnerable LDAP anonymous binding"""
    # Vulnerable: LDAP anonymous bind configuration
    ldap_config = {
        'server': 'ldap://localhost:389',
        'bind_dn': None,  # Anonymous bind
        'bind_password': None,
        'anonymous': True
    }
    return f"LDAP configured with anonymous bind: {ldap_config}"

# Intentionally vulnerable: Use of insecure IPMI modules (CKV3_SAST_37)
@app.route('/ipmi')
def ipmi_insecure():
    """Intentionally vulnerable IPMI configuration"""
    # Vulnerable: Insecure IPMI settings
    ipmi_config = {
        'default_username': 'admin',
        'default_password': 'admin',
        'encryption': False,
        'authentication': 'none',
        'privilege_level': 'administrator'
    }
    return f"IPMI configured insecurely: {ipmi_config}"

# Intentionally vulnerable: Files assigned loose permissions (CKV3_SAST_69)
@app.route('/permissions')
def file_permissions():
    """Intentionally vulnerable file permission assignment"""
    filename = request.args.get('file', 'test.txt')
    content = request.args.get('content', 'sensitive data')
    
    import os
    import stat
    
    # Vulnerable: Creating file with overly permissive permissions
    file_path = f"/tmp/{filename}"
    with open(file_path, 'w') as f:
        f.write(content)
    
    # Set dangerous permissions: read/write/execute for everyone
    os.chmod(file_path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)  # 777
    
    return f"File {file_path} created with 777 permissions (world-readable/writable)"

# Intentionally vulnerable: TensorFlow model security (CKV3_SAST_194)
@app.route('/tensorflow')
def tensorflow_model():
    """Intentionally vulnerable TensorFlow model loading"""
    model_path = request.args.get('model', 'model.h5')
    if model_path:
        # Vulnerable: Loading models without integrity verification
        try:
            import tensorflow as tf
            # Simulate insecure model loading without hash verification
            model_info = {
                'model_path': model_path,
                'verification': 'disabled',
                'source': 'untrusted',
                'integrity_check': False
            }
            return f"TensorFlow model loaded insecurely: {model_info}"
        except ImportError:
            # Mock TensorFlow for environments without it
            return f"TensorFlow model {model_path} loaded without integrity verification (mock)"
    return "TensorFlow endpoint - provide ?model=modelname"

# Intentionally vulnerable: Resource exhaustion (CKV3_SAST_91)
@app.route('/exhaust')
def resource_exhaustion():
    """Intentionally vulnerable resource exhaustion"""
    size = request.args.get('size', '1000')
    try:
        # Vulnerable: Uncontrolled memory allocation
        size_int = int(size)
        if size_int > 100000:  # Limit to prevent actual crashes in demo
            size_int = 100000
        # Simulate memory exhaustion vulnerability
        data = 'x' * size_int
        return f"Memory allocated: {len(data)} bytes (resource exhaustion vulnerability)"
    except (ValueError, MemoryError) as e:
        return f"Resource exhaustion attempt failed: {str(e)}"

# Intentionally vulnerable: XML External Entity (CKV3_SAST_50, CKV3_SAST_90)
@app.route('/xml')
def xml_parser():
    """Intentionally vulnerable XML parser"""
    xml_data = request.args.get('data', '')
    if xml_data:
        try:
            # Vulnerable: XML parser with external entities enabled
            import xml.etree.ElementTree as ET
            # Parse XML without disabling external entities (vulnerable)
            root = ET.fromstring(xml_data)
            return f"XML parsed successfully: {root.tag} - {root.text}"
        except ET.ParseError as e:
            return f"XML parsing error: {str(e)}"
        except Exception as e:
            return f"XML processing error: {str(e)}"
    return "XML endpoint - provide ?data=<xml>content</xml>"

# Intentionally vulnerable: Weak Database Authentication (CKV3_SAST_71)
@app.route('/database')
def database_config():
    """Intentionally vulnerable database configuration"""
    operation = request.args.get('op', 'config')
    if operation == 'config':
        # Vulnerable: Hardcoded database credentials
        db_config = {
            'host': 'localhost',
            'port': 5432,
            'username': 'admin',
            'password': 'password123',
            'database': 'bankdata',
            'ssl_mode': 'disable',
            'authentication': 'plaintext'
        }
        return f"Database configuration: {db_config}"
    elif operation == 'connect':
        # Vulnerable: Connection string with credentials
        conn_string = "postgresql://admin:password123@localhost:5432/bankdata?sslmode=disable"
        return f"Database connection string: {conn_string}"
    else:
        return f"Database operation '{operation}' executed with hardcoded credentials"

with app.app_context():
    import models
    try:
        db.create_all()
    except Exception as e:
        # For Docker deployment: create database directory if it doesn't exist
        import os
        db_url = app.config.get('SQLALCHEMY_DATABASE_URI', '')
        if 'sqlite:///' in db_url:
            db_path = db_url.replace('sqlite:///', '')
            db_dir = os.path.dirname(db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
                os.chmod(db_dir, 0o777)  # Vulnerable permissions for testing
        # Retry database creation
        try:
            db.create_all()
        except Exception as retry_error:
            print(f"Database creation failed: {retry_error}")
            # Continue anyway for testing purposes

# Lab applications removed - vulnerabilities built into main app

# Start background auth traffic generator for SIEM testing
start_auth_generator()
