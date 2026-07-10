from flask import Flask, jsonify, request, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import secrets
import requests
import re
import json
import logging
import os
from functools import wraps
from dotenv import load_dotenv
from bs4 import BeautifulSoup

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///sep_x.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_SORT_KEYS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

db = SQLAlchemy(app)
CORS(app, supports_credentials=True)

# ============ LOGGING ============
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============ MODELS ============

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    tokens = db.relationship('DeepSeekToken', backref='user', lazy=True, cascade='all, delete-orphan')
    api_keys = db.relationship('APIKey', backref='user', lazy=True, cascade='all, delete-orphan')

class DeepSeekToken(db.Model):
    __tablename__ = 'deepseek_tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    access_token = db.Column(db.Text)
    refresh_token = db.Column(db.Text)
    cookies = db.Column(db.JSON)
    local_storage = db.Column(db.JSON)
    
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_valid = db.Column(db.Boolean, default=True)
    
    def get_auth_headers(self):
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Origin': 'https://chat.deepseek.com',
            'Referer': 'https://chat.deepseek.com/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        if self.access_token:
            headers['Authorization'] = f'Bearer {self.access_token}'
        if self.cookies:
            cookie_str = '; '.join([f'{k}={v}' for k, v in self.cookies.items()])
            headers['Cookie'] = cookie_str
        return headers

class APIKey(db.Model):
    __tablename__ = 'api_keys'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    key = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(100))
    description = db.Column(db.Text)
    
    rate_limit = db.Column(db.Integer, default=30)
    requests_count = db.Column(db.Integer, default=0)
    last_reset = db.Column(db.DateTime, default=datetime.utcnow)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    logs = db.relationship('APILog', backref='api_key', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'key': self.key[:8] + '...' + self.key[-4:],
            'key_full': self.key,
            'name': self.name,
            'description': self.description,
            'rate_limit': self.rate_limit,
            'requests_count': self.requests_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_active': self.is_active
        }

class APILog(db.Model):
    __tablename__ = 'api_logs'
    id = db.Column(db.Integer, primary_key=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey('api_keys.id'))
    
    endpoint = db.Column(db.String(100))
    method = db.Column(db.String(10))
    status_code = db.Column(db.Integer)
    response_time = db.Column(db.Float)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ============ CREATE TABLES ============
with app.app_context():
    db.create_all()
    logger.info("Database tables created")

# ============ API KEY AUTH DECORATOR ============

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key required. Provide X-API-Key header'}), 401
        
        key = APIKey.query.filter_by(key=api_key, is_active=True).first()
        if not key:
            return jsonify({'error': 'Invalid or inactive API key'}), 401
        
        if key.expires_at and key.expires_at < datetime.utcnow():
            return jsonify({'error': 'API key expired'}), 401
        
        # Rate limiting
        if key.last_reset.date() < datetime.utcnow().date():
            key.requests_count = 0
            key.last_reset = datetime.utcnow()
            db.session.commit()
        
        if key.requests_count >= key.rate_limit:
            return jsonify({'error': f'Rate limit exceeded ({key.rate_limit}/hour)'}), 429
        
        key.requests_count += 1
        db.session.commit()
        
        request.api_key = key
        return f(*args, **kwargs)
    return decorated

# ============ ROUTES ============

@app.route('/')
def index():
    """Serve the dashboard HTML directly"""
    try:
        with open('dashboard.html', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return jsonify({
            'service': 'SEP X - DeepSeek API Gateway',
            'status': 'running',
            'message': 'dashboard.html not found, but API is working',
            'endpoints': {
                'POST /api/login': 'Login to DeepSeek (email/password)',
                'GET /auth/google': 'Google Sign-In',
                'GET /api/token/status': 'Check token status',
                'POST /api/keys': 'Generate API key',
                'GET /api/keys': 'List API keys',
                'DELETE /api/keys/<id>': 'Revoke API key',
                'POST /api/keys/<id>/regenerate': 'Regenerate API key',
                'POST /v1/chat/completions': 'Chat with DeepSeek (requires X-API-Key)',
                'POST /v1/chat/completions/stream': 'Stream chat (requires X-API-Key)',
                'GET /api/logs': 'View API logs'
            }
        }), 200

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'database': 'connected'
    })

@app.route('/api/login', methods=['POST'])
def login_to_deepseek():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        user_id = data.get('user_id', 'default')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        session = requests.Session()
        
        # Get CSRF token
        initial = session.get('https://chat.deepseek.com')
        csrf_token = extract_csrf(initial.text)
        
        if not csrf_token:
            logger.warning("Could not extract CSRF token, proceeding without it")
        
        # Login
        login_payload = {'email': email, 'password': password}
        if csrf_token:
            login_payload['csrf_token'] = csrf_token
        
        login_response = session.post(
            'https://chat.deepseek.com/api/v0/auth/login',
            json=login_payload,
            headers={'Content-Type': 'application/json'}
        )
        
        if login_response.status_code != 200:
            return jsonify({
                'error': 'Login failed',
                'details': login_response.text,
                'status_code': login_response.status_code
            }), 401
        
        login_data = login_response.json()
        
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            user = User(user_id=user_id, email=email)
            db.session.add(user)
            db.session.commit()
        
        token = DeepSeekToken(
            user_id=user.id,
            access_token=login_data.get('access_token'),
            refresh_token=login_data.get('refresh_token'),
            cookies=session.cookies.get_dict(),
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_valid=True
        )
        
        DeepSeekToken.query.filter_by(user_id=user.id).delete()
        db.session.add(token)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Token extracted and stored',
            'expires_at': token.expires_at.isoformat()
        }), 200
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error during login: {str(e)}")
        return jsonify({'error': f'Network error: {str(e)}'}), 500
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/token/status', methods=['GET'])
def token_status():
    user_id = request.args.get('user_id', 'default')
    user = User.query.filter_by(user_id=user_id).first()
    
    if not user:
        return jsonify({'token_exists': False, 'message': 'User not found'}), 200
    
    token = DeepSeekToken.query.filter_by(user_id=user.id, is_valid=True).first()
    if not token:
        return jsonify({'token_exists': False}), 200
    
    now = datetime.utcnow()
    days_left = (token.expires_at - now).total_seconds() / (24 * 3600) if token.expires_at else 0
    
    return jsonify({
        'token_exists': True,
        'is_valid': token.is_valid,
        'expires_at': token.expires_at.isoformat() if token.expires_at else None,
        'expires_in_days': max(0, days_left),
        'extracted_at': token.created_at.isoformat()
    }), 200

# ============ API KEY MANAGEMENT ============

@app.route('/api/keys', methods=['POST'])
def create_api_key():
    try:
        data = request.get_json()
        user_id = data.get('user_id', 'default')
        name = data.get('name', 'My API Key')
        description = data.get('description', '')
        rate_limit = data.get('rate_limit', 30)
        expires_days = data.get('expires_days', 30)
        
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found. Login to DeepSeek first.'}), 404
        
        key = secrets.token_urlsafe(32)
        
        api_key = APIKey(
            user_id=user.id,
            key=key,
            name=name,
            description=description,
            rate_limit=rate_limit,
            expires_at=datetime.utcnow() + timedelta(days=expires_days),
            is_active=True
        )
        
        db.session.add(api_key)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'api_key': api_key.to_dict(),
            'key_full': key
        }), 201
        
    except Exception as e:
        logger.error(f"Create API key error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/keys', methods=['GET'])
def list_api_keys():
    user_id = request.args.get('user_id', 'default')
    user = User.query.filter_by(user_id=user_id).first()
    
    if not user:
        return jsonify([]), 200
    
    keys = APIKey.query.filter_by(user_id=user.id).all()
    return jsonify([k.to_dict() for k in keys]), 200

@app.route('/api/keys/<int:key_id>', methods=['DELETE'])
def revoke_api_key(key_id):
    api_key = APIKey.query.get(key_id)
    if not api_key:
        return jsonify({'error': 'API key not found'}), 404
    
    api_key.is_active = False
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'API key revoked'}), 200

@app.route('/api/keys/<int:key_id>/regenerate', methods=['POST'])
def regenerate_api_key(key_id):
    api_key = APIKey.query.get(key_id)
    if not api_key:
        return jsonify({'error': 'API key not found'}), 404
    
    new_key = secrets.token_urlsafe(32)
    api_key.key = new_key
    api_key.created_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'success': True,
        'new_key': new_key,
        'message': 'API key regenerated'
    }), 200

# ============ CHAT PROXY ============

@app.route('/v1/chat/completions', methods=['POST'])
@require_api_key
def proxy_chat():
    try:
        data = request.get_json()
        
        user = User.query.get(request.api_key.user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        token = DeepSeekToken.query.filter_by(user_id=user.id, is_valid=True).first()
        if not token:
            return jsonify({'error': 'No valid DeepSeek token. Please login first.'}), 401
        
        start_time = datetime.utcnow()
        
        response = requests.post(
            'https://chat.deepseek.com/api/v0/chat/completion',
            json=data,
            headers=token.get_auth_headers(),
            timeout=60
        )
        
        response_time = (datetime.utcnow() - start_time).total_seconds()
        
        log = APILog(
            api_key_id=request.api_key.id,
            endpoint='/v1/chat/completions',
            method='POST',
            status_code=response.status_code,
            response_time=response_time,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify(response.json()), response.status_code
        
    except requests.exceptions.Timeout:
        return jsonify({'error': 'DeepSeek API timeout'}), 504
    except Exception as e:
        logger.error(f"Proxy error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/v1/chat/completions/stream', methods=['POST'])
@require_api_key
def proxy_chat_stream():
    try:
        data = request.get_json()
        
        user = User.query.get(request.api_key.user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        token = DeepSeekToken.query.filter_by(user_id=user.id, is_valid=True).first()
        if not token:
            return jsonify({'error': 'No valid DeepSeek token'}), 401
        
        data['stream'] = True
        
        response = requests.post(
            'https://chat.deepseek.com/api/v0/chat/completion',
            json=data,
            headers=token.get_auth_headers(),
            stream=True,
            timeout=60
        )
        
        def generate():
            for line in response.iter_lines():
                if line:
                    yield line.decode('utf-8') + '\n'
        
        return app.response_class(generate(), mimetype='text/event-stream')
        
    except Exception as e:
        logger.error(f"Stream error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============ LOGS ============

@app.route('/api/logs', methods=['GET'])
def get_logs():
    user_id = request.args.get('user_id', 'default')
    limit = int(request.args.get('limit', 50))
    
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify([]), 200
    
    logs = APILog.query.join(APIKey).filter(
        APIKey.user_id == user.id
    ).order_by(
        APILog.created_at.desc()
    ).limit(limit).all()
    
    return jsonify([{
        'timestamp': log.created_at.isoformat(),
        'endpoint': log.endpoint,
        'method': log.method,
        'status_code': log.status_code,
        'response_time': log.response_time,
        'ip': log.ip_address,
        'api_key': log.api_key.key[:8] if log.api_key else None
    } for log in logs]), 200

# ============ GOOGLE OAUTH ROUTES ============

@app.route('/auth/google', methods=['GET'])
def google_auth():
    """Initiate Google OAuth flow"""
    user_id = request.args.get('user_id', 'default')
    session['oauth_user_id'] = user_id
    
    return render_google_auth_page(user_id)

def render_google_auth_page(user_id):
    """Render the Google auth redirect page"""
    google_auth_url = 'https://chat.deepseek.com/auth/google'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sign in with Google</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: #0b0b1a;
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
                margin: 0;
                padding: 20px;
            }}
            .container {{
                text-align: center;
                max-width: 400px;
            }}
            .spinner {{
                width: 48px;
                height: 48px;
                border: 4px solid rgba(255,255,255,0.05);
                border-top-color: #667eea;
                border-radius: 50%;
                animation: spin 0.8s linear infinite;
                margin: 0 auto 20px;
            }}
            @keyframes spin {{
                to {{ transform: rotate(360deg); }}
            }}
            h3 {{
                color: #eaeef2;
                font-weight: 500;
                font-size: 18px;
                margin: 0 0 8px;
            }}
            p {{
                color: #6b7280;
                font-size: 14px;
                margin: 0;
            }}
            .btn {{
                margin-top: 20px;
                padding: 10px 24px;
                border: none;
                border-radius: 10px;
                background: linear-gradient(135deg, #667eea, #764ba2);
                color: white;
                font-weight: 600;
                font-size: 14px;
                cursor: pointer;
                font-family: inherit;
            }}
            .btn:hover {{
                transform: translateY(-1px);
                box-shadow: 0 8px 24px rgba(102, 126, 234, 0.3);
            }}
            .error {{
                color: #f87171;
                margin-top: 12px;
                font-size: 14px;
                display: none;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="spinner"></div>
            <h3>Redirecting to Google</h3>
            <p>You'll be asked to sign in to your Google account</p>
            <div id="errorMsg" class="error"></div>
            <button class="btn" onclick="redirectToGoogle()">Continue</button>
        </div>

        <script>
            const user_id = '{user_id}';
            
            function redirectToGoogle() {{
                window.location.href = '{google_auth_url}?user_id=' + user_id;
            }}

            setTimeout(redirectToGoogle, 1500);
            
            window.onerror = function(msg, url, line, col, error) {{
                document.getElementById('errorMsg').style.display = 'block';
                document.getElementById('errorMsg').textContent = 'Error: ' + msg;
            }};
        </script>
    </body>
    </html>
    '''

@app.route('/auth/google/callback', methods=['GET', 'POST'])
def google_callback():
    """Handle Google OAuth callback from DeepSeek"""
    try:
        code = request.args.get('code') or request.form.get('code')
        error = request.args.get('error') or request.form.get('error')
        
        if error:
            logger.error(f"Google auth error: {error}")
            return render_error_page(f'Google auth error: {error}')
        
        if not code:
            logger.error("No authorization code received")
            return render_error_page('No authorization code received')
        
        # Exchange code for tokens
        exchange_response = requests.post(
            'https://chat.deepseek.com/api/v0/auth/google/callback',
            json={'code': code},
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        if exchange_response.status_code != 200:
            logger.error(f"Token exchange failed: {exchange_response.text}")
            return render_error_page(f'Token exchange failed: {exchange_response.text}')
        
        token_data = exchange_response.json()
        
        # Get user_id from session
        user_id = session.get('oauth_user_id', 'default')
        
        # Store tokens
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            user = User(
                user_id=user_id, 
                email=token_data.get('email', ''),
                created_at=datetime.utcnow()
            )
            db.session.add(user)
            db.session.commit()
        
        token = DeepSeekToken(
            user_id=user.id,
            access_token=token_data.get('access_token'),
            refresh_token=token_data.get('refresh_token'),
            cookies=token_data.get('cookies', {}),
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_valid=True
        )
        
        DeepSeekToken.query.filter_by(user_id=user.id).delete()
        db.session.add(token)
        db.session.commit()
        
        logger.info(f"Google auth successful for user {user_id}")
        return render_success_page(user_id)
        
    except requests.exceptions.Timeout:
        logger.error("Google token exchange timeout")
        return render_error_page('Request timeout')
    except Exception as e:
        logger.error(f"Google callback error: {str(e)}")
        return render_error_page(str(e))

def render_success_page(user_id):
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Authentication Successful</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: #0b0b1a;
                color: #eaeef2;
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
                margin: 0;
                padding: 20px;
                text-align: center;
            }}
            .success {{ color: #34d399; }}
            .sub {{ color: #6b7280; margin-top: 8px; }}
            .btn {{
                margin-top: 20px;
                padding: 10px 24px;
                border: none;
                border-radius: 10px;
                background: linear-gradient(135deg, #667eea, #764ba2);
                color: white;
                font-weight: 600;
                font-size: 14px;
                cursor: pointer;
                font-family: inherit;
            }}
            .btn:hover {{
                transform: translateY(-1px);
                box-shadow: 0 8px 24px rgba(102, 126, 234, 0.3);
            }}
        </style>
    </head>
    <body>
        <div>
            <h1 class="success">✅ Authentication Successful!</h1>
            <p class="sub">You can close this window and return to the dashboard.</p>
            <button class="btn" onclick="sendSuccess()">Return to Dashboard</button>
        </div>

        <script>
            function sendSuccess() {{
                if (window.opener) {{
                    window.opener.postMessage({{
                        type: 'google_auth_callback',
                        success: true,
                        user_id: '{user_id}',
                        message: 'Google authentication successful'
                    }}, '*');
                }}
                window.close();
            }}

            if (window.opener) {{
                setTimeout(sendSuccess, 2000);
            }} else {{
                document.body.innerHTML += '<p style="color:#fbbf24;margin-top:12px;">⚠️ No parent window found. Please close this window manually.</p>';
            }}
        </script>
    </body>
    </html>
    '''

def render_error_page(error_message):
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Authentication Error</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: #0b0b1a;
                color: #eaeef2;
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
                margin: 0;
                padding: 20px;
                text-align: center;
            }}
            .error {{ color: #f87171; }}
            .sub {{ color: #6b7280; margin-top: 8px; }}
            .btn {{
                margin-top: 20px;
                padding: 10px 24px;
                border: none;
                border-radius: 10px;
                background: #2a2a4a;
                color: white;
                font-weight: 600;
                font-size: 14px;
                cursor: pointer;
                font-family: inherit;
            }}
            .btn:hover {{
                background: #3a3a5a;
            }}
            .details {{
                background: #1a1a2e;
                padding: 12px;
                border-radius: 8px;
                margin: 12px 0;
                font-size: 13px;
                color: #9ca3af;
                word-break: break-all;
                max-width: 500px;
                margin-left: auto;
                margin-right: auto;
            }}
        </style>
    </head>
    <body>
        <div>
            <h1 class="error">❌ Authentication Error</h1>
            <p class="sub">Something went wrong during authentication</p>
            <div class="details">{error_message}</div>
            <button class="btn" onclick="window.close()">Close Window</button>
        </div>
    </body>
    </html>
    '''

# ============ HELPER FUNCTIONS ============

def extract_csrf(html):
    """Extract CSRF token from HTML using html.parser"""
    if not html:
        return None
    
    # Try BeautifulSoup first
    try:
        soup = BeautifulSoup(html, 'html.parser')
        
        # Check meta tags
        meta = soup.find('meta', {'name': 'csrf-token'})
        if meta and meta.get('content'):
            return meta.get('content')
        
        meta = soup.find('meta', {'name': 'csrf_token'})
        if meta and meta.get('content'):
            return meta.get('content')
    except Exception as e:
        logger.warning(f"BeautifulSoup parsing error: {e}")
    
    # Fallback: regex patterns
    patterns = [
        r'csrf_token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'X-CSRF-Token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'window\.csrfToken\s*=\s*["\']([^"\']+)["\']',
        r'csrfToken\s*=\s*["\']([^"\']+)["\']',
        r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']',
        r'name=["\']_csrf["\']\s+value=["\']([^"\']+)["\']'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
