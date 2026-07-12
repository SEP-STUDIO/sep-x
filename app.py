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
    sync_history = db.relationship('SyncHistory', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_active': self.is_active
        }

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
    source = db.Column(db.String(50), default='extension')
    
    def get_auth_headers(self):
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Origin': 'https://chat.deepseek.com',
            'Referer': 'https://chat.deepseek.com/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Use the stored access_token
        if self.access_token:
            headers['Authorization'] = f'Bearer {self.access_token}'
            logger.info(f"Using Authorization header with token: {self.access_token[:20]}...")
        
        # Also add cookies if available
        if self.cookies:
            cookie_str = ''
            if isinstance(self.cookies, list):
                for cookie in self.cookies:
                    if isinstance(cookie, dict):
                        cookie_str += f"{cookie.get('name', '')}={cookie.get('value', '')}; "
            elif isinstance(self.cookies, dict):
                cookie_str = '; '.join([f'{k}={v}' for k, v in self.cookies.items()])
            if cookie_str:
                headers['Cookie'] = cookie_str.rstrip('; ')
                logger.info("Added cookies to headers")
        
        return headers
    
    def to_dict(self):
        return {
            'id': self.id,
            'access_token': self.access_token[:20] + '...' if self.access_token else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_valid': self.is_valid,
            'source': self.source
        }

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

class SyncHistory(db.Model):
    __tablename__ = 'sync_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    sync_type = db.Column(db.String(50))
    source = db.Column(db.String(100))
    status = db.Column(db.String(20))
    error_message = db.Column(db.Text)
    token_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'sync_type': self.sync_type,
            'source': self.source,
            'status': self.status,
            'error_message': self.error_message,
            'token_count': self.token_count,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

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
    try:
        with open('dashboard.html', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return jsonify({
            'service': 'SEP X - DeepSeek API Gateway',
            'status': 'running',
            'version': '2.0.0',
            'message': 'Dashboard not found',
            'endpoints': {
                'POST /api/tokens/sync': 'Sync tokens from Chrome Extension',
                'GET /api/token/status': 'Check token status',
                'POST /api/tokens/clear': 'Clear tokens',
                'GET /api/sync/history': 'Get sync history',
                'POST /api/user/create': 'Create user',
                'POST /api/keys': 'Generate API key',
                'GET /api/keys': 'List API keys',
                'DELETE /api/keys/<id>': 'Revoke API key',
                'POST /api/keys/<id>/regenerate': 'Regenerate API key',
                'POST /v1/chat/completions': 'Chat with DeepSeek (requires X-API-Key)',
                'POST /v1/chat/completions/stream': 'Stream chat (requires X-API-Key)',
                'GET /api/logs': 'View API logs',
                'GET /api/debug/token': 'Debug token (temporary)'
            }
        }), 200

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'database': 'connected',
        'version': '2.0.0'
    })

# ============ USER CREATION ============

@app.route('/api/user/create', methods=['POST'])
def create_user():
    try:
        data = request.get_json()
        user_id = data.get('user_id', 'default')
        
        user = User.query.filter_by(user_id=user_id).first()
        if user:
            return jsonify({
                'success': True,
                'message': f'User {user_id} already exists',
                'user': user.to_dict()
            }), 200
        
        user = User(
            user_id=user_id,
            email=f"{user_id}@sync.local",
            created_at=datetime.utcnow()
        )
        db.session.add(user)
        db.session.commit()
        
        logger.info(f"User created manually: {user_id}")
        
        return jsonify({
            'success': True,
            'message': f'User {user_id} created successfully',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        logger.error(f"Create user error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============ TOKEN SYNC ============

@app.route('/api/tokens/sync', methods=['POST'])
def sync_tokens():
    try:
        data = request.get_json()
        user_id = data.get('user_id', 'default')
        token_data = data.get('tokens', {})
        cookies = data.get('cookies', {})
        source = data.get('source', 'unknown')
        
        logger.info(f"Token sync request from {source} for user {user_id}")
        logger.info(f"Token data keys: {list(token_data.keys())}")
        logger.info(f"Cookies type: {type(cookies)}")
        
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            user = User(
                user_id=user_id,
                email=f"{user_id}@sync.local",
                created_at=datetime.utcnow()
            )
            db.session.add(user)
            db.session.commit()
            logger.info(f"Created new user: {user_id}")
        
        access_token = None
        
        # ============ IMPROVED TOKEN EXTRACTION ============
        
        # Method 1: Check token_data directly
        if token_data.get('access_token'):
            access_token = token_data.get('access_token')
            logger.info("Found token in token_data")
        
        # Method 2: Extract from cookies list
        if not access_token and cookies:
            if isinstance(cookies, list):
                for cookie in cookies:
                    if isinstance(cookie, dict):
                        name = cookie.get('name', '')
                        value = cookie.get('value', '')
                        # Look for any token-like cookie
                        if name == 'ds_session_id' or 'token' in name.lower() or 'auth' in name.lower():
                            if len(value) > 10:
                                access_token = value
                                logger.info(f"Found token in cookie: {name}")
                                break
            elif isinstance(cookies, dict):
                for cookie_name in ['ds_session_id', 'access_token', 'token', 'auth_token', 'session', 'sid']:
                    if cookie_name in cookies:
                        access_token = cookies[cookie_name]
                        logger.info(f"Found token in cookie dict: {cookie_name}")
                        break
        
        # Method 3: Try to get from localStorage via token_data
        if not access_token and token_data.get('localStorage'):
            local_data = token_data.get('localStorage', {})
            if isinstance(local_data, dict):
                for key in ['access_token', 'token', 'auth_token', 'session']:
                    if key in local_data:
                        access_token = local_data[key]
                        logger.info(f"Found token in localStorage: {key}")
                        break
        
        # Method 4: Try to get from token_data's cookies field
        if not access_token and token_data.get('cookies'):
            tcookies = token_data.get('cookies')
            if isinstance(tcookies, dict):
                for cookie_name in ['ds_session_id', 'access_token', 'token', 'auth_token']:
                    if cookie_name in tcookies:
                        access_token = tcookies[cookie_name]
                        logger.info(f"Found token in token_data.cookies: {cookie_name}")
                        break
        
        if not access_token:
            logger.warning(f"No access token found for user {user_id}")
            
            sync_log = SyncHistory(
                user_id=user.id,
                sync_type='manual',
                source=source,
                status='failed',
                error_message='No access token found',
                token_count=0
            )
            db.session.add(sync_log)
            db.session.commit()
            
            return jsonify({
                'success': False,
                'error': 'No access token found. Please ensure you are logged into DeepSeek and refresh the page.'
            }), 400
        
        # Delete old tokens and store new one
        DeepSeekToken.query.filter_by(user_id=user.id).delete()
        
        token = DeepSeekToken(
            user_id=user.id,
            access_token=access_token,
            refresh_token=token_data.get('refresh_token'),
            cookies=cookies,
            local_storage=token_data.get('localStorage', {}),
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_valid=True,
            source=source
        )
        
        db.session.add(token)
        db.session.commit()
        
        # Verify token was saved
        saved_token = DeepSeekToken.query.filter_by(user_id=user.id, is_valid=True).first()
        if saved_token:
            logger.info(f"Token verified in database for user {user_id}")
            logger.info(f"Token preview: {saved_token.access_token[:20]}...")
        else:
            logger.error(f"Token NOT saved in database for user {user_id}")
        
        sync_log = SyncHistory(
            user_id=user.id,
            sync_type='manual',
            source=source,
            status='success',
            token_count=1
        )
        db.session.add(sync_log)
        db.session.commit()
        
        logger.info(f"Tokens synced successfully for user {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'Tokens synced successfully',
            'expires_at': token.expires_at.isoformat(),
            'user_id': user_id,
            'source': source,
            'token_preview': access_token[:20] + '...'
        }), 200
        
    except Exception as e:
        logger.error(f"Token sync error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/token/status', methods=['GET'])
def token_status():
    try:
        user_id = request.args.get('user_id', 'default')
        user = User.query.filter_by(user_id=user_id).first()
        
        if not user:
            return jsonify({
                'token_exists': False,
                'message': 'User not found'
            }), 200
        
        token = DeepSeekToken.query.filter_by(
            user_id=user.id, 
            is_valid=True
        ).order_by(
            DeepSeekToken.created_at.desc()
        ).first()
        
        if not token:
            return jsonify({
                'token_exists': False,
                'message': 'No valid token found'
            }), 200
        
        now = datetime.utcnow()
        days_left = (token.expires_at - now).total_seconds() / (24 * 3600) if token.expires_at else 0
        
        return jsonify({
            'token_exists': True,
            'is_valid': token.is_valid,
            'expires_at': token.expires_at.isoformat() if token.expires_at else None,
            'expires_in_days': max(0, days_left),
            'extracted_at': token.created_at.isoformat(),
            'source': token.source,
            'has_access_token': bool(token.access_token),
            'has_cookies': bool(token.cookies),
            'token_preview': token.access_token[:20] + '...' if token.access_token else None
        }), 200
        
    except Exception as e:
        logger.error(f"Token status error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/tokens/clear', methods=['POST'])
def clear_tokens():
    try:
        data = request.get_json()
        user_id = data.get('user_id', 'default') if data else 'default'
        
        user = User.query.filter_by(user_id=user_id).first()
        if user:
            DeepSeekToken.query.filter_by(user_id=user.id).delete()
            db.session.commit()
            logger.info(f"Tokens cleared for user {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'Tokens cleared successfully',
            'user_id': user_id
        }), 200
        
    except Exception as e:
        logger.error(f"Clear tokens error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/sync/history', methods=['GET'])
def get_sync_history():
    try:
        user_id = request.args.get('user_id', 'default')
        limit = int(request.args.get('limit', 20))
        
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            return jsonify([]), 200
        
        history = SyncHistory.query.filter_by(
            user_id=user.id
        ).order_by(
            SyncHistory.created_at.desc()
        ).limit(limit).all()
        
        return jsonify([h.to_dict() for h in history]), 200
        
    except Exception as e:
        logger.error(f"Sync history error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============ DEBUG TOKEN ENDPOINT ============

@app.route('/api/debug/token', methods=['GET'])
def debug_token():
    user_id = request.args.get('user_id', 'default')
    user = User.query.filter_by(user_id=user_id).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    token = DeepSeekToken.query.filter_by(user_id=user.id, is_valid=True).first()
    
    if not token:
        return jsonify({
            'user_id': user_id,
            'has_token': False,
            'message': 'No valid token found'
        }), 200
    
    return jsonify({
        'user_id': user_id,
        'has_token': bool(token.access_token),
        'token_preview': token.access_token[:30] + '...' if token.access_token else None,
        'expires_at': token.expires_at.isoformat() if token.expires_at else None,
        'source': token.source,
        'has_cookies': bool(token.cookies),
        'cookies_count': len(token.cookies) if token.cookies else 0,
        'is_valid': token.is_valid
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
            return jsonify({'error': 'User not found. Sync tokens first.'}), 404
        
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
        
        logger.info(f"API key created for user {user_id}: {name}")
        
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
    
    logger.info(f"API key {key_id} revoked")
    
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
    
    logger.info(f"API key {key_id} regenerated")
    
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
            return jsonify({'error': 'No valid DeepSeek token. Please sync tokens via Chrome Extension.'}), 401
        
        # ============ BUILD PROPER DEEPSEEK PAYLOAD ============
        messages = data.get('messages', [])
        if not messages:
            return jsonify({'error': 'No messages provided'}), 400
        
        # Get the last user message
        last_message = messages[-1].get('content', '') if messages else ''
        
        # Build payload exactly as DeepSeek expects
        payload = {
            "chat_session_id": data.get('chat_session_id'),
            "prompt": last_message,
            "model_type": data.get('model_type', 'default'),
            "parent_message_id": data.get('parent_message_id'),
            "preempt": data.get('preempt', False),
            "thinking_enabled": data.get('thinking_enabled', False),
            "search_enabled": data.get('search_enabled', False),
            "ref_file_ids": data.get('ref_file_ids', [])
        }
        
        # Remove None values
        payload = {k: v for k, v in payload.items() if v is not None}
        
        start_time = datetime.utcnow()
        
        headers = token.get_auth_headers()
        
        response = requests.post(
            'https://chat.deepseek.com/api/v0/chat/completion',
            json=payload,
            headers=headers,
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

# ============ HELPER FUNCTIONS ============

def extract_csrf(html):
    if not html:
        return None
    
    try:
        soup = BeautifulSoup(html, 'html.parser')
        meta = soup.find('meta', {'name': 'csrf-token'})
        if meta and meta.get('content'):
            return meta.get('content')
        
        meta = soup.find('meta', {'name': 'csrf_token'})
        if meta and meta.get('content'):
            return meta.get('content')
    except Exception as e:
        logger.warning(f"BeautifulSoup parsing error: {e}")
    
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
