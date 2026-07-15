from flask import Flask, jsonify, request, session, Response, stream_with_context
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime, timedelta
import secrets
import requests
import re
import json
import logging
import os
import uuid
import time
import threading
from functools import wraps
from dotenv import load_dotenv
from bs4 import BeautifulSoup
import redis
from urllib.parse import urlparse

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

# Initialize SocketIO for real-time communication
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', ping_timeout=120, ping_interval=30)

# ============ LOGGING ============
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============ REDIS SETUP ============
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
redis_client = None
redis_available = False

def init_redis():
    """Initialize Redis connection"""
    global redis_client, redis_available
    try:
        if REDIS_URL:
            # Parse Redis URL
            parsed = urlparse(REDIS_URL)
            if parsed.scheme in ['redis', 'rediss']:
                redis_client = redis.from_url(REDIS_URL, decode_responses=True)
                redis_client.ping()
                redis_available = True
                logger.info(f"✅ Redis connected successfully to {REDIS_URL}")
            else:
                logger.warning(f"⚠️ Invalid Redis URL scheme: {parsed.scheme}")
        else:
            logger.warning("⚠️ No REDIS_URL environment variable set")
    except Exception as e:
        logger.warning(f"⚠️ Redis connection failed: {e}. Using in-memory fallback.")
        redis_client = None
        redis_available = False

# Initialize Redis on startup
init_redis()

# ============ REDIS HELPER FUNCTIONS ============

def store_job_result(job_id, data, expiry=300):
    """Store job result in Redis or memory"""
    try:
        if redis_available and redis_client:
            redis_client.setex(
                f'job_result:{job_id}',
                expiry,
                json.dumps(data)
            )
            return True
    except Exception as e:
        logger.warning(f"Redis store error: {e}")
    
    # Fallback to memory
    with job_lock:
        job_results[job_id] = data
    return True

def get_job_result(job_id):
    """Get job result from Redis or memory"""
    try:
        if redis_available and redis_client:
            data = redis_client.get(f'job_result:{job_id}')
            if data:
                return json.loads(data)
    except Exception as e:
        logger.warning(f"Redis get error: {e}")
    
    # Fallback to memory
    with job_lock:
        return job_results.get(job_id)

def delete_job_result(job_id):
    """Delete job result from Redis or memory"""
    try:
        if redis_available and redis_client:
            redis_client.delete(f'job_result:{job_id}')
    except Exception as e:
        logger.warning(f"Redis delete error: {e}")
    
    # Fallback to memory
    with job_lock:
        job_results.pop(job_id, None)

def store_session_token(user_id, token_data, expiry=604800):  # 7 days
    """Store session token in Redis"""
    try:
        if redis_available and redis_client:
            redis_client.setex(
                f'session:{user_id}',
                expiry,
                json.dumps(token_data)
            )
            return True
    except Exception as e:
        logger.warning(f"Redis session store error: {e}")
    return False

def get_session_token(user_id):
    """Get session token from Redis"""
    try:
        if redis_available and redis_client:
            data = redis_client.get(f'session:{user_id}')
            if data:
                return json.loads(data)
    except Exception as e:
        logger.warning(f"Redis session get error: {e}")
    return None

def delete_session_token(user_id):
    """Delete session token from Redis"""
    try:
        if redis_available and redis_client:
            redis_client.delete(f'session:{user_id}')
    except Exception as e:
        logger.warning(f"Redis session delete error: {e}")

def publish_job_update(job_id, data):
    """Publish job update to Redis channel for real-time notifications"""
    try:
        if redis_available and redis_client:
            redis_client.publish(
                f'job_updates:{job_id}',
                json.dumps(data)
            )
            return True
    except Exception as e:
        logger.warning(f"Redis publish error: {e}")
    return False

def subscribe_to_job_updates(job_id, callback):
    """Subscribe to job updates (for WebSocket/SSE)"""
    # This would use Redis pub/sub in a separate thread
    # For simplicity, we'll use the in-memory approach
    pass

# ============ MODELS ============

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

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

    user = db.relationship('User', backref=db.backref('tokens', lazy=True, cascade='all, delete-orphan'))

    def get_auth_headers(self):
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Origin': 'https://chat.deepseek.com',
            'Referer': 'https://chat.deepseek.com/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36',
            'x-client-bundle-id': 'com.deepseek.chat',
            'x-client-platform': 'web',
            'x-client-version': '2.2.0',
            'x-client-locale': 'en_US',
            'x-client-timezone-offset': '3600'
        }

        if self.access_token:
            headers['Authorization'] = f'Bearer {self.access_token}'

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

    user = db.relationship('User', backref=db.backref('api_keys', lazy=True, cascade='all, delete-orphan'))

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

    api_key = db.relationship('APIKey', backref=db.backref('logs', lazy=True, cascade='all, delete-orphan'))

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

    user = db.relationship('User', backref=db.backref('sync_history', lazy=True, cascade='all, delete-orphan'))

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

class ChatJob(db.Model):
    __tablename__ = 'chat_jobs'
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    api_key_id = db.Column(db.Integer, db.ForeignKey('api_keys.id'))

    prompt = db.Column(db.Text)
    session_id = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')  # pending, processing, completed, failed, timeout
    response = db.Column(db.Text)
    error_message = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

    user = db.relationship('User', backref=db.backref('chat_jobs', lazy=True))
    api_key = db.relationship('APIKey', backref=db.backref('chat_jobs', lazy=True))

    def to_dict(self):
        return {
            'job_id': self.job_id,
            'prompt': self.prompt[:100] + '...' if self.prompt and len(self.prompt) > 100 else self.prompt,
            'session_id': self.session_id,
            'status': self.status,
            'response': self.response,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }

# ============ CREATE TABLES ============
with app.app_context():
    db.create_all()
    logger.info("Database tables created")

# ============ GLOBAL STORAGE ============
# In-memory job results (fallback when Redis is not available)
job_results = {}
job_lock = threading.Lock()
# Active WebSocket connections
active_connections = {}

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
    try:
        with open('dashboard.html', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return jsonify({
            'service': 'SEP X - DeepSeek API Gateway',
            'status': 'running',
            'version': '3.0.0',
            'redis_available': redis_available,
            'message': 'Dashboard not found',
            'endpoints': {
                'POST /v1/chat/completions': 'Create chat job (non-blocking)',
                'POST /v1/chat/completions/stream': 'Stream chat response (SSE)',
                'GET /api/job/<job_id>': 'Check job status',
                'POST /api/extension/sync': 'Extension sync endpoint',
                'GET /api/extension/job': 'Extension get pending job',
                'POST /api/tokens/sync': 'Sync tokens from Chrome Extension',
                'GET /api/token/status': 'Check token status',
                'POST /api/tokens/clear': 'Clear tokens',
                'POST /api/user/create': 'Create user',
                'POST /api/keys': 'Generate API key',
                'GET /api/keys': 'List API keys',
                'GET /api/logs': 'View API logs',
                'WebSocket': '/socket.io/ for real-time communication'
            }
        }), 200

@app.route('/health')
def health():
    redis_status = 'connected' if redis_available else 'disabled'
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'database': 'connected',
        'redis': redis_status,
        'version': '3.0.0'
    })

@app.route('/api/status')
def api_status():
    """Get system status including Redis"""
    return jsonify({
        'redis_available': redis_available,
        'redis_url': REDIS_URL if REDIS_URL else 'not configured',
        'job_results_count': len(job_results),
        'timestamp': datetime.utcnow().isoformat()
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

        if token_data.get('access_token'):
            access_token = token_data.get('access_token')
            logger.info(f"Found token in token_data: {access_token[:20]}...")

        if not access_token and cookies:
            if isinstance(cookies, list):
                for cookie in cookies:
                    if isinstance(cookie, dict) and cookie.get('name') == 'ds_session_id':
                        access_token = cookie.get('value')
                        logger.info("Found token in cookie list: ds_session_id")
                        break

        if not access_token:
            logger.warning(f"No access token found for user {user_id}")
            return jsonify({
                'success': False,
                'error': 'No access token found. Please ensure you are logged into DeepSeek.'
            }), 400

        # Delete old tokens
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

        # Store in Redis for fast access
        store_session_token(user_id, {
            'access_token': access_token,
            'expires_at': token.expires_at.isoformat(),
            'source': source
        })

        logger.info(f"Tokens synced successfully for user {user_id}")

        return jsonify({
            'success': True,
            'message': 'Tokens synced successfully',
            'expires_at': token.expires_at.isoformat(),
            'user_id': user_id,
            'source': source,
            'token_preview': access_token[:20] + '...',
            'redis_cached': redis_available
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
            'redis_cached': redis_available
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
            delete_session_token(user_id)
            logger.info(f"Tokens cleared for user {user_id}")

        return jsonify({
            'success': True,
            'message': 'Tokens cleared successfully',
            'user_id': user_id
        }), 200

    except Exception as e:
        logger.error(f"Clear tokens error: {str(e)}")
        return jsonify({'error': str(e)}), 500

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

# ============ CHAT COMPLETION (Non-Blocking) ============

@app.route('/v1/chat/completions', methods=['POST'])
@require_api_key
def chat_completions():
    """Receive chat request - non-blocking version. Returns job_id immediately."""
    try:
        data = request.get_json()
        prompt = data.get('prompt') or data.get('message')
        session_id = data.get('session_id') or str(uuid.uuid4())
        timeout = data.get('timeout', 120)
        clear_previous = data.get('clear_previous', False)

        if not prompt:
            return jsonify({'error': 'prompt or message required'}), 400

        user = User.query.get(request.api_key.user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Generate job ID
        job_id = str(uuid.uuid4())

        # Create job record
        job = ChatJob(
            job_id=job_id,
            user_id=user.id,
            api_key_id=request.api_key.id,
            prompt=prompt,
            session_id=session_id,
            status='pending',
            created_at=datetime.utcnow()
        )
        db.session.add(job)
        db.session.commit()

        # Store in Redis for fast access
        store_job_result(job_id, {
            'status': 'pending',
            'session_id': session_id,
            'user_id': user.user_id,
            'prompt': prompt[:100],
            'created_at': datetime.utcnow().isoformat()
        })

        logger.info(f"Chat job created: {job_id} for user {user.user_id}")

        # Return job ID immediately - client can poll or use WebSocket
        return jsonify({
            'success': True,
            'job_id': job_id,
            'session_id': session_id,
            'status': 'pending',
            'message': 'Job created. Poll /api/job/<job_id> for status or use /v1/chat/completions/stream for streaming.',
            'poll_endpoint': f'/api/job/{job_id}',
            'stream_endpoint': f'/v1/chat/completions/stream'
        }), 202

    except Exception as e:
        logger.error(f"Chat error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============ CHAT COMPLETION (Streaming) ============

@app.route('/v1/chat/completions/stream', methods=['POST'])
@require_api_key
def chat_completions_stream():
    """Stream chat response using Server-Sent Events (SSE)."""
    try:
        data = request.get_json()
        prompt = data.get('prompt') or data.get('message')
        session_id = data.get('session_id') or str(uuid.uuid4())
        timeout = data.get('timeout', 120)
        clear_previous = data.get('clear_previous', False)

        if not prompt:
            return jsonify({'error': 'prompt or message required'}), 400

        user = User.query.get(request.api_key.user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Generate job ID
        job_id = str(uuid.uuid4())

        # Create job record
        job = ChatJob(
            job_id=job_id,
            user_id=user.id,
            api_key_id=request.api_key.id,
            prompt=prompt,
            session_id=session_id,
            status='pending',
            created_at=datetime.utcnow()
        )
        db.session.add(job)
        db.session.commit()

        # Store in Redis for fast access
        store_job_result(job_id, {
            'status': 'pending',
            'session_id': session_id,
            'user_id': user.user_id,
            'prompt': prompt[:100],
            'created_at': datetime.utcnow().isoformat()
        })

        logger.info(f"Stream job created: {job_id} for user {user.user_id}")

        # Server-Sent Events generator
        def generate():
            start_time = time.time()
            last_sent_progress = 0
            check_count = 0
            last_heartbeat = 0
            
            # Send initial event
            yield f"data: {json.dumps({'type': 'start', 'job_id': job_id, 'session_id': session_id, 'message': 'Job created, waiting for extension...'})}\n\n"
            
            while time.time() - start_time < timeout:
                check_count += 1
                
                # Check Redis/memory for job status
                result = get_job_result(job_id)
                
                if result:
                    status = result.get('status')
                    
                    if status == 'completed':
                        yield f"data: {json.dumps({'type': 'complete', 'response': result.get('response'), 'job_id': job_id, 'session_id': session_id, 'elapsed': int(time.time() - start_time)})}\n\n"
                        yield "data: [DONE]\n\n"
                        delete_job_result(job_id)
                        return
                    elif status == 'failed':
                        yield f"data: {json.dumps({'type': 'error', 'error': result.get('error', 'Job failed'), 'job_id': job_id, 'elapsed': int(time.time() - start_time)})}\n\n"
                        delete_job_result(job_id)
                        return
                    elif status == 'timeout':
                        yield f"data: {json.dumps({'type': 'error', 'error': result.get('error', 'Job timed out'), 'job_id': job_id, 'elapsed': int(time.time() - start_time)})}\n\n"
                        delete_job_result(job_id)
                        return
                
                # Check database periodically (every 2 seconds)
                if check_count % 4 == 0:
                    db_job = ChatJob.query.filter_by(job_id=job_id).first()
                    if db_job:
                        if db_job.status == 'completed':
                            store_job_result(job_id, {
                                'status': 'completed',
                                'response': db_job.response,
                                'session_id': session_id
                            })
                            # Next loop iteration will pick this up
                        elif db_job.status == 'failed':
                            store_job_result(job_id, {
                                'status': 'failed',
                                'error': db_job.error_message
                            })
                        elif db_job.status == 'timeout':
                            store_job_result(job_id, {
                                'status': 'timeout',
                                'error': 'Job timed out'
                            })
                
                # Send progress updates every 5 seconds
                elapsed = int(time.time() - start_time)
                if elapsed > 0 and elapsed % 5 == 0 and elapsed != last_sent_progress:
                    last_sent_progress = elapsed
                    yield f"data: {json.dumps({'type': 'progress', 'elapsed': elapsed, 'status': 'waiting_for_extension', 'message': f'Waiting for extension to process... ({elapsed}s elapsed)'})}\n\n"
                
                # Send heartbeat every 10 seconds to keep connection alive
                if elapsed > 0 and elapsed % 10 == 0 and elapsed != last_heartbeat:
                    last_heartbeat = elapsed
                    yield f"data: {json.dumps({'type': 'heartbeat', 'elapsed': elapsed})}\n\n"
                
                time.sleep(0.5)
            
            # Timeout - check one last time
            final_result = get_job_result(job_id)
            if final_result and final_result.get('status') == 'completed':
                yield f"data: {json.dumps({'type': 'complete', 'response': final_result.get('response'), 'job_id': job_id, 'session_id': session_id, 'elapsed': int(time.time() - start_time)})}\n\n"
                yield "data: [DONE]\n\n"
                delete_job_result(job_id)
                return
            
            # Really timed out
            yield f"data: {json.dumps({'type': 'error', 'error': f'Timeout waiting for response from browser after {timeout}s', 'job_id': job_id, 'elapsed': timeout})}\n\n"
            delete_job_result(job_id)

        return Response(
            stream_with_context(generate()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache, no-transform',
                'X-Accel-Buffering': 'no',
                'Connection': 'keep-alive',
                'Content-Type': 'text/event-stream'
            }
        )

    except Exception as e:
        logger.error(f"Stream chat error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============ JOB STATUS ============

@app.route('/api/job/<job_id>', methods=['GET'])
def get_job_status(job_id):
    """Check job status"""
    try:
        job = ChatJob.query.filter_by(job_id=job_id).first()
        if not job:
            return jsonify({'error': 'Job not found'}), 404

        # Check if job is completed in cache
        cached = get_job_result(job_id)
        if cached and cached.get('status') in ['completed', 'failed', 'timeout']:
            if cached.get('status') == 'completed':
                job.status = 'completed'
                job.response = cached.get('response')
                job.completed_at = datetime.utcnow()
                db.session.commit()
            elif cached.get('status') == 'failed':
                job.status = 'failed'
                job.error_message = cached.get('error')
                db.session.commit()

        return jsonify(job.to_dict()), 200

    except Exception as e:
        logger.error(f"Job status error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============ EXTENSION ENDPOINTS ============

@app.route('/api/extension/job', methods=['GET'])
def extension_get_job():
    """Extension polls for pending jobs"""
    try:
        # Get pending jobs (older than 3 seconds to avoid race conditions)
        pending_jobs = ChatJob.query.filter_by(
            status='pending'
        ).order_by(
            ChatJob.created_at.asc()
        ).limit(1).all()

        if not pending_jobs:
            return jsonify({'has_job': False}), 200

        job = pending_jobs[0]
        
        # Mark as processing to prevent duplicate pickup
        job.status = 'processing'
        db.session.commit()
        
        logger.info(f"Extension picked up job: {job.job_id}")

        return jsonify({
            'has_job': True,
            'job_id': job.job_id,
            'prompt': job.prompt,
            'session_id': job.session_id,
            'created_at': job.created_at.isoformat() if job.created_at else None
        }), 200

    except Exception as e:
        logger.error(f"Extension get job error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/extension/sync', methods=['POST'])
def extension_sync():
    """Extension sends completed response back"""
    try:
        data = request.get_json()
        job_id = data.get('job_id')
        response = data.get('response')
        session_id = data.get('session_id')
        error = data.get('error')

        if not job_id:
            return jsonify({'error': 'job_id required'}), 400

        logger.info(f"Extension sync: job {job_id} received response")

        # Update job in database
        job = ChatJob.query.filter_by(job_id=job_id).first()
        if job:
            if error:
                job.status = 'failed'
                job.error_message = error
            else:
                job.status = 'completed'
                job.response = response
                job.completed_at = datetime.utcnow()
            
            db.session.commit()
            logger.info(f"Job {job_id} updated in database: {job.status}")

        # Store in Redis/memory for quick access
        if error:
            store_job_result(job_id, {
                'status': 'failed',
                'error': error,
                'session_id': session_id,
                'timestamp': datetime.utcnow().isoformat()
            })
        else:
            store_job_result(job_id, {
                'status': 'completed',
                'response': response,
                'session_id': session_id,
                'timestamp': datetime.utcnow().isoformat()
            })

        # Publish job update for WebSocket clients
        publish_job_update(job_id, {
            'job_id': job_id,
            'status': 'completed' if not error else 'failed',
            'response': response,
            'error': error
        })

        # Notify WebSocket clients if connected
        if job_id in active_connections:
            socketio.emit('job_update', {
                'job_id': job_id,
                'status': 'completed' if not error else 'failed',
                'response': response,
                'error': error
            }, room=job_id)

        return jsonify({
            'success': True,
            'message': 'Response received',
            'job_id': job_id,
            'cached': redis_available
        }), 200

    except Exception as e:
        logger.error(f"Extension sync error: {str(e)}")
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

# ============ WEBSOCKET EVENTS ============

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    logger.info(f"WebSocket client connected: {request.sid}")
    emit('connected', {
        'status': 'connected',
        'sid': request.sid,
        'redis_available': redis_available,
        'timestamp': datetime.utcnow().isoformat()
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    logger.info(f"WebSocket client disconnected: {request.sid}")
    # Clean up active connections
    for job_id, sid in list(active_connections.items()):
        if sid == request.sid:
            del active_connections[job_id]

@socketio.on('subscribe')
def handle_subscribe(data):
    """Subscribe to job updates"""
    job_id = data.get('job_id')
    if not job_id:
        emit('error', {'error': 'job_id required'})
        return
    
    join_room(job_id)
    active_connections[job_id] = request.sid
    
    logger.info(f"Client {request.sid} subscribed to job {job_id}")
    
    # Check if job already has a result
    result = get_job_result(job_id)
    if result:
        status = result.get('status')
        if status in ['completed', 'failed', 'timeout']:
            emit('job_update', {
                'job_id': job_id,
                'status': status,
                'response': result.get('response'),
                'error': result.get('error')
            }, room=job_id)
    
    emit('subscribed', {
        'job_id': job_id,
        'status': 'subscribed',
        'redis_available': redis_available
    })

@socketio.on('chat_request')
def handle_chat_request(data):
    """Handle chat request via WebSocket"""
    try:
        prompt = data.get('prompt')
        session_id = data.get('session_id') or str(uuid.uuid4())
        timeout = data.get('timeout', 120)
        user_id = data.get('user_id', 'default')
        
        if not prompt:
            emit('error', {'error': 'prompt required'})
            return
        
        # Find user
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            emit('error', {'error': 'User not found'})
            return
        
        # Create job
        job_id = str(uuid.uuid4())
        
        # Store in Redis/memory
        store_job_result(job_id, {
            'status': 'pending',
            'socket_id': request.sid,
            'session_id': session_id
        })
        
        # Create database record
        job = ChatJob(
            job_id=job_id,
            user_id=user.id,
            prompt=prompt,
            session_id=session_id,
            status='pending'
        )
        db.session.add(job)
        db.session.commit()
        
        # Subscribe to this job
        join_room(job_id)
        active_connections[job_id] = request.sid
        
        logger.info(f"WebSocket chat job created: {job_id}")
        
        # Send acknowledgment
        emit('job_created', {
            'job_id': job_id,
            'session_id': session_id,
            'status': 'pending'
        })
        
        # Wait for result in background
        def wait_for_result():
            start_time = time.time()
            while time.time() - start_time < timeout:
                result = get_job_result(job_id)
                if result:
                    status = result.get('status')
                    if status == 'completed':
                        socketio.emit('chat_response', {
                            'job_id': job_id,
                            'response': result.get('response'),
                            'session_id': session_id
                        }, room=job_id)
                        return
                    elif status == 'failed':
                        socketio.emit('error', {
                            'job_id': job_id,
                            'error': result.get('error', 'Job failed')
                        }, room=job_id)
                        return
                    elif status == 'timeout':
                        socketio.emit('error', {
                            'job_id': job_id,
                            'error': 'Timeout waiting for response'
                        }, room=job_id)
                        return
                time.sleep(1)
            
            socketio.emit('error', {
                'job_id': job_id,
                'error': 'Timeout waiting for response'
            }, room=job_id)
        
        # Start background thread
        thread = threading.Thread(target=wait_for_result)
        thread.daemon = True
        thread.start()
        
    except Exception as e:
        logger.error(f"WebSocket chat error: {str(e)}")
        emit('error', {'error': str(e)})

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

# ============ MAIN ============

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Use socketio.run for WebSocket support
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=debug,
        allow_unsafe_werkzeug=True
    )
