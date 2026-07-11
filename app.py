@app.route('/api/tokens/sync', methods=['POST'])
def sync_tokens():
    """Sync tokens from Chrome Extension"""
    try:
        data = request.get_json()
        user_id = data.get('user_id', 'default')
        token_data = data.get('tokens', {})
        cookies = data.get('cookies', {})
        source = data.get('source', 'unknown')
        
        logger.info(f"Token sync request from {source} for user {user_id}")
        logger.info(f"Token data keys: {list(token_data.keys())}")
        
        # Get or create user
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
        
        # Extract access token from multiple sources
        access_token = None
        
        # Method 1: Check token_data
        if token_data.get('access_token'):
            access_token = token_data.get('access_token')
            logger.info("Found token in token_data")
        
        # Method 2: Check cookies for ds_session_id
        if not access_token and cookies:
            if isinstance(cookies, dict):
                # Direct cookie dict
                for cookie_name in ['ds_session_id', 'access_token', 'token', 'auth_token', 'session', 'sid']:
                    if cookie_name in cookies:
                        access_token = cookies[cookie_name]
                        logger.info(f"Found token in cookie dict: {cookie_name}")
                        break
            else:
                # Cookies might be a list
                for cookie in cookies:
                    if isinstance(cookie, dict) and cookie.get('name') in ['ds_session_id', 'access_token', 'token']:
                        access_token = cookie.get('value')
                        logger.info(f"Found token in cookie list: {cookie.get('name')}")
                        break
        
        # Method 3: Check localStorage
        if not access_token and token_data.get('localStorage'):
            local_data = token_data.get('localStorage', {})
            if isinstance(local_data, dict):
                for key in ['access_token', 'token', 'auth_token']:
                    if key in local_data:
                        access_token = local_data[key]
                        logger.info(f"Found token in localStorage: {key}")
                        break
        
        if not access_token:
            logger.warning(f"No access token found for user {user_id}")
            
            return jsonify({
                'success': False,
                'error': 'No access token found. Please ensure you are logged into DeepSeek.'
            }), 400
        
        # Store token
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
        
        # Delete old tokens
        DeepSeekToken.query.filter_by(user_id=user.id).delete()
        db.session.add(token)
        db.session.commit()
        
        logger.info(f"Tokens synced successfully for user {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'Tokens synced successfully',
            'expires_at': token.expires_at.isoformat(),
            'user_id': user_id,
            'source': source
        }), 200
        
    except Exception as e:
        logger.error(f"Token sync error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
