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
        
        # ============ FIX: HANDLE COOKIES AS LIST OR DICT ============
        if token_data.get('access_token'):
            access_token = token_data.get('access_token')
            logger.info("Found token in token_data")
        
        if not access_token and cookies:
            # If cookies is a list (from extension)
            if isinstance(cookies, list):
                for cookie in cookies:
                    if isinstance(cookie, dict) and cookie.get('name') == 'ds_session_id':
                        access_token = cookie.get('value')
                        logger.info(f"Found token in cookie list: ds_session_id")
                        break
            # If cookies is a dict
            elif isinstance(cookies, dict):
                for cookie_name in ['ds_session_id', 'access_token', 'token', 'auth_token', 'session', 'sid']:
                    if cookie_name in cookies:
                        access_token = cookies[cookie_name]
                        logger.info(f"Found token in cookie dict: {cookie_name}")
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
                'error': 'No access token found. Please ensure you are logged into DeepSeek.'
            }), 400
        
        # Delete old tokens first
        DeepSeekToken.query.filter_by(user_id=user.id).delete()
        
        # Create new token
        token = DeepSeekToken(
            user_id=user.id,
            access_token=access_token,
            refresh_token=token_data.get('refresh_token'),
            cookies=cookies,  # Store as-is (list or dict)
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
