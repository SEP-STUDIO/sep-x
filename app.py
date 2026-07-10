@app.route('/api/tokens/sync', methods=['POST'])
def sync_tokens():
    """Sync tokens from Chrome Extension"""
    try:
        data = request.get_json()
        user_id = data.get('user_id', 'default')
        token_data = data.get('tokens', {})
        cookies = data.get('cookies', {})
        source = data.get('source', 'unknown')
        
        # Get or create user
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            user = User(user_id=user_id, email=f"{user_id}@sync.local")
            db.session.add(user)
            db.session.commit()
        
        # Check if we have a valid token
        access_token = token_data.get('access_token')
        if not access_token:
            return jsonify({
                'success': False,
                'error': 'No access token found'
            }), 400
        
        # Store token
        token = DeepSeekToken(
            user_id=user.id,
            access_token=access_token,
            refresh_token=token_data.get('refresh_token'),
            cookies=cookies,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_valid=True
        )
        
        # Delete old tokens
        DeepSeekToken.query.filter_by(user_id=user.id).delete()
        db.session.add(token)
        db.session.commit()
        
        logger.info(f"Tokens synced for user {user_id} from {source}")
        
        return jsonify({
            'success': True,
            'message': 'Tokens synced successfully',
            'expires_at': token.expires_at.isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Token sync error: {str(e)}")
        return jsonify({'error': str(e)}), 500
