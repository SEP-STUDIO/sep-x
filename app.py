@app.route('/v1/chat/completions', methods=['POST'])
@require_api_key
def proxy_chat():
    try:
        data = request.get_json()
        logger.info(f"Chat request received: {data}")
        
        user = User.query.get(request.api_key.user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        token = DeepSeekToken.query.filter_by(user_id=user.id, is_valid=True).first()
        if not token:
            return jsonify({'error': 'No valid DeepSeek token. Please sync tokens via Chrome Extension.'}), 401
        
        # ============ EXACT DEEPSEEK PAYLOAD FORMAT ============
        import uuid
        
        # Get or generate chat_session_id
        chat_session_id = data.get('chat_session_id') or str(uuid.uuid4())
        
        # Get parent_message_id if provided, or use None
        parent_message_id = data.get('parent_message_id')
        
        # Get the prompt from messages
        messages = data.get('messages', [])
        if not messages:
            return jsonify({'error': 'No messages provided'}), 400
        
        # Extract the last user message as prompt
        prompt = messages[-1].get('content', '') if messages else ''
        
        # Build payload exactly as DeepSeek expects
        payload = {
            "chat_session_id": chat_session_id,
            "parent_message_id": parent_message_id,
            "model_type": data.get('model_type'),
            "prompt": prompt,
            "preempt": data.get('preempt', False),
            "thinking_enabled": data.get('thinking_enabled', False),
            "search_enabled": data.get('search_enabled', False),
            "ref_file_ids": data.get('ref_file_ids', []),
            "action": data.get('action')
        }
        
        # Remove None values (but keep null explicitly if needed)
        payload = {k: v for k, v in payload.items() if v is not None}
        
        # If model_type is None, set to null (remove from payload)
        if data.get('model_type') is None:
            payload.pop('model_type', None)
        if data.get('action') is None:
            payload.pop('action', None)
        
        logger.info(f"Forwarding to DeepSeek: {payload}")
        
        start_time = datetime.utcnow()
        
        headers = token.get_auth_headers()
        logger.info(f"Using headers: {list(headers.keys())}")
        
        response = requests.post(
            'https://chat.deepseek.com/api/v0/chat/completion',
            json=payload,
            headers=headers,
            timeout=60
        )
        
        response_time = (datetime.utcnow() - start_time).total_seconds()
        
        logger.info(f"DeepSeek response status: {response.status_code}")
        logger.info(f"DeepSeek response body: {response.text[:500]}")
        
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
        
        # Return the response with the session ID
        try:
            result = response.json()
            result['chat_session_id'] = chat_session_id
            return jsonify(result), response.status_code
        except:
            return jsonify({'error': 'Invalid response from DeepSeek', 'raw': response.text}), 500
        
    except requests.exceptions.Timeout:
        return jsonify({'error': 'DeepSeek API timeout'}), 504
    except Exception as e:
        logger.error(f"Proxy error: {str(e)}")
        return jsonify({'error': str(e)}), 500
