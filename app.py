# ============ GOOGLE OAUTH ROUTES ============

@app.route('/auth/google', methods=['GET'])
def google_auth():
    """Initiate Google OAuth flow using DeepSeek's Google login"""
    user_id = request.args.get('user_id', 'default')
    session['oauth_user_id'] = user_id
    
    # We'll use an iframe approach to capture the session
    return render_google_auth_embedded(user_id)

def render_google_auth_embedded(user_id):
    """Render an embedded Google auth page that captures the session"""
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sign in to DeepSeek</title>
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
            }}
            .container {{
                text-align: center;
                max-width: 600px;
                width: 100%;
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
            .iframe-container {{
                margin-top: 20px;
                border-radius: 12px;
                overflow: hidden;
                border: 1px solid rgba(255,255,255,0.05);
                height: 500px;
                background: #1a1a2e;
                position: relative;
            }}
            .iframe-container iframe {{
                width: 100%;
                height: 100%;
                border: none;
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
            .status {{
                margin-top: 12px;
                padding: 10px;
                border-radius: 8px;
                font-size: 13px;
                display: none;
            }}
            .status.loading {{
                display: block;
                background: rgba(251, 191, 36, 0.08);
                border: 1px solid rgba(251, 191, 36, 0.15);
                color: #fbbf24;
            }}
            .status.success {{
                display: block;
                background: rgba(52, 211, 153, 0.08);
                border: 1px solid rgba(52, 211, 153, 0.15);
                color: #34d399;
            }}
            .status.error {{
                display: block;
                background: rgba(248, 113, 113, 0.08);
                border: 1px solid rgba(248, 113, 113, 0.15);
                color: #f87171;
            }}
            .user-id {{
                color: #6b7280;
                font-size: 12px;
                margin-top: 8px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="spinner"></div>
            <h3>🔐 Sign in to DeepSeek</h3>
            <p>Use your Google account to authenticate</p>
            <div class="user-id">User ID: {user_id}</div>
            
            <div class="iframe-container">
                <iframe id="authFrame" src="https://chat.deepseek.com/auth/google"></iframe>
            </div>
            
            <div id="status" class="status loading">
                ⏳ Waiting for authentication...
            </div>
            
            <button class="btn" onclick="checkAuth()">🔄 Check Authentication</button>
            <button class="btn" style="background:#2a2a4a;margin-left:8px;" onclick="window.close()">Close</button>

            <script>
                const user_id = '{user_id}';
                let authCheckInterval = null;
                let attempts = 0;
                const MAX_ATTEMPTS = 30;

                // Check for authentication by trying to get token status
                async function checkAuth() {{
                    const status = document.getElementById('status');
                    status.className = 'status loading';
                    status.textContent = '⏳ Checking authentication...';
                    
                    try {{
                        const response = await fetch(`/api/token/status?user_id=${{user_id}}`);
                        const data = await response.json();
                        
                        if (data.token_exists && data.is_valid) {{
                            status.className = 'status success';
                            status.textContent = '✅ Authentication successful! Closing...';
                            
                            // Send success to parent
                            if (window.opener) {{
                                window.opener.postMessage({{
                                    type: 'google_auth_callback',
                                    success: true,
                                    user_id: user_id,
                                    message: 'Google authentication successful'
                                }}, '*');
                            }}
                            
                            setTimeout(() => window.close(), 1500);
                            return true;
                        }}
                    }} catch (e) {{
                        // Ignore errors - token not ready yet
                    }}
                    
                    status.className = 'status loading';
                    status.textContent = '⏳ Still waiting... please complete the login in the iframe.';
                    return false;
                }}

                // Auto-check every 3 seconds
                authCheckInterval = setInterval(async () => {{
                    attempts++;
                    const success = await checkAuth();
                    if (success) {{
                        clearInterval(authCheckInterval);
                    }} else if (attempts >= MAX_ATTEMPTS) {{
                        clearInterval(authCheckInterval);
                        const status = document.getElementById('status');
                        status.className = 'status error';
                        status.textContent = '❌ Authentication timeout. Please try again.';
                    }}
                }}, 3000);

                // Also try when iframe loads
                document.getElementById('authFrame').onload = function() {{
                    setTimeout(checkAuth, 2000);
                }};

                // Manual check button
                window.checkAuth = checkAuth;
            </script>
        </div>
    </body>
    </html>
    '''

@app.route('/auth/google/callback', methods=['GET', 'POST'])
def google_callback():
    """
    Handle Google OAuth callback from DeepSeek
    This captures the redirect after Google login
    """
    try:
        # Get the full URL and extract any params
        code = request.args.get('code') or request.form.get('code')
        error = request.args.get('error') or request.form.get('error')
        state = request.args.get('state') or request.form.get('state')
        
        # Log what we received
        logger.info(f"Google callback received: code={bool(code)}, error={error}, state={bool(state)}")
        logger.info(f"Full request: {request.url}")
        logger.info(f"Headers: {dict(request.headers)}")
        
        if error:
            logger.error(f"Google auth error: {error}")
            return render_oauth_result(False, f'Google auth error: {error}')
        
        # If we have a code, exchange it
        if code:
            try:
                # Exchange code with DeepSeek
                exchange_response = requests.post(
                    'https://chat.deepseek.com/api/v0/auth/google/callback',
                    json={'code': code},
                    headers={
                        'Content-Type': 'application/json',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    },
                    timeout=30
                )
                
                if exchange_response.status_code == 200:
                    token_data = exchange_response.json()
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
                    return render_oauth_result(True, 'Authentication successful!')
                else:
                    logger.error(f"Token exchange failed: {exchange_response.text}")
                    return render_oauth_result(False, f'Token exchange failed: {exchange_response.text}')
                    
            except Exception as e:
                logger.error(f"Token exchange error: {str(e)}")
                return render_oauth_result(False, str(e))
        
        # If no code but we have session, try to extract from cookies
        # This handles the case where DeepSeek sets cookies directly
        user_id = session.get('oauth_user_id', 'default')
        
        # Check if we have a valid token already
        user = User.query.filter_by(user_id=user_id).first()
        if user:
            token = DeepSeekToken.query.filter_by(user_id=user.id, is_valid=True).first()
            if token:
                logger.info(f"Existing token found for user {user_id}")
                return render_oauth_result(True, 'Existing token found')
        
        # If we got here, we don't have a token
        logger.warning("No code or token found in callback")
        return render_oauth_result(False, 'No authentication data received. Please try again.')
        
    except Exception as e:
        logger.error(f"Google callback error: {str(e)}")
        return render_oauth_result(False, str(e))

def render_oauth_result(success, message):
    """Render OAuth result page"""
    status = 'success' if success else 'error'
    icon = '✅' if success else '❌'
    title = 'Authentication Successful' if success else 'Authentication Failed'
    color = '#34d399' if success else '#f87171'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>{title}</title>
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
            .result {{
                max-width: 500px;
                padding: 40px;
                background: rgba(255,255,255,0.02);
                border-radius: 16px;
                border: 1px solid rgba(255,255,255,0.05);
            }}
            .icon {{
                font-size: 64px;
                margin-bottom: 16px;
            }}
            h1 {{
                color: {color};
                font-size: 24px;
                margin-bottom: 8px;
            }}
            p {{
                color: #6b7280;
                font-size: 14px;
                margin-bottom: 20px;
            }}
            .btn {{
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
            .details {{
                background: #1a1a2e;
                padding: 12px;
                border-radius: 8px;
                margin: 16px 0;
                font-size: 13px;
                color: #9ca3af;
                word-break: break-all;
            }}
        </style>
    </head>
    <body>
        <div class="result">
            <div class="icon">{icon}</div>
            <h1>{title}</h1>
            <p>{message}</p>
            <div class="details">User ID: {session.get('oauth_user_id', 'default')}</div>
            <button class="btn" onclick="closeWindow()">Close Window</button>
        </div>

        <script>
            function closeWindow() {{
                // Notify parent if successful
                if ({str(success).lower()}) {{
                    if (window.opener) {{
                        window.opener.postMessage({{
                            type: 'google_auth_callback',
                            success: true,
                            user_id: '{session.get('oauth_user_id', 'default')}',
                            message: 'Authentication successful'
                        }}, '*');
                    }}
                }}
                window.close();
            }}
            
            // Auto-close after 2 seconds if successful
            if ({str(success).lower()}) {{
                setTimeout(closeWindow, 2000);
            }}
        </script>
    </body>
    </html>
    '''
