# SEP X - DeepSeek API Gateway

## Overview
SEP X is an API management platform that provides REST API access to DeepSeek's chat models.

## Features
- 🔐 **Google Sign-In** & Email/Password login
- 🔑 **API Key Management** - Generate, revoke, regenerate
- 📊 **Usage Logs** - Track all API requests
- ⚡ **Rate Limiting** - Per-key rate limits
- 🚀 **Proxy Endpoint** - Forward requests to DeepSeek

## Deployment

### Render.com
1. Fork this repository
2. Create a new Web Service on Render
3. Connect your repository
4. Add PostgreSQL database
5. Deploy

### Environment Variables
- `SECRET_KEY`: Flask secret key
- `DATABASE_URL`: PostgreSQL connection string

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/chat/completions` | POST | Send chat request (requires X-API-Key) |
| `/v1/chat/completions/stream` | POST | Stream chat response |
| `/api/keys` | GET/POST | List/Create API keys |
| `/api/keys/<id>` | DELETE | Revoke API key |
| `/api/keys/<id>/regenerate` | POST | Regenerate API key |
| `/api/logs` | GET | View usage logs |

## Usage Example

```python
import requests

response = requests.post(
    'https://your-service.onrender.com/v1/chat/completions',
    headers={
        'X-API-Key': 'your-api-key',
        'Content-Type': 'application/json'
    },
    json={
        'messages': [{'role': 'user', 'content': 'Hello!'}],
        'model': 'deepseek-chat'
    }
)
print(response.json())
