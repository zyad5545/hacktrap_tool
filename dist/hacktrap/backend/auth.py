from functools import wraps
from flask import request, jsonify
import os

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-KEY')
        if api_key == os.getenv('API_KEY', 'demo-key'):
            return f(*args, **kwargs)
        return jsonify({"error": "Invalid API key"}), 401
    return decorated_function