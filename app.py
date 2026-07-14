# app.py - Simplified Queue System

from flask import Flask, jsonify, request
import requests
import threading
import queue
import time
import uuid

app = Flask(__name__)

# Job queue
job_queue = {}
job_results = {}

@app.route('/v1/chat/completions', methods=['POST'])
def handle_chat():
    """Receive chat request from client"""
    data = request.get_json()
    prompt = data.get('prompt')
    session_id = data.get('session_id', str(uuid.uuid4()))
    
    # Create job
    job_id = str(uuid.uuid4())
    job_queue[job_id] = {
        'session_id': session_id,
        'prompt': prompt,
        'status': 'pending',
        'created_at': time.time()
    }
    
    # Wait for response (with timeout)
    start_time = time.time()
    while time.time() - start_time < 120:  # 2 minute timeout
        if job_id in job_results:
            result = job_results.pop(job_id)
            return jsonify({
                'success': True,
                'response': result['response'],
                'session_id': session_id,
                'job_id': job_id
            })
        time.sleep(0.5)
    
    return jsonify({
        'success': False,
        'error': 'Timeout waiting for response',
        'job_id': job_id
    }), 408

@app.route('/api/job/<job_id>/status', methods=['GET'])
def job_status(job_id):
    """Check job status"""
    if job_id in job_queue:
        return jsonify(job_queue[job_id])
    return jsonify({'status': 'not_found'}), 404

@app.route('/api/extension/sync', methods=['POST'])
def extension_sync():
    """Extension sends completed response"""
    data = request.get_json()
    job_id = data.get('job_id')
    response = data.get('response')
    session_id = data.get('session_id')
    
    job_results[job_id] = {
        'response': response,
        'session_id': session_id
    }
    
    if job_id in job_queue:
        job_queue[job_id]['status'] = 'completed'
    
    return jsonify({'success': True})
