import os
import json
import time
import hashlib
import logging
import re
from threading import Lock
from collections import OrderedDict
import requests
from flask import Flask, request, Response, stream_with_context, send_from_directory, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.')
CORS(app)

NVIDIA_API_KEY = os.getenv('NVIDIA_API_KEY')
NVIDIA_BASE_URL = 'https://integrate.api.nvidia.com/v1'
MODEL = os.getenv('NVIDIA_MODEL', 'meta/llama-3.1-8b-instruct')

if not NVIDIA_API_KEY:
    log.warning('NVIDIA_API_KEY not found in .env file')

# ── metrics ──
metrics = {
    'requests_total': 0,
    'cache_hits': 0,
    'errors': 0,
    'avg_latency_ms': 0,
    'started_at': time.time()
}
metrics_lock = Lock()

def inc_metric(name, val=1):
    with metrics_lock:
        if name == 'latency':
            n = metrics['requests_total']
            metrics['avg_latency_ms'] = (metrics['avg_latency_ms'] * (n - 1) + val) / n if n else val
        else:
            metrics[name] = metrics.get(name, 0) + val

# ── in-memory cache (LRU, TTL 60s) ──
class TTLCache:
    def __init__(self, maxsize=200, ttl=60):
        self.maxsize = maxsize
        self.ttl = ttl
        self._store = OrderedDict()
        self._lock = Lock()

    def _key(self, data):
        raw = json.dumps(data, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, data):
        key = self._key(data)
        with self._lock:
            if key not in self._store:
                return None
            entry = self._store[key]
            if time.time() - entry['ts'] > self.ttl:
                del self._store[key]
                return None
            self._store.move_to_end(key)
            return entry['value']

    def set(self, data, value):
        key = self._key(data)
        with self._lock:
            self._store[key] = {'ts': time.time(), 'value': value}
            self._store.move_to_end(key)
            while len(self._store) > self.maxsize:
                self._store.popitem(last=False)

cache = TTLCache()

# ── rate limiter (token bucket, per-IP) ──
class RateLimiter:
    def __init__(self, rate=10, burst=20):
        self.rate = rate
        self.burst = burst
        self._buckets = {}
        self._lock = Lock()

    def allow(self, key):
        now = time.time()
        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = {'tokens': self.burst, 'ts': now}
                return True
            b = self._buckets[key]
            elapsed = now - b['ts']
            b['tokens'] = min(self.burst, b['tokens'] + elapsed * self.rate)
            b['ts'] = now
            if b['tokens'] < 1:
                return False
            b['tokens'] -= 1
            return True

    def cleanup(self):
        now = time.time()
        with self._lock:
            stale = [k for k, v in self._buckets.items() if now - v['ts'] > 60]
            for k in stale:
                del self._buckets[k]

rate_limiter = RateLimiter(rate=10, burst=20)

# ── input validation ──
MAX_CONTENT_LEN = 10000
MAX_SENDER_LEN = 256
MAX_SUBJECT_LEN = 512

VALID_MSG_TYPES = {'Email', 'SMS', 'Social Media', 'Website', 'Document'}

def sanitize_text(text, maxlen):
    if not text or not isinstance(text, str):
        return ''
    text = text.strip()
    if len(text) > maxlen:
        text = text[:maxlen]
    return text

def validate_input(data):
    errors = []
    content = data.get('content', '')
    if not content or not isinstance(content, str) or not content.strip():
        errors.append('content is required')
    content_safe = sanitize_text(content, MAX_CONTENT_LEN)
    if not content_safe:
        errors.append('content must be non-empty after sanitization')

    sender = data.get('sender', '')
    if sender and len(sender) > MAX_SENDER_LEN:
        errors.append(f'sender exceeds {MAX_SENDER_LEN} characters')

    subject = data.get('subject', '')
    if subject and len(subject) > MAX_SUBJECT_LEN:
        errors.append(f'subject exceeds {MAX_SUBJECT_LEN} characters')

    msg_type = data.get('msgType', '')
    if msg_type and msg_type not in VALID_MSG_TYPES:
        errors.append(f'invalid msgType: {msg_type}')

    return errors, {
        'sender': sanitize_text(sender, MAX_SENDER_LEN),
        'subject': sanitize_text(subject, MAX_SUBJECT_LEN),
        'msgType': msg_type if msg_type in VALID_MSG_TYPES else 'Email',
        'content': content_safe
    }

# ── prompt builder ──
def build_prompt(data):
    sender = data.get('sender', '')
    subject = data.get('subject', '')
    msg_type = data.get('msgType', '') or 'Not specified'
    content = data.get('content', '')

    details = [f'Message Content:\n---\n{content}\n---']
    if sender:
        details.append(f'Source/Sender: {sender}')
    if subject:
        details.append(f'Subject: {subject}')
    if msg_type != 'Not specified':
        details.append(f'Message Type: {msg_type}')

    prompt = f"""Analyze this message for cybersecurity threats. Return ONLY valid JSON.

Rules:
- 1 financial keyword (bank/OTP/account/card/UPI/payment/password/PIN) → risk_level≥Medium score≥30, 2+ → ≥High/60, 3+ → Critical/85
- Suspicious sender URL or phone → at least Medium
- Urgent subject (urgent/blocked/suspended/verify/alert) → at least Medium
- Everyday harmless words → Safe 0-9

JSON: risk_level (Critical/High/Medium/Low/Safe), threat_types[], analysis, indicators[], recommended_actions[], legal_references[], confidence_score 0-100

{chr(10).join(details)}"""
    return prompt

# ── response validation ──
REQUIRED_FIELDS = {'risk_level', 'threat_types', 'analysis', 'indicators', 'recommended_actions', 'confidence_score'}
VALID_RISK_LEVELS = {'Critical', 'High', 'Medium', 'Low', 'Safe'}

def validate_ai_response(text):
    try:
        m = re.search(r'\{[\s\S]*\}', text)
        if not m:
            return None, 'no JSON found in response'
        parsed = json.loads(m.group(0))
        missing = REQUIRED_FIELDS - set(parsed.keys())
        if missing:
            return None, f'missing fields: {missing}'
        if parsed.get('risk_level') not in VALID_RISK_LEVELS:
            return None, f'invalid risk_level: {parsed.get("risk_level")}'
        score = parsed.get('confidence_score', 0)
        if not isinstance(score, (int, float)) or score < 0 or score > 100:
            return None, f'invalid confidence_score: {score}'
        return parsed, None
    except json.JSONDecodeError as e:
        return None, f'JSON parse error: {e}'

# ── AI call with retry ──
def call_nvidia(prompt, max_retries=1):
    headers = {
        'Authorization': f'Bearer {NVIDIA_API_KEY}',
        'Content-Type': 'application/json'
    }
    payload = {
        'model': MODEL,
        'messages': [{'role': 'user', 'content': prompt}],
        'temperature': 0.3,
        'top_p': 0.9,
                'max_tokens': 512,
        'stream': True
    }

    for attempt in range(max_retries + 1):
        try:
            resp = requests.post(
                f'{NVIDIA_BASE_URL}/chat/completions',
                headers=headers,
                json=payload,
                stream=True,
                timeout=60
            )
            resp.raise_for_status()
            return resp, None
        except requests.exceptions.RequestException as e:
            log.warning(f'NVIDIA API attempt {attempt + 1}/{max_retries + 1} failed: {e}')
            if attempt < max_retries:
                time.sleep(1 * (attempt + 1))
            else:
                return None, str(e)
    return None, 'max retries exceeded'

# ── routes ──
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('.', path)

@app.route('/api/analyze', methods=['POST'])
def analyze():
    start = time.time()
    inc_metric('requests_total')

    client_ip = request.remote_addr or 'unknown'
    if not rate_limiter.allow(client_ip):
        inc_metric('errors')
        log.warning(f'Rate limit exceeded for {client_ip}')
        return jsonify({'error': 'Rate limit exceeded. Try again shortly.'}), 429

    data = request.get_json()
    if not data:
        inc_metric('errors')
        return jsonify({'error': 'Request body must be JSON'}), 400

    errors, cleaned = validate_input(data)
    if errors:
        inc_metric('errors')
        log.info(f'Validation failed: {errors}')
        return jsonify({'error': '; '.join(errors)}), 400

    # Check cache
    cached = cache.get(cleaned)
    if cached:
        inc_metric('cache_hits')
        log.info(f'Cache hit for content hash')
        return Response(
            cached,
            mimetype='text/event-stream',
            headers={'Cache-Control': 'no-cache', 'X-Cache': 'hit'}
        )

    prompt = build_prompt(cleaned)

    def generate():
        nonlocal start
        full_reasoning = ''
        full_content = ''

        try:
            resp, err = call_nvidia(prompt)
            if err:
                inc_metric('errors')
                yield f'data: {json.dumps({"type": "error", "content": err})}\n\n'
                return

            for line in resp.iter_lines():
                if not line:
                    continue
                decoded = line.decode('utf-8')
                if decoded.startswith('data: '):
                    data_str = decoded[6:]
                    if data_str.strip() == '[DONE]':
                        break
                    try:
                        chunk = json.loads(data_str)
                    except json.JSONDecodeError:
                        continue

                    choices = chunk.get('choices', [])
                    if not choices:
                        continue

                    delta = choices[0].get('delta', {})
                    reasoning = delta.get('reasoning_content', None)
                    content = delta.get('content', None)

                    if reasoning:
                        full_reasoning += reasoning
                        yield f'data: {json.dumps({"type": "reasoning", "content": reasoning})}\n\n'

                    if content:
                        full_content += content
                        yield f'data: {json.dumps({"type": "content", "content": content})}\n\n'

            # Validate final response
            combined = full_reasoning + full_content
            validated, val_err = validate_ai_response(combined)

            if not validated:
                log.warning(f'AI response validation failed: {val_err}')
                # Fallback: send the raw content anyway with a lower confidence
                fallback = {
                    'risk_level': 'Medium',
                    'threat_types': [],
                    'analysis': combined,
                    'indicators': [],
                    'recommended_actions': [],
                    'legal_references': [],
                    'confidence_score': 30
                }
                fallback_json = json.dumps(fallback)
                yield f'data: {json.dumps({"type": "content", "content": fallback_json})}\n\n'
                yield f'data: {json.dumps({"type": "done", "reasoning": full_reasoning, "content": fallback_json})}\n\n'
            else:
                yield f'data: {json.dumps({"type": "done", "reasoning": full_reasoning, "content": combined})}\n\n'

            # Cache the result
            cache.set(cleaned, f'data: {json.dumps({"type": "done", "reasoning": full_reasoning, "content": combined})}\n\n')

        except requests.exceptions.RequestException as e:
            inc_metric('errors')
            log.error(f'Stream error: {e}')
            yield f'data: {json.dumps({"type": "error", "content": str(e)})}\n\n'

        finally:
            elapsed = (time.time() - start) * 1000
            inc_metric('latency', elapsed)

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'model': MODEL,
        'api_key_configured': bool(NVIDIA_API_KEY),
        'uptime_seconds': int(time.time() - metrics['started_at'])
    })

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    rate_limiter.cleanup()
    return jsonify({
        'requests_total': metrics['requests_total'],
        'cache_hits': metrics['cache_hits'],
        'errors': metrics['errors'],
        'avg_latency_ms': round(metrics['avg_latency_ms'], 2),
        'uptime_seconds': int(time.time() - metrics['started_at']),
        'cache_size': cache._store.__len__() if hasattr(cache._store, '__len__') else len(cache._store)
    })

# ── production entry point ──
if __name__ == '__main__':
    import sys
    if '--prod' in sys.argv:
        log.info('Starting in production mode (use gunicorn)')
        log.info('Run: gunicorn -w 4 -k sync -t 120 server:app')
    else:
        log.info(f'Starting ScanForge dev server on http://localhost:5000')
        app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
