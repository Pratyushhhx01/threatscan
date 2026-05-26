import os
import json
import requests
from flask import Flask, request, Response, stream_with_context, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder='.')
CORS(app)

NVIDIA_API_KEY = os.getenv('NVIDIA_API_KEY')
NVIDIA_BASE_URL = 'https://integrate.api.nvidia.com/v1'
MODEL = 'openai/gpt-oss-120b'

if not NVIDIA_API_KEY:
    print('WARNING: NVIDIA_API_KEY not found in .env file')

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('.', path)

def build_prompt(data):
    sender = data.get('sender', '').strip()
    subject = data.get('subject', '').strip()
    msg_type = data.get('msgType', '').strip() or 'Not specified'
    content = data.get('content', '').strip()

    details = []
    details.append(f'Message Content:\n---\n{content}\n---')
    if sender:
        details.append(f'Source/Sender: {sender}')
    if subject:
        details.append(f'Subject: {subject}')
    if msg_type != 'Not specified':
        details.append(f'Message Type: {msg_type}')

    prompt = f"""You are an enterprise-grade cybersecurity threat analysis AI. Analyze the following message for potential security threats, scams, phishing, malware, or social engineering attempts.

Provide your analysis in a structured JSON format with the following fields:
- risk_level: one of "Critical", "High", "Medium", "Low", "Safe"
- threat_types: array of detected threat types (e.g., "Phishing", "Social Engineering", "Malware", "Financial Fraud", "Spam", "Harassment", "Impersonation", etc.)
- analysis: detailed paragraph explaining the threat analysis
- indicators: array of specific suspicious indicators found
- recommended_actions: array of steps the user should take
- legal_references: array of applicable legal frameworks or charges
- confidence_score: number 0-100

Message Details:
{chr(10).join(details)}

First, think through your analysis step by step (this is your reasoning). Then provide the structured JSON response."""
    return prompt

@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    if not data:
        return {'error': 'No data provided'}, 400

    message_content = data.get('content', '').strip()
    if not message_content:
        return {'error': 'Message content is required'}, 400

    prompt = build_prompt(data)

    def generate():
        headers = {
            'Authorization': f'Bearer {NVIDIA_API_KEY}',
            'Content-Type': 'application/json'
        }

        payload = {
            'model': MODEL,
            'messages': [{'role': 'user', 'content': prompt}],
            'temperature': 0.3,
            'top_p': 0.9,
            'max_tokens': 4096,
            'stream': True
        }

        full_reasoning = ''
        full_content = ''

        try:
            resp = requests.post(
                f'{NVIDIA_BASE_URL}/chat/completions',
                headers=headers,
                json=payload,
                stream=True,
                timeout=120
            )
            resp.raise_for_status()

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

            yield f'data: {json.dumps({"type": "done", "reasoning": full_reasoning, "content": full_content})}\n\n'

        except requests.exceptions.RequestException as e:
            yield f'data: {json.dumps({"type": "error", "content": str(e)})}\n\n'

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

if __name__ == '__main__':
    print('Starting ThreatScan server on http://localhost:5000')
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
