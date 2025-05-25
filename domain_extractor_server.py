from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import tempfile
from domain_extractor import extract_domains, get_domain_ip

app = Flask(__name__)
CORS(app)

def process_domains(text):
    """Extract and resolve domains using domain_extractor.py functions"""
    domains = extract_domains(text)
    results = []
    
    for domain in domains:
        ip = get_domain_ip(domain)
        results.append({
            'domain': domain,
            'status': 'resolved' if ip else 'valid',
            'ip': ip,
            'id': domain.replace('.', '_')
        })
    
    return results

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/extract', methods=['POST'])
def extract_domains_api():
    try:
        data = request.get_json()
        text = data.get('text', '')
        if not text:
            return jsonify({'error': 'No text provided'}), 400

        results = process_domains(text)
        return jsonify({
            'success': True,
            'results': results,
            'stats': {
                'total': len(results),
                'resolved': len([r for r in results if r['ip']]),
                'valid': len([r for r in results if not r['ip']])
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/extract-file', methods=['POST'])
def extract_from_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        text = file.read().decode('utf-8')
        results = process_domains(text)

        return jsonify({
            'success': True,
            'results': results,
            'stats': {
                'total': len(results),
                'resolved': len([r for r in results if r['ip']]),
                'valid': len([r for r in results if not r['ip']])
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download', methods=['POST'])
def download_results():
    try:
        data = request.get_json()
        results = data.get('results', [])
        
        lines = [f"{r['domain']} {r['ip']}" if r.get('ip') else r['domain'] for r in results]
        content = '\n'.join(lines)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(content)
            temp_path = f.name

        return send_from_directory(
            os.path.dirname(temp_path),
            os.path.basename(temp_path),
            as_attachment=True,
            download_name='extracted_domains.txt'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Domain Extractor Server running on http://localhost:5000")
    app.run(debug=True, port=5000)
