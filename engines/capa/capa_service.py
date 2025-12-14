from flask import Flask, request, jsonify
import tempfile
import os
import subprocess

app = Flask(__name__)

@app.route('/scan', methods=['POST'])
def scan():
    file = request.files['file']
    if not file:
        return jsonify({'error': 'No file provided'}), 400

    with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as tmp:
        file.save(tmp.name)
        try:
            # Run capa via subprocess
            result = subprocess.run(
                ['capa', tmp.name, '-j'],
                capture_output=True,
                text=True,
                timeout=30
            )
            os.unlink(tmp.name)
            
            if result.returncode == 0:
                return jsonify({'status': 'analyzed', 'details': result.stdout[:500]})
            else:
                return jsonify({'status': 'no_capabilities', 'info': 'File analyzed'})
        except subprocess.TimeoutExpired:
            os.unlink(tmp.name)
            return jsonify({'error': 'Analysis timeout'})
        except Exception as e:
            if os.path.exists(tmp.name):
                os.unlink(tmp.name)
            return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
