from flask import Flask, request, jsonify
import subprocess
import tempfile
import os

app = Flask(__name__)

@app.route('/scan', methods=['POST'])
def scan():
    file = request.files['file']
    if not file:
        return jsonify({'error': 'No file provided'}), 400

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        file.save(tmp.name)
        try:
            result = subprocess.run(['clamscan', '--no-summary', tmp.name], capture_output=True, text=True)
            os.unlink(tmp.name)
            if result.returncode == 0:
                return jsonify({'status': 'clean'})
            elif result.returncode == 1:
                return jsonify({'status': 'infected', 'details': result.stdout.strip()})
            else:
                return jsonify({'error': 'scan failed', 'details': result.stderr})
        except Exception as e:
            os.unlink(tmp.name)
            return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
