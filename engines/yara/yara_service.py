from flask import Flask, request, jsonify
import yara
import tempfile
import os

app = Flask(__name__)

# Load rules
rules = yara.compile(filepath='/rules/yara/index.yar')

@app.route('/scan', methods=['POST'])
def scan():
    file = request.files['file']
    if not file:
        return jsonify({'error': 'No file provided'}), 400

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        file.save(tmp.name)
        try:
            matches = rules.match(tmp.name)
            os.unlink(tmp.name)
            if matches:
                return jsonify({'status': 'suspicious', 'matches': [str(m) for m in matches]})
            else:
                return jsonify({'status': 'clean'})
        except Exception as e:
            os.unlink(tmp.name)
            return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
