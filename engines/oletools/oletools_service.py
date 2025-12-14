from flask import Flask, request, jsonify
from oletools.olevba import VBA_Parser
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
            vba_parser = VBA_Parser(tmp.name)
            if vba_parser.detect_vba_macros():
                macros = vba_parser.get_vba_code()
                suspicious = any('suspicious' in str(m).lower() for m in macros)  # Simple check
                os.unlink(tmp.name)
                if suspicious:
                    return jsonify({'status': 'suspicious', 'details': 'Macros detected'})
                else:
                    return jsonify({'status': 'clean', 'details': 'Macros present but not suspicious'})
            else:
                os.unlink(tmp.name)
                return jsonify({'status': 'clean', 'details': 'No macros'})
        except Exception as e:
            os.unlink(tmp.name)
            return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
