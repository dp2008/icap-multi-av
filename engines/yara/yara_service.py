from flask import Flask, request, jsonify
import yara
import tempfile
import os
import glob

app = Flask(__name__)

# Load rules - compile all .yar files in /rules directory
yar_files = glob.glob('/rules/**/*.yar', recursive=True)
if yar_files:
    rules = yara.compile(filepaths={f'rule_{i}': f for i, f in enumerate(yar_files[:10])})  # Limit to 10 rules for performance
else:
    rules = None

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
