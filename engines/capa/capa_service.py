from flask import Flask, request, jsonify
import capa.main
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
            # Run capa analysis
            rules_path = '/rules'  # Assume rules are available
            args = capa.main.get_default_config()
            args.input_file = tmp.name
            args.rules = rules_path
            result = capa.main.main(args)
            os.unlink(tmp.name)
            if result:
                return jsonify({'status': 'capabilities_detected', 'details': str(result)})
            else:
                return jsonify({'status': 'no_capabilities'})
        except Exception as e:
            os.unlink(tmp.name)
            return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
