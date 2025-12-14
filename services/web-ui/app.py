from flask import Flask, render_template, request, redirect, url_for
import requests

app = Flask(__name__)

CORE_API_URL = 'http://core-api:5000'

@app.route('/')
def index():
    try:
        engines = requests.get(f'{CORE_API_URL}/engines').json()
    except:
        engines = {}
    return render_template('index.html', engines=engines)

@app.route('/scan', methods=['POST'])
def scan():
    file = request.files['file']
    if file:
        files = {'file': (file.filename, file.stream, file.mimetype)}
        response = requests.post(f'{CORE_API_URL}/scan', files=files)
        result = response.json()
        return render_template('result.html', result=result)
    return redirect(url_for('index'))

@app.route('/toggle/<engine>', methods=['POST'])
def toggle(engine):
    active = request.form.get('active') == 'true'
    requests.post(f'{CORE_API_URL}/engines/{engine}/toggle', data={'active': active})
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)
