from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_file
import requests
import json
import os
from datetime import datetime
from werkzeug.utils import secure_filename
import zipfile
import io

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'

CORE_API_URL = 'http://core-api:5000'
UPLOAD_FOLDER = '/tmp/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# In-memory storage for scan history (in production, use database)
scan_history = []
maintenance_logs = []

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    try:
        engines = requests.get(f'{CORE_API_URL}/engines').json()
        
        # Calculate statistics
        total_scans = len(scan_history)
        active_engines = sum(1 for e in engines.values() if e.get('active', False))
        total_engines = len(engines)
        
        # Recent scans
        recent_scans = scan_history[-10:] if scan_history else []
        recent_scans.reverse()
        
        # Threat statistics
        threats_detected = sum(1 for scan in scan_history if scan.get('threats_found', False))
        clean_files = total_scans - threats_detected
        
        stats = {
            'total_scans': total_scans,
            'threats_detected': threats_detected,
            'clean_files': clean_files,
            'active_engines': active_engines,
            'total_engines': total_engines,
            'recent_scans': recent_scans
        }
    except Exception as e:
        stats = {
            'total_scans': 0,
            'threats_detected': 0,
            'clean_files': 0,
            'active_engines': 0,
            'total_engines': 0,
            'recent_scans': []
        }
        engines = {}
    
    return render_template('dashboard.html', stats=stats, engines=engines)

@app.route('/scan-file')
def scan_file_page():
    try:
        engines = requests.get(f'{CORE_API_URL}/engines').json()
    except:
        engines = {}
    return render_template('scan_file.html', engines=engines)

@app.route('/scan', methods=['POST'])
def scan():
    file = request.files.get('file')
    if file:
        filename = secure_filename(file.filename)
        files = {'file': (filename, file.stream, file.mimetype)}
        
        try:
            response = requests.post(f'{CORE_API_URL}/scan', files=files)
            result = response.json()
            
            # Check if any threats were detected
            threats_found = any(
                'detected' in str(engine_result).lower() or 
                'malicious' in str(engine_result).lower() or
                'virus' in str(engine_result).lower()
                for engine_result in result.values()
                if isinstance(engine_result, dict)
            )
            
            # Calculate hash
            import hashlib
            file.stream.seek(0)
            file_hash = hashlib.sha256(file.stream.read()).hexdigest()
            file.stream.seek(0)
            
            # Check if from cache
            from_cache = result.get('from_cache', False)
            
            # Add to history
            scan_entry = {
                'id': len(scan_history) + 1,
                'filename': filename,
                'hash': file_hash,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'Threat detected' if threats_found else 'Clean',
                'threats_found': threats_found,
                'from_cache': from_cache,
                'result': result
            }
            scan_history.append(scan_entry)
            
            return render_template('result.html', result=result, filename=filename, threats_found=threats_found)
        except Exception as e:
            flash(f'Fehler beim Scannen: {str(e)}', 'error')
            return redirect(url_for('scan_file_page'))
    
    flash('Keine Datei ausgewählt', 'error')
    return redirect(url_for('scan_file_page'))

@app.route('/scan-folder', methods=['POST'])
def scan_folder():
    files = request.files.getlist('folder')
    if not files:
        flash('Keine Dateien ausgewählt', 'error')
        return redirect(url_for('scan_file_page'))
    
    results = []
    for file in files:
        if file.filename:
            filename = secure_filename(file.filename)
            try:
                files_data = {'file': (filename, file.stream.read(), file.mimetype)}
                response = requests.post(f'{CORE_API_URL}/scan', files=files_data)
                result = response.json()
                
                threats_found = any(
                    'detected' in str(engine_result).lower() or 
                    'malicious' in str(engine_result).lower() or
                    'virus' in str(engine_result).lower()
                    for engine_result in result.values()
                    if isinstance(engine_result, dict)
                )
                
                scan_entry = {
                    'id': len(scan_history) + 1,
                    'filename': filename,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'status': 'Threat detected' if threats_found else 'Clean',
                    'threats_found': threats_found,
                    'result': result
                }
                scan_history.append(scan_entry)
                results.append(scan_entry)
            except Exception as e:
                results.append({
                    'filename': filename,
                    'status': 'Error',
                    'error': str(e)
                })
    
    return render_template('folder_results.html', results=results)

@app.route('/history')
def history():
    # Reverse for most recent first
    history_reversed = list(reversed(scan_history))
    return render_template('history.html', scans=history_reversed)

@app.route('/history/<int:scan_id>')
def history_detail(scan_id):
    scan = next((s for s in scan_history if s['id'] == scan_id), None)
    if scan:
        return render_template('result.html', 
                             result=scan['result'], 
                             filename=scan['filename'],
                             threats_found=scan['threats_found'])
    flash('Scan nicht gefunden', 'error')
    return redirect(url_for('history'))

@app.route('/inventory')
def inventory():
    try:
        engines = requests.get(f'{CORE_API_URL}/engines').json()
    except:
        engines = {}
    return render_template('inventory.html', engines=engines)

@app.route('/inventory/<engine>/signatures')
def engine_signatures(engine):
    try:
        engines = requests.get(f'{CORE_API_URL}/engines').json()
        signatures = requests.get(f'{CORE_API_URL}/engines/{engine}/signatures').json()
    except:
        engines = {}
        signatures = {'signatures': []}
    return render_template('engine_signatures.html', engine=engine, engines=engines, signatures=signatures.get('signatures', []))

@app.route('/inventory/<engine>/signatures/upload', methods=['POST'])
def upload_signature(engine):
    file = request.files.get('signature_file')
    if file:
        try:
            files = {'file': (file.filename, file.stream, file.mimetype)}
            response = requests.post(f'{CORE_API_URL}/engines/{engine}/signatures/upload', files=files)
            if response.status_code == 200:
                flash(f'Signatur {file.filename} erfolgreich hochgeladen', 'success')
            else:
                flash('Fehler beim Hochladen der Signatur', 'error')
        except Exception as e:
            flash(f'Fehler: {str(e)}', 'error')
    else:
        flash('Keine Datei ausgewählt', 'error')
    return redirect(url_for('engine_signatures', engine=engine))

@app.route('/inventory/<engine>/signatures/<signature_name>/delete', methods=['POST'])
def delete_signature(engine, signature_name):
    try:
        response = requests.delete(f'{CORE_API_URL}/engines/{engine}/signatures/{signature_name}')
        if response.status_code == 200:
            flash(f'Signatur {signature_name} erfolgreich gelöscht', 'success')
        else:
            flash('Fehler beim Löschen der Signatur', 'error')
    except Exception as e:
        flash(f'Fehler: {str(e)}', 'error')
    return redirect(url_for('engine_signatures', engine=engine))

@app.route('/inventory/<engine>/update', methods=['POST'])
def update_engine_signatures(engine):
    try:
        response = requests.post(f'{CORE_API_URL}/engines/{engine}/signatures/update')
        if response.status_code == 200:
            data = response.json()
            flash(f'Signaturen für {engine} erfolgreich aktualisiert! Neue Version: {data.get("version")}', 'success')
            log_entry = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'action': f'Signatures updated for {engine}',
                'status': 'Success'
            }
            maintenance_logs.append(log_entry)
        else:
            flash('Fehler beim Aktualisieren der Signaturen', 'error')
    except Exception as e:
        flash(f'Fehler: {str(e)}', 'error')
    return redirect(url_for('inventory'))

@app.route('/inventory/<engine>/auto-update', methods=['POST'])
def set_auto_update(engine):
    try:
        enabled = request.form.get('enabled') == 'true'
        schedule = request.form.get('schedule', 'daily')
        
        response = requests.post(f'{CORE_API_URL}/engines/{engine}/auto-update',
                               json={'enabled': enabled, 'schedule': schedule})
        
        if response.status_code == 200:
            status = 'aktiviert' if enabled else 'deaktiviert'
            flash(f'Automatische Updates für {engine} {status} ({schedule})', 'success')
        else:
            flash('Fehler beim Aktualisieren der Auto-Update-Einstellungen', 'error')
    except Exception as e:
        flash(f'Fehler: {str(e)}', 'error')
    return redirect(url_for('inventory'))

@app.route('/toggle/<engine>', methods=['POST'])
def toggle(engine):
    try:
        active = request.form.get('active') == 'true'
        response = requests.post(f'{CORE_API_URL}/engines/{engine}/toggle', 
                               json={'active': active})
        
        if response.status_code == 200:
            status = 'aktiviert' if active else 'deaktiviert'
            flash(f'Engine {engine} wurde {status}', 'success')
        else:
            flash(f'Fehler beim Aktualisieren der Engine', 'error')
    except Exception as e:
        flash(f'Fehler: {str(e)}', 'error')
    
    return redirect(url_for('inventory'))

@app.route('/maintenance')
def maintenance():
    logs_reversed = list(reversed(maintenance_logs))
    return render_template('maintenance.html', logs=logs_reversed)

@app.route('/maintenance/clear-cache', methods=['POST'])
def clear_cache():
    try:
        response = requests.post(f'{CORE_API_URL}/maintenance/clear-cache')
        if response.status_code == 200:
            log_entry = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'action': 'Cache cleared',
                'status': 'Success'
            }
            maintenance_logs.append(log_entry)
            flash('Cache erfolgreich geleert', 'success')
        else:
            flash('Fehler beim Leeren des Cache', 'error')
    except Exception as e:
        flash(f'Fehler: {str(e)}', 'error')
    
    return redirect(url_for('maintenance'))

@app.route('/maintenance/clear-history', methods=['POST'])
def clear_history():
    global scan_history
    scan_history = []
    log_entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'action': 'History cleared',
        'status': 'Success'
    }
    maintenance_logs.append(log_entry)
    flash('Scan-Historie erfolgreich geleert', 'success')
    return redirect(url_for('maintenance'))

@app.route('/config')
def config():
    return render_template('config.html')

@app.route('/config/export', methods=['POST'])
def export_config():
    try:
        engines = requests.get(f'{CORE_API_URL}/engines').json()
        
        config_data = {
            'engines': engines,
            'export_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'version': '1.0'
        }
        
        # Create JSON file
        json_str = json.dumps(config_data, indent=2)
        buffer = io.BytesIO()
        buffer.write(json_str.encode('utf-8'))
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f'metascanner_config_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json',
            mimetype='application/json'
        )
    except Exception as e:
        flash(f'Fehler beim Exportieren: {str(e)}', 'error')
        return redirect(url_for('config'))

@app.route('/config/import', methods=['POST'])
def import_config():
    file = request.files.get('config_file')
    if file:
        try:
            config_data = json.load(file)
            
            # Apply configuration
            if 'engines' in config_data:
                for engine, settings in config_data['engines'].items():
                    if 'active' in settings:
                        requests.post(f'{CORE_API_URL}/engines/{engine}/toggle', 
                                    json={'active': settings['active']})
            
            log_entry = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'action': 'Configuration imported',
                'status': 'Success'
            }
            maintenance_logs.append(log_entry)
            flash('Konfiguration erfolgreich importiert', 'success')
        except Exception as e:
            flash(f'Fehler beim Importieren: {str(e)}', 'error')
    else:
        flash('Keine Datei ausgewählt', 'error')
    
    return redirect(url_for('config'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)
