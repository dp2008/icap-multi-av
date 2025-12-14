from flask import Flask, request, jsonify
import subprocess
import tempfile
import os
import re
from datetime import datetime

app = Flask(__name__)

def get_clamav_version():
    """
    Liest die ClamAV-Programmversion und Signatur-Datenbankversion aus.
    Nutzt clamscan --version für die Programmversion und sigtool für die DB-Version.
    """
    try:
        # ClamAV Programmversion abrufen
        version_result = subprocess.run(['clamscan', '--version'], 
                                      capture_output=True, text=True, timeout=5)
        program_version = version_result.stdout.strip()
        
        # Signatur-Datenbankversion aus main.cvd/cld auslesen
        db_version = None
        db_date = None
        
        # Versuche sigtool zu verwenden (bevorzugte Methode)
        try:
            sigtool_result = subprocess.run(['sigtool', '--info', '/var/lib/clamav/main.cvd'], 
                                          capture_output=True, text=True, timeout=5)
            
            # Falls main.cvd nicht existiert, versuche main.cld
            if sigtool_result.returncode != 0:
                sigtool_result = subprocess.run(['sigtool', '--info', '/var/lib/clamav/main.cld'], 
                                              capture_output=True, text=True, timeout=5)
            
            if sigtool_result.returncode == 0:
                output = sigtool_result.stdout
                
                # Version extrahieren (z.B. "Version: 62")
                version_match = re.search(r'Version:\s*(\d+)', output)
                if version_match:
                    db_version = version_match.group(1)
                
                # Build time extrahieren
                build_match = re.search(r'Build time:\s*(.+)', output)
                if build_match:
                    db_date = build_match.group(1).strip()
                    
        except FileNotFoundError:
            # sigtool nicht verfügbar, nutze Alternative
            pass
        
        # Falls sigtool nicht funktioniert, versuche freshclam.log
        if not db_version:
            try:
                with open('/var/log/clamav/freshclam.log', 'r') as f:
                    log_content = f.read()
                    # Suche nach der letzten Version in den Logs
                    version_matches = re.findall(r'main\.cvd.*version:\s*(\d+)', log_content)
                    if version_matches:
                        db_version = version_matches[-1]
            except:
                pass
        
        # Falls immer noch keine Version gefunden, nutze Dateistempel
        if not db_version:
            db_version = "unknown"
            
        if not db_date:
            # Versuche Dateistempel als Fallback
            try:
                cvd_path = '/var/lib/clamav/main.cvd'
                if not os.path.exists(cvd_path):
                    cvd_path = '/var/lib/clamav/main.cld'
                
                if os.path.exists(cvd_path):
                    timestamp = os.path.getmtime(cvd_path)
                    db_date = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            except:
                db_date = "unknown"
        
        return {
            'program_version': program_version,
            'signature_version': db_version,
            'last_update': db_date
        }
        
    except Exception as e:
        return {
            'program_version': 'unknown',
            'signature_version': 'unknown',
            'last_update': 'unknown',
            'error': str(e)
        }

@app.route('/version', methods=['GET'])
def version():
    """
    Endpoint zum Abrufen der ClamAV-Version und Signaturdatenbank-Version
    """
    version_info = get_clamav_version()
    return jsonify(version_info)

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
