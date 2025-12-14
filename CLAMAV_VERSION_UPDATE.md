# ClamAV Virendefinitionen - Version Auslesen

## Überblick

Die ClamAV-Versionserkennung wurde überarbeitet, um die echte Signaturversion aus dem Docker-Container auszulesen, anstatt eine hardcodierte Version anzuzeigen.

## Implementierte Änderungen

### 1. ClamAV Service (`engines/clamav/clamav_service.py`)

**Neuer `/version` Endpoint hinzugefügt:**

Der ClamAV-Service verfügt nun über einen neuen Endpoint, der die Versionsinformationen ausliest:

```python
@app.route('/version', methods=['GET'])
def version():
    """
    Endpoint zum Abrufen der ClamAV-Version und Signaturdatenbank-Version
    """
    version_info = get_clamav_version()
    return jsonify(version_info)
```

**Methoden zur Versionsauslesung:**

Die Funktion `get_clamav_version()` nutzt verschiedene Methoden in folgender Priorität:

1. **`clamscan --version`**: Liest die ClamAV-Programmversion aus
2. **`sigtool --info /var/lib/clamav/main.cvd`**: Liest die Datenbankversion aus der CVD-Datei (bevorzugte Methode)
3. **Fallback auf `main.cld`**: Falls main.cvd nicht existiert
4. **`/var/log/clamav/freshclam.log`**: Alternative, falls sigtool nicht verfügbar ist
5. **Dateistempel**: Als letzter Fallback wird das Änderungsdatum der Datenbankdatei verwendet

**Rückgabeformat:**

```json
{
  "program_version": "ClamAV 1.0.0/27123/...",
  "signature_version": "62",
  "last_update": "2024-12-14 10:30:00"
}
```

### 2. Core API (`services/core-api/app.py`)

**Neue Funktion `get_engine_version()`:**

Diese asynchrone Funktion ruft die Versionsinformationen vom jeweiligen Engine-Service ab:

```python
async def get_engine_version(engine_name: str):
    """
    Ruft die echte Signaturversion vom Engine-Service ab.
    Für ClamAV wird der /version Endpoint verwendet.
    """
    # Erstellt Version-URL (z.B. http://clamav:8080/version)
    # Ruft die Informationen ab
    # Aktualisiert die Engine-Daten
```

**Angepasste Endpoints:**

- **`GET /engines`**: Ruft nun automatisch die echte ClamAV-Version ab
- **`POST /engines/{engine}/signatures/update`**: Aktualisiert die Version nach einem Signatur-Update

## Verwendung

### Version im Webinterface anzeigen

Wenn Sie die Engine-Übersicht im Webinterface aufrufen, wird automatisch die aktuelle ClamAV-Version vom Container abgerufen und angezeigt.

### Manuell Version abfragen

**Direkt vom ClamAV-Container:**

```bash
# Container-ID finden
docker ps | grep clamav

# Version abfragen
docker exec <container_id> curl http://localhost:8080/version
```

**Über die Core-API:**

```bash
curl http://localhost:5000/engines
```

### Container neu starten (um Änderungen zu übernehmen)

```bash
cd C:\Users\Administrator\Desktop\multiscanner

# Mit docker-compose v2
docker compose up -d --build clamav core-api

# ODER mit docker-compose v1
docker-compose up -d --build clamav core-api
```

## Technische Details

### Warum sigtool?

`sigtool` ist das offizielle ClamAV-Tool zur Inspektion von Signaturdatenbanken. Es liefert detaillierte Informationen:

```bash
docker exec <container_id> sigtool --info /var/lib/clamav/main.cvd
```

Ausgabe:
```
File: /var/lib/clamav/main.cvd
Build time: 14 Dec 2024 10:30 +0000
Version: 62
Signatures: 6647427
...
```

### Fallback-Mechanismen

Falls `sigtool` nicht verfügbar ist (z.B. in minimalen Docker-Images), gibt es mehrere Fallback-Optionen:

1. **freshclam.log**: Enthält Update-Logs mit Versionsinformationen
2. **Dateistempel**: Verwendet das Änderungsdatum der CVD/CLD-Datei
3. **"unknown"**: Falls alle Methoden fehlschlagen

### Performance

- Die Version wird nur abgerufen, wenn `/engines` aufgerufen wird
- Timeout: 5 Sekunden
- Bei Fehler: Verwendet die zuletzt bekannte Version

## Vorteile

✅ **Echte Daten**: Zeigt die tatsächliche Signaturversion aus dem Container an  
✅ **Automatisch**: Keine manuelle Aktualisierung der Version nötig  
✅ **Robust**: Mehrere Fallback-Mechanismen  
✅ **Erweiterbar**: Kann für andere Engines (YARA, etc.) adaptiert werden  

## Nächste Schritte (Optional)

1. **Auto-Update implementieren**: freshclam automatisch aufrufen
2. **Für andere Engines erweitern**: YARA, OleTools, etc.
3. **Caching**: Versionsinformationen für bessere Performance cachen
4. **Benachrichtigungen**: Bei veralteten Signaturen warnen

## Fehlerbehebung

**Problem: Version zeigt "unknown"**

Lösung:
```bash
# Prüfen, ob sigtool verfügbar ist
docker exec <container_id> which sigtool

# Prüfen, ob Datenbankdateien existieren
docker exec <container_id> ls -l /var/lib/clamav/

# Logs überprüfen
docker logs <container_id>
```

**Problem: Timeout beim Abrufen**

Lösung: Erhöhen Sie das Timeout in `core-api/app.py`:
```python
async with httpx.AsyncClient(timeout=10.0) as client:  # von 5.0 auf 10.0
```

## Zusammenfassung

Die Implementierung folgt genau dem beschriebenen Schema und nutzt:
- ✅ `clamscan --version` für die Programmversion
- ✅ `sigtool --info` für die Datenbankversion
- ✅ Docker exec über HTTP-Endpoints
- ✅ Fallback-Mechanismen für Robustheit
