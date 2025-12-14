# MetaScanner - Verbessertes Webinterface

## Übersicht

Das Webinterface wurde komplett überarbeitet und orientiert sich am Design und den Funktionen von **MetaDefender Core von OPSWAT**.

## Implementierte Funktionen

### 1. **Dashboard** (`/`)
- Übersicht über alle Scan-Aktivitäten
- Statistiken: Gesamte Scans, Bedrohungen, saubere Dateien, aktive Engines
- Aktuelle Scan-Aktivitäten in Tabellenform
- Engine-Status-Übersicht
- Schnellaktionen für häufige Aufgaben

### 2. **Dateien scannen** (`/scan-file`)
- **Einzeldatei-Scan**: Upload und Scan von einzelnen Dateien
- **Ordner-Scan (NEU)**: Upload und Scan mehrerer Dateien gleichzeitig
- Übersicht der aktiven Scan-Engines
- Hinweise zur Nutzung
- Interaktive Upload-Bereiche mit Drag & Drop Support

### 3. **Scan-Verlauf / Processing History** (`/history`)
- Vollständige Historie aller durchgeführten Scans
- Filtermöglichkeiten und Sortierung
- Detailansicht für jeden Scan
- Möglichkeit zum Löschen des gesamten Verlaufs
- Status-Badges (Sauber, Bedrohung erkannt)

### 4. **Inventory Management** (`/inventory`)
- Verwaltung aller Scan-Engines
- Aktivieren/Deaktivieren von Engines
- Detaillierte Engine-Informationen
- Engine-Beschreibungen (ClamAV, YARA, OleTools, CAPA)
- Status-Übersicht und Endpunkt-Informationen

### 5. **Regular Maintenance** (`/maintenance`)
- Cache leeren (Redis)
- Scan-Verlauf löschen
- Systemstatus anzeigen
- Wartungsprotokoll
- Wartungsempfehlungen und Best Practices

### 6. **Import/Export Configuration** (`/config`)
- **Export**: Konfiguration als JSON-Datei exportieren
  - Engine-Einstellungen
  - Zeitstempel
  - Versionsinformationen
- **Import**: Konfiguration aus JSON-Datei importieren
- Anwendungsfälle und Dokumentation
- Beispiel-Konfiguration

## Design-Features

### Modern und Professionell
- **Farbschema**: Blaue/graue Palette (MetaDefender-Stil)
- **Sidebar-Navigation**: Fixierte Navigation mit Icons
- **Responsive Cards**: Moderne Karten-Layouts
- **Status-Badges**: Farbcodierte Status-Anzeigen
- **Statistik-Karten**: Übersichtliche Darstellung von KPIs

### Benutzerfreundlichkeit
- Klare visuelle Hierarchie
- Intuitive Navigation
- Aussagekräftige Icons und Emojis
- Flash-Nachrichten für Benutzer-Feedback
- Bestätigungsdialoge für kritische Aktionen

### Professionelle UX
- Empty States für leere Listen
- Ladezustände und Feedback
- Konsistente Button-Stile
- Hover-Effekte und Transitions
- Responsive Tabellen

## Technische Details

### Backend (Flask)
- **Framework**: Flask 2.3.3
- **Features**:
  - Session-Management
  - File Upload Handling
  - Multi-File Support
  - Configuration Management
  - History Tracking

### Frontend (Templates)
- **Template Engine**: Jinja2
- **Base Template**: Wiederverwendbares Layout
- **CSS**: Inline-Styles für einfache Wartung
- **JavaScript**: Minimaler JS für Interaktivität

### API (FastAPI)
- **Framework**: FastAPI
- **Endpoints**:
  - `/scan` - Dateien scannen
  - `/engines` - Engine-Liste abrufen
  - `/engines/{engine}/toggle` - Engine aktivieren/deaktivieren
  - `/maintenance/clear-cache` - Cache leeren

## Dateistruktur

```
services/web-ui/
├── app.py                          # Flask-Anwendung (erweitert)
├── requirements.txt                # Python-Dependencies
├── Dockerfile                      # Container-Konfiguration
└── templates/
    ├── base.html                   # Basis-Template mit Navigation
    ├── dashboard.html              # Dashboard-Seite
    ├── scan_file.html              # Datei-Scan-Seite (neu/erweitert)
    ├── result.html                 # Einzelergebnis-Seite (überarbeitet)
    ├── folder_results.html         # Ordner-Scan-Ergebnisse (neu)
    ├── history.html                # Scan-Verlauf (neu)
    ├── inventory.html              # Engine-Verwaltung (neu)
    ├── maintenance.html            # Wartungs-Seite (neu)
    └── config.html                 # Import/Export-Seite (neu)

services/core-api/
└── app.py                          # FastAPI-Backend (erweitert)
```

## Starten des Systems

### Mit Docker Compose (empfohlen):
```bash
cd C:\Users\Administrator\Desktop\multiscanner
docker compose up --build -d
```

### Zugriff:
- **Webinterface**: http://localhost:3000
- **Core API**: http://localhost:5000

## Navigation

Die Sidebar enthält alle Hauptbereiche:
1. 📊 **Dashboard** - Übersicht
2. 🔍 **Dateien scannen** - Scan-Funktionen
3. 📋 **Scan-Verlauf** - Historie
4. 📦 **Inventory Management** - Engine-Verwaltung
5. 🔧 **Wartung** - Maintenance-Funktionen
6. ⚙️ **Konfiguration** - Import/Export

## Neue Features im Detail

### Ordner-Scan
- Upload mehrerer Dateien gleichzeitig
- Parallele Verarbeitung
- Zusammenfassende Statistiken
- Einzelne Detailansichten für jede Datei

### Dashboard-Statistiken
- Echtzeit-Übersicht aller Aktivitäten
- Engine-Status auf einen Blick
- Schnellzugriff auf wichtige Funktionen

### Configuration Management
- Backup der Systemkonfiguration
- Einfache Migration zwischen Instanzen
- Versionskontrolle für Einstellungen

## Verbesserungen gegenüber vorher

### Alt:
- Einfache HTML-Seite ohne Styling
- Nur Einzeldatei-Upload
- Keine Navigation
- Kein Dashboard
- Keine Historie
- Keine Engine-Verwaltung

### Neu:
- ✅ Professionelles Design im MetaDefender-Stil
- ✅ Vollständige Navigation
- ✅ Dashboard mit Statistiken
- ✅ Ordner-Scan-Funktion
- ✅ Processing History
- ✅ Inventory Management
- ✅ Maintenance-Bereich
- ✅ Configuration Import/Export
- ✅ Benutzerfreundliche UX
- ✅ Status-Feedback und Benachrichtigungen

## Anpassungen und Erweiterungen

### Farben ändern:
In `base.html` können die Farben im `<style>`-Bereich angepasst werden:
- Header: `background: #1e3a8a;`
- Sidebar: `background: #1f2937;`
- Primärfarbe: `#3b82f6`

### Weitere Engines hinzufügen:
In `services/core-api/app.py` im `engines`-Dictionary:
```python
engines = {
    'neue_engine': {'url': 'http://neue-engine:8080/scan', 'active': True},
}
```

### Datenbank-Integration:
Aktuell werden Scan-Historie und Logs im Speicher gehalten. Für Produktion empfohlen:
- PostgreSQL oder MongoDB für persistente Speicherung
- SQLAlchemy für ORM
- Alembic für Migrations

## Support und Wartung

Bei Fragen oder Problemen:
1. Logs prüfen: `docker compose logs -f web-ui`
2. Container neustarten: `docker compose restart web-ui`
3. Cache leeren über Maintenance-Bereich

## Lizenz

Siehe Hauptprojekt-README
