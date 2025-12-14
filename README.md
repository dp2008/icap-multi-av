# Multi-Engine Virenscanner mit ICAP-Anbindung

Ein modulares, lokales Multi-Engine Antivirus-System mit ICAP-Schnittstelle.

## Features

- **Multi-Engine Scanning**: ClamAV, YARA (Neo23x0), Oletools, Capa
- **Parallele Scans**: Alle Engines arbeiten gleichzeitig
- **Hash-Cache**: Redis-basierter Cache für schnelle Wiederholungsprüfungen
- **Web-Interface**: Steuerung und Datei-Upload
- **ICAP-Service**: Integration mit Proxies
- **Docker Compose**: Vollständig containerisiert

## Voraussetzungen

- Docker
- Docker Compose
- Git

## Installation & Start

```bash
# Repository klonen
git clone https://github.com/dp2008/icap-multi-av.git
cd icap-multi-av

# System starten
docker-compose up --build

# Im Hintergrund
docker-compose up -d --build
```

## Services

- **Web-UI**: http://localhost:3000
- **Core-API**: http://localhost:5000
- **ICAP**: Port 1344
- **Redis**: Port 6379

## Engines

- **ClamAV** (Port 8081): Signatur-basierte Erkennung
- **YARA** (Port 8082): Neo23x0 Rules
- **Oletools** (Port 8083): Office-Makro-Analyse
- **Capa** (Port 8084): Capabilities-Erkennung

## Logs anzeigen

```bash
# Alle Logs
docker-compose logs -f

# Einzelner Service
docker-compose logs -f core-api
docker-compose logs -f web-ui
```

## Stoppen

```bash
docker-compose down
```

## Troubleshooting

Falls Services nicht starten:
```bash
# Services neu bauen
docker-compose down
docker-compose up --build

# Logs prüfen
docker-compose logs core-api
docker-compose logs yara
