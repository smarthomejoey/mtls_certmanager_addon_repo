# mTLS Cert Manager Add-on für Home Assistant

Dieses Add-on ermöglicht das Erstellen von mTLS Client-Zertifikaten im lokalen Netzwerk mit WebUI.  
Das Zertifikat wird als `.p12` (PKCS#12) exportiert und mit einer einmalig generierten UUID-Passphrase geschützt.  

## Features
- Zertifikatserstellung mit OpenSSL (10 Jahre gültig)  
- Export als `.p12` inklusive privatem Schlüssel und CA-Zertifikat  
- Passphrase wird nur einmal angezeigt und nicht gespeichert  
- WebUI für einfache Bedienung im LAN  
- Optionaler automatischer Sync der CA & CRL per SSH zum Nginx Proxy Manager  
- Automatisches Dependency-Update via Dependabot (wenn auf GitHub gehostet)  
- GitHub Actions Workflow für Build und Lint

## Installation

1. Repository als Add-on Repository im Home Assistant Supervisor hinzufügen  
2. Add-on installieren und starten  
3. WebUI über `http://<deine-homeassistant-ip>:5000` aufrufen  
4. Common Name (CN) eingeben und Zertifikat erstellen  
5. Passphrase notieren und `.p12` Datei herunterladen

## Konfiguration

In den Add-on Optionen können SSH-Zugangsdaten und Pfade für den Sync zu Nginx Proxy Manager hinterlegt werden.  

## Lizenz

MIT

