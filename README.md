# Nmap Tool für OpenWebUI / Ollama

Ein OpenWebUI-kompatibles Tool für Nmap-Portscans, das direkt über Ollama-Modelle genutzt werden kann.

---

## Voraussetzungen

### System
- OpenWebUI (v0.3.x oder neuer)
- Ollama mit einem tool-fähigen Modell (z.B. `llama3.1`, `mistral-nemo`, `qwen2.5`)
- nmap installiert auf dem Host-System

### Installation nmap
```bash
# Debian / Ubuntu
sudo apt install nmap

# RHEL / CentOS / Fedora
sudo dnf install nmap

# macOS
brew install nmap
```

### SYN-Scan (Optional, erfordert Root-Rechte)
```bash
# Methode 1: SUID-Bit setzen
sudo chmod u+s $(which nmap)

# Methode 2: OpenWebUI als Root betreiben (nicht empfohlen für Produktion)
```

---

## Installation in OpenWebUI

1. **Admin Panel** → **Tools** → **➕ Neues Tool**
2. Inhalt von `nmap_tool.py` vollständig einfügen
3. **Speichern**
4. In einem Chat das Tool über den **Tool-Toggle** aktivieren

---

## Verfügbare Funktionen

| Funktion | Beschreibung | Erfordert Root |
|---|---|---|
| `nmap_quick_scan` | Top-1000 Ports + Service-Detection | Nein |
| `nmap_port_scan` | Gezielter Scan mit wählbarem Typ | Nur bei SYN |
| `nmap_os_detection` | OS-Fingerprinting + Services | Ja |
| `nmap_vulnerability_scan` | NSE `--script=vuln` | Nein |
| `nmap_custom_scan` | Eigene nmap-Argumente (Experten) | Abhängig |

---

## Konfiguration (Valves)

Einstellbar unter **Tool-Settings** im Admin Panel:

| Parameter | Standard | Beschreibung |
|---|---|---|
| `allowed_networks` | *(leer)* | Whitelist für Ziele als CIDR/IP, kommagetrennt. Leer = keine Einschränkung. Beispiel: `192.168.1.0/24,10.0.0.0/8` |
| `max_ports` | `10000` | Maximale Anzahl scanbarer Ports |
| `timeout` | `300` | Scan-Timeout in Sekunden |

---

## Beispiel-Prompts für Ollama

```
Scanne 192.168.1.1 auf die häufigsten offenen Ports.

Führe einen TCP-Scan auf 10.0.0.5 für Ports 22, 80, 443, 8080 durch.

Mache eine OS-Erkennung auf dem Host 172.16.0.10.

Scanne das Netz 192.168.1.0/24 schnell auf offene Ports.

Führe einen Vulnerability Scan auf 10.0.0.1 Port 80 und 443 durch.

Nutze folgende nmap-Argumente auf 192.168.1.5: -sV -p 21,22,23,25,53,80,110,443 --script=banner
```

---

## Unterstützte Scan-Typen (`nmap_port_scan`)

| Typ | Flag | Beschreibung |
|---|---|---|
| `SYN` | `-sS` | Stealth-Scan, schnell, erfordert Root |
| `TCP` | `-sT` | Vollständiger TCP-Connect, kein Root nötig |
| `UDP` | `-sU` | UDP-Scan, langsamer |
| `Version` | `-sV` | Nur Service-Version, kein Port-Typ-Scan |

---

## Sicherheitshinweise

> ⚠️ **Dieses Tool ist ausschließlich für autorisierte Penetrationstests und Sicherheitsaudits bestimmt.**

- Scans nur auf Systeme durchführen, für die eine ausdrückliche schriftliche Genehmigung vorliegt.
- Die `allowed_networks`-Valve sollte in produktiven Umgebungen immer gesetzt werden.
- Shell-Injection wird durch Validierung der Argumente in `nmap_custom_scan` verhindert.
- Logs des OpenWebUI-Systems aufbewahren (Compliance / Nachweispflicht).

---

## Kompatible Ollama-Modelle (Tool-Use)

Folgende Modelle unterstützen nativ Function/Tool Calling:

- `llama3.1:8b` / `llama3.1:70b`
- `llama3.2:3b`
- `mistral-nemo`
- `qwen2.5:7b` / `qwen2.5:14b`
- `command-r` / `command-r-plus`
- `firefunction-v2`

> ℹ️ Modelle ohne nativen Tool-Support können das Tool nicht automatisch aufrufen. In OpenWebUI erscheint dann kein Tool-Call.

---

## Fehlersuche

| Fehlermeldung | Ursache | Lösung |
|---|---|---|
| `nmap nicht gefunden` | nmap nicht im PATH | `apt install nmap` ausführen |
| `Timeout nach Xs` | Netz nicht erreichbar oder zu groß | Timeout in Valves erhöhen oder kleineren Bereich scannen |
| `Ungültiges Zielformat` | Sonderzeichen oder falsches Format | Gültige IP, CIDR oder Hostname verwenden |
| `Ziel nicht in erlaubten Netzwerken` | Valve `allowed_networks` gesetzt | Valve anpassen oder Ziel zur Whitelist hinzufügen |
| SYN-Scan schlägt fehl | Fehlende Root-Rechte | SUID-Bit auf nmap setzen |

---

## Dateistruktur

```
nmap_tool.py    ← Das OpenWebUI Tool (hier einfügen)
README.md       ← Diese Dokumentation
```

---

## Lizenz

MIT – Nur für legale, autorisierte Sicherheitstests verwenden.
