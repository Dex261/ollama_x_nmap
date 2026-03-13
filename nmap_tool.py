"""
title: Nmap Port Scanner
author: SOC Tool
description: Führt Nmap-Scans durch und gibt strukturierte Ergebnisse zurück. Nur für autorisierte Penetrationstests verwenden.
version: 1.0.0
license: MIT
requirements: python-nmap
"""

import subprocess
import json
import re
from typing import Optional
from pydantic import BaseModel, Field


class Tools:
    class Valves(BaseModel):
        # Optionale Einschränkung: nur bestimmte Netzwerke erlauben
        allowed_networks: str = Field(
            default="",
            description="Kommagetrennte Liste erlaubter Netzwerke/IPs (leer = alle erlaubt). Beispiel: 192.168.1.0/24,10.0.0.0/8",
        )
        max_ports: int = Field(
            default=10000,
            description="Maximale Anzahl zu scannender Ports (Sicherheitslimit)",
        )
        timeout: int = Field(
            default=300,
            description="Timeout in Sekunden für einen Scan",
        )

    def __init__(self):
        self.valves = self.Valves()

    def _validate_target(self, target: str) -> bool:
        """Validiert, ob das Ziel ein gültiges Format hat."""
        # Einfache Validierung: IP, Hostname, CIDR
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"
        hostname_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
        range_pattern = r"^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$"

        return bool(
            re.match(ip_pattern, target)
            or re.match(hostname_pattern, target)
            or re.match(range_pattern, target)
        )

    def _check_allowed_networks(self, target: str) -> bool:
        """Prüft ob Ziel in erlaubten Netzwerken ist (falls konfiguriert)."""
        if not self.valves.allowed_networks.strip():
            return True  # Keine Einschränkung
        allowed = [n.strip() for n in self.valves.allowed_networks.split(",")]
        return any(target.startswith(net.split("/")[0][:6]) for net in allowed)

    def nmap_quick_scan(self, target: str) -> str:
        """
        Führt einen schnellen Nmap-Scan der 1000 häufigsten Ports durch.

        :param target: Ziel-IP, Hostname oder CIDR-Bereich (z.B. 192.168.1.1 oder 10.0.0.0/24)
        :return: Scan-Ergebnisse als formatierter Text
        """
        if not self._validate_target(target):
            return "❌ Fehler: Ungültiges Zielformat. Bitte IP, Hostname oder CIDR angeben."

        if not self._check_allowed_networks(target):
            return f"❌ Fehler: Ziel '{target}' ist nicht in den erlaubten Netzwerken."

        try:
            cmd = ["nmap", "-sV", "--open", "-T4", "--reason", target]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.valves.timeout,
            )
            output = result.stdout if result.stdout else result.stderr
            return f"**Nmap Quick Scan – {target}**\n```\n{output}\n```"
        except subprocess.TimeoutExpired:
            return f"❌ Timeout: Scan auf '{target}' hat das Zeitlimit von {self.valves.timeout}s überschritten."
        except FileNotFoundError:
            return "❌ Fehler: nmap ist nicht installiert oder nicht im PATH. Bitte `apt install nmap` ausführen."
        except Exception as e:
            return f"❌ Unerwarteter Fehler: {str(e)}"

    def nmap_port_scan(
        self,
        target: str,
        ports: str = "1-1024",
        scan_type: str = "SYN",
    ) -> str:
        """
        Führt einen Nmap-Portscan auf definierten Ports durch.

        :param target: Ziel-IP, Hostname oder CIDR-Bereich
        :param ports: Portbereich (z.B. '22,80,443' oder '1-1024' oder 'top100')
        :param scan_type: Scan-Typ: SYN (erfordert root), TCP, UDP, Version
        :return: Scan-Ergebnisse als formatierter Text
        """
        if not self._validate_target(target):
            return "❌ Fehler: Ungültiges Zielformat."

        if not self._check_allowed_networks(target):
            return f"❌ Fehler: Ziel '{target}' ist nicht in den erlaubten Netzwerken."

        # Scan-Typ mapping
        scan_flags = {
            "SYN": "-sS",
            "TCP": "-sT",
            "UDP": "-sU",
            "Version": "-sV",
        }
        flag = scan_flags.get(scan_type.upper(), "-sT")

        # Ports-Argument aufbauen
        if ports == "top100":
            port_arg = "--top-ports 100"
        elif ports == "top1000":
            port_arg = "--top-ports 1000"
        else:
            port_arg = f"-p {ports}"

        try:
            cmd = [
                "nmap",
                flag,
                port_arg,
                "-sV",
                "--open",
                "-T4",
                "--reason",
                "-oG",
                "-",
                target,
            ]
            # Flatten die Liste (port_arg könnte 2 Tokens sein)
            cmd_flat = ["nmap", flag] + port_arg.split() + ["-sV", "--open", "-T4", "--reason", target]

            result = subprocess.run(
                cmd_flat,
                capture_output=True,
                text=True,
                timeout=self.valves.timeout,
            )
            output = result.stdout if result.stdout else result.stderr
            return f"**Nmap Port Scan – {target} (Ports: {ports}, Typ: {scan_type})**\n```\n{output}\n```"
        except subprocess.TimeoutExpired:
            return f"❌ Timeout nach {self.valves.timeout}s."
        except FileNotFoundError:
            return "❌ Fehler: nmap nicht gefunden. Bitte installieren."
        except Exception as e:
            return f"❌ Fehler: {str(e)}"

    def nmap_os_detection(self, target: str) -> str:
        """
        Führt OS-Erkennung und Service-Detection auf einem Ziel durch (erfordert root/sudo).

        :param target: Ziel-IP oder Hostname
        :return: OS und Service Informationen
        """
        if not self._validate_target(target):
            return "❌ Fehler: Ungültiges Zielformat."

        if not self._check_allowed_networks(target):
            return f"❌ Fehler: Ziel nicht erlaubt."

        try:
            cmd = ["nmap", "-O", "-sV", "--osscan-guess", "-T4", target]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.valves.timeout,
            )
            output = result.stdout if result.stdout else result.stderr
            return f"**Nmap OS Detection – {target}**\n```\n{output}\n```"
        except subprocess.TimeoutExpired:
            return f"❌ Timeout nach {self.valves.timeout}s."
        except FileNotFoundError:
            return "❌ nmap nicht gefunden."
        except Exception as e:
            return f"❌ Fehler: {str(e)}"

    def nmap_vulnerability_scan(self, target: str, ports: str = "top100") -> str:
        """
        Führt einen Vulnerability-Scan mit NSE-Scripts durch (vulners, vulscan).

        :param target: Ziel-IP oder Hostname
        :param ports: Ports (z.B. '80,443,22' oder 'top100')
        :return: Gefundene Schwachstellen
        """
        if not self._validate_target(target):
            return "❌ Fehler: Ungültiges Zielformat."

        if not self._check_allowed_networks(target):
            return f"❌ Fehler: Ziel nicht erlaubt."

        port_arg = "--top-ports 100" if ports == "top100" else f"-p {ports}"

        try:
            cmd_flat = (
                ["nmap"]
                + port_arg.split()
                + ["-sV", "--script=vuln", "-T4", target]
            )
            result = subprocess.run(
                cmd_flat,
                capture_output=True,
                text=True,
                timeout=self.valves.timeout,
            )
            output = result.stdout if result.stdout else result.stderr
            return f"**Nmap Vuln Scan – {target}**\n```\n{output}\n```"
        except subprocess.TimeoutExpired:
            return f"❌ Timeout nach {self.valves.timeout}s."
        except FileNotFoundError:
            return "❌ nmap nicht gefunden."
        except Exception as e:
            return f"❌ Fehler: {str(e)}"

    def nmap_custom_scan(self, target: str, nmap_args: str) -> str:
        """
        Führt einen Nmap-Scan mit eigenen Argumenten aus (für Experten).

        :param target: Ziel-IP, Hostname oder CIDR
        :param nmap_args: Eigene nmap-Argumente (z.B. '-sS -p 80,443 -sV --script=http-headers')
        :return: Scan-Ergebnisse
        """
        if not self._validate_target(target):
            return "❌ Fehler: Ungültiges Zielformat."

        if not self._check_allowed_networks(target):
            return f"❌ Fehler: Ziel nicht erlaubt."

        # Sicherheitscheck: keine Shell-Injection
        dangerous = [";", "&&", "||", "`", "$", "|", ">", "<", "\n"]
        if any(c in nmap_args for c in dangerous):
            return "❌ Sicherheitsfehler: Unerlaubte Sonderzeichen in den Argumenten."

        try:
            args = nmap_args.strip().split()
            cmd = ["nmap"] + args + [target]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.valves.timeout,
            )
            output = result.stdout if result.stdout else result.stderr
            return f"**Nmap Custom Scan – {target}**\n```\n{output}\n```"
        except subprocess.TimeoutExpired:
            return f"❌ Timeout nach {self.valves.timeout}s."
        except FileNotFoundError:
            return "❌ nmap nicht gefunden."
        except Exception as e:
            return f"❌ Fehler: {str(e)}"
