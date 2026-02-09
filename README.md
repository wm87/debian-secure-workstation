![MIT License](https://img.shields.io/badge/license-MIT-green)
![Debian Version](https://img.shields.io/badge/debian-13.3-blue)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Security](https://img.shields.io/badge/security-hardened-red)
![WIP](https://img.shields.io/badge/status-WIP-orange)

# WIP - Debian Secure Workstation - Automatisierte Sicherheits-ISO

## 📋 Projektübersicht

Dieses Projekt entstand aus der Motivation, Entwicklern, Security-Professionals und Unternehmen eine **sichere, sofort einsatzbereite Arbeitsumgebung** zu bieten. Viele Workstations werden heute ohne konsistente Sicherheitskonfiguration eingesetzt, was Risiken für Daten und Compliance birgt. Meine automatisierte Lösung reduziert Aufwand, minimiert Risiken und stellt sicher, dass die Workstation von Anfang an sicher und produktiv ist. Bei dem Shell-Skript wird eine gehärtete Debian Workstation-ISO erzeugt. Die Installation läuft vollautomatisch durch. Dabei werden moderne Sicherheitsfunktionen integriert. Die ISO vereint aktuelle Sicherheitsstandards mit sofort einsatzbereiten Entwicklungsumgebungen.

Ideal für Entwickler, Security-Professionals und Unternehmen, die Sicherheit und Produktivität kombinieren möchten.

---

## ✨ Kernfunktionen

### 🔒 Sicherheits-Features

* **TPM2-basierte LUKS-Verschlüsselung** – automatische Entschlüsselung via TPM
* **Secure Boot Integration** – vollständige UEFI Secure Boot Unterstützung
* **AppArmor Sandboxing** – Mandatory Access Control für Systemdienste
* **USBGuard Device Control** – dynamische USB-Gerätekontrolle
* **Firewall & Netzwerk-Härtung** – UFW mit vorkonfigurierten Regeln
* **SSH Hardening** – gesicherte Konfiguration mit Schlüsselauthentifizierung
* **Auditd Logging** – ISO 27001-konforme Sicherheitsüberwachung

### 💻 Entwicklungsumgebung

* IntelliJ IDEA Community Edition (via Snap)
* PyCharm Community Edition (via Snap)
* Visual Studio Code (via Snap)
* Docker & Container-Tools
* Python 3 Development Stack
* Git, Build Tools, Debugging Utilities

### 🛠️ Systemoptimierungen

* **Automatische Updates** – Sicherheitsupdates ohne Benutzerinteraktion
* **Kernel Hardening** – erweiterte Sicherheitsparameter
* **Resource Limits** – kontrollierte Ressourcennutzung
* **tmpfs Isolation** – gesicherte temporäre Dateisysteme

---

## 📝 To-Do / Tests

* [ ] **Secure Boot**: Überprüfung der UEFI-Signaturen und Boot-Sicherheit auf verschiedenen Hardware-Plattformen
* [ ] **AIDE**: Vollständige Integritätsprüfung der Systemdateien
* [ ] **Auditd**: Tests für Logging kritischer Ereignisse, sudo-Befehle, Admin-Commands
* [ ] **AppArmor**: Profile für alle Flatpak-Apps testen, Durchsetzung prüfen
* [ ] **Snap/Flatpak Security**: Sandbox-Härtung testen, Logging-Verifizierung
* [ ] **USBGuard**: Dynamische USB-Blockierung und Ausnahmen testen
* [ ] **Firewall/UFW**: Regeln validieren, Penetrationstest-Simulationen durchführen
* [ ] **Kernel Hardening**: Überprüfen von Sicherheitsparametern und sysctl-Konfigurationen
* [ ] **Automatische Updates**: Test der Update-Mechanismen ohne Benutzereingriff
* [ ] **Post-Installation Snaps**: Installation und Startverhalten überprüfen
* [ ] **TPM/LUKS Integration**: Verschlüsselung und automatische Entschlüsselung testen
* [ ] **Auditd Reports**: Zusammenfassungen und Admin-Überwachung validieren
* [ ] **Resource Limits**: Limits für Prozesse und Container prüfen

---

## 🚀 Schnellstart

### Voraussetzungen

```bash
# Auf Debian/Ubuntu Systemen:
sudo apt-get update
sudo apt-get install -y isolinux syslinux-common xorriso \
    rsync wget curl gnupg tar squashfs-tools
```

### ISO erstellen

```bash
./create_secure_iso.sh
```

Das Skript führt durch:

* Benutzereingabe für Credentials
* Download des Debian Basis-ISOs
* Integration aller Sicherheitskomponenten
* Erstellung der hybriden UEFI/BIOS ISO

### 🖥️ Installationsprozess

1. **Boot-Medium erstellen**

```bash
sudo dd if=debian-13.3.0-desktop-secure.iso of=/dev/sdX bs=4M status=progress
```

2. **Automatische Installation**

* Vollautomatischer Prozess, keine Benutzerinteraktion nötig
* Partitionierung: LUKS + LVM mit separaten Partitionen für `/`, `/home`, `swap`
* TPM-Integration automatisch konfiguriert

3. **Post-Installation**

* Snap-Pakete werden automatisch installiert (Internetverbindung erforderlich)
* Sicherheitsdienste werden aktiviert
* Entwicklungsumgebung ist sofort einsatzbereit

---

## 🔧 Technische Details

### TPM2/LUKS Integration

```bash
# TPM Status überprüfen
tpm-status

# LUKS Konfiguration anzeigen
luks-status

# Secure Boot Status
secureboot-check
```

* LUKS bindet automatisch an TPM2 PCRs: PCR 0, 2, 4, 7

### Sicherheitsüberwachung

```bash
# Auditd Reports
audit-summary        # Zusammenfassung der Sicherheitsereignisse
audit-sudo           # sudo-Nutzung überwachen
audit-admin          # Administrative Befehle protokollieren
```

---

## 📁 Projektstruktur

```
├── create_secure_iso.sh          # Hauptskript zur ISO-Erstellung
├── work/                         # Temporäre Arbeitsverzeichnisse
│   ├── extras/                  # Zusätzliche Skripte
│   │   ├── tpm-luks-setup.sh    # TPM2/LUKS Konfiguration
│   │   ├── profiles.sh          # AppArmor Profile
│   │   └── install.sh           # Post-Installation
│   └── iso/                     # ISO-Inhalte
└── README.md                    # Diese Datei
```

---

## 🛡️ Compliance & Best Practices

* **ISO 27001** – Auditd Logging
* **NIST SP 800-53** – mehrschichtige Sicherheitskontrollen
* **CIS Benchmarks** – Debian Security Hardening

**Security-by-Design Prinzipien:**

* Least Privilege
* Defense in Depth
* Automated Hardening
* Tamper Evidence

---

## 🎯 Zielgruppe

* **Entwickler:** Produktive IDE-Umgebung, Container-Entwicklung, Python/Java Toolchain
* **Security Professionals:** sichere Baseline, forensik-taugliches Logging, Compliance-ready
* **Unternehmen:** reproduzierbare Sicherheitskonfiguration, automatisierte Patch-Verwaltung, zentrale Überwachung

---

## 📈 Nutzen für Ihre Organisation

* **Zeitersparnis:** 90% weniger Aufwand für Systemhärtung, konsistente Sicherheitskonfiguration, automatisierte Compliance-Dokumentation
* **Risikominimierung:** reduzierte Angriffsfläche, frühzeitige Erkennung, Wiederherstellbarkeit

---

## 🔄 Wartung und Updates

```bash
# Status automatische Updates
systemctl status snap-auto-update.timer
systemctl status unattended-upgrades

# Manuelle Updates
update  # Alias für apt-get update && apt-get upgrade

# Sicherheitsstatus prüfen
check-apparmor
check-ufw
check-fail2ban
check-audit
```

---

## 🤝 Beitragen & Weiterentwicklung

* **Fehler melden:** detaillierte Beschreibung, Systemumgebung, Log-Ausgaben aus `/var/log/install/`
* **Feedback jederzeit!**

---

## 📄 Lizenz

Dieses Projekt steht unter der MIT-Lizenz. Siehe LICENSE-Datei für Details.
