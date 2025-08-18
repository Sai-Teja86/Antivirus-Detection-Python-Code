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
  - Double extensions: `file.txt.exe`
  - Large executables over **50 MB**
  - Suspicious keywords inside scripts (configurable via `signatures.json`)
- **Quarantine/Removal**: Move to a quarantine folder (preserving structure) or delete.
- **Report Generation**: JSON report with totals and per-file actions.
- **Real-time Scanner** (Bonus): Uses `watchdog` to monitor a folder for new files.

## Quick Start/ Usage

Quarantine on detection:
python antivirus.py --path /path/to/scan --action quarantine --quarantine-dir ./quarantine --signatures ./signatures.json --report ./report.json

Delete on detection:
python antivirus.py --path /path/to/scan --action delete --signatures ./signatures.json

Monitor in real time (Ctrl+C to stop):
python antivirus.py --path /path/to/scan --monitor --action quarantine --quarantine-dir ./quarantine


## File Overview
- `antivirus.py` — main scanner script.
- `antivirus_gui.py` — main scanner script with GUI access.
- `antivirus.py` — Executable GUI. ('used pyinstaller --onefile antivirus_gui.py to convert to exe')
- `signatures.json` — sample signatures database (edit to add your IoCs).
- `requirements.txt` — optional dependency for real-time monitoring (`watchdog`).
- `report.json` — generated after a scan (path configurable).
- `test` — contains test virus files.

## Signatures Format
`signatures.json` expects:
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
- False positives/negatives are possible; tune `signatures.json` to your environment.
- For real-time monitoring, install `watchdog` and ensure the process has access to the target path.

## Install
Python 3.8+ recommended.
pip install -r requirements.txt


## Generate a Sample Report

python antivirus.py --path . --action none --signatures ./signatures.json --report ./report.json


## Security Tips
- Keep your signatures up to date (hashes and IoCs).
- Run scans with least privilege needed.

## License
MIT (for educational use)
