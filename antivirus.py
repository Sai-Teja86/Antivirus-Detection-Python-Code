#!/usr/bin/env python3
"""
Simple Antivirus Prototype
Author: ChatGPT (for Sai Teja)
Python: 3.x

Features:
- Recursive directory scan
- Signature-based detection (text patterns + SHA256 hashes)
- Heuristic detection:
    * Suspicious extensions (.exe, .bat, .vbs, .js, .jar, .ps1, .cmd, .scr)
    * Double extensions (e.g., file.txt.exe)
    * Large executable files (> 50MB)
    * Suspicious keywords in scripts (eval, exec, base64, subprocess, powershell, from base64 import b64decode)
- Quarantine or Delete actions
- JSON report
- Optional real-time monitoring with watchdog

Usage examples:
    python antivirus.py --path /path/to/scan --action quarantine --quarantine-dir ./quarantine --report ./report.json
    python antivirus.py --path /path/to/scan --action delete --signatures ./signatures.json
    python antivirus.py --path /path/to/scan --monitor --signatures ./signatures.json
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional

# --------------------------- Configuration ---------------------------

SUSPICIOUS_EXTENSIONS = {'.exe', '.bat', '.vbs', '.js', '.jar', '.ps1', '.cmd', '.scr', '.msi'}
SCRIPT_EXTENSIONS = {'.py', '.ps1', '.js', '.vbs', '.bat', '.cmd', '.sh', '.psm1'}
LARGE_EXECUTABLE_BYTES = 50 * 1024 * 1024  # 50 MB
DOUBLE_EXT_REGEX = re.compile(r'.+\.[a-z0-9]{1,5}\.(exe|bat|vbs|js|scr|cmd|msi)$', re.IGNORECASE)
KEYWORD_DEFAULTS = ['eval', 'exec', 'base64', 'subprocess', 'powershell', 'b64decode']

READ_CHUNK_BYTES = 2 * 1024 * 1024  # read up to first 2MB when scanning content

# --------------------------- Utility Functions ---------------------------

def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def safe_read_text_prefix(path: str, limit: int = READ_CHUNK_BYTES) -> Optional[str]:
    try:
        with open(path, 'rb') as f:
            data = f.read(limit)
        # try utf-8 first; fallback to latin-1 to avoid decode errors
        try:
            return data.decode('utf-8', errors='ignore')
        except Exception:
            return data.decode('latin-1', errors='ignore')
    except Exception:
        return None

def ensure_dir(p: str) -> None:
    os.makedirs(p, exist_ok=True)

def unique_dest_path(dest_path: str) -> str:
    if not os.path.exists(dest_path):
        return dest_path
    base, ext = os.path.splitext(dest_path)
    i = 1
    while True:
        candidate = f"{base}__{i}{ext}"
        if not os.path.exists(candidate):
            return candidate
        i += 1

# --------------------------- Signature Loading ---------------------------

def load_signatures(path: Optional[str]) -> Dict[str, List[str]]:
    signatures = {"patterns": [], "hashes": []}
    if path and os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            signatures["patterns"] = list(set([str(p).strip() for p in data.get("patterns", []) if str(p).strip()]))
            signatures["hashes"] = list(set([str(h).lower().strip() for h in data.get("hashes", []) if str(h).strip()]))
        except Exception as e:
            print(f"[!] Failed to load signatures from {path}: {e}", file=sys.stderr)
    else:
        # default signatures (fallback)
        signatures["patterns"] = KEYWORD_DEFAULTS.copy()
        signatures["hashes"] = []
    return signatures

# --------------------------- Detection Logic ---------------------------

def detect_file(path: str, signatures: Dict[str, List[str]]) -> List[str]:
    reasons: List[str] = []
    _, ext = os.path.splitext(path)
    ext_lower = ext.lower()

    # Heuristic: suspicious extension
    if ext_lower in SUSPICIOUS_EXTENSIONS:
        reasons.append(f"suspicious_extension:{ext_lower}")

    # Heuristic: double extension
    name_lower = os.path.basename(path).lower()
    if DOUBLE_EXT_REGEX.match(name_lower):
        reasons.append("double_extension")

    # Heuristic: large executable (by extension + size > threshold)
    try:
        if ext_lower in SUSPICIOUS_EXTENSIONS and os.path.getsize(path) > LARGE_EXECUTABLE_BYTES:
            reasons.append("large_executable_over_50MB")
    except Exception:
        pass

    # Signature: hash match
    if signatures.get("hashes"):
        try:
            file_hash = sha256_of_file(path)
            if file_hash.lower() in set(signatures["hashes"]):
                reasons.append(f"hash_match:{file_hash.lower()}")
        except Exception:
            # ignore hashing failures (e.g., permissions)
            pass

    # Signature/Heuristic: content-based keyword/patterns
    should_read_content = (ext_lower in SCRIPT_EXTENSIONS) or (ext_lower not in SUSPICIOUS_EXTENSIONS)
    if signatures.get("patterns") and should_read_content:
        text = safe_read_text_prefix(path, READ_CHUNK_BYTES)
        if text:
            for pat in signatures["patterns"]:
                try:
                    if re.search(pat, text, flags=re.IGNORECASE):
                        reasons.append(f"pattern_match:{pat}")
                except re.error:
                    # treat as literal if invalid regex
                    if pat.lower() in text.lower():
                        reasons.append(f"literal_match:{pat}")
    return reasons

# --------------------------- Actions ---------------------------

def quarantine_file(src_path: str, root_scan: str, quarantine_dir: str) -> str:
    rel = os.path.relpath(src_path, root_scan)
    dest_full = os.path.join(quarantine_dir, rel)
    ensure_dir(os.path.dirname(dest_full))
    # avoid clobbering existing file in quarantine
    dest_full = unique_dest_path(dest_full)
    shutil.move(src_path, dest_full)
    return dest_full

def delete_file(path: str) -> None:
    try:
        os.remove(path)
    except IsADirectoryError:
        shutil.rmtree(path, ignore_errors=True)

# --------------------------- Scanner ---------------------------

def scan_directory(root_path: str, action: str, quarantine_dir: Optional[str], signatures: Dict[str, List[str]]) -> Dict:
    total_files = 0
    detections = []

    for dirpath, _, filenames in os.walk(root_path):
        for name in filenames:
            fpath = os.path.join(dirpath, name)
            total_files += 1
            reasons = detect_file(fpath, signatures)
            if reasons:
                record = {
                    "file": fpath,
                    "reasons": reasons,
                    "action": None,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                }
                if action == "quarantine" and quarantine_dir:
                    try:
                        dest = quarantine_file(fpath, root_path, quarantine_dir)
                        record["action"] = f"quarantined:{dest}"
                    except Exception as e:
                        record["action"] = f"quarantine_failed:{e}"
                elif action == "delete":
                    try:
                        delete_file(fpath)
                        record["action"] = "deleted"
                    except Exception as e:
                        record["action"] = f"delete_failed:{e}"
                else:
                    record["action"] = "none"
                detections.append(record)

    report = {
        "scanned_path": os.path.abspath(root_path),
        "scan_started": datetime.utcnow().isoformat() + "Z",
        "total_files_scanned": total_files,
        "malicious_files_detected": len(detections),
        "detections": detections,
    }
    return report

# --------------------------- Watchdog Monitor (Optional) ---------------------------

def monitor_path(path: str, action: str, quarantine_dir: Optional[str], signatures: Dict[str, List[str]]) -> None:
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except Exception:
        print("[!] watchdog is not installed. Install with: pip install watchdog", file=sys.stderr)
        return

    class Handler(FileSystemEventHandler):
        def on_created(self, event):
            if event.is_directory:
                return
            fpath = event.src_path
            reasons = detect_file(fpath, signatures)
            if reasons:
                print(f"[Monitor] Suspicious file detected: {fpath} -> {reasons}")
                if action == "quarantine" and quarantine_dir:
                    try:
                        dest = quarantine_file(fpath, path, quarantine_dir)
                        print(f"[Monitor] Quarantined to: {dest}")
                    except Exception as e:
                        print(f"[Monitor] Quarantine failed: {e}", file=sys.stderr)
                elif action == "delete":
                    try:
                        delete_file(fpath)
                        print("[Monitor] Deleted")
                    except Exception as e:
                        print(f"[Monitor] Delete failed: {e}", file=sys.stderr)

    observer = Observer()
    handler = Handler()
    observer.schedule(handler, path, recursive=True)
    observer.start()
    print(f"[+] Monitoring started on {path}. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# --------------------------- Main ---------------------------

def main():
    parser = argparse.ArgumentParser(description="Simple Antivirus Prototype")
    parser.add_argument("--path", required=True, help="Directory to scan or monitor")
    parser.add_argument("--action", choices=["none", "quarantine", "delete"], default="none",
                        help="Action to take on detected files")
    parser.add_argument("--quarantine-dir", default="./quarantine",
                        help="Directory to store quarantined files (used when action=quarantine)")
    parser.add_argument("--signatures", default="./signatures.json",
                        help="Path to signatures JSON (keys: patterns[list of regex/literals], hashes[list of sha256])")
    parser.add_argument("--report", default="./report.json", help="Path to write JSON report")
    parser.add_argument("--monitor", action="store_true", help="Enable real-time monitoring with watchdog")
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"[!] Path not found or not a directory: {args.path}", file=sys.stderr)
        sys.exit(2)

    signatures = load_signatures(args.signatures)

    if args.action == "quarantine":
        ensure_dir(args.quarantine_dir)

    if args.monitor:
        # Start monitor (does not produce a report file)
        monitor_path(args.path, args.action, args.quarantine_dir if args.action == "quarantine" else None, signatures)
        return

    # One-time scan
    report = scan_directory(args.path, args.action, args.quarantine_dir if args.action == "quarantine" else None, signatures)
    try:
        with open(args.report, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report written to {args.report}")
    except Exception as e:
        print(f"[!] Failed to write report: {e}", file=sys.stderr)
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
