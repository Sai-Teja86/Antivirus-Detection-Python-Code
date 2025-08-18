import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading, os, time
from antivirus import detect_file, load_signatures, quarantine_file, delete_file, ensure_dir, scan_directory
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# ------------------- Watchdog Handler -------------------
class MonitorHandler(FileSystemEventHandler):
    def __init__(self, action, signatures, output_box, root_scan, quarantine_dir="./quarantine"):
        self.action = action
        self.signatures = signatures
        self.output_box = output_box
        self.root_scan = root_scan
        self.quarantine_dir = quarantine_dir

    def on_created(self, event):
        if event.is_directory:
            return
        fpath = event.src_path
        reasons = detect_file(fpath, self.signatures)
        if reasons:
            action_taken = "none"
            if self.action == "quarantine":
                try:
                    ensure_dir(self.quarantine_dir)
                    dest = quarantine_file(fpath, self.root_scan, self.quarantine_dir)
                    action_taken = f"quarantined:{dest}"
                except Exception as e:
                    action_taken = f"quarantine_failed:{e}"
            elif self.action == "delete":
                try:
                    delete_file(fpath)
                    action_taken = "deleted"
                except Exception as e:
                    action_taken = f"delete_failed:{e}"
            self.output_box.insert(tk.END, f"[Monitor] {fpath} -> {reasons} ({action_taken})\n")
            self.output_box.see(tk.END)


# ------------------- Monitoring Logic -------------------
observer = None

def start_monitor(path, action, signatures, output_box):
    global observer
    path = os.path.abspath(path)
    quarantine_dir = os.path.abspath("./quarantine")

    if action == "quarantine":
        ensure_dir(quarantine_dir)
    event_handler = MonitorHandler(action, signatures, output_box, path, quarantine_dir)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    output_box.insert(tk.END, f"[+] Monitoring started on {path} (action={action})...\n")
    output_box.see(tk.END)

    try:
        while observer.is_alive():
            time.sleep(1)
    except Exception as e:
        output_box.insert(tk.END, f"[!] Monitor stopped unexpectedly: {e}\n")
        output_box.see(tk.END)


def stop_monitor(output_box):
    global observer
    if observer:
        observer.stop()
        observer.join()
        observer = None
        output_box.insert(tk.END, "[+] Monitoring stopped.\n")
        output_box.see(tk.END)


def start_monitor_thread(path_var, action_var, output_box):
    path = path_var.get()
    action = action_var.get()
    if not os.path.isdir(path):
        messagebox.showerror("Error", "Invalid directory")
        return
    signatures = load_signatures("signatures.json")
    threading.Thread(target=start_monitor,
                     args=(path, action, signatures, output_box),
                     daemon=True).start()


# ------------------- Scan Logic -------------------
def start_scan(path_var, action_var, output_box):
    path = path_var.get()
    action = action_var.get()
    if not os.path.isdir(path):
        messagebox.showerror("Error", "Invalid directory")
        return
    signatures = load_signatures("signatures.json")
    report = scan_directory(path, action,
                            "./quarantine" if action == "quarantine" else None,
                            signatures)
    output_box.insert(tk.END, f"\n[+] Scan Complete!\n")
    output_box.insert(tk.END, f"Files scanned: {report['total_files_scanned']}\n")
    output_box.insert(tk.END, f"Malicious detected: {report['malicious_files_detected']}\n")
    for d in report['detections']:
        output_box.insert(tk.END, f"{d['file']} -> {d['reasons']} ({d['action']})\n")
    output_box.see(tk.END)


# ------------------- GUI -------------------
def main():
    root = tk.Tk()
    root.title("Simple Antivirus Prototype")

    # Directory input
    tk.Label(root, text="Directory to Scan/Monitor:").pack(anchor="w")
    path_var = tk.StringVar()
    tk.Entry(root, textvariable=path_var, width=50).pack(anchor="w")
    tk.Button(root, text="Browse", command=lambda: path_var.set(filedialog.askdirectory())).pack(anchor="w")

    # Mode dropdown (scan or monitor)
    tk.Label(root, text="Mode:").pack(anchor="w")
    mode_var = tk.StringVar(value="scan")
    tk.OptionMenu(root, mode_var, "scan", "monitor").pack(anchor="w")

    # Action dropdown (always: none, quarantine, delete)
    tk.Label(root, text="Action:").pack(anchor="w")
    action_var = tk.StringVar(value="none")
    tk.OptionMenu(root, action_var, "none", "quarantine", "delete").pack(anchor="w")

    # Output box
    output_box = scrolledtext.ScrolledText(root, width=80, height=20)
    output_box.pack()

    # Buttons
    scan_btn = tk.Button(root, text="Start Scan",
                         command=lambda: start_scan(path_var, action_var, output_box))
    start_monitor_btn = tk.Button(root, text="Start Monitor",
                                  command=lambda: start_monitor_thread(path_var, action_var, output_box))
    stop_monitor_btn = tk.Button(root, text="Stop Monitor",
                                 command=lambda: stop_monitor(output_box))

    # Default: Scan visible
    scan_btn.pack()
    start_monitor_btn.pack_forget()
    stop_monitor_btn.pack_forget()

    # Switch UI based on mode
    def on_mode_change(*args):
        if mode_var.get() == "monitor":
            scan_btn.pack_forget()
            start_monitor_btn.pack()
            stop_monitor_btn.pack()
        else:
            start_monitor_btn.pack_forget()
            stop_monitor_btn.pack_forget()
            scan_btn.pack()

    mode_var.trace_add("write", on_mode_change)

    root.mainloop()


if __name__ == "__main__":
    main()
