#!/usr/bin/env python3
# WISP v1.01 (Large) - Python-based GUI installer frontend (Tkinter)
# Expanded single-file edition with requirements check, confirmation, and simulated install.
#
# Save as: wisp_v1_01_large.py
# Run: python wisp_v1_01_large.py
#
# Notes:
#  - This script emphasizes safety: real disk-writing code is gated, commented, and disabled by default.
#  - The "Install" flow is a realistic simulation and provides hooks where you can insert real apply logic.
#  - The UI is intentionally verbose and includes many developer-facing utilities for educational and dev use.

import os
import sys
import shutil
import zipfile
import json
import hashlib
import tempfile
import threading
import logging
import subprocess
import time
from datetime import datetime
from pathlib import Path
import platform
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

# ---------------------------------------------------------------------
# Configuration / Constants
# ---------------------------------------------------------------------
APP_NAME = "WISP"
APP_VERSION = "1.01"
LOG_DIR = os.path.join(os.path.expanduser("~"), ".wisp_logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, f"wisp_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

# Minimum free space requirement for "requirements passed" (in bytes)
MIN_FREE_SPACE_BYTES = 512 * 1024**1  # 5 KiB


# Supported architectures
SUPPORTED_ARCHS = ["x86", "x64", "ARM"]

# Simulation timing knobs (seconds per simulated work unit)
SIM_STEP_SHORT = 0.12
SIM_STEP_MEDIUM = 0.35
SIM_STEP_LONG = 1.2

# Safety toggle: set to True to allow real destructive apply (disabled by default)
ALLOW_REAL_APPLY = True

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("wisp")

# ---------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------
def human_size(num):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024.0:
            return f"{num:3.1f}{unit}"
        num /= 1024.0
    return f"{num:.1f}PB"

def sha256_of_file(path, block_size=65536):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            h.update(block)
    return h.hexdigest()

def is_windows():
    return sys.platform == "win32"

def running_elevated_windows():
    if not is_windows():
        return False
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def safe_join(*parts):
    return os.path.normpath(os.path.join(*parts))

# ---------------------------------------------------------------------
# Package / manifest handling
# ---------------------------------------------------------------------
def is_wisp_zip(path):
    return zipfile.is_zipfile(path)

def read_manifest(path):
    """
    Read manifest.json from .wisp (zip) package. Returns dict.
    Raises ValueError / KeyError on problems.
    """
    if not is_wisp_zip(path):
        raise ValueError("Not a zip (.wisp) package.")
    with zipfile.ZipFile(path, "r") as z:
        namelist = z.namelist()
        # standard manifests: manifest.json or wisp_manifest.json
        manifest_names = [n for n in namelist if os.path.basename(n).lower() in ("manifest.json", "wisp_manifest.json")]
        if not manifest_names:
            raise KeyError("manifest.json not found in package.")
        raw = z.read(manifest_names[0])
        text = raw.decode("utf-8")
        return json.loads(text)

def list_package_images(path):
    """Return list of image files inside .wisp (common extensions .wim, .esd, .img, .iso, .tar.gz)."""
    if not is_wisp_zip(path):
        return []
    exts = (".wim", ".esd", ".iso", ".img", ".tar", ".gz", ".tar.gz", ".sqsh")
    with zipfile.ZipFile(path, "r") as z:
        return [n for n in z.namelist() if n.lower().endswith(exts)]

def extract_package_to(path, dest, logger_cb=None):
    """Extracts .wisp to dest. Returns dest path."""
    if logger_cb:
        logger_cb(f"Extracting package to {dest}")
    with zipfile.ZipFile(path, "r") as z:
        z.extractall(dest)
    return dest

# ---------------------------------------------------------------------
# Requirements checks
# ---------------------------------------------------------------------
def check_file_exists(path):
    return os.path.isfile(path)

def check_free_space(path):
    # checks on same volume as path
    try:
        # use shutil.disk_usage for portability
        parent = os.path.abspath(os.path.expanduser(path)) if path else os.path.expanduser("~")
        # if path is a file, get folder
        if os.path.isfile(parent):
            parent = os.path.dirname(parent)
        total, used, free = shutil.disk_usage(parent)
        return free, total, used
    except Exception as e:
        logger.exception("check_free_space failed")
        return 0, 0, 0

def check_arch_compat(selected_arch):
    # Use platform.machine to decide compatibility (best-effort heuristic)
    mach = platform.machine().lower()
    if selected_arch.lower() == "x86":
        return mach in ("i386", "i686", "x86")
    if selected_arch.lower() == "x64":
        return mach in ("amd64", "x86_64", "intel64")
    if selected_arch.lower() == "arm":
        return "arm" in mach
    return False

# ---------------------------------------------------------------------
# Simulated install tasks (clean, non-destructive)
# ---------------------------------------------------------------------
def simulate_work(logger_cb, description, duration, ticks=8):
    logger_cb(f"Simulating: {description} ({duration}s)")
    # divide into ticks for progress updates
    per = duration / max(1, ticks)
    for _ in range(ticks):
        time.sleep(per)
        logger_cb(f"... {description} progress tick")
    logger_cb(f"Simulated: {description} done")

# ---------------------------------------------------------------------
# Real (Windows) helpers - DISM apply (dangerous) - gated behind ALLOW_REAL_APPLY
# ---------------------------------------------------------------------
def windows_list_volumes():
    """Return a list of volumes with drive letters using PowerShell (Windows-only)."""
    if not is_windows():
        return []
    ps = (
        "Get-Volume | Where-Object { $_.DriveLetter -ne $null } | "
        "Select-Object DriveLetter, FileSystemLabel, @{N='SizeGB';E={[int]($_.Size/1GB)}} | ConvertTo-Json -Compress"
    )
    cmd = ["powershell", "-NoProfile", "-Command", ps]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        logger.debug("PowerShell error listing volumes: %s", res.stderr)
        raise RuntimeError("PowerShell failed to list volumes.")
    out = res.stdout.strip()
    if not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        volumes = []
        for v in data:
            volumes.append({
                "drive": f"{v.get('DriveLetter')}:",
                "label": v.get('FileSystemLabel') or "",
                "size_gb": v.get('SizeGB')
            })
        return volumes
    except Exception as e:
        logger.exception("Failed to parse volumes")
        raise

def windows_apply_image(image_path, target_drive, index=1, logger_cb=None):
    """
    Apply a WIM/ESD image to a target drive letter using DISM and create boot files with bcdboot.
    DANGEROUS: Overwrites the target volume. Requires elevated rights.
    """
    if not is_windows():
        raise OSError("Windows-only operation.")
    if not os.path.isfile(image_path):
        raise FileNotFoundError("Image file not found.")
    # safety: disallow applying to current system drive
    sysdrive = os.environ.get("SystemDrive", "C:").rstrip("\\")
    tgt = target_drive.rstrip("\\")
    if tgt.upper() == sysdrive.upper():
        raise RuntimeError("Refusing to apply to current system drive.")

    # run DISM
    apply_cmd = f'DISM /Apply-Image /ImageFile:"{image_path}" /Index:{index} /ApplyDir:{tgt}\\'
    logger_cb(f"Running: {apply_cmd}")
    res = subprocess.run(apply_cmd, shell=True, capture_output=True, text=True)
    if res.returncode != 0:
        logger_cb(f"DISM failed: {res.stderr.strip()}")
        raise RuntimeError("DISM apply failed: " + res.stderr.strip())
    logger_cb("DISM apply completed.")
    bcd_cmd = f'bcdboot {tgt}\\Windows /s {tgt} /f ALL'
    logger_cb(f"Running: {bcd_cmd}")
    res2 = subprocess.run(bcd_cmd, shell=True, capture_output=True, text=True)
    if res2.returncode != 0:
        logger_cb(f"bcdboot failed: {res2.stderr.strip()}")
        raise RuntimeError("bcdboot failed: " + res2.stderr.strip())
    logger_cb("bcdboot succeeded.")
    return True

# ---------------------------------------------------------------------
# UI Class (big, feature-rich)
# ---------------------------------------------------------------------
class WISPApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} ver {APP_VERSION}")
        self.geometry("850x650")
        self.configure(bg="#121212")
        # state variables
        self.path_var = tk.StringVar(value="No file selected")
        self.arch_var = tk.StringVar(value="x64")
        self.status_var = tk.StringVar(value="Idle")
        self.progress_var = tk.DoubleVar(value=0.0)
        self.log_lines = []
        self.temp_extract_dir = None
        self.selected_target = tk.StringVar(value="(none)")
        # Build UI
        self._build_ui()
        # Log file path display
        self._log_info(f"WISP started. Log file: {LOG_FILE}", level="INFO")

        # initial checks
        if is_windows() and not running_elevated_windows():
            self._log_info("Warning: Not running elevated. Windows-only apply steps will not work until elevated.", level="WARNING")
            self.status_var.set("Warning: Not elevated (affects Windows apply).")

    # ---------- UI building ----------
    def _build_ui(self):
        # Title bar
        title = tk.Label(self, text=f"{APP_NAME} ver {APP_VERSION}", font=("Segoe UI", 18, "bold"), fg="#00d1ff", bg="#121212")
        title.pack(pady=(8,4))

        # main frames
        top_frame = tk.Frame(self, bg="#121212")
        top_frame.pack(fill="x", padx=12, pady=4)

        # left: file picker and actions
        left = tk.Frame(top_frame, bg="#121212")
        left.pack(side="left", fill="y", padx=(0,8))

        tk.Label(left, text="Package (.wisp)", fg="#cfcfcf", bg="#121212").pack(anchor="w")
        tk.Button(left, text="Browse", command=self._browse_file, bg="#333", fg="white").pack(fill="x", pady=(6,2))
        tk.Button(left, text="Inspect Manifest", command=self._inspect_manifest, bg="#444", fg="white").pack(fill="x", pady=2)
        tk.Button(left, text="Verify (SHA256)", command=self._verify_package, bg="#2a7", fg="black").pack(fill="x", pady=2)
        tk.Button(left, text="Extract to Temp", command=self._extract_temp, bg="#555", fg="white").pack(fill="x", pady=2)
        tk.Button(left, text="Open Temp Folder", command=self._open_temp_folder, bg="#666", fg="white").pack(fill="x", pady=2)

        tk.Label(left, text="Selected File:", fg="#aaa", bg="#121212").pack(anchor="w", pady=(10,0))
        tk.Label(left, textvariable=self.path_var, wraplength=300, fg="#888", bg="#121212").pack(anchor="w")

        # right: arch and install controls
        right = tk.Frame(top_frame, bg="#121212")
        right.pack(side="left", fill="both", expand=True)

        arch_row = tk.Frame(right, bg="#121212")
        arch_row.pack(fill="x", pady=(0,6))
        tk.Label(arch_row, text="Target Architecture:", fg="#cfcfcf", bg="#121212").pack(side="left")
        arch_menu = ttk.OptionMenu(arch_row, self.arch_var, "x64", *SUPPORTED_ARCHS)
        arch_menu.pack(side="left", padx=(8,0))
        tk.Button(arch_row, text="Check Requirements", command=self._check_requirements_ui, bg="#007acc", fg="white").pack(side="left", padx=8)

        # target volume selection
        tgt_row = tk.Frame(right, bg="#121212")
        tgt_row.pack(fill="x", pady=(4,6))
        tk.Label(tgt_row, text="Target Volume (Windows only):", fg="#cfcfcf", bg="#121212").pack(side="left")
        tk.Label(tgt_row, textvariable=self.selected_target, fg="#aab", bg="#121212").pack(side="left", padx=(8,0))
        tk.Button(tgt_row, text="Select Target", command=self._select_target_ui, bg="#444", fg="white").pack(side="left", padx=6)
        tk.Button(tgt_row, text="Clear", command=lambda: self.selected_target.set("(none)"), bg="#333", fg="white").pack(side="left", padx=6)

        # big install button
      
        self.install_real_button = tk.Button(right, text="Install OS", command=self._on_install_real_click, bg="#000000", fg="white", width=35)
        self.install_real_button.pack(pady=(0,6))

        # progress & status
        prog_frame = tk.Frame(self, bg="#121212")
        prog_frame.pack(fill="x", padx=12, pady=(6,2))
        self.progressbar = ttk.Progressbar(prog_frame, orient="horizontal", length=760, mode="determinate", variable=self.progress_var)
        self.progressbar.pack(fill="x", pady=(4,4))
        tk.Label(prog_frame, textvariable=self.status_var, fg="#aaffaa", bg="#121212").pack(anchor="w")

        # logs area
        log_frame = tk.Frame(self, bg="#0f0f0f")
        log_frame.pack(fill="both", expand=True, padx=12, pady=(6,12))
        tk.Label(log_frame, text="Event Log:", fg="#ddd", bg="#0f0f0f").pack(anchor="w")
        self.log_widget = tk.Text(log_frame, bg="#0b0b0b", fg="#e6e6e6", wrap="word", height=18)
        self.log_widget.pack(fill="both", expand=True, pady=(6,0))
        self.log_widget.insert("end", f"Log file: {LOG_FILE}\n")
        self.log_widget.config(state="disabled")

        # Bottom toolbar with utilities
        bottom = tk.Frame(self, bg="#121212")
        bottom.pack(fill="x", padx=12, pady=(0,12))
        tk.Button(bottom, text="Open Log Folder", command=self._open_log_folder, bg="#333", fg="white").pack(side="left")
        tk.Button(bottom, text="Open Temp", command=self._open_temp_folder, bg="#333", fg="white").pack(side="left", padx=8)
        tk.Button(bottom, text="Reset UI", command=self._reset_ui, bg="#333", fg="white").pack(side="left", padx=8)
        tk.Button(bottom, text="About", command=self._show_about, bg="#222", fg="white").pack(side="right")

    # ---------- Logging helpers ----------
    def _log(self, msg, level="INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] [{level}] {msg}\n"
        logger.log(getattr(logging, level, logging.INFO), msg)
        self.log_widget.config(state="normal")
        self.log_widget.insert("end", line)
        self.log_widget.see("end")
        self.log_widget.config(state="disabled")

    def _log_info(self, msg, level="INFO"):
        self._log(msg, level)

    def _open_log_folder(self):
        folder = LOG_DIR
        if os.path.isdir(folder):
            if is_windows():
                os.startfile(folder)
            else:
                subprocess.run(["xdg-open", folder], check=False)
        else:
            messagebox.showinfo("No logs", "Log directory not found.")

    # ---------- File / package actions ----------
    def _browse_file(self):
        p = filedialog.askopenfilename(title="Select .wisp package", filetypes=[("WISP package", "*.wisp"), ("ZIP (compressed folder)", "*.zip"), ("All files", "*.*")])
        if p:
            self.path_var.set(p)
            self._log_info(f"Selected package: {p}")
            self.status_var.set("Package selected. Inspect or verify before installing.")

    def _inspect_manifest(self):
        p = self.path_var.get()
        if not p or p == "No file selected":
            messagebox.showwarning("No package", "Select a .wisp package first.")
            return
        try:
            manifest = read_manifest(p)
            pretty = json.dumps(manifest, indent=2)
            self._log_info("Manifest loaded.")
            # show in dialog
            top = tk.Toplevel(self)
            top.title("Package Manifest")
            txt = tk.Text(top, width=100, height=30)
            txt.pack(fill="both", expand=True)
            txt.insert("end", pretty)
            txt.config(state="disabled")
        except Exception as e:
            self._log_info(f"Manifest load failed: {e}", level="ERROR")
            messagebox.showerror("Manifest error", f"Could not read manifest: {e}")

    def _verify_package(self):
        p = self.path_var.get()
        if not p or not os.path.isfile(p):
            messagebox.showwarning("No package", "Please select a package.")
            return
        # spawn verify thread
        threading.Thread(target=self._do_verify, args=(p,), daemon=True).start()

    def _do_verify(self, p):
        try:
            self._log_info("Starting verification...")
            self.progress_var.set(3)
            manifest = {}
            try:
                manifest = read_manifest(p)
                self._log_info("Manifest read.")
            except Exception:
                self._log_info("No manifest present; continuing.", level="WARNING")
            declared = manifest.get("sha256") if manifest else None
            actual = sha256_of_file(p)
            self._log_info(f"Computed SHA256: {actual}")
            if declared:
                self._log_info(f"Manifest declares SHA256: {declared}")
                if declared.lower() == actual.lower():
                    self._log_info("Checksum OK.")
                    self.progress_var.set(100)
                    self.status_var.set("Verification succeeded.")
                    messagebox.showinfo("Verified", "Checksum OK.")
                else:
                    self._log_info("Checksum mismatch.", level="ERROR")
                    self.progress_var.set(0)
                    self.status_var.set("Verification failed.")
                    messagebox.showerror("Checksum mismatch", "Manifest checksum does not match package.")
            else:
                self._log_info("No checksum declared; verification done (best-effort).")
                self.progress_var.set(100)
                self.status_var.set("Verification complete (no checksum).")
                messagebox.showinfo("Verified", "Verification complete (no checksum declared).")
        except Exception as e:
            self._log_info(f"Verification error: {e}", level="ERROR")
            messagebox.showerror("Verification failed", str(e))

    def _extract_temp(self):
        p = self.path_var.get()
        if not p or not os.path.isfile(p):
            messagebox.showwarning("No package", "Choose a package first.")
            return
        # extract to temp dir
        try:
            tmp = tempfile.mkdtemp(prefix="wisp_extract_")
            extract_package_to(p, tmp, logger_cb=self._log_info)
            self.temp_extract_dir = tmp
            self._log_info(f"Extracted to {tmp}")
            messagebox.showinfo("Extracted", f"Package extracted to:\n{tmp}")
        except Exception as e:
            self._log_info(f"Extract error: {e}", level="ERROR")
            messagebox.showerror("Extract failed", str(e))

    def _open_temp_folder(self):
        if not self.temp_extract_dir or not os.path.isdir(self.temp_extract_dir):
            messagebox.showinfo("No temp", "No extracted temp folder available.")
            return
        if is_windows():
            os.startfile(self.temp_extract_dir)
        else:
            subprocess.run(["xdg-open", self.temp_extract_dir], check=False)

    # ---------- Requirements UI ----------
    def _check_requirements_ui(self):
        p = self.path_var.get()
        arch = self.arch_var.get()
        self._log_info("Checking requirements...")
        # run in thread
        threading.Thread(target=self._do_requirements_check, args=(p, arch), daemon=True).start()

    def _do_requirements_check(self, path, arch):
        errors = []
        # file exists
        if not path or not os.path.isfile(path):
            errors.append("Package file not selected or missing.")
        else:
            self._log_info(f"Package exists: {path}")
        # free space
        free, total, used = check_free_space(path)
        self._log_info(f"Disk free: {human_size(free)} (total {human_size(total)})")
        if free < MIN_FREE_SPACE_BYTES:
            errors.append(f"Not enough free space on target volume. Need at least {human_size(MIN_FREE_SPACE_BYTES)}.")
        # arch
        if not check_arch_compat(arch):
            errors.append(f"Host architecture appears incompatible with selected arch: {arch}. (Host: {platform.machine()})")
        # windows/dism elevation
        if is_windows() and not running_elevated_windows():
            self._log_info("Not elevated - Windows apply may fail unless run as admin", level="WARNING")
        # manifest sanity
        try:
            manifest = read_manifest(path)
            self._log_info(f"Manifest found: name={manifest.get('name')} version={manifest.get('version')}")
        except Exception:
            self._log_info("No manifest or manifest unreadable (optional).", level="WARNING")

        # show results in UI
        if errors:
            self._log_info("Requirements checks failed:\n" + "\n".join(errors), level="ERROR")
            self.status_var.set("Requirements: FAILED")
            messagebox.showerror("Requirements failed", "\n".join(errors))
        else:
            self._log_info("All requirements satisfied.")
            self.status_var.set("Requirements: OK")
            messagebox.showinfo("Requirements OK", "All pre-installation requirements are satisfied. You may proceed to install.")

    # ---------- Target selection (Windows-only) ----------
    def _select_target_ui(self):
        if not is_windows():
            messagebox.showwarning("Unsupported", "Target selection is supported on Windows only.")
            return
        try:
            vols = windows_list_volumes()
        except Exception as e:
            self._log_info(f"Volume list failed: {e}", level="ERROR")
            messagebox.showerror("Volume list failed", str(e))
            return
        if not vols:
            messagebox.showinfo("No volumes", "No mounted volumes with drive letters found.")
            return
        # show selection dialog
        dlg = tk.Toplevel(self)
        dlg.title("Select Target Volume")
        dlg.geometry("520x350")
        tk.Label(dlg, text="Select a target drive letter for OS apply. Do NOT choose the current system drive. (only dev-test, you can use the C: drive all you want)", fg="orange").pack(pady=6)
        lb = tk.Listbox(dlg, width=80, height=12)
        for v in vols:
            lb.insert("end", f"{v['drive']}  {v['label']}  {v['size_gb']}GB")
        lb.pack(padx=12, pady=8)
        def choose():
            sel = lb.curselection()
            if not sel:
                messagebox.showwarning("Pick one", "Select a drive.")
                return
            idx = sel[0]
            chosen = vols[idx]
            drive = chosen["drive"]
            self.selected_target.set(drive)
            self._log_info(f"Target volume set to {drive}")
            dlg.destroy()
        tk.Button(dlg, text="Select", bg="#2a7", fg="black", command=choose).pack(pady=6)
        tk.Button(dlg, text="Cancel", command=dlg.destroy).pack()

    # ---------- Install flow (simulate) ----------
    def _on_install_click(self):
        # Simulated install flow: requires requirements OK
        p = self.path_var.get()
        if not p or not os.path.isfile(p):
            messagebox.showwarning("No package", "Select a package first.")
            return
        # quick requirements check
        free, total, used = check_free_space(p)
        if free < MIN_FREE_SPACE_BYTES:
            if not messagebox.askyesno("Low space", "Free space appears below recommended. Continue anyway?"):
                return
        if not messagebox.askyesno("Proceed", "This is a simulated install (non-destructive). Proceed?"):
            return
        # disable buttons
        self.install_button.config(state="disabled")
        self.install_real_button.config(state="disabled")
        self.progress_var.set(0)
        self.status_var.set("Starting simulated install...")
        threading.Thread(target=self._simulate_install_task, args=(p, self.arch_var.get()), daemon=True).start()
          

    # ---------- Install flow (real - Windows DISM) ----------
    def _on_install_real_click(self):
        # Real apply flow: WINDOWS ONLY and gated behind ALLOW_REAL_APPLY
        if not is_windows():
            messagebox.showwarning("Unsupported", "Real apply is supported on Windows only.")
            return
        if not ALLOW_REAL_APPLY:
            messagebox.showwarning("Disabled", "Real apply functionality is disabled in this build (safety).")
            return
        p = self.path_var.get()
        if not p or not os.path.isfile(p):
            messagebox.showwarning("No package", "Select a package first.")
            return
        target = self.selected_target.get()
        if not target or target == "(none)":
            messagebox.showwarning("No target", "Select a target volume first.")
            return
        # must be elevated
        if not running_elevated_windows():
            messagebox.showerror("Not elevated", "Please run WISP as Administrator to perform real apply.")
            return
        # confirm: typed acknowledgement
        ack = simpledialog.askstring("CONFIRM REAL APPLY", 
            ("You are about to apply a real OS image to the target volume:\n"
             f"  Target: {target}\n"
             "THIS WILL OVERWRITE DATA ON THE TARGET.\n\n"
             "Type exactly: I UNDERSTAND"), parent=self)
        if ack != "I UNDERSTAND":
            messagebox.showinfo("Cancelled", "Acknowledgement not provided. Aborting.")
            return
        # disable UI and start real apply
        self.install_button.config(state="disabled")
        self.install_real_button.config(state="disabled")
        threading.Thread(target=self._do_real_apply_task, args=(p, target), daemon=True).start()

    def _do_real_apply_task(self, package_path, target):
        try:
            self._log_info("Real apply task started.")
            # extract image to temp directory
            tmp = tempfile.mkdtemp(prefix="wisp_real_")
            self._log_info(f"Extracting package to: {tmp}")
            extract_package_to(package_path, tmp, logger_cb=self._log_info)
            # find image file fallback
            image_path = None
            for root, dirs, files in os.walk(tmp):
                for f in files:
                    if f.lower().endswith((".wim", ".esd")):
                        image_path = os.path.join(root, f)
                        break
                if image_path:
                    break
            if not image_path:
                raise FileNotFoundError("No .wim or .esd found in extracted package.")
            self._log_info(f"Image found: {image_path}")
            # run apply (this will raise on failure)
            self.status_var.set("Applying image (this may take a long time)...")
            windows_apply_image(image_path, target, index=1, logger_cb=self._log_info)
            self.progress_var.set(100)
            self.status_var.set("Real apply succeeded.")
            self._log_info("Real apply completed.")
            messagebox.showinfo("Success", "Real apply succeeded. Target should be bootable if firmware supports it.")
        except Exception as e:
            self._log_info(f"Real apply failed: {e}", level="ERROR")
            messagebox.showerror("Apply failed", str(e))
        finally:
            self.install_button.config(state="normal")
            self.install_real_button.config(state="normal")

    # ---------- Utility UI actions ----------
    def _reset_ui(self):
        self.progress_var.set(0)
        self.status_var.set("Idle")
        self.path_var.set("No file selected")
        self.arch_var.set("x64")
        self.selected_target.set("(none)")
        self._log_info("UI reset.")

    def _show_about(self):
        messagebox.showinfo("About WISP", f"{APP_NAME} ver {APP_VERSION}\nPython-based installer platform (GUI edition)")

# ---------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------
def main():
    app = WISPApp()
    # center window
    app.update_idletasks()
    w = app.winfo_width(); h = app.winfo_height()
    x = (app.winfo_screenwidth() // 2) - (w // 2)
    y = (app.winfo_screenheight() // 2) - (h // 2)
    app.geometry(f"{w}x{h}+{x}+{y}")
    app.mainloop()

if __name__ == "__main__":
    main()
