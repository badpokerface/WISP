# WISP - Windows Installer Service Platform

An ultra-lightweight Python-based OS deployment tool.  
**Main program: ~29KB. Whole folder: <40KB.**  
Deploy Windows and (upcoming) Gentoo with a fast, simple GUI!

---

## System Requirements
- **Operating System:** Windows 7 or later (x86/x64/ARM compatible)
- **Python Version:** 3.8 or higher
- **Required Libraries:** tkinter (standard library only)
- **Disk Space:** Less than 40KB total! (Main program just 29KB)
- **Memory:** 2 GB RAM recommended

---

## Key Features

- **Ultra-lightweight:** The entire WISP folder is under 40KB. The main Python program itself is just 29KB.
- **Fast and resource-friendly:** Runs instantly, ideal for minimal systems or portable use.
- **Overflow Error Codes:** Quirky error codes (like W-0x0000000098) to help you troubleshoot—and sometimes make you smile.

---

## Versioning Trivia & Overflow Errors

### Skipped Versions (The Great 0 & 2 Fear)
WISP versions 1.0.2, 1.1.0, and 1.1.2 are intentionally skipped!  
Why? Due to a quirky bug, WISP would sometimes confuse its own version number with the system requirements (512KB) if the version ended in `0` or `2`, leading to possible crashes.  
To avoid this, those versions are skipped—until the bug is fixed!

### WISP 1.1.3: The Liberation
Starting with WISP 1.1.3, this bug is squashed!  
WISP now happily supports versions ending in `0` and `2` (e.g., 1.1.3.2, 1.4.2, etc.), with no risk of disk space/version confusion.  
WISP is lightweight, fast, and numerically fearless!

### Overflow Error Codes
If you try to install an OS without clicking "Verify (SHA256)" first, or run into an edge case, you might see fun error codes like:
> Error (W-0x0000000098) -- WISP encountered an error.  
> Perhaps you forgot to click the Verify (SHA256) button before clicking Install OS?

Other error codes may appear for disk space, corrupted files, or just to make you smile.

---

## Upcoming Features

- **WISP 1.1.3 (Coming Soon):**
  - Gentoo Linux OS deployment support!
  - Even more lightweight and modular.
  - Stay tuned for updates!

---

## Getting Started

1. Download the latest version of WISP.
2. Download the latest version of Python (3.8+).
3. Run the Python script directly using:
   ```bash
   python wisp.py
   ```
4. The WISP Setup GUI will appear.

## Interface Overview

- **Browse Button:** Select a `.wisp` installation file from your system.
- **Architecture Dropdown:** Choose between `x86`, `x64`, or `ARM`.
- **Install Button:** Begins installation using the chosen file and architecture.
- **Status Bar:** Displays installation progress and status messages.

---

## File Handling

WISP recognizes `.wisp` files as structured OS packages.  
Each file may include setup scripts, metadata, and core system images.

When a file is selected:
- The program verifies file integrity.
- Displays path confirmation and readiness state.

---

## Installation Workflow

1. Launch the program.
2. Select your desired `.wisp` file.
3. Click "Verify (SHA256)" to check the package.
4. Choose the target architecture.
5. Click **Install OS**.
6. The status bar will indicate success or prompt for corrections if errors occur.

---

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| "Please select a .wisp file" | No file selected | Use the **Browse** button to pick a file |
| GUI not launching | Missing tkinter | Ensure Python’s tkinter library is installed |
| Status not updating | Script blocked | Run as administrator or verify permissions |
| Fun overflow error (W-0x0000000098) | Forgot to verify package | Click "Verify (SHA256)" before "Install OS" |

---

## Developer Notes
- WISP uses `tkinter` for all graphical interfaces.
- The script can be expanded with backend logic for actual OS deployment.
- Support for scripting, custom `.wisp` package formats, and log handling is planned for future updates.
- Versioning is now numerically fearless!

---

## Version History

**1.00 (Stable)** — Initial release of WISP GUI installer platform.  
**1.1.3 (Beta 1)** — Overflow fixes, and versioning liberation.
**1.1.3 (Beta 2, next)** — Overflow fixes, versioning liberation, and Gentoo support (partial).
More versions listing soon!
---