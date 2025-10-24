# WISP ver 1.00

## Overview
WISP (Windows Installer Service Platform) is a Python-based graphical installer platform designed to simplify the process of installing operating systems.  
It provides an intuitive and lightweight GUI for selecting, verifying, and deploying installation files across architectures.

WISP is built to handle `.wisp` installation packages — specialized containers that can include OS images, setup scripts, and metadata.

---

## System Requirements
- **Operating System:** Windows 7 or later (x86/x64/ARM compatible)
- **Python Version:** 3.8 or higher  
- **Required Libraries:** tkinter, standard library only  
- **Disk Space:** 100 MB minimum (excluding OS files)
- **Memory:** 2 GB RAM recommended

---

## Getting Started

### Installation
1. Download the latest version of WISP.
   (and the latest version of python)  
2. Run the Python script directly using:
   ```bash
   python wisp_setup.py
   ```
3. The WISP Setup GUI will appear.

### Interface Overview
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
3. Choose the target architecture.  
4. Click **Install OS**.  
5. The status bar will indicate success or prompt for corrections if errors occur.

---

## Troubleshooting

| Issue | Cause | Solution |
|-------|--------|-----------|
| "Please select a .wisp file" | No file selected | Use the **Browse** button to pick a file |
| GUI not launching | Missing tkinter | Ensure Python’s tkinter library is installed |
| Status not updating | Script blocked | Run as administrator or verify permissions |

---

## Developer Notes
- WISP uses `tkinter` for all graphical interfaces.
- The script can be expanded with backend logic for actual OS deployment.
- Support for scripting, custom `.wisp` package formats, and log handling is planned for future updates.

---

## Version History
**1.00 (Stable)** — Initial release of WISP GUI installer platform.
