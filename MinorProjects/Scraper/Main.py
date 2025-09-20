import subprocess
import sys
import os

MENU = """
Wi-Fi Monitor Launcher
----------------------
1) Run Collector (background logger)
2) Run API (FastAPI server on http://127.0.0.1:8000)
3) Run Dash UI (http://127.0.0.1:8050)
4) Run PyQt UI (desktop app)
5) Exit
"""

PYTHON = sys.executable  # use the current venv Python
processes = {}  # track running processes

def run_background(name, path):
    """Start a Python script in the background"""
    if name in processes and processes[name].poll() is None:
        print(f"{name} is already running.")
        return
    proc = subprocess.Popen([PYTHON, path])
    processes[name] = proc
    print(f"{name} started (PID {proc.pid}).")

def stop_process(name):
    """Stop a background process if running"""
    if name in processes and processes[name].poll() is None:
        processes[name].terminate()
        print(f"{name} terminated.")
    else:
        print(f"{name} is not running.")

def main():
    while True:
        print(MENU)
        choice = input("Select option: ").strip()

        if choice == "1":
            run_background("Collector", os.path.join("src", "collector", "service.py"))
        elif choice == "2":
            run_background("API", os.path.join("src", "api", "server.py"))
        elif choice == "3":
            run_background("Dash UI", os.path.join("src", "ui_dash", "app.py"))
        elif choice == "4":
            run_background("PyQt UI", os.path.join("src", "ui_pyqt", "Main.py"))
        elif choice == "5":
            print("Shutting down all processes...")
            for name, proc in processes.items():
                if proc.poll() is None:
                    proc.terminate()
                    print(f"Stopped {name}")
            break
        else:
            print("Invalid choice, try again.")

if __name__ == "__main__":
    main()
