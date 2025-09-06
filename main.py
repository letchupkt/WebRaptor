#!/usr/bin/env python3
import os
import sys
import subprocess
import platform

def clear_screen():
    # Clear screen for Windows/Linux/Mac
    os.system("cls" if platform.system() == "Windows" else "clear")

def check_dependencies():
    required_modules = ["requests", "colorama", "rich"]
    missing = []

    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)

    if missing:
        print("[!] Installing missing dependencies...")
        subprocess.call([sys.executable, "-m", "pip", "install"] + missing)

def main():
    clear_screen()
    check_dependencies()

    try:
        from core.shell import WebRaptorShell
    except ImportError as e:
        print(f"[!] Error importing WebRaptorShell: {e}")
        sys.exit(1)

    shell = WebRaptorShell()
    shell.cmdloop()

if __name__ == "__main__":
    main()
