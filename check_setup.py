import shutil
import sys

def check_environment():
    print("🔍 Checking SentinelAI Environment...\n")
    
    # 1. Check Python Modules
    try:
        import streamlit
        print("✅ Streamlit is installed.")
    except ImportError:
        print("❌ Streamlit is MISSING. Run: pip install streamlit --break-system-packages")

    try:
        import nmap
        print("✅ python-nmap is installed.")
    except ImportError:
        print("❌ python-nmap is MISSING. Run: pip install python-nmap --break-system-packages")

    # 2. Check Nmap System Tool
    if shutil.which("nmap"):
        print("✅ Nmap tool is installed and in PATH.")
    else:
        print("❌ Nmap tool is MISSING or not in PATH. Install it from nmap.org or 'sudo apt install nmap'.")

if __name__ == "__main__":
    check_environment()