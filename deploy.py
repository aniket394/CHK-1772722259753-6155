import os
import sys
import socket
import subprocess
import time

def get_local_ip():
    """Finds the local IP address of this computer on the network."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't actually connect, just determines the interface used for internet
        s.connect(('8.8.8.8', 80))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def main():
    # Clear screen
    os.system('cls' if os.name == 'nt' else 'clear')
    
    ip = get_local_ip()
    
    print("\n" + "="*60)
    print("      🚀 SENTINEL AI - MOBILE DEPLOYMENT HUB")
    print("="*60)
    print(f"\n✅ Server Address: http://{ip}:5001")
    print("\n📱 INSTRUCTIONS FOR PHONES:")
    print("-" * 40)
    print(f"1. Connect your phone to the SAME Wi-Fi as this PC.")
    print(f"2. Open Chrome/Safari on the phone.")
    print(f"3. Type this URL to chat:  http://{ip}:5001/chat")
    print("-" * 40)
    print("\nℹ️  CONNECTION TIPS:")
    print("   - If the site won't load, Windows Firewall is likely blocking it.")
    print("   - Try disabling the Firewall temporarily for 'Private Networks'.")
    print("   - Or allow 'python.exe' through the firewall.")
    print("\n" + "="*60)
    print("Starting Server... (Press Ctrl+C to stop)")
    print("="*60 + "\n")

    # Run the existing mobile server
    try:
        subprocess.run([sys.executable, "mobile_server.py"])
    except KeyboardInterrupt:
        print("\n🛑 Deployment stopped.")

if __name__ == "__main__":
    main()