import sys
import time
import threading

# Requires: pip install python-socketio[client]
try:
    import socketio
except ImportError:
    print("❌ Error: 'python-socketio' library is missing.")
    print("   Run: pip install \"python-socketio[client]\"")
    sys.exit()

# Default Configuration
SERVER_URL = "http://localhost:5001"

# Allow IP override via command line: python sms_client.py 192.168.1.10
if len(sys.argv) > 1:
    SERVER_URL = f"http://{sys.argv[1]}:5001"

sio = socketio.Client()

@sio.event
def connect():
    print(f"\n✅ Connected to Sentinel Secure Chat at {SERVER_URL}")
    print("==================================================")
    print("   Type a message and press Enter to send.")
    print("   (Links will be auto-scanned for threats)")
    print("==================================================\n")

@sio.event
def disconnect():
    print("\n❌ Disconnected from server.")
    sys.exit()

@sio.on('receive_chat')
def on_message(data):
    sender = data.get('sender_id', 'Unknown')
    msg = data.get('message', '')
    risk = data.get('risk_level', 'Unknown')
    score = data.get('score', 0)
    
    # Skip pending messages in console view to keep it clean
    if risk == "pending":
        return

    # Define Colors
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"
    
    # Determine Color Tag
    tag_color = GREEN
    if "High" in risk or "Critical" in risk:
        tag_color = RED
    elif "Medium" in risk:
        tag_color = YELLOW
        
    print(f"\r[{sender[-4:]}] {msg}")
    print(f"   └── {tag_color}Analysis: {risk} (Score: {score}){RESET}")
    print("\n> ", end="", flush=True)

def input_loop():
    while True:
        try:
            msg = input("> ")
            if msg.strip():
                # Send to server
                sio.emit('send_chat', {'message': msg, 'tempId': int(time.time()*1000)})
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            sio.disconnect()
            break

if __name__ == "__main__":
    print(f"Connecting to {SERVER_URL}...")
    try:
        sio.connect(SERVER_URL)
        # Start input thread
        threading.Thread(target=input_loop, daemon=True).start()
        sio.wait()
    except Exception as e:
        print(f"❌ Connection Failed: {e}")
        print("   Make sure 'mobile_server.py' is running!")