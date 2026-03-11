from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
import logging
import socket
import re
import sys
import os
import time
import base64
from urllib.parse import urlparse

# Ensure project root is in path for imports
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# Fix Nmap Path on Windows (if not in system PATH)
if sys.platform.startswith("win"):
    nmap_paths = [r"C:\Program Files (x86)\Nmap", r"C:\Program Files\Nmap"]
    for path in nmap_paths:
        if os.path.exists(path):
            os.environ['PATH'] += ";" + path

# Safe Imports: Ensure server runs even if scanner modules are missing/reorganized
try:
    from scanner.nmap_scan import scan_target
    from parser.scan_parser import analyze_risk
except ImportError:
    print("⚠️  Warning: Scanner modules not found. Using simulation mode for Nmap.")
    def scan_target(target): 
        return []
    def analyze_risk(ports, msg, link): 
        return {"level": "Low Risk", "score": 10, "logs": [], "reasons": ["Simulation (Module Missing)"]}

from image_scanner import analyze_image_file
try:
    from nmap import PortScannerError
except ImportError:
    class PortScannerError(Exception): pass

# Initialize Flask and SocketIO
app = Flask(__name__)

# Suppress verbose Flask development server logs to reduce confusion
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Suppress Flask Server Banner
from flask import cli
cli.show_server_banner = lambda *args: None

# Use threading to avoid eventlet bind errors on Python 3.14
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', max_http_buffer_size=10 * 1024 * 1024) # 10MB limit

def get_local_ip():
    """Finds the local IP address of this computer on the network."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to a public DNS server (doesn't actually send data)
        s.connect(('8.8.8.8', 80))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

print("📱 SentinelAI Mobile Bridge is running...")
print(f"   Open this URL on your Mobile Browser: http://{get_local_ip()}:5001")

@app.route('/')
def index():
    """Serves the Mobile App Interface."""
    return render_template('index.html')

@app.route('/chat')
def chat_interface():
    """Serves the Web-based SMS/Chat Interface for device-to-device communication."""
    return render_template('chat.html')

@app.route('/trigger_alert', methods=['POST'])
def trigger_alert():
    """Receives threat data from the Dashboard and pushes it to Mobile."""
    data = request.json
    print(f"⚡ Dashboard Alert: {data.get('risk_level')}")
    
    source = data.get('source', 'DASHBOARD')
    
    # Convert Dashboard alert to a Chat Message format
    chat_payload = {
        "sender_id": "System",
        "message": f"🚨 {source} ALERT: {data.get('message', '')}",
        "risk_level": data.get('risk_level', 'Low Risk'),
        "score": data.get('score', 0),
        "target": data.get('target', 'Unknown')
    }
    socketio.emit('receive_chat', chat_payload)
    return jsonify({"status": "sent"}), 200

@socketio.on('send_chat') # This is the correct event name
def handle_chat(data):
    """Receives a chat message, scans it, and delivers it to all clients."""
    sender_id = request.sid
    message = data.get('message', '')
    temp_id = data.get('tempId') # For client-side pending messages
    
    if not temp_id:
        temp_id = int(time.time() * 1000)

    print(f"📩 Chat from {sender_id} (tempId: {temp_id}): {message}")

    # 1. Broadcast "Pending" state immediately so receiver sees it arriving
    pending_payload = {
        "sender_id": sender_id,
        "tempId": temp_id,
        "message": message,
        "risk_level": "pending",
        "score": 0,
        "target": "Scanning..."
    }
    socketio.emit('receive_chat', pending_payload)

    # 1. Extract Target (URL or IP)
    target = None
    full_link = None
    url_match = re.search(r'(?:http[s]?://|www\.)(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', message)
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)

    if url_match:
        full_link = url_match.group()
        if full_link.startswith("www."):
            full_link = "http://" + full_link
        target = urlparse(full_link).hostname
    elif ip_match:
        full_link = ip_match.group()
        target = full_link
    
    # 2. Scan & Analyze
    if target:
        print(f"[*] Scanning Target: {target}")
        try:
            scan_results = scan_target(target)
            open_ports = [port for port, _ in scan_results]
            assessment = analyze_risk(open_ports, message, full_link)
        except PortScannerError:
            print("❌ FATAL: Nmap is not installed or not in your system's PATH.")
            print("   Please install it from https://nmap.org/download.html")
            assessment = {"level": "Medium Risk", "score": 50}
            message += " (Scan Failed: Nmap not found)"
        except Exception as e:
            print(f"⚠️ Scan Error: {e}")
            # If scan fails, warn the user but still deliver the message
            assessment = {"level": "Medium Risk", "score": 50}
            message += " (Scan Failed)"
    else:
        # Analyze text content even if no link is present
        print("[*] Analyzing Text Content (No Link Detected)")
        assessment = analyze_risk([], message, "Text Only")
        target = "Text Content"

    # 3. Broadcast to ALL clients
    payload = {
        "sender_id": sender_id,
        "tempId": temp_id,
        "message": message,
        "risk_level": assessment['level'],
        "score": assessment['score'],
        "target": target
    }
    socketio.emit('receive_chat', payload)

@socketio.on('analyze_image')
def handle_image_upload(data):
    """Receives a base64 image, saves it, scans it, and returns the result."""
    sender_id = request.sid
    image_data = data.get('image', '')
    temp_id = data.get('tempId')
    
    if not image_data:
        return

    print(f"🖼️ Image received from {sender_id}")

    # Decode and save image temporarily
    filepath = None
    try:
        header, encoded = image_data.split(",", 1)
        file_ext = header.split('/')[1].split(';')[0]
        if file_ext == 'jpeg': file_ext = 'jpg'
        
        filename = f"temp_{temp_id}.{file_ext}"
        filepath = os.path.join("images", filename)
        
        if not os.path.exists("images"):
            os.makedirs("images")
            
        with open(filepath, "wb") as f:
            f.write(base64.b64decode(encoded))
            
        # Analyze the saved image
        result = analyze_image_file(filepath)
        
        # Construct response payload
        if result:
            # Build a descriptive analysis message
            analysis_text = f"📷 Analysis: {result['analysis']} ({result['score']}/100)"
            if result['reasons']:
                analysis_text += f"\n⚠️ {result['reasons'][0]}"
            if len(result['reasons']) > 1:
                analysis_text += f"\n(+{len(result['reasons'])-1} other flags)"

            response_payload = {
                "sender_id": sender_id,
                "tempId": temp_id,
                "message": analysis_text,
                "risk_level": result['analysis'],
                "score": result['score'],
                "target": "Image Scan"
            }
            socketio.emit('receive_chat', response_payload)
        else:
            # Handle analysis failure (e.g. corrupt image)
            socketio.emit('receive_chat', {
                "sender_id": sender_id,
                "tempId": temp_id,
                "message": "⚠️ Analysis Failed: Could not process image.",
                "risk_level": "Error",
                "score": 0,
                "target": "Image Scan"
            })

        # Clean up
        try:
            if filepath and os.path.exists(filepath):
                os.remove(filepath)
        except:
            pass
    except Exception as e:
        print(f"❌ Image processing error: {e}")
        socketio.emit('receive_chat', {
            "sender_id": sender_id,
            "tempId": temp_id,
            "message": "⚠️ Server Error: Image processing failed.",
            "risk_level": "Error",
            "score": 0,
            "target": "Image Scan"
        })

# --- REST API FOR EXTERNAL INTEGRATION ---
@app.route('/api/scan/image', methods=['POST'])
def api_scan_image():
    """API Endpoint for other apps to scan images."""
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    filename = f"api_temp_{int(time.time())}_{file.filename}"
    filepath = os.path.join("images", filename)
    if not os.path.exists("images"):
        os.makedirs("images")
    
    file.save(filepath)
    result = analyze_image_file(filepath)
    try: os.remove(filepath)
    except: pass
    
    if result:
        # Reformat the result to match the API client's expectations
        api_response = {
            "level": result.get("analysis", "Error"),
            "score": result.get("score", 0),
            "qr_links": result.get("qr_links", []),
            "reasons": result.get("reasons", [])
        }
        return jsonify(api_response)
    return jsonify({"error": "Analysis failed"}), 500

if __name__ == '__main__':
    # Host 0.0.0.0 allows devices on the same WiFi to connect
    socketio.run(app, host='0.0.0.0', port=5001, allow_unsafe_werkzeug=True)