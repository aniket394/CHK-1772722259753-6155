from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
import logging
import socket

# Initialize Flask and SocketIO
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

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
print(f"   Open this URL on your Mobile Browser: http://{get_local_ip()}:5000")

@app.route('/')
def index():
    """Serves the Mobile App Interface."""
    return render_template('index.html')

@app.route('/trigger_alert', methods=['POST'])
def trigger_alert():
    """Receives threat data from the Dashboard and pushes it to Mobile."""
    data = request.json
    print(f"⚡ Sending Alert to Mobile: {data['risk_level']}")
    
    # Broadcast the alert to all connected mobile devices
    socketio.emit('security_alert', data)
    return jsonify({"status": "sent"}), 200

if __name__ == '__main__':
    # Host 0.0.0.0 allows devices on the same WiFi to connect
    socketio.run(app, host='0.0.0.0', port=5000)