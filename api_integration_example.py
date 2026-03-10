import requests
import os

# This script demonstrates how to integrate SentinelAI into another Python app.
# It sends an image to the SentinelAI server and prints the risk report.

SERVER_API_URL = "http://localhost:5001/api/scan/image"
TEST_IMAGE_PATH = "test_image.png" # Make sure this file exists or change name

def scan_image_via_api(image_path):
    if not os.path.exists(image_path):
        print(f"❌ File not found: {image_path}")
        return

    print(f"🚀 Sending {image_path} to SentinelAI for analysis...")
    
    try:
        with open(image_path, 'rb') as f:
            files = {'file': f}
            response = requests.post(SERVER_API_URL, files=files)
        
        if response.status_code == 200:
            result = response.json()
            print("\n✅ Analysis Result Received:")
            print(f"   Risk Level: {result.get('level', 'N/A')}")
            print(f"   Score: {result.get('score', 0)}/100")
            print(f"   Reasons: {result.get('reasons', [])}")
            if result.get('qr_links'):
                print(f"   QR Links Found: {result['qr_links']}")
        else:
            print(f"❌ Error: {response.text}")
            
    except Exception as e:
        print(f"❌ Connection Failed: {e}")

if __name__ == "__main__":
    # Create a dummy file for testing if needed
    if not os.path.exists(TEST_IMAGE_PATH):
        from PIL import Image
        img = Image.new('RGB', (100, 30), color = (73, 109, 137))
        img.save(TEST_IMAGE_PATH)
        
    scan_image_via_api(TEST_IMAGE_PATH)