# SentinelAI Image Scanner
# A backend demo program to analyze images for potential security threats.
# This script reads images, scans for QR codes, extracts EXIF metadata,
# and calculates a threat score based on simulated message content and image properties.

import os
import time
from PIL import Image
import cv2
import exifread

try:
    import winsound
except ImportError:
    winsound = None

# --- CONFIGURATION ---

# Automatically detect the system Downloads folder
IMAGE_FOLDER = os.path.join(os.path.expanduser("~"), "Downloads")

# Threat scoring weights
SCORE_QR_CODE_DETECTED = 60  # High Risk if a QR code is found
SCORE_METADATA_PRESENT = 30  # Medium Risk if metadata is present

# --- HELPER FUNCTIONS ---

def analyze_image_file(image_path):
    """
    Analyzes a single image for QR codes, metadata, and simulated message threats.
    Returns a dictionary with the assessment results.
    Args:
        image_path (str): The full path to the image file.
    """
    print(f"\n{'='*20} Analyzing: {os.path.basename(image_path)} {'='*20}")
    
    threat_score = 0
    qr_links_found = []
    metadata_keys = []

    # 1. Safely open the image using Pillow
    try:
        with Image.open(image_path) as img:
            # Display the image (opens in default image viewer)
            # img.show() # Uncomment this line if you want to see each image as it's scanned
            
            # 2. Scan for QR codes using OpenCV
            img_cv = cv2.imread(image_path)
            if img_cv is not None:
                detector = cv2.QRCodeDetector()
                
                try:
                    data, bbox, _ = detector.detectAndDecode(img_cv)
                    if data:
                        threat_score += SCORE_QR_CODE_DETECTED
                        qr_links_found.append(data)
                except Exception as cv_err:
                    print(f"    [!] OpenCV QR Scan Error: {cv_err}")

    except Exception as e:
        print(f"    [!] Could not open or process image: {e}")
        return None

    # 3. Read EXIF metadata
    try:
        with open(image_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)
            if tags:
                threat_score += SCORE_METADATA_PRESENT
                metadata_keys = list(tags.keys())
    except Exception as e:
        print(f"    [!] Could not read EXIF data: {e}")

    # Determine final threat level based on actual content
    threat_level = "LOW"
    if threat_score > 50:
        threat_level = "HIGH"
    elif threat_score > 25:
        threat_level = "MEDIUM"

    return {
        "filename": os.path.basename(image_path),
        "qr_links": qr_links_found,
        "metadata_count": len(metadata_keys),
        "score": threat_score,
        "level": threat_level,
    }

def start_monitoring():
    """
    Main function to monitor the folder for NEW images in real-time.
    """
    print("🚀 SentinelAI Real-Time Image Monitor started.")
    print(f"👀 Watching folder: {IMAGE_FOLDER}")
    print("   (Any new image downloaded here will be scanned instantly!)")
    
    if not os.path.exists(IMAGE_FOLDER):
        print(f"❌ Error: Folder '{IMAGE_FOLDER}' not found.")
        return

    # Initialize with existing files so we don't rescan old ones
    print("   [Init] Indexing existing files...")
    seen_files = set(os.listdir(IMAGE_FOLDER))
    print(f"   [Init] Indexed {len(seen_files)} existing files. Waiting for new ones...")

    while True:
        try:
            current_files = set(os.listdir(IMAGE_FOLDER))
            new_files = current_files - seen_files
            
            for filename in new_files:
                if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tiff', '.tif', '.ico')):
                    full_path = os.path.join(IMAGE_FOLDER, filename)
                    # Wait a moment for the download to finish writing the file
                    time.sleep(1)
                    result = analyze_image_file(full_path)
                    
                    if result:
                        print("\n    --- THREAT REPORT ---")
                        print(f"    File: {result['filename']}")
                        print(f"    QR Links: {result['qr_links'] or 'None'}")
                        print(f"    Metadata Keys: {result['metadata_count']}")
                        print(f"    Threat Score: {result['score']}")
                        print(f"    Threat Level: {result['level']}")
                        print(f"{'='*50}")

                        if result['level'] == "HIGH" and winsound:
                            winsound.Beep(1000, 1000)
                        elif result['level'] == "MEDIUM" and winsound:
                            winsound.Beep(700, 500)
            
            seen_files = current_files
            time.sleep(1) # Check every second
        except KeyboardInterrupt:
            print("\n🛑 Monitor stopped.")
            break
        except Exception as e:
            print(f"Error in monitoring loop: {e}")
            time.sleep(1)

# --- MAIN EXECUTION ---

if __name__ == "__main__":
    start_monitoring()
