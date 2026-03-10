# SentinelAI Image Scanner
# A backend demo program to analyze images for potential security threats.
# This script reads images, scans for QR codes, extracts EXIF metadata,
# and calculates a threat score based on simulated message content and image properties.

import os
import time
from PIL import Image
import cv2
import pytesseract
import numpy as np
import exifread
try:
    from pyzbar.pyzbar import decode
except (ImportError, OSError):
    print("⚠️ Warning: QR Code detection disabled. 'pyzbar' DLLs not found (Missing VC++ 2013 Redist?).")
    decode = None
try:
    from stegano import lsb
except ImportError:
    lsb = None

try:
    import winsound
except ImportError:
    winsound = None

# --- CONFIGURATION ---

# Automatically detect the system Downloads folder
IMAGE_FOLDER = os.path.join(os.path.expanduser("~"), "Downloads")

# Threat scoring weights
FRAUD_KEYWORDS = ["otp", "verify", "urgent", "bank", "payment", "click link", "lottery", "reward", "update account"]

# --- HELPER FUNCTIONS ---

def analyze_image_file(image_path):
    """
    Analyzes a single image for QR codes, metadata, and simulated message threats.
    Returns a dictionary with the assessment results.
    Args:
        image_path (str): The full path to the image file.
    """
    print(f"\n{'='*20} Analyzing: {os.path.basename(image_path)} {'='*20}")
    
    score = 0
    reasons = []

    # 1. Safely open the image using Pillow
    try:
        with Image.open(image_path) as img:
            # Convert to RGB for consistency
            img = img.convert('RGB')
            
            # --- 1. QR Code Detection (pyzbar) ---
            try:
                if decode:
                    decoded_objects = decode(img)
                    if decoded_objects:
                        score += 60
                        reasons.append("QR code detected in image")
                        for obj in decoded_objects:
                            print(f"    [+] QR Data: {obj.data.decode('utf-8')}")
            except Exception as e:
                print(f"    [!] QR Scan Error: {e}")
            
            # --- 2. OCR Text Detection (Pytesseract) ---
            try:
                text_content = pytesseract.image_to_string(img).lower()
                found_keywords = [word for word in FRAUD_KEYWORDS if word in text_content]
                
                for word in found_keywords:
                    score += 10
                    reasons.append(f"Suspicious keyword detected: {word}")
                    
            except Exception as ocr_err:
                print(f"    [!] OCR Error (Tesseract not installed?): {ocr_err}")

            # --- 3. Steganography Detection (Stegano LSB) ---
            # Note: LSB usually requires PNG/BMP. JPG compression destroys it.
            if lsb:
                try:
                    # Stegano library works best with PNG. We try to reveal data.
                    # If the image is a JPG, this might fail or return nothing, which is expected.
                    hidden_message = lsb.reveal(image_path)
                    if hidden_message:
                        score += 40
                        reasons.append("Hidden steganography message detected")
                        print(f"    [!] Hidden Data: {hidden_message[:50]}...")
                except Exception:
                    # Expected error for JPEGs or non-stegano images
                    pass

    except Exception as e:
        print(f"    [!] Could not open or process image: {e}")
        return None

    # --- 4. EXIF Metadata Check ---
    try:
        with open(image_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)
            if tags:
                # Check for specific suspicious tags or just presence of extensive metadata
                if len(tags) > 5: # Arbitrary threshold for "unusual" amount of metadata
                    score += 10
                    reasons.append("Unusual EXIF metadata detected")
    except Exception as e:
        print(f"    [!] Could not read EXIF data: {e}")

    # --- 5. Risk Level Classification ---
    score = min(score, 100) # Cap at 100
    
    analysis = "LOW"
    if score >= 70:
        analysis = "HIGH"
    elif score >= 30:
        analysis = "MEDIUM"

    return {
        "analysis": analysis,
        "score": score,
        "reasons": reasons
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
                        print(f"    File: {filename}")
                        print(f"    Analysis: {result['analysis']}")
                        print(f"    Threat Score: {result['score']}")
                        print(f"    Reasons: {result['reasons']}")
                        print(f"{'='*50}")

                        if result['analysis'] == "HIGH" and winsound:
                            winsound.Beep(1000, 1000)
                        elif result['analysis'] == "MEDIUM" and winsound:
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
