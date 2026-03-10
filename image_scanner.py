# SentinelAI Image Scanner
# A backend demo program to analyze images for potential security threats.
# This script reads images, scans for QR codes, extracts EXIF metadata,
# and calculates a threat score based on simulated message content and image properties.

import os
import time
from PIL import Image
import pytesseract
import numpy as np
import exifread
import sys

# --- Fix for pyzbar on Windows ---
if sys.platform.startswith("win"):
    # Add common ZBar install locations to the system PATH so pyzbar can find the DLLs
    zbar_paths = [r"C:\Program Files\ZBar\bin", r"C:\Program Files (x86)\ZBar\bin"]
    for path in zbar_paths:
        if os.path.exists(path) and path not in os.environ['PATH']:
            os.environ['PATH'] += ";" + path

try:
    from pyzbar.pyzbar import decode
except (ImportError, OSError):
    print("⚠️ Warning: QR Code detection disabled. 'pyzbar' DLLs not found (Missing VC++ 2013 Redist?).")
    decode = None
try:
    from stegano import lsb
except ImportError:
    print("⚠️ Warning: Steganography detection disabled. 'stegano' library not found. (Run: pip install stegano)")
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

# Set this to True to FORCE every image to be High Risk (for testing alerts)
SIMULATION_MODE = True

# --- HELPER FUNCTIONS ---

def analyze_image_file(image_path):
    """
    Analyzes a single image for QR codes, metadata, and simulated message threats.
    Returns a dictionary with the assessment results.
    Args:
        image_path (str): The full path to the image file.
    """
    print(f"\n{'='*20} Analyzing: {os.path.basename(image_path)} {'='*20}")
    
    # --- SIMULATION / TESTING TRIGGER ---
    # Checks if global SIMULATION_MODE is on OR if filename contains "test_threat"
    if SIMULATION_MODE or "test_threat" in os.path.basename(image_path).lower():
        print("    [!] SIMULATION MODE: Test Trigger Detected!")
        return {
            "analysis": "HIGH",
            "score": 98,
            "reasons": ["⚠️ SIMULATION: Manual Test Triggered", "Filename contains 'test_threat'"],
            "qr_links": []
        }

    score = 0
    reasons = []
    qr_links = []

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
                            qr_data = obj.data.decode('utf-8')
                            qr_links.append(qr_data)
                            print(f"    [+] QR Data: {qr_data}")
                            
                            # Check for fraud keywords inside the QR link itself
                            for keyword in FRAUD_KEYWORDS:
                                if keyword in qr_data.lower():
                                    score += 15
                                    reasons.append(f"Suspicious term in QR: {keyword}")
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
            
            # A. Check for Simulation Keyword in Filename
            if "stego" in os.path.basename(image_path).lower() or "hidden" in os.path.basename(image_path).lower():
                score += 85
                reasons.append("⚠️ CRITICAL: Steganography Keyword in Filename")

            # B. Actual Library Scan
            if lsb and image_path.lower().endswith('.png'):
                try:
                    # Stegano library works best with PNG. We try to reveal data.
                    # If the image is a JPG, this might fail or return nothing, which is expected.
                    hidden_message = lsb.reveal(image_path)
                    if hidden_message:
                        score += 40
                        reasons.append("Hidden steganography message detected")
                        print(f"    [!] Hidden Data: {hidden_message[:50]}...")
                except Exception as steg_err:
                    print(f"    [!] Steganography check failed: {steg_err}")
            elif lsb and not image_path.lower().endswith('.png'):
                print("    [i] Info: Steganography scan requires PNG format (JPG compression destroys hidden data).")

    except Exception as e:
        print(f"    [!] Could not open or process image: {e}")
        return None

    # --- 4. EXIF Metadata Check ---
    try:
        with open(image_path, 'rb') as f:
            try:
                tags = exifread.process_file(f, details=False)
                
                # Check for GPS in filename (Simulation) OR in actual tags
                has_gps_name = "gps" in os.path.basename(image_path).lower()
                has_gps_data = tags and ('GPS GPSLatitude' in tags or 'GPS GPSLongitude' in tags)

                if has_gps_name or has_gps_data:
                    score += 80
                    reasons.append("⚠️ CRITICAL: Hidden GPS Location Data Found")
                elif tags:
                    # Check for specific suspicious tags or just presence of extensive metadata
                    if len(tags) > 5:  # Arbitrary threshold for "unusual" amount of metadata
                        score += 10
                        reasons.append("Extensive EXIF metadata detected")
                else:
                    print("    [i] No EXIF data found in image.")
                    # Treat completely stripped metadata as slightly suspicious
                    score += 35
                    reasons.append("⚠️ Warning: File metadata is stripped (Suspicious)")
            except Exception as exif_err:
                print(f"    [!] Error processing EXIF data: {exif_err}")


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
        "reasons": reasons,
        "qr_links": qr_links
    }

def start_monitoring():
    """
    Main function to monitor the folder for NEW images in real-time.
    """
    # Enable ANSI colors in Windows terminal
    if os.name == 'nt':
        os.system('color')

    print("🚀 SentinelAI Real-Time Image Monitor started.")
    
    if SIMULATION_MODE:
        print("    ⚠️  WARNING: SIMULATION_MODE IS ON. All images will be High Risk! ⚠️")
    
    # Check Detector Status
    ocr_status = "❌ Disabled (Tesseract EXE not found)"
    try:
        pytesseract.get_tesseract_version()
        ocr_status = "✅ Active"
    except:
        pass
    print(f"   [System] QR Scanner:  {'✅ Active' if decode else '❌ Disabled (pyzbar/DLLs missing)'}")
    print(f"   [System] OCR Scanner: {ocr_status}")

    print(f"👀 Watching folder: {IMAGE_FOLDER}")
    print("   (Watching for all image types: PNG, JPG, GIF, BMP, WEBP, TIFF, HEIC, RAW, etc.)")
    
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
                # Expanded list to support almost all image formats
                valid_extensions = ('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tiff', '.tif', '.ico', 
                                  '.jfif', '.pjpeg', '.pjp', '.dib', '.heic', '.heif', '.raw', '.cr2', '.nef', '.orf')
                if filename.lower().endswith(valid_extensions):
                    full_path = os.path.join(IMAGE_FOLDER, filename)
                    # Wait a moment for the download to finish writing the file
                    time.sleep(1)
                    result = analyze_image_file(full_path)
                    
                    if result:
                        # ANSI Color Codes (Standard for better compatibility)
                        RED = "\033[31m"
                        YELLOW = "\033[33m"
                        GREEN = "\033[32m"
                        RESET = "\033[0m"
                        BOLD = "\033[1m"

                        color = GREEN
                        if result['analysis'] == "HIGH":
                            color = RED
                        elif result['analysis'] == "MEDIUM":
                            color = YELLOW

                        print(f"\n    {color}{'='*15} THREAT REPORT {'='*15}{RESET}")
                        print(f"    File: {BOLD}{filename}{RESET}")
                        print(f"    Analysis: {color}{BOLD}{result['analysis']}{RESET}")
                        print(f"    Threat Score: {color}{result['score']}/100{RESET}")
                        print(f"    Reasons: {result['reasons']}")
                        print(f"    {color}{'='*45}{RESET}")

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
