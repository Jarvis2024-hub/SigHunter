import subprocess
import shutil

def detect_steganography(image_path, wordlist):
    if not shutil.which("stegcracker"):
        return "❌ Error: 'stegcracker' is not installed. Install it using 'pip install stegcracker'."
    
    try:
        subprocess.run(["stegcracker", image_path, wordlist])
        return f"🖼️ Steganography scan complete for {image_path}."
    except Exception as e:
        return f"❌ Error in steganography scan: {e}"
