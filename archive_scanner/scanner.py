import zipfile
import os

def extract_and_scan(zip_path):
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall("extracted_files")
        return "📂 ZIP file extracted successfully. Scanning contents..."
    except Exception as e:
        return f"❌ Error extracting ZIP: {e}"
