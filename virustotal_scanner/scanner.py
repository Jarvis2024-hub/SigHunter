import requests
import os

VT_API_KEY = "2751eec3f096fd275a1b08609d89ccbd1e06a02b31beec396fc19051faca8847"

def scan_with_virustotal(file_path):
    try:
        url = "https://www.virustotal.com/api/v3/files"
        headers = {"x-apikey": VT_API_KEY}
        files = {"file": (os.path.basename(file_path), open(file_path, "rb"))}
        response = requests.post(url, headers=headers, files=files)
        return f"📄 VirusTotal Report: {response.json()}"
    except Exception as e:
        return f"❌ Error in VirusTotal Scan: {e}"
