import hashlib

try:
    import ssdeep
    ssdeep_available = True
except ImportError:
    ssdeep_available = False

def calculate_hashes(file_path):
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
            md5_hash = hashlib.md5(file_data).hexdigest()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
            ssdeep_hash = ssdeep.hash(file_data) if ssdeep_available else "❌ SSDEEP not available"

        return f"🔍 Hashes for {file_path}:\nMD5: {md5_hash}\nSHA256: {sha256_hash}\nSSDEEP: {ssdeep_hash}"
    except Exception as e:
        return f"❌ Error calculating hashes: {e}"

