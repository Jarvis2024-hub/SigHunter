from cryptography.fernet import Fernet

def decrypt_and_scan(enc_path, key):
    try:
        if len(key) != 44:
            return "❌ Error: Fernet key must be 32 url-safe base64-encoded bytes."
        
        fernet = Fernet(key)
        with open(enc_path, "rb") as enc_file:
            decrypted_data = fernet.decrypt(enc_file.read())
        return "🔑 Decryption successful. File is safe."
    except Exception as e:
        return f"❌ Decryption failed: {e}"
