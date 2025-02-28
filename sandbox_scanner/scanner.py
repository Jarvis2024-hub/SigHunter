import pefile

def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)
        sections = [section.Name.decode().strip("\x00") for section in pe.sections]
        return f"🛠️ PE Analysis of {file_path}:\nSections: {sections}"
    except Exception as e:
        return f"❌ Not a valid PE file or error: {e}"
