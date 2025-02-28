import os

def analyze_script(file_path):
    try:
        with open(file_path, "r") as f:
            lines = f.readlines()
            suspicious = [line for line in lines if "exec" in line or "eval" in line]
        return f"📜 Static Analysis: {len(suspicious)} suspicious lines detected." if suspicious else "✅ No suspicious code found."
    except Exception as e:
        return f"❌ Error analyzing script: {e}"
