import yara
import os

yara_rules_path = os.path.join(os.path.dirname(__file__), 'malware_rules.yar')

if os.path.exists(yara_rules_path):
    yara_rules = yara.compile(filepath=yara_rules_path)
else:
    yara_rules = None

def scan_with_yara(file_path):
    if yara_rules:
        matches = yara_rules.match(file_path)
        if matches:
            return f"🔴 [ALERT] Malware detected in {file_path}! Matched YARA rules: {matches}"
        return f"✅ [SAFE] No malware found in {file_path}."
    return "⚠️ YARA scanning skipped due to missing rule file. Please add 'malware_rules.yar'."
