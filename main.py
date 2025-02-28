
import signature_scanner.scanner as sig_scan
import hash_scanner.scanner as hash_scan
import sandbox_scanner.scanner as sandbox_scan
import virustotal_scanner.scanner as vt_scan
import reputation_scanner.scanner as rep_scan
import static_analysis.scanner as static_scan
import archive_scanner.scanner as archive_scan
import steg_scanner.scanner as steg_scan
import encryption_scanner.scanner as enc_scan

file_path = input("📂 Enter file path: ")

print(sig_scan.scan_with_yara(file_path))
print(hash_scan.calculate_hashes(file_path))
print(sandbox_scan.analyze_pe(file_path))
print(vt_scan.scan_with_virustotal(file_path))
print(rep_scan.check_ip_reputation("8.8.8.8"))  # Example IP
print(static_scan.analyze_script(file_path))
print(archive_scan.extract_and_scan(file_path))
print(steg_scan.detect_steganography(file_path, "wordlist.txt"))
print(enc_scan.decrypt_and_scan(file_path, "your_encryption_key"))
