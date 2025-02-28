import os
import telebot
import magic  # Detects file type
import signature_scanner.scanner as sig
import hash_scanner.scanner as hash
import sandbox_scanner.scanner as sandbox
import virustotal_scanner.scanner as vt
import reputation_scanner.scanner as rep
import static_analysis.scanner as static
import archive_scanner.scanner as archive
import steg_scanner.scanner as steg
import encryption_scanner.scanner as enc
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton


BOT_TOKEN = "7734778811:AAEW4rpQnCP9hWTGPpfu6EsZxQ9oXwfnDKU"
bot = telebot.TeleBot(BOT_TOKEN)

from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

@bot.message_handler(commands=['start'])
def welcome_message(message):
    welcome_text = "🤖 *Welcome to SigHunter\\!*  \n" \
                   "🔍 I specialize in analyzing all types of files to determine if they are *safe or malicious*\\.  \n\n" \
                   "📂 *What I can do:*  \n" \
                   "✅ *Scan files* for malware using multiple techniques\\.  \n" \
                   "✅ *Check file hashes* against known malware databases\\.  \n" \
                   "✅ *Analyze scripts and executables* for suspicious behavior\\.  \n" \
                   "✅ *Detect steganography* in images and audio files\\.  \n" \
                   "✅ *Unpack and scan* encrypted or archived files\\.  \n\n" \
                   "📤 *Send me a file, and I'll analyze it for you\\!*"  

    # ✅ Create a button that sends the /help command
    keyboard = InlineKeyboardMarkup()
    help_button = InlineKeyboardButton("💡 Click here for help", callback_data="help_command")
    keyboard.add(help_button)

    bot.send_message(message.chat.id, welcome_text, parse_mode="MarkdownV2", reply_markup=keyboard)

# ✅ Handle button click to send the /help message
@bot.callback_query_handler(func=lambda call: call.data == "help_command")
def send_help_callback(call):
    help_message(call.message)






@bot.chat_member_handler()
def on_user_added(message):
    if message.new_chat_member.status == "member":
        bot.send_message(message.chat.id, "👋 *Hello! I'm SigHunter\\!* Type /start to get started\\!", parse_mode="MarkdownV2")
        welcome_message(message)  # Send the full /start message automatically








@bot.message_handler(commands=['help'])
def help_message(message):
    help_text = """
🆘 **Help Menu - SigHunter**  

📌 **How to use me:**  
1️⃣ Send **any file**, and I will analyze it for potential threats.  
2️⃣ Type **/start** to see an introduction.  
3️⃣ Type **/help** to view this menu.  

🛠 **Features:**  
🔹 **Malware Scanning** - Detects viruses and malicious scripts.  
🔹 **File Type Analysis** - Identifies file formats and suspicious behavior.  
🔹 **Steganography Detection** - Finds hidden data in images/audio.  
🔹 **Archive & Encryption Analysis** - Extracts and scans ZIP, encrypted files.  
🔹 **Reputation Checks** - Checks IPs, hashes, and URLs for known threats.  

📞 Need assistance? Contact the admin.  
"""
    bot.send_message(message.chat.id, help_text, parse_mode="Markdown")


@bot.message_handler(content_types=['document'])
def handle_files(message):
    file_info = bot.get_file(message.document.file_id)
    file_path = file_info.file_path
    downloaded_file = bot.download_file(file_path)
    
    filename = message.document.file_name
    with open(filename, 'wb') as new_file:
        new_file.write(downloaded_file)

    # 🔍 **Check File Type First**
    mime = magic.Magic(mime=True)
    file_type = mime.from_file(filename)
    bot.send_message(message.chat.id, f"📂 Detected file type: {file_type}")

    result = []

    # 1️⃣ **Run Signature & Hash Scanning on All Files**
    result.append(sig.scan_with_yara(filename))
    result.append(hash.calculate_hashes(filename))

    # 2️⃣ **Run PE Analysis Only for Executables**
    if "executable" in file_type:
        result.append(sandbox.analyze_pe(filename))

    # 3️⃣ **Run VirusTotal & Reputation Check for All Files**
    result.append(vt.scan_with_virustotal(filename))
    result.append(rep.check_ip_reputation("8.8.8.8"))  # Example IP

    # 4️⃣ **Run Static Analysis Only for Scripts**
    if "python" in file_type or "javascript" in file_type or "shell script" in file_type:
        result.append(static.analyze_script(filename))

    # 5️⃣ **Run ZIP Extraction Only for ZIP Files**
    if "zip" in file_type:
        result.append(archive.extract_and_scan(filename))

    # 6️⃣ **Run Steganography Only for Image/Audio Files**
    if "jpeg" in file_type or "bmp" in file_type or "wav" in file_type:
        result.append(steg.detect_steganography(filename, "wordlist.txt"))

    # 7️⃣ **Run Decryption Only for Encrypted Files**
    if filename.endswith(".enc"):
        result.append(enc.decrypt_and_scan(filename, "lxZFNhknXb3wHxoh_S-pCDeIGNV5y6hwgr748wyr308="))

    # 📤 Send results back
    bot.send_message(message.chat.id, "\n".join(result))

bot.polling()
