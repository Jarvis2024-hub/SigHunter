import requests

SHODAN_API_KEY = "D2q0hfEu97OhG7Vp2RCZZN7H07U6Qo5n"
ABUSEIPDB_API_KEY = "05f7e006a8abcf95b30fa07b39155ca30b2a5dc36aa9fc7811a9044f8cf224472194bfb3b33d37e8"

def check_ip_reputation(ip):
    try:
        response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers={"Key": ABUSEIPDB_API_KEY},timeout=10)
        return f"📡 IP Reputation Report: {response.json()}"
    except Exception as e:
        return f"❌ Error checking IP reputation: {e}"
