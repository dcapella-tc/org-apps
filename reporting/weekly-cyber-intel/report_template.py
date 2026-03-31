
CYBER_BREACH_AND_COMPROMISE_NEWS = 'Cyber Breach and Compromise News'
ELECTRICITY_INFORMATION_SHARING_AND_ANALYSIS_CENTER_E_ISAC_ALERTS_AND_ADVISORIES = 'Electricity Information Sharing and Analysis Center (E-ISAC) Alerts and Advisories'
CYBER_SECURITY_NEWS = 'Cyber Security News'
CYBER_SECURITY_NEWS_RUSSIA_UKRAINE = 'Russia / Ukraine'
CYBER_SECURITY_NEWS_GENERAL = 'General'
CYBER_SECURITY_NEWS_GOVERNMENTS = 'Governments'
CYBER_SECURITY_NEWS_BUSINESSES = 'Businesses'
MALWARE_BOTNET_CRYPTO_MINING_NEWS = 'Malware/Botnet/Cryptomining News'
PHISHING_NEWS = 'Phishing News'
PRODUCT_VULNERABILITY_NEWS = 'Product Vulnerability News'
MOBILE_DEVICES = 'Mobile Devices'

TITLE_DIV = '<div style="font-size:16px; font-weight:700; text-decoration:underline; margin:34px 0 10px 0;">'
HTML_BEGINNING = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Weekly Cyber Intel</title>
</head>

<body style="margin:0; background:#f4f4f4; font-family:Arial, Helvetica, sans-serif; color:#000; line-height:1.35;">
  <div style="max-width:900px; margin:28px auto; background:#fff; padding:70px 90px; border:1px solid #d9d9d9; box-shadow:0 6px 18px rgba(0,0,0,0.08);">

    <div style="text-align:center; font-size:18px; font-weight:600; margin:0 0 70px 0; letter-spacing:0.2px;">
      __DGMSOC Weekly Cyber Intel__
    </div>
"""
HTML_ENDING = """
  </div>
</body>
</html>
"""
CYBER_BREACH_AND_COMPROMISE_NEWS_KEYWORDS = '(insights contains "data breach" OR insights contains "breach" OR insights contains "security incident" OR insights contains "compromise" OR insights contains "unauthorized access" OR insights contains "intrusion" OR insights contains "data leak" OR insights contains "data exfiltration" OR insights contains "stolen data" OR insights contains "records exposed" OR insights contains "customer data exposed" OR insights contains "PII exposed")'

# ELECTRICITY_INFORMATION_SHARING_AND_ANALYSIS_CENTER_E_ISAC_ALERTS_AND_ADVISORIES_KEYWORDS = '(insights contains "data breach" OR insights contains "breach" OR insights contains "security incident" OR insights contains "compromise" OR insights contains "unauthorized access" OR insights contains "intrusion" OR insights contains "data leak" OR insights contains "data exfiltration" OR insights contains "stolen data" OR insights contains "records exposed" OR insights contains "customer data exposed" OR insights contains "PII exposed")'
# Specific
CYBER_SECURITY_NEWS_RUSSIA_UKRAINE_KEYWORDS = '(insights contains "Russia" OR insights contains "Ukraine" OR insights contains "GRU" OR insights contains "SVR" OR insights contains "Sandworm" OR insights contains "Killnet") AND (insights contains "cyber" OR insights contains "hacking" OR insights contains "malware" OR insights contains "ransomware" OR insights contains "DDoS" OR insights contains "wiper" OR insights contains "intrusion" OR insights contains "critical infrastructure" OR insights contains "power grid")'

CYBER_SECURITY_NEWS_GENERAL_KEYWORDS = '(insights contains "cybersecurity" OR insights contains "cyber attack" OR insights contains "threat actor" OR insights contains "APT" OR insights contains "state-sponsored" OR insights contains "incident response" OR insights contains "intrusion" OR insights contains "compromise" OR insights contains "ransomware" OR insights contains "data breach" OR insights contains "zero-day" OR insights contains "patch")'

CYBER_SECURITY_NEWS_GOVERNMENTS_KEYWORDS = '(insights contains "government agency" OR insights contains "public sector" OR insights contains "ministry" OR insights contains "defense department" OR insights contains "intelligence service" OR insights contains "national CERT" OR insights contains "CISA advisory" OR insights contains "FBI warning" OR insights contains "election security") AND (insights contains "breach" OR insights contains "ransomware" OR insights contains "intrusion" OR insights contains "compromise" OR insights contains "data leak" OR insights contains "incident response")'

CYBER_SECURITY_NEWS_BUSINESSES_KEYWORDS = '(insights contains "enterprise" OR insights contains "corporate network" OR insights contains "customer data" OR insights contains "vendor breach" OR insights contains "third-party risk" OR insights contains "supply chain attack" OR insights contains "SaaS breach" OR insights contains "cloud compromise" OR insights contains "credential theft" OR insights contains "insider threat" OR insights contains "business disruption" OR insights contains "financial impact") AND (insights contains "breach" OR insights contains "ransomware" OR insights contains "incident" OR insights contains "compromise" OR insights contains "data leak")'

MALWARE_BOTNET_CRYPTO_MINING_NEWS_KEYWORDS = '(insights contains "malware" OR insights contains "infostealer" OR insights contains "trojan" OR insights contains "worm" OR insights contains "loader" OR insights contains "backdoor") OR ((insights contains "botnet" OR insights contains "command and control" OR insights contains "C2" OR insights contains "DGA") AND (insights contains "malware" OR insights contains "campaign" OR insights contains "infected" OR insights contains "compromised")) OR (insights contains "cryptominer" OR insights contains "cryptojacking" OR (insights contains "mining pool" AND (insights contains "malware" OR insights contains "infected")))'

PHISHING_NEWS_KEYWORDS = '(insights contains "phishing" OR insights contains "spearphishing" OR insights contains "credential harvesting" OR insights contains "phishing kit" OR insights contains "fake login page" OR insights contains "typosquatting" OR insights contains "smishing" OR insights contains "vishing" OR insights contains "QR phishing" OR insights contains "MFA fatigue") OR ((insights contains "business email compromise" OR insights contains "BEC") AND (insights contains "invoice" OR insights contains "wire transfer" OR insights contains "payroll" OR insights contains "gift card" OR insights contains "banking"))'

PRODUCT_VULNERABILITY_NEWS_KEYWORDS = '(insights contains "CVE" OR insights contains "zero-day" OR insights contains "actively exploited") OR (insights contains "vulnerability" AND (insights contains "patch released" OR insights contains "security update" OR insights contains "proof of concept" OR insights contains "PoC" OR insights contains "exploit chain" OR insights contains "remote code execution" OR insights contains "RCE" OR insights contains "privilege escalation"))'

MOBILE_DEVICES_KEYWORDS = '((insights contains "Android" OR insights contains "iOS" OR insights contains "mobile") AND (insights contains "mobile malware" OR insights contains "mobile spyware" OR insights contains "stalkerware" OR insights contains "malicious app" OR insights contains "APK" OR insights contains "App Store" OR insights contains "mobile phishing" OR insights contains "mobile zero-day" OR insights contains "SIM swapping" OR insights contains "MDM")) OR (insights contains "Pegasus" OR insights contains "NSO")'