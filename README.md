# Rooted-recon
Reconnaissance Tool

ReconX ek Python-based reconnaissance & information gathering tool hai jo penetration testers aur ethical hackers ke liye banaya gaya hai. Ye tool multiple modules ke zariye target ke baare mein valuable information collect karta hai.

# Feature ✨

✅ Domain Information Lookup

✅ DNS Enumeration

✅ Subdomain Finder

✅ Port Scanning (multi-threaded)

✅ WHOIS Lookup

✅ Banner Grabbing

✅ HTTP Headers Detection

✅ IP Geolocation

✅ Reverse DNS Lookup

✅ Rich CLI Interface (Progress bars, Colors, Tables)

# Example output:

[+] Target: example.com
[+] IP Address: 93.184.216.34
[+] Open Ports: 80, 443
[+] DNS Records:
   - A: 93.184.216.34
   - NS: ns1.example.com
   - MX: mail.example.com

# ⚙️ Installation

Termux / Linux

pkg update && pkg upgrade -y
pkg install git python -y
pip install requests dnspython colorama rich pyfiglet
git clone https://github.com/your-username/ReconX.git
cd ReconX
python ff.py

# Windows

git clone https://github.com/your-username/ReconX.git
cd ReconX
pip install -r requirements.txt
python Rooted.py

# 🚀 Usage

python Rooted.py

# Options:

-u, --url → Target domain (e.g., google.com)

-p, --ports → Custom port range (default: 1-1000)

--threads → Number of threads for port scan (default: 50)

--full → Run all modules together


# 📦 Requirements

Python 3.x

Modules: requests, socket, dnspython, colorama, rich, pyfiglet


# Install dependencies:

pip install -r requirements.txt

⚠️ Disclaimer

> ⚡ This tool is made for educational and ethical hacking purposes only.
❌ Author is not responsible for any misuse or illegal activity done using this tool.



# 👨‍💻 Author

# Name: Rooted-x 

# GitHub: Rooted-x Arbab

# Tool Name: Rooted-recon-x
