# 📌 ZMAP-WAF: Advanced Web Security Scanner & WAF
ZMAP-WAF is a powerful and automated security tool that combines multiple security scanning techniques, including **fast network scanning**, **vulnerability assessment**, **malware detection**, **backdoor scanning**, **real-time monitoring**, and **Web Application Firewall (WAF) protection**. It integrates **ZMap**, **Nmap**, **ClamAV**, **Chkrootkit**, **ModSecurity**, and **Suricata** to provide a comprehensive security solution for web servers.

## 🚀 Features
- **Fast Network Scanning:** Uses ZMap for rapid server scanning.
- **Port & Vulnerability Scanning:** Uses Nmap to detect open ports and vulnerabilities.
- **Malware & Backdoor Detection:** Uses ClamAV and Chkrootkit to scan for threats.
- **Web Application Firewall (WAF):** Integrates ModSecurity for real-time web security.
- **Real-Time Intrusion Detection:** Uses Suricata for monitoring potential attacks.
- **Automated Security Reports:** Generates a security report after every scan.

## 🛠️ Installation
1. **Update System & Install Dependencies**
   ```bash
   sudo apt update && sudo apt upgrade -y
   sudo apt install zmap nmap clamav chkrootkit apache2 libapache2-mod-security2 suricata -y
   ```

2. **Enable ModSecurity (WAF)**
```bash
sudo a2enmod security2
sudo systemctl restart apache2
```

3. **Run Malware Database Update**
```bash
sudo freshclam
```

4. **Clone the Repository & Run the Script**

```bash
git clone https://github.com/odaysec/ZMAP-WAF.git
cd ZMAP-WAF
python3 fast_server_waf.py
```

## 🔍 Usage
1. Run the script:
```bash
python3 fast_server_waf.py
```
2. Enter the target IP for scanning.
3. Enter the directory to scan for malware.
4. The script will execute:
   - ZMap for fast network scanning
   - Nmap for vulnerability assessment
   - ClamAV & Chkrootkit for malware detection
   - ModSecurity for WAF protection
   - Suricata for real-time intrusion detection
5. Security results will be saved in `security_report.txt`.

## 📜 License
This project is licensed under the MIT License.

## 🤝 Contributing
Feel free to fork this repository and submit pull requests to enhance the functionality of ZMAP-WAF!

---
**Author:** [odaysec](https://github.com/odaysec)

