import os
import subprocess

def run_zmap_scan(target_ip, output_file):
    print(f"Scanning {target_ip} using ZMap...")
    cmd = f"zmap -p 80,443 -o {output_file} {target_ip}"
    os.system(cmd)
    print(f"Scan completed! Results saved in {output_file}")

def run_nmap_scan(target_ip, output_file):
    print(f"Running Nmap scan on {target_ip}...")
    cmd = f"nmap -sV -p 80,443 --script=vuln -oN {output_file} {target_ip}"
    os.system(cmd)
    print(f"Nmap scan completed! Results saved in {output_file}")

def run_malware_scan(directory):
    print(f"Scanning {directory} for malware using ClamAV...")
    cmd = f"clamscan -r {directory}"
    os.system(cmd)
    print("ClamAV scan completed!")

def run_backdoor_scan():
    print("Scanning for backdoors using chkrootkit...")
    cmd = "chkrootkit"
    os.system(cmd)
    print("Chkrootkit scan completed!")

def run_waf_protection():
    print("Enabling ModSecurity Web Application Firewall (WAF)...")
    cmd = "sudo systemctl start apache2 && sudo a2enmod security2 && sudo systemctl restart apache2"
    os.system(cmd)
    print("WAF Protection enabled!")

def run_real_time_monitoring():
    print("Starting real-time intrusion detection using Suricata...")
    cmd = "sudo suricata -c /etc/suricata/suricata.yaml -i eth0"
    os.system(cmd)
    print("Suricata is running for real-time monitoring!")

def run_vulnerability_scan(target_ip):
    print(f"Running advanced web vulnerability scanning on {target_ip} using Nikto...")
    cmd = f"nikto -h {target_ip} -output nikto_results.txt"
    os.system(cmd)
    print("Nikto scan completed! Results saved in nikto_results.txt")

def detect_ddos():
    print("Checking for potential DDoS attacks...")
    cmd = "netstat -an | awk '/:80/ {print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -10"
    os.system(cmd)
    print("DDoS detection check completed!")

def check_ssl_security(target_ip):
    print(f"Checking SSL/TLS security for {target_ip}...")
    cmd = f"sslscan {target_ip} > ssl_security.txt"
    os.system(cmd)
    print("SSL security scan completed! Results saved in ssl_security.txt")

def generate_security_report():
    print("Generating security report...")
    with open("security_report.txt", "w") as report:
        report.write("--- Security Scan Report ---\n")
        report.write("[+] ZMap Scan Results:\n")
        with open("zmap_results.txt", "r") as f:
            report.write(f.read())
        report.write("\n[+] Nmap Scan Results:\n")
        with open("nmap_results.txt", "r") as f:
            report.write(f.read())
        report.write("\n[+] Nikto Vulnerability Scan Results:\n")
        with open("nikto_results.txt", "r") as f:
            report.write(f.read())
        report.write("\n[+] SSL Security Scan Results:\n")
        with open("ssl_security.txt", "r") as f:
            report.write(f.read())
    print("Security report generated: security_report.txt")

def main():
    target_ip = input("Enter target IP for scanning: ")
    output_zmap = "zmap_results.txt"
    output_nmap = "nmap_results.txt"
    
    run_zmap_scan(target_ip, output_zmap)
    run_nmap_scan(target_ip, output_nmap)
    run_vulnerability_scan(target_ip)
    check_ssl_security(target_ip)
    
    directory_to_scan = input("Enter directory to scan for malware: ")
    run_malware_scan(directory_to_scan)
    
    run_backdoor_scan()
    run_waf_protection()
    run_real_time_monitoring()
    detect_ddos()
    generate_security_report()
    
    print("All security features executed successfully!")

if __name__ == "__main__":
    main()
