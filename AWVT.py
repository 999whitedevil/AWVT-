import subprocess
import socket
from fpdf import FPDF

# ASCII Art Logo
def print_logo():
    logo = """
                                                       
      _/_/    _/          _/  _/      _/  _/_/_/_/_/   
   _/    _/  _/          _/  _/      _/      _/        
  _/_/_/_/  _/    _/    _/  _/      _/      _/         
 _/    _/    _/  _/  _/      _/  _/        _/          
_/    _/      _/  _/          _/          _/           
                                                       
 
                                                     Developer: Aditya Kumar Sahu
    """
    print(logo)

def save_output(file_name, output):
    with open(file_name, 'a') as file:
        file.write(output + "\n")

# 1. NSLookup and DNS Lookup
def nslookup_scan(domain):
    print("[INFO] Running NSLookup...")
    try:
        ns_output = subprocess.check_output(["nslookup", domain], text=True)
        save_output("scan_results.txt", "[NSLookup Scan]\n" + ns_output)
        print(ns_output)
    except Exception as e:
        save_output("scan_results.txt", "[NSLookup Scan Error] " + str(e))

def dnslookup_scan(domain):
    print("[INFO] Running DNS Lookup...")
    try:
        dns_output = subprocess.check_output(["dig", domain], text=True)
        save_output("scan_results.txt", "[DNS Lookup Scan]\n" + dns_output)
        print(dns_output)
    except Exception as e:
        save_output("scan_results.txt", "[DNS Lookup Scan Error] " + str(e))

# 2. TCP Port Scanning
def tcp_port_scan(ip, pdf):
    print(f"[INFO] Scanning TCP ports for {ip}...")
    open_ports = []

    # Known TCP ports for scanning
    known_ports = {
        20: ("FTP Data", "File Transfer Protocol Data Transfer"),
        21: ("FTP", "File Transfer Protocol"),
        22: ("SSH", "Secure Shell"),
        23: ("Telnet", "Telnet Protocol"),
        25: ("SMTP", "Simple Mail Transfer Protocol"),
        53: ("DNS", "Domain Name System"),
        80: ("HTTP", "Hypertext Transfer Protocol"),
        110: ("POP3", "Post Office Protocol version 3"),
        143: ("IMAP", "Internet Message Access Protocol"),
        443: ("HTTPS", "HTTP Secure"),
        3306: ("MySQL", "MySQL Database Service"),
        3389: ("RDP", "Remote Desktop Protocol"),
        5432: ("PostgreSQL", "PostgreSQL Database Service"),
        6379: ("Redis", "Redis Database"),
        8080: ("HTTP Alternate", "Alternative HTTP port"),
    }

    for port, (service_name, description) in known_ports.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                pdf.cell(0, 10, f"[TCP Port {port} ({service_name})] State: open - {description}", ln=True)
                print(f"[TCP Port {port} ({service_name})] State: open - {description}")
            else:
                pdf.cell(0, 10, f"[TCP Port {port} ({service_name})] State: closed - {description}", ln=True)
                print(f"[TCP Port {port} ({service_name})] State: closed - {description}")

    save_output("scan_results.txt", "[TCP Port Scan Results]\n" + str(open_ports))
    return open_ports

# 3. CMS Detection (Joomla, WordPress, Drupal)
def cms_detection(url):
    print("[INFO] Running CMS Detection...")
    try:
        cms_output = subprocess.check_output(["whatweb", url], text=True)
        save_output("scan_results.txt", "[CMS Detection]\n" + cms_output)
        print(cms_output)
    except Exception as e:
        save_output("scan_results.txt", "[CMS Detection Error] " + str(e))

# 4. SSL Vulnerability Scan
def ssl_vulnerability_scan(domain):
    print("[INFO] Running SSL Vulnerability Scan...")
    try:
        ssl_output = subprocess.check_output(["sslscan", domain], text=True)
        save_output("scan_results.txt", "[SSL Vulnerability Scan]\n" + ssl_output)
        print(ssl_output)
    except Exception as e:
        save_output("scan_results.txt", "[SSL Vulnerability Scan Error] " + str(e))

# 5. DNS Zone Transfer
def dns_zone_transfer(domain):
    print("[INFO] Running DNS Zone Transfer...")
    try:
        zone_output = subprocess.check_output(["dnsrecon", "-d", domain], text=True)
        save_output("scan_results.txt", "[DNS Zone Transfer]\n" + zone_output)
        print(zone_output)
    except Exception as e:
        save_output("scan_results.txt", "[DNS Zone Transfer Error] " + str(e))

# 6. Subdomain Brute Forcing
def subdomain_bruteforce(domain):
    print("[INFO] Running Subdomain Brute Forcing...")
    try:
        sub_output = subprocess.check_output(["amass", "enum", "-d", domain], text=True)
        save_output("scan_results.txt", "[Subdomain Brute Forcing]\n" + sub_output)
        print(sub_output)
    except Exception as e:
        save_output("scan_results.txt", "[Subdomain Brute Forcing Error] " + str(e))

# 7. Open Directory/File Brute Forcing
def open_directory_bruteforce(url):
    print("[INFO] Running Open Directory/File Brute Forcing...")
    try:
        dir_output = subprocess.check_output(["gobuster", "dir", "-u", url, "-w", "/usr/share/wordlists/dirb/common.txt"], text=True)
        save_output("scan_results.txt", "[Open Directory/File Brute Forcing]\n" + dir_output)
        print(dir_output)
    except Exception as e:
        save_output("scan_results.txt", "[Open Directory/File Brute Forcing Error] " + str(e))

# 8. Vulnerability Summary
def vulnerability_summary():
    print("[INFO] Generating Vulnerability Summary...")
    try:
        with open("scan_results.txt", "r") as file:
            results = file.read()
            vuln_count = results.count("VULNERABLE") + results.count("FOUND")
            total_checks = results.count("[")
            vuln_percentage = (vuln_count / total_checks) * 100 if total_checks > 0 else 0
            summary = f"\nVulnerability Summary:\nTotal Checks: {total_checks}\nVulnerabilities Found: {vuln_count}\nVulnerability Percentage: {vuln_percentage:.2f}%\n"
            save_output("scan_results.txt", summary)
            print(summary)
    except Exception as e:
        save_output("scan_results.txt", "[Summary Error] " + str(e))

# Main Execution Function
def main():
    print_logo()
    url = input("Enter the target URL (e.g., http://example.com): ")
    domain = url.split("//")[-1].split("/")[0]
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Run all scans
    nslookup_scan(domain)
    dnslookup_scan(domain)
    tcp_port_scan(domain, pdf)
    cms_detection(url)
    ssl_vulnerability_scan(domain)
    dns_zone_transfer(domain)
    subdomain_bruteforce(domain)
    open_directory_bruteforce(url)
    vulnerability_summary()

    pdf.output("scan_report.pdf")
    print("[INFO] Report generated as 'scan_report.pdf'.")

if __name__ == "__main__":
    main()
