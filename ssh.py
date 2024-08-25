"""
OpenSSH Vulnerabilities Scanner for OpenSSH CVE-2024-6387, CVE-2024-6409, and 19 Other CVEs

Supported Versions:
- **CVE-2024-6387:** Affects OpenSSH versions 8.5 to 9.7.
- **CVE-2024-6409:** Affects OpenSSH versions 8.5p1 to 9.7p1.
- **CVE-2019-6111:** Affects OpenSSH versions 5.6 to 7.9.
- **CVE-2018-15473:** Affects OpenSSH version 7.7.
- **CVE-2016-10012:** Affects OpenSSH version 6.9.
- **CVE-2016-10009:** Affects OpenSSH version 7.2.
- **CVE-2016-6210:** Affects OpenSSH version 7.2.
- **CVE-2016-3115:** Affects OpenSSH version 7.1.
- **CVE-2016-0777:** Affects OpenSSH versions 5.4 to 7.1.
- **CVE-2015-6564:** Affects OpenSSH version 7.0.
- **CVE-2015-6563:** Affects OpenSSH version 6.8.
- **CVE-2015-5600:** Affects OpenSSH versions 6.8 and 6.9.
- **CVE-2014-2532:** Affects OpenSSH version 6.6.
- **CVE-2013-4548:** Affects OpenSSH version 6.2.
- **CVE-2012-0814:** Affects OpenSSH version 6.1.
- **CVE-2012-0816:** Affects OpenSSH version 6.0.
- **CVE-2008-5161:** Affects OpenSSH version 5.0.
- **CVE-2006-5051 and CVE-2008-4109:** Affects OpenSSH versions before 4.4.
- **CVE-2003-0190:** Affects OpenSSH versions before 3.7.1p2.
- **CVE-2002-0083:** Affects OpenSSH versions before 3.1.
- **CVE-2001-0817:** Affects OpenSSH versions before 2.3.0.

Tool Author: x.com/MohamedNab1l
GitHub: https://github.com/bigb0x/CVE-2024-6387

Usage:
    python ssh.py -f targets.txt --output out.txt -t 4

Please feel free to contact me if you have any comments or suggestions

Version: 1.1.0

Disclaimer:
    This provided tool is for educational purposes only. I do not encourage, condone, or support unauthorized access to any system or network. Use this tool responsibly and only on systems you have explicit permission to test. Any actions and consequences resulting from misuse of this tool are your own responsibility.

"""
import sys
import socket
import argparse
import threading
import queue
import os
import json
import csv
from datetime import datetime
from urllib.parse import urlparse
from packaging.version import parse as parse_version, InvalidVersion

# ANSI color codes
light_gray_color = '\033[37;1m'
dimmed_gray_color = '\033[90m'
honey_yellow_color = "\033[38;5;214m"
dim_yellow_color = "\033[33;1m"
cyan_color = '\033[96m'
green_color = '\033[92m'
dimmed_green_color = '\033[2;32m'
red_color = '\033[31m'
light_orange_color = '\033[38;5;214m'
reset_color = '\033[0m'
the_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
LOG_DIR = 'logs'
LOG_FILE = os.path.join(LOG_DIR, 'scan.log')
the_version ="1.1.0"

def banner():
    print(f"""
{light_orange_color}
▒█▀▀▀█ █▀▀█ █▀▀ █▀▀▄ ▒█▀▀▀█ ▒█▀▀▀█ ▒█░▒█ 　 ▒█▀▀▀█ █▀▀ █▀▀█ █▀▀▄ █▀▀▄ █▀▀ █▀▀█ 
▒█░░▒█ █░░█ █▀▀ █░░█ ░▀▀▀▄▄ ░▀▀▀▄▄ ▒█▀▀█ 　 ░▀▀▀▄▄ █░░ █▄▄█ █░░█ █░░█ █▀▀ █▄▄▀ 
▒█▄▄▄█ █▀▀▀ ▀▀▀ ▀░░▀ ▒█▄▄▄█ ▒█▄▄▄█ ▒█░▒█ 　 ▒█▄▄▄█ ▀▀▀ ▀░░▀ ▀░░▀ ▀░░▀ ▀▀▀ ▀░▀▀
  {reset_color}{light_gray_color}
  -> Bulk Scanning tool for OpenSSH Vulnabilities. Version: {reset_color}{light_orange_color}{the_version}{reset_color}
  -> Supports CVE-2024-6387, CVE-2024-6409, and 19 Other CVEs.{reset_color}
    
""")

def create_log_dir():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
        print_message('info', f"Log directory created: {LOG_DIR}")

def log_message(message):
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(f"{the_time} - {message}\n")

# ANSI colors
def print_message(level, message):
    if level == 'vulnerable':
        print(f"[{light_gray_color}{the_time}] {light_orange_color}[VULN] {message}{reset_color}")
    if level == 'info':
        print(f"[{light_gray_color}{the_time}] {dimmed_gray_color}[INFO] {message}{reset_color}")
    elif level == 'ok':
        print(f"[{light_gray_color}{the_time}] {dimmed_green_color}[OK] {message}{reset_color}")
    elif level == 'warning':
        print(f"[{light_gray_color}{the_time}] {light_gray_color}[INFO] {message}{reset_color}")
    elif level == 'error':
        print(f"[{light_gray_color}{the_time}] {red_color}[ERROR] {message}{reset_color}")
    log_message(message)

from packaging.version import parse as parse_version, Version

def is_vulnerable(version):
    if version.startswith("OpenSSH_"):
        version_str = version.split('_')[1].split()[0]
        try:
            # Handle 'p' suffix separately
            if 'p' in version_str:
                base_version, patch_version = version_str.split('p')
                # Create a custom version object
                parsed_version = Version(f"{base_version}.{int(patch_version)-1}")
            else:
                parsed_version = parse_version(version_str)
        except ValueError:
            return False, None

        # Define version ranges for vulnerabilities
        cve_ranges = [
            (parse_version("0"), parse_version("2.3.0"), "CVE-2001-0817"),
            (parse_version("0"), parse_version("3.1"), "CVE-2002-0083"),
            (parse_version("0"), parse_version("3.7.1p2"), "CVE-2003-0190"),
            (parse_version("0"), parse_version("4.4"), "CVE-2006-5051, CVE-2008-4109"),
            (parse_version("5.0"), parse_version("5.0p2"), "CVE-2008-5161"),
            (parse_version("5.6"), parse_version("7.9p1"), "CVE-2019-6111"),
            (parse_version("5.4"), parse_version("7.1p1"), "CVE-2016-0777"),
            (parse_version("6.0"), parse_version("6.0p2"), "CVE-2012-0816"),
            (parse_version("6.1"), parse_version("6.1p2"), "CVE-2012-0814"),
            (parse_version("6.2"), parse_version("6.2p3"), "CVE-2013-4548"),
            (parse_version("6.6"), parse_version("6.6p2"), "CVE-2014-2532"),
            (parse_version("6.8"), parse_version("6.9p2"), "CVE-2015-5600"),
            (parse_version("6.8"), parse_version("6.9p1"), "CVE-2015-6563"),
            (parse_version("7.0"), parse_version("7.0p2"), "CVE-2015-6564"),
            (parse_version("7.1"), parse_version("7.1p2"), "CVE-2016-3115"),
            (parse_version("7.2"), parse_version("7.2p5"), "CVE-2016-6210"),
            (parse_version("7.2"), parse_version("7.2p4"), "CVE-2016-10009"),
            (parse_version("6.9"), parse_version("6.9p1"), "CVE-2016-10012"),
            (parse_version("7.7"), parse_version("7.7p2"), "CVE-2018-15473"),
            (parse_version("8.5"), parse_version("9.7"), "CVE-2024-6387"),
            (parse_version("8.5p1"), parse_version("9.7p1"), "CVE-2024-6409"),
            (parse_version("8.5"), parse_version("9.7"), "CVE-2024-6387"),
            (parse_version("8.5"), parse_version("9.7"), "CVE-2024-6409")
        ]

        for start, end, cve in cve_ranges:
            if start <= parsed_version < end:
                return True, cve

    return False, None


def check_ssh_vulnerability(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=2)
        sock.sendall(b'SSH-2.0-CheckVersion\r\n')
        response = sock.recv(256)
        sock.close()

        # Try multiple encodings
        encodings = ['utf-8', 'latin-1', 'ascii', 'utf-16']
        decoded_response = None
        for encoding in encodings:
            try:
                decoded_response = response.decode(encoding)
                break
            except UnicodeDecodeError:
                continue

        if decoded_response is None:
            # If all decoding attempts fail, use a byte string representation
            decoded_response = str(response)

        stripped_response = decoded_response.strip()
        if stripped_response:
            vulnerable, cve = is_vulnerable(stripped_response)
            if vulnerable:
                print_message('vulnerable', f"{host}:{port} - {stripped_response} - {cve}")
            else:
                if 'HTTP' in stripped_response:
                    print_message('error', f"{host}:{port} - Not valid SSH host")
                else:
                    print_message('ok', f"{host}:{port} - {stripped_response} - Not Vulnerable")
        else:
            print_message('error', f"{host}:{port} - Empty response")
    except socket.timeout:
        print_message('error', f"{host}:{port} - Connection timed out")
    except socket.error as e:
        print_message('error', f"{host}:{port} - {e}")

def worker(queue):
    while not queue.empty():
        host, port = queue.get()
        check_ssh_vulnerability(host, port)
        queue.task_done()

def main():
    parser = argparse.ArgumentParser(description='Bulk Scanning tool for OpenSSH Vulnabilities')
    parser.add_argument('-f', '--file', type=str, help='File containing list of targets')
    parser.add_argument('-u', '--ip', type=str, help='Single target in the form of IP or IP:port')
    parser.add_argument('--output', type=str, help='Output file to save results')
    parser.add_argument('-t', '--threads', type=int, default=3, help='Number of threads (default: 3)')
    parser.add_argument('--format', type=str, choices=['txt', 'json', 'csv'], default='txt', help='Output format (default: txt)')
    args = parser.parse_args()

    banner()
    if not args.ip and not args.file:
        #parser.error("one of the arguments -u to scan a single IP or -f Bulk IPs file path is required")
        print_message('error', "Missing arguments.")
        print_message('info', "python3 ssh.py -f targets.txt --output out.txt -t 4")
        print_message('info', "python ssh.py -h for the full scanning options.")
        exit()
    create_log_dir()
    q = queue.Queue()

    if args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    target = line.strip()
                
                    if target:
                        if "://" in target:
                            target = target.split("://")[-1]
                        target = target.rstrip('/')
                        if ':' in target:
                            parts = target.split(':')
                            host = parts[0]
                            try:
                                port = int(parts[-1])
                            except ValueError:
                                print_message('warning', f"Invalid port in line: {line.strip()}. Using default port 22.")
                                port = 22
                            q.put((host, port))
                        else:
                            q.put((target, 22))
        except FileNotFoundError:
            print_message('error', f"File not found: {args.file}")
            sys.exit(1)
    elif args.ip:
        if ':' in args.ip:
            host, port = args.url.split(':')
            q.put((host, int(port)))
        else:
            q.put((args.ip, 22))

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(q,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if args.output:
        save_results(args.output, args.format)

def save_results(output_file, output_format):
    if output_format == 'txt':
        with open(output_file, 'w') as f:
            f.write(f"Scan completed on {datetime.now()}\n")
            with open(LOG_FILE, 'r') as log_file:
                f.write(log_file.read())
    elif output_format == 'json':
        results = []
        with open(LOG_FILE, 'r') as log_file:
            for line in log_file:
                timestamp, level, message = line.strip().split(' - ', 2)
                results.append({"timestamp": timestamp, "level": level, "message": message})
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
    elif output_format == 'csv':
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Level", "Message"])
            with open(LOG_FILE, 'r') as log_file:
                for line in log_file:
                    writer.writerow(line.strip().split(' - '))

if __name__ == "__main__":
    main()
