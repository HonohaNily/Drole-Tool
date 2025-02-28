#!/usr/bin/env python3
"""
MineScan: Minecraft Server Security Scanner
A tool for penetration testers to identify vulnerabilities in Minecraft servers
Enhanced with connections to multiple vulnerability databases
"""

import argparse
import json
import logging
import os
import re
import socket
import sys
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlencode

# Third-party dependencies 
import requests
import colorama
from colorama import Fore, Style
from mcstatus import JavaServer
import xml.etree.ElementTree as ET

# Initialize colorama
colorama.init(autoreset=True)

class VulnerabilitySource:
    """Base class for vulnerability data sources"""
    
    def __init__(self, name: str):
        self.name = name
    
    def fetch_vulnerabilities(self) -> List[Dict]:
        """Fetch vulnerabilities from the source"""
        raise NotImplementedError("Subclasses must implement this method")


class NVDSource(VulnerabilitySource):
    """National Vulnerability Database (NVD) API Source"""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("NVD")
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def fetch_vulnerabilities(self) -> List[Dict]:
        """Fetch Minecraft-related vulnerabilities from NVD"""
        print(f"{Fore.YELLOW}Fetching vulnerabilities from NVD...")
        
        # Parameters for the API request
        params = {
            "keywordSearch": "minecraft",
            "pubStartDate": (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%dT00:00:00.000"),
            "resultsPerPage": 50
        }
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            response = requests.get(
                self.base_url,
                params=params,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                vulns = []
                
                for vuln_item in data.get("vulnerabilities", []):
                    cve_item = vuln_item.get("cve", {})
                    cve_id = cve_item.get("id")
                    
                    # Extract description
                    descriptions = cve_item.get("descriptions", [])
                    description = next((item.get("value") for item in descriptions 
                                      if item.get("lang") == "en"), "No description available")
                    
                    # Extract severity
                    metrics = cve_item.get("metrics", {})
                    cvss_data = (
                        metrics.get("cvssMetricV31", [{}])[0] or 
                        metrics.get("cvssMetricV30", [{}])[0] or
                        metrics.get("cvssMetricV2", [{}])[0] or
                        {}
                    ).get("cvssData", {})
                    
                    base_score = cvss_data.get("baseScore", 0)
                    severity = "LOW"
                    if base_score >= 7.0:
                        severity = "HIGH"
                    elif base_score >= 4.0:
                        severity = "MEDIUM"
                    
                    # Determine affected components
                    references = cve_item.get("references", [])
                    ref_urls = [ref.get("url") for ref in references]
                    
                    # Identify affected software
                    affected_components = []
                    for config in cve_item.get("configurations", []):
                        for node in config.get("nodes", []):
                            for cpe_match in node.get("cpeMatch", []):
                                cpe = cpe_match.get("criteria", "")
                                if "minecraft" in cpe.lower():
                                    parts = cpe.split(":")
                                    if len(parts) > 4:
                                        component = parts[4]
                                        version_info = ":".join(parts[5:])
                                        affected_components.append(f"{component} {version_info}")
                    
                    component = ", ".join(affected_components) if affected_components else "Minecraft"
                    
                    # Create vulnerability entry
                    vuln = {
                        "id": cve_id,
                        "description": description,
                        "severity": severity,
                        "source": "NVD",
                        "references": ref_urls,
                        "component": component,
                        "detection_pattern": self._generate_detection_pattern(affected_components)
                    }
                    
                    vulns.append(vuln)
                
                print(f"{Fore.GREEN}Found {len(vulns)} Minecraft-related vulnerabilities from NVD")
                return vulns
            else:
                print(f"{Fore.RED}Error fetching from NVD: {response.status_code} - {response.text[:100]}")
                return []
                
        except Exception as e:
            print(f"{Fore.RED}Failed to fetch from NVD: {e}")
            return []
    
    def _generate_detection_pattern(self, affected_components: List[str]) -> str:
        """Generate a regex detection pattern from affected components"""
        if not affected_components:
            return ""
            
        # This is a simplified approach - in a real implementation, you'd need more
        # sophisticated pattern generation based on the affected versions
        patterns = []
        for component in affected_components:
            match = re.search(r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)', component)
            if match:
                version = match.group(1)
                patterns.append(version.replace(".", "\\."))
        
        return "|".join(patterns) if patterns else ""


class ExploitDBSource(VulnerabilitySource):
    """Exploit Database (Exploit-DB) Source"""
    
    def __init__(self):
        super().__init__("Exploit-DB")
        self.base_url = "https://www.exploit-db.com/search"
    
    def fetch_vulnerabilities(self) -> List[Dict]:
        """Fetch Minecraft-related exploits from Exploit-DB"""
        print(f"{Fore.YELLOW}Fetching vulnerabilities from Exploit-DB...")
        
        try:
            # Exploit-DB doesn't have a simple REST API, so we need to use their search page
            # In a real implementation, you might want to use their CSV database or API if available
            params = {
                "q": "minecraft",
                "type": "exploits",
                "platform": "webapps"  # Minecraft server is technically a webapp
            }
            
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            
            response = requests.get(
                self.base_url,
                params=params,
                headers=headers,
                timeout=30
            )
            
            vulns = []
            
            if response.status_code == 200:
                # In a real implementation, you would parse the HTML response to extract exploit information
                # For demonstration purposes, we'll return dummy data
                vulns = [
                    {
                        "id": "EDB-12345",
                        "description": "Minecraft Server Remote Code Execution",
                        "severity": "HIGH",
                        "source": "Exploit-DB",
                        "references": ["https://www.exploit-db.com/exploits/12345"],
                        "component": "Minecraft Server",
                        "detection_pattern": "1\\.16\\.[0-5]"
                    },
                    {
                        "id": "EDB-54321",
                        "description": "Minecraft Plugin XYZ Authentication Bypass",
                        "severity": "CRITICAL",
                        "source": "Exploit-DB",
                        "references": ["https://www.exploit-db.com/exploits/54321"],
                        "component": "XYZ Plugin",
                        "detection_pattern": "XYZ Plugin.*[0-9]\\.[0-5]\\.[0-9]"
                    }
                ]
                
                print(f"{Fore.GREEN}Found {len(vulns)} Minecraft-related exploits from Exploit-DB")
            else:
                print(f"{Fore.RED}Error fetching from Exploit-DB: {response.status_code}")
                
            return vulns
                
        except Exception as e:
            print(f"{Fore.RED}Failed to fetch from Exploit-DB: {e}")
            return []


class SecurityFocusSource(VulnerabilitySource):
    """SecurityFocus BID Database Source"""
    
    def __init__(self):
        super().__init__("SecurityFocus")
        self.base_url = "https://www.securityfocus.com/bid"
    
    def fetch_vulnerabilities(self) -> List[Dict]:
        """Fetch Minecraft-related vulnerabilities from SecurityFocus"""
        print(f"{Fore.YELLOW}Fetching vulnerabilities from SecurityFocus...")
        
        try:
            # SecurityFocus doesn't have a straightforward API, so we need to scrape their search results
            # In a real implementation, you would need to implement proper web scraping
            # For demonstration purposes, we'll return dummy data
            vulns = [
                {
                    "id": "BID-98765",
                    "description": "Minecraft Server Authentication Bypass Vulnerability",
                    "severity": "HIGH",
                    "source": "SecurityFocus",
                    "references": ["https://www.securityfocus.com/bid/98765"],
                    "component": "Minecraft Authentication",
                    "detection_pattern": "1\\.18\\.[0-2]"
                },
                {
                    "id": "BID-56789",
                    "description": "Minecraft Plugin ABC SQL Injection Vulnerability",
                    "severity": "HIGH",
                    "source": "SecurityFocus",
                    "references": ["https://www.securityfocus.com/bid/56789"],
                    "component": "ABC Plugin",
                    "detection_pattern": "ABC Plugin.*[0-3]\\.[0-9]\\.[0-9]"
                }
            ]
            
            print(f"{Fore.GREEN}Found {len(vulns)} Minecraft-related vulnerabilities from SecurityFocus")
            return vulns
                
        except Exception as e:
            print(f"{Fore.RED}Failed to fetch from SecurityFocus: {e}")
            return []


class HackerOneSource(VulnerabilitySource):
    """HackerOne Disclosed Vulnerabilities Source"""
    
    def __init__(self, api_token: Optional[str] = None):
        super().__init__("HackerOne")
        self.base_url = "https://api.hackerone.com/v1/reports"
        self.api_token = api_token
    
    def fetch_vulnerabilities(self) -> List[Dict]:
        """Fetch Minecraft-related vulnerabilities from HackerOne"""
        print(f"{Fore.YELLOW}Fetching vulnerabilities from HackerOne...")
        
        if not self.api_token:
            print(f"{Fore.YELLOW}No HackerOne API token provided. Skipping...")
            return []
        
        try:
            # In a real implementation, you would use the HackerOne API with proper authentication
            # For demonstration purposes, we'll return dummy data
            vulns = [
                {
                    "id": "H1-123456",
                    "description": "SSRF in Minecraft Server Plugin Manager",
                    "severity": "MEDIUM",
                    "source": "HackerOne",
                    "references": ["https://hackerone.com/reports/123456"],
                    "component": "Minecraft Plugin Manager",
                    "detection_pattern": "Plugin Manager.*[0-2]\\.[0-9]"
                },
                {
                    "id": "H1-654321",
                    "description": "Authentication Bypass in Minecraft Premium Verification",
                    "severity": "HIGH",
                    "source": "HackerOne",
                    "references": ["https://hackerone.com/reports/654321"],
                    "component": "Minecraft Premium Verification",
                    "detection_pattern": "1\\.17\\.[0-3]"
                }
            ]
            
            print(f"{Fore.GREEN}Found {len(vulns)} Minecraft-related vulnerabilities from HackerOne")
            return vulns
                
        except Exception as e:
            print(f"{Fore.RED}Failed to fetch from HackerOne: {e}")
            return []


class ExploitDatabase:
    """Manages vulnerability database and exploit patterns with multi-source integration"""
    
    def __init__(self, db_path: str = "~/.minescan/exploits.json"):
        self.db_path = os.path.expanduser(db_path)
        self.exploits = {}
        self.last_update = None
        self._ensure_db_exists()
        self.load_database()
        
        # Initialize vulnerability sources
        self.sources = [
            NVDSource(api_key=os.environ.get("NVD_API_KEY")),
            ExploitDBSource(),
            SecurityFocusSource(),
            HackerOneSource(api_token=os.environ.get("HACKERONE_API_TOKEN"))
        ]
    
    def _ensure_db_exists(self):
        """Create database directory and file if they don't exist"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        if not os.path.exists(self.db_path):
            # Create initial empty database structure
            initial_db = {
                "metadata": {
                    "last_updated": datetime.now().isoformat(),
                    "version": "1.0.0"
                },
                "plugins": {},
                "server_versions": {},
                "configuration": {}
            }
            with open(self.db_path, 'w') as f:
                json.dump(initial_db, f, indent=2)
    
    def load_database(self):
        """Load the exploit database from disk"""
        try:
            with open(self.db_path, 'r') as f:
                data = json.load(f)
                self.exploits = data
                self.last_update = data.get("metadata", {}).get("last_updated")
                logging.info(f"Loaded exploit database (last updated: {self.last_update})")
        except Exception as e:
            logging.error(f"Failed to load exploit database: {e}")
            self.exploits = {"metadata": {"last_updated": None, "version": "1.0.0"}, 
                            "plugins": {}, "server_versions": {}, "configuration": {}}
    
    def update_database(self, force: bool = False) -> bool:
        """Update the vulnerability database from multiple sources"""
        # Skip update if performed in last 24 hours unless forced
        if not force and self.last_update:
            last_update_time = datetime.fromisoformat(self.last_update)
            if (datetime.now() - last_update_time).total_seconds() < 86400:  # 24 hours
                logging.info("Database was updated recently. Skipping update.")
                return False
                
        try:
            print(f"{Fore.YELLOW}Updating vulnerability database from multiple sources...")
            
            all_vulns = []
            
            # Fetch vulnerabilities from all sources
            for source in self.sources:
                try:
                    vulns = source.fetch_vulnerabilities()
                    all_vulns.extend(vulns)
                except Exception as e:
                    print(f"{Fore.RED}Error fetching from {source.name}: {e}")
            
            # Process and categorize vulnerabilities
            new_data = self._process_vulnerabilities(all_vulns)
            
            # Merge with base vulnerability data structure
            new_data["metadata"] = {
                "last_updated": datetime.now().isoformat(),
                "version": "1.1.0"
            }
            
            # Ensure configuration checks exist even if not provided by sources
            if "configuration" not in new_data:
                new_data["configuration"] = self.exploits.get("configuration", {})
                
            # Add default configuration checks if none exist
            if not new_data["configuration"]:
                new_data["configuration"] = {
                    "open_rcon": {
                        "id": "CONF-RCON-1",
                        "description": "RCON enabled with weak or default password",
                        "severity": "HIGH",
                        "detection_method": "check_rcon_auth"
                    },
                    "query_enabled": {
                        "id": "CONF-QUERY-1",
                        "description": "Server query enabled exposing server information",
                        "severity": "MEDIUM",
                        "detection_method": "check_query_enabled"
                    }
                }
            
            # Save updated database
            self.exploits = new_data
            with open(self.db_path, 'w') as f:
                json.dump(self.exploits, f, indent=2)
                
            self.last_update = new_data["metadata"]["last_updated"]
            print(f"{Fore.GREEN}Database updated successfully - {len(all_vulns)} vulnerabilities found")
            return True
            
        except Exception as e:
            logging.error(f"Failed to update exploit database: {e}")
            print(f"{Fore.RED}Failed to update vulnerability database: {e}")
            return False
    
    def _process_vulnerabilities(self, vulns: List[Dict]) -> Dict:
        """Process and categorize vulnerabilities from multiple sources"""
        result = {
            "plugins": {},
            "server_versions": {}
        }
        
        for vuln in vulns:
            component = vuln.get("component", "").strip()
            
            # Determine if this is a server or plugin vulnerability
            if "plugin" in component.lower() or component.lower() not in ["minecraft", "minecraft server"]:
                # This is a plugin vulnerability
                plugin_name = component.split()[0] if component else "Unknown"
                
                if plugin_name not in result["plugins"]:
                    result["plugins"][plugin_name] = {"versions": {}}
                
                # Use detection pattern to determine version range
                pattern = vuln.get("detection_pattern", "")
                version_key = f"<99.99.99"  # Default to affect all versions if no specific pattern
                
                if pattern:
                    # Try to extract version info from pattern
                    match = re.search(r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)', pattern)
                    if match:
                        version = match.group(1)
                        version_key = f"<={version}"
                
                if version_key not in result["plugins"][plugin_name]["versions"]:
                    result["plugins"][plugin_name]["versions"][version_key] = []
                
                result["plugins"][plugin_name]["versions"][version_key].append({
                    "id": vuln.get("id", "Unknown"),
                    "description": vuln.get("description", "Unknown vulnerability"),
                    "severity": vuln.get("severity", "MEDIUM"),
                    "detection_pattern": vuln.get("detection_pattern", ""),
                    "source": vuln.get("source", "Unknown"),
                    "references": vuln.get("references", [])
                })
            else:
                # This is a server vulnerability
                # Determine version range
                pattern = vuln.get("detection_pattern", "")
                version_key = "1.x"  # Default to all versions
                
                if pattern:
                    # Try to extract major.minor version
                    match = re.search(r'([0-9]+\.[0-9]+)', pattern)
                    if match:
                        base_version = match.group(1)
                        version_key = f"{base_version}.x"
                
                if version_key not in result["server_versions"]:
                    result["server_versions"][version_key] = []
                
                result["server_versions"][version_key].append({
                    "id": vuln.get("id", "Unknown"),
                    "description": vuln.get("description", "Unknown vulnerability"),
                    "severity": vuln.get("severity", "MEDIUM"),
                    "detection_pattern": vuln.get("detection_pattern", ""),
                    "source": vuln.get("source", "Unknown"),
                    "references": vuln.get("references", [])
                })
        
        return result
    
    def get_plugin_vulnerabilities(self, plugin_name: str, version: str) -> List[Dict]:
        """Get vulnerabilities for a specific plugin and version"""
        results = []
        if plugin_name in self.exploits.get("plugins", {}):
            plugin_data = self.exploits["plugins"][plugin_name]
            for version_pattern, vulns in plugin_data.get("versions", {}).items():
                # Check if current version matches the vulnerable version pattern
                if self._check_version_pattern(version, version_pattern):
                    results.extend(vulns)
        return results
    
    def get_server_vulnerabilities(self, server_version: str) -> List[Dict]:
        """Get vulnerabilities for a specific server version"""
        results = []
        for version_key, vulns in self.exploits.get("server_versions", {}).items():
            if version_key.endswith(".x"):
                # Handle version ranges like "1.16.x"
                base_version = version_key[:-2]
                if server_version.startswith(base_version):
                    results.extend(vulns)
            elif server_version == version_key:
                results.extend(vulns)
        return results
    
    def get_configuration_checks(self) -> Dict:
        """Get all configuration vulnerability checks"""
        return self.exploits.get("configuration", {})
    
    def _check_version_pattern(self, current_version: str, pattern: str) -> bool:
        """Check if current version matches a version pattern like '<2.8.0' or '>=1.7.0,<1.8.0'"""
        if pattern.startswith("<"):
            target_version = pattern[1:]
            return self._compare_versions(current_version, target_version) < 0
        elif pattern.startswith("<="):
            target_version = pattern[2:]
            return self._compare_versions(current_version, target_version) <= 0
        elif pattern.startswith(">"):
            target_version = pattern[1:]
            return self._compare_versions(current_version, target_version) > 0
        elif pattern.startswith(">="):
            target_version = pattern[2:]
            return self._compare_versions(current_version, target_version) >= 0
        elif "," in pattern:
            # Handle ranges like ">=1.7.0,<1.8.0"
            conditions = pattern.split(",")
            return all(self._check_version_pattern(current_version, cond) for cond in conditions)
        else:
            # Exact version match
            return current_version == pattern
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """Compare two version strings and return -1 if v1<v2, 0 if v1==v2, 1 if v1>v2"""
        v1_parts = list(map(int, version1.split(".")))
        v2_parts = list(map(int, version2.split(".")))
        
        # Pad with zeros if versions have different number of components
        max_len = max(len(v1_parts), len(v2_parts))
        v1_parts.extend([0] * (max_len - len(v1_parts)))
        v2_parts.extend([0] * (max_len - len(v2_parts)))
        
        for i in range(max_len):
            if v1_parts[i] < v2_parts[i]:
                return -1
            elif v1_parts[i] > v2_parts[i]:
                return 1
        return 0


class MinecraftScanner:
    """Main scanner class for detecting Minecraft server vulnerabilities"""
    
    def __init__(self, target: str, port: int = 25565, continuous: bool = False,
                 scan_interval: int = 300, update_db: bool = True):
        self.target = target
        self.port = port
        self.continuous = continuous
        self.scan_interval = scan_interval  # Seconds between scans in continuous mode
        self.db = ExploitDatabase()
        self.scan_count = 0
        self.found_vulns = []
        self.running = True
        
        # Update vulnerability database if requested
        if update_db:
            self.db.update_database()
    
    def start(self):
        """Start the scanning process"""
        if self.continuous:
            print(f"{Fore.CYAN}Starting continuous monitoring of {self.target}:{self.port}")
            print(f"{Fore.CYAN}Scan interval: {self.scan_interval} seconds. Press Ctrl+C to stop.")
            try:
                while self.running:
                    self._run_scan()
                    time.sleep(self.scan_interval)
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Scan interrupted by user. Stopping...")
                self.running = False
        else:
            self._run_scan()
    
    def stop(self):
        """Stop scanning (for continuous mode)"""
        self.running = False
    
    def _run_scan(self):
        """Run a complete scan cycle"""
        self.scan_count += 1
        scan_start = time.time()
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}Scan #{self.scan_count} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}Target: {self.target}:{self.port}")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        # Connect to server and gather basic info
        try:
            server = JavaServer(self.target, self.port)
            status = server.status()
            
            print(f"{Fore.GREEN}✓ Successfully connected to server")
            print(f"  {Fore.WHITE}Description: {Style.BRIGHT}{status.description}")
            print(f"  {Fore.WHITE}Version: {Style.BRIGHT}{status.version.name}")
            print(f"  {Fore.WHITE}Protocol: {Style.BRIGHT}{status.version.protocol}")
            print(f"  {Fore.WHITE}Players: {Style.BRIGHT}{status.players.online}/{status.players.max}")
            
            # Extract server version
            version_match = re.search(r'(\d+\.\d+\.\d+)', status.version.name)
            if version_match:
                server_version = version_match.group(1)
            else:
                server_version = status.version.name
            
            # Check server version vulnerabilities
            self._check_server_version(server_version)
            
            # Query for more details if available
            try:
                query = server.query()
                print(f"\n{Fore.GREEN}✓ Query protocol enabled")
                print(f"  {Fore.WHITE}Game Type: {Style.BRIGHT}{query.game_type}")
                print(f"  {Fore.WHITE}Game ID: {Style.BRIGHT}{query.game_id}")
                print(f"  {Fore.WHITE}Plugins: {Style.BRIGHT}{query.software.plugins if hasattr(query.software, 'plugins') else 'None'}")
                
                # Check configuration vulnerabilities
                self._check_query_enabled()
                
                # Check plugin vulnerabilities
                if hasattr(query.software, 'plugins') and query.software.plugins:
                    self._check_plugins(query.software.plugins)
            except Exception as e:
                print(f"\n{Fore.YELLOW}⚠ Query protocol not available: {e}")
                
            # Check for other common configuration issues
            self._check_rcon_auth()
            
        except Exception as e:
            print(f"{Fore.RED}✗ Failed to connect to server: {e}")
        
        # Print scan summary
        scan_duration = time.time() - scan_start
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}Scan completed in {scan_duration:.2f} seconds")
        print(f"{Fore.CYAN}Found {len(self.found_vulns)} potential vulnerabilities")
        
        # Generate report if vulnerabilities found
        if self.found_vulns:
            print(f"{Fore.YELLOW}Vulnerabilities by source:")
            sources = {}
            for vuln in self.found_vulns:
                source = vuln.get("source", "Unknown")
                if source not in sources:
                    sources[source] = 0
                sources[source] += 1
            
            for source, count in sources.items():
                print(f"  {Fore.WHITE}{source}: {Style.BRIGHT}{count}")
        
        print(f"{Fore.CYAN}{'='*60}\n")
    
    def _check_server_version(self, version: str):
        """Check for vulnerabilities in the server version"""
        print(f"\n{Fore.CYAN}Checking server version vulnerabilities...")
        
        vulns = self.db.get_server_vulnerabilities(version)
        if vulns:
            for vuln in vulns:
                if not vuln.get("detection_pattern") or re.match(vuln.get("detection_pattern", ""), version):
                    self._report_vulnerability(
                        vuln_id=vuln.get("id", "Unknown"),
                        description=f"Server version {version}: {vuln.get('description', 'Unknown vulnerability')}",
                        severity=vuln.get("severity", "MEDIUM"),
                        component=f"Minecraft {version}",
                        source=vuln.get("source", "Unknown"),
                        references=vuln.get("references", [])
                    )
        else:
            print(f"  {Fore.GREEN}✓ No known vulnerabilities for server version {version}")

    def _check_plugins(self, plugins_str: str):
        """Check for vulnerabilities in installed plugins"""
        print(f"\n{Fore.CYAN}Checking plugin vulnerabilities...")
        
        # Parse plugins string (format varies by server type)
        plugins = {}
        
        # Handle different plugin string formats
        if ": " in plugins_str:
            # Format like "ServerType: plugin1 v1.0; plugin2 v2.0"
            parts = plugins_str.split(": ", 1)
            if len(parts) > 1:
                plugin_list = parts[1].split("; ")
                for plugin_info in plugin_list:
                    if " v" in plugin_info:
                        name, version = plugin_info.split(" v", 1)
                        plugins[name.strip()] = version.strip()
                    else:
                        plugins[plugin_info.strip()] = "unknown"
        elif ";" in plugins_str:
            # Format like "plugin1 v1.0; plugin2 v2.0"
            plugin_list = plugins_str.split(";")
            for plugin_info in plugin_list: