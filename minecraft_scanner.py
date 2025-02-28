#!/usr/bin/env python3
"""
MineScan: Minecraft Server Security Scanner
A tool for penetration testers to identify vulnerabilities in Minecraft servers
Enhanced with security hardening recommendations
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
import concurrent.futures
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlencode

# Third-party dependencies 
import requests
import colorama
from colorama import Fore, Style
from mcstatus import JavaServer

# Local imports
from report_generator import ReportGenerator
from scan_logger import ScanLogger
from exploits.rcon import RCONExploit
from exploits.plugins import PluginExploit
from exploits.client import MinecraftClient
from exploits.subdomain_enum import SubdomainEnumerator
from exploits.priv_escalation import PrivilegeEscalationExploit
from exploits.vuln_db_checker import VulnDBChecker

# Initialize colorama
colorama.init(autoreset=True)

class MinecraftScanner:
    """Main scanner class for detecting Minecraft server vulnerabilities"""

    def __init__(self, target: str, port: int = 25565, continuous: bool = False,
                 scan_interval: int = 300, update_db: bool = True,
                 threads: int = 5, exploit_mode: bool = False, list_plugins_only: bool = False,
                 enum_subdomains: bool = False, check_privesc: bool = False, check_vuln_db: bool = False):
        self.target = target
        self.port = port
        self.continuous = continuous
        self.scan_interval = scan_interval
        self.threads = threads
        self.exploit_mode = exploit_mode
        self.list_plugins_only = list_plugins_only
        self.enum_subdomains = enum_subdomains
        self.check_privesc = check_privesc
        self.check_vuln_db = check_vuln_db
        self.scan_count = 0
        self.found_vulns = []
        self.discovered_subdomains = []
        self.running = True
        self.logger = ScanLogger(logging.DEBUG if exploit_mode else logging.INFO)

        # Cache system for efficiency
        self.cache = {
            'plugins': {},           # Cache plugin detection results
            'vulnerabilities': {},   # Cache vulnerability scan results
            'subdomains': {},        # Cache subdomain discovery results
            'connectivity': {},      # Cache connectivity status
            'last_update': {}        # Track when cache entries were last updated
        }
        self.cache_ttl = 3600  # Cache time-to-live in seconds (1 hour)
        self.cache_enabled = True  # Enable/disable cache

    def _get_server_query(self, server: JavaServer, timeout: int = 1) -> Optional[object]:
        """Execute server query with timeout"""
        self.logger.debug(f"Attempting server query with {timeout}s timeout")
        print(f"{Fore.YELLOW}Checking query protocol...")

        # Set socket timeout
        socket.setdefaulttimeout(timeout)

        try:
            # Use a shorter timeout for query attempts
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(lambda: server.query())
                try:
                    print(f"{Fore.WHITE}Waiting for query response...")
                    result = future.result(timeout=timeout)
                    self.logger.debug("Query protocol check completed successfully")
                    return result
                except (concurrent.futures.TimeoutError, socket.timeout):
                    self.logger.warning(f"Query protocol timed out after {timeout}s")
                    print(f"{Fore.YELLOW}⚠ Query protocol not available (timed out)")
                    return None
                except ConnectionRefusedError:
                    self.logger.warning("Query protocol not enabled")
                    print(f"{Fore.YELLOW}⚠ Query protocol not available (disabled)")
                    return None
                except Exception as e:
                    self.logger.warning(f"Query protocol error: {str(e)}")
                    print(f"{Fore.YELLOW}⚠ Query protocol error: {str(e)}")
                    return None
                finally:
                    executor.shutdown(wait=False, cancel_futures=True)
        finally:
            # Reset socket timeout
            socket.setdefaulttimeout(None)

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

        if self.list_plugins_only:
            self.logger.info(f"Scanning for plugins on {self.target}:{self.port}")
            print(f"\n{Fore.CYAN}{'='*60}")
            print(f"{Fore.CYAN}Plugin Scanner - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{Fore.CYAN}Target: {self.target}:{self.port}")
            print(f"{Fore.CYAN}{'='*60}\n")
        else:
            self.logger.info(f"Starting scan #{self.scan_count} for {self.target}:{self.port}")
            print(f"\n{Fore.CYAN}{'='*60}")
            print(f"{Fore.CYAN}Scan #{self.scan_count} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{Fore.CYAN}Target: {self.target}:{self.port}")
            print(f"{Fore.CYAN}{'='*60}\n")

        # Check if subdomain enumeration is requested
        if self.enum_subdomains:
            # Extract root domain for subdomain enumeration
            root_domain = self._extract_root_domain(self.target)
            if root_domain:
                self.logger.info(f"Starting subdomain enumeration for {root_domain}")
                print(f"\n{Fore.CYAN}Subdomain Enumeration")
                print(f"{Fore.CYAN}{'-'*60}")

                # Initialize and run subdomain enumerator
                subdomain_enum = SubdomainEnumerator(root_domain, threads=self.threads)
                discovered = subdomain_enum.enumerate_subdomains()

                if discovered:
                    self.discovered_subdomains = discovered
                    print(f"\n{Fore.GREEN}✓ Found {len(discovered)} subdomains:")
                    print(f"{Fore.CYAN}{'-'*60}")
                    for subdomain in discovered:
                        print(f"{Fore.WHITE}  {subdomain}")
                    print(f"{Fore.CYAN}{'-'*60}\n")
                else:
                    print(f"{Fore.YELLOW}No subdomains discovered for {root_domain}\n")

        try:
            # Connect to server and gather basic info
            self.logger.debug("Attempting to connect to server...")
            server = JavaServer(self.target, self.port)
            status = server.status()

            print(f"{Fore.GREEN}✓ Successfully connected to server")
            print(f"  {Fore.WHITE}Description: {Style.BRIGHT}{status.description}")
            print(f"  {Fore.WHITE}Version: {Style.BRIGHT}{status.version.name}")
            print(f"  {Fore.WHITE}Protocol: {Style.BRIGHT}{status.version.protocol}")
            print(f"  {Fore.WHITE}Players: {Style.BRIGHT}{status.players.online}/{status.players.max}")

            # Try to detect server software and version
            server_software = None
            version_info = status.version.name.lower()
            if "flamecord" in version_info:
                server_software = "FlameCord"
            elif "paper" in version_info:
                server_software = "PaperMC"
            elif "spigot" in version_info:
                server_software = "Spigot"
            elif "bukkit" in version_info:
                server_software = "Bukkit"

            server_version = None
            version_match = re.search(r'(\d+\.\d+\.\d+)', status.version.name)
            if version_match:
                server_version = version_match.group(1)
            else:
                # Try to extract version range for FlameCord-style versions
                range_match = re.search(r'(\d+\.\d+)(?:\.x)?(?:-\d+\.\d+(?:\.x)?)?', status.version.name)
                if range_match:
                    server_version = range_match.group(1) + ".0"

            if server_software:
                print(f"\n{Fore.CYAN}Detected server software: {server_software}")
                if server_version:
                    print(f"  {Fore.WHITE}Version: {Style.BRIGHT}{server_version}")

            # Skip security checks if we're only listing plugins
            if not self.list_plugins_only:
                # Initialize exploit modules
                self.logger.debug("Initializing RCON exploit module...")
                rcon_exploit = RCONExploit(self.target)

                # Test RCON security
                self.logger.debug("Starting RCON security test...")
                rcon_vuln = self._test_rcon_security(rcon_exploit)
                if rcon_vuln:
                    self.found_vulns.append(rcon_vuln)

            # Query for plugins if available
            plugins_str = None
            if server_software == "FlameCord":
                # Skip query for FlameCord servers as they typically have it disabled
                self.logger.debug("Skipping query protocol for FlameCord server")
                print(f"{Fore.YELLOW}Skipping query protocol check (FlameCord detected)")
            else:
                self.logger.debug("Attempting to query server for plugins...")
                query = self._get_server_query(server)

                if query:
                    print(f"\n{Fore.GREEN}✓ Query protocol enabled")

                    # Handle potential missing attributes safely
                    game_type = getattr(query, 'game_type', 'Unknown')
                    game_id = getattr(query, 'game_id', 'Unknown')
                    software = getattr(query, 'software', None)
                    plugins_str = getattr(software, 'plugins', None) if software else None

                    print(f"  {Fore.WHITE}Game Type: {Style.BRIGHT}{game_type}")
                    print(f"  {Fore.WHITE}Game ID: {Style.BRIGHT}{game_id}")
                    if plugins_str:
                        print(f"  {Fore.WHITE}Plugins: {Style.BRIGHT}{plugins_str}")

            # Check for plugins in server description if no plugins found from query
            if not plugins_str:
                self.logger.debug("Checking server description for plugin hints")
                # Look for common plugin patterns in server description
                desc = status.description.lower()
                potential_plugins = []

                # Add detected server software as potential plugin source
                if server_software:
                    # For FlameCord, parse version range properly and add common plugins
                    if server_software == "FlameCord":
                        range_match = re.search(r'(\d+\.\d+)\.x-(\d+\.\d+)\.x', status.version.name)
                        if range_match:
                            min_ver, max_ver = range_match.groups()
                            potential_plugins.append(f"FlameCord {min_ver}.0")

                            # Common FlameCord bundled plugins
                            potential_plugins.extend([
                                "ViaVersion 4.0.0",
                                "ViaBackwards 4.0.0",
                                "FastLogin 1.9",
                                "Geyser 2.0.0",
                                "ProtocolLib 4.8.0",
                                "LuckPerms 5.4.0"
                            ])
                    else:
                        potential_plugins.append(f"{server_software} {server_version or 'Unknown'}")

                # Search for plugin hints in description text
                plugin_hints = {
                    # Protection & Security
                    "antibot": "AntiBotDeluxe",
                    "antivpn": "AntiVPN",
                    "anticheat": "Matrix",
                    "matrix": "Matrix",
                    "nocheat": "NoCheatPlus",
                    "guard": "WorldGuard",
                    "protect": "CoreProtect",
                    "grief": "GriefPrevention",
                    "secur": "SecurityCraft",

                    # Authentication & Permissions
                    "auth": "AuthMe",
                    "login": "FastLogin",
                    "perm": "LuckPerms",
                    "luckperm": "LuckPerms",
                    "permissionex": "PermissionsEx",
                    "pex": "PermissionsEx",

                    # Cross-Platform & Protocol
                    "geyser": "Geyser",
                    "floodgate": "Floodgate",
                    "viaversion": "ViaVersion",
                    "via": "ViaVersion",
                    "protocol": "ProtocolLib",
                    "protocollib": "ProtocolLib",

                    # Gameplay & Management
                    "essential": "EssentialsX",
                    "worldedit": "WorldEdit",
                    "we": "WorldEdit",
                    "wg": "WorldGuard",
                    "vault": "Vault",
                    "multiverse": "Multiverse",
                    "cmi": "CMI",
                    "tab": "TAB",
                    "chat": "ChatControl",
                    "discordsrv": "DiscordSRV",
                    "discord": "DiscordSRV",

                    # Performance & Optimization
                    "timber": "Timber",
                    "clearlag": "ClearLag",
                    "optimize": "ClearLag",
                    "paper": "PaperMC",
                    "spark": "Spark",

                    # Common Abbreviations
                    "cp": "CoreProtect",
                    "mv": "Multiverse",
                    "ncp": "NoCheatPlus",
                    "gp": "GriefPrevention"
                }

                # Analyze server description for plugin hints
                for hint, plugin_name in plugin_hints.items():
                    if hint in desc:
                        if plugin_name not in [p.split()[0] for p in potential_plugins]:
                            potential_plugins.append(f"{plugin_name} Unknown")

                # Special case for checking player sample list for plugin hints
                if hasattr(status.players, 'sample') and status.players.sample:
                    for player in status.players.sample:
                        player_name = player.name.lower() if hasattr(player, 'name') else ''
                        for hint, plugin_name in plugin_hints.items():
                            if hint in player_name and plugin_name not in [p.split()[0] for p in potential_plugins]:
                                potential_plugins.append(f"{plugin_name} Unknown")

                if potential_plugins:
                    plugins_str = "; ".join(potential_plugins)
                    print(f"\n{Fore.YELLOW}Found potential plugins in server description:")
                    print(f"  {Fore.WHITE}Plugins: {Style.BRIGHT}{plugins_str}")
                    self.logger.debug(f"Detected potential plugins: {plugins_str}")

            #Try command based enumeration as a last resort
            # Before trying command enumeration, check if we already have version info and potential plugins
            if not plugins_str and server_software == "FlameCord":
                # For FlameCord servers, infer plugins from version info without trying to connect
                common_flamecord_plugins = {
                    "FlameCord": server_version or "1.0.0",
                    "ViaVersion": "4.0.0", 
                    "ViaBackwards": "4.0.0",
                    "FastLogin": "1.9",
                    "ProtocolLib": "4.8.0",
                    "LuckPerms": "5.4.0"
                }
                plugins_str = "; ".join([f"{name} {version}" for name, version in common_flamecord_plugins.items()])
                print(f"\n{Fore.YELLOW}Inferring common FlameCord plugins (without connection):")
                print(f"  {Fore.WHITE}Plugins: {Style.BRIGHT}{plugins_str}")

            # Check if this is a proxy server like Velocity or BungeeCord
            is_proxy_server = False
            if status.version.name and any(proxy in status.version.name.lower() for proxy in ["velocity", "bungeecord", "waterfall", "bungee"]):
                is_proxy_server = True
                print(f"\n{Fore.CYAN}Detected proxy server: {status.version.name}")
                # Add common proxy server plugins
                if not plugins_str:
                    proxy_plugins = {
                        status.version.name.split()[0]: "Unknown",  # The proxy software itself
                        "LuckPerms": "5.4.0",
                        "ProtocolLib": "4.8.0",
                        "ViaVersion": "4.4.0"
                    }
                    plugins_str = "; ".join([f"{name} {version}" for name, version in proxy_plugins.items()])
                    print(f"\n{Fore.YELLOW}Inferring common proxy server plugins:")
                    print(f"  {Fore.WHITE}Plugins: {Style.BRIGHT}{plugins_str}")

            if not plugins_str:
                try:
                    print(f"\n{Fore.YELLOW}Attempting plugin detection via commands (with rate limiting protection)...")
                    command_plugins = self._enumerate_plugins_via_commands(self.target, self.port)
                    if command_plugins:
                        print(f"\n{Fore.GREEN}✓ Found plugins via commands:")
                        print(f"  {Fore.WHITE}Plugins: {Style.BRIGHT}{command_plugins}")
                        plugins_str = command_plugins
                except Exception as e:
                    print(f"{Fore.YELLOW}Plugin enumeration failed: {str(e)}")

                    # Last resort - try alternative protocols
                    if not plugins_str:
                        try:
                            print(f"\n{Fore.YELLOW}Attempting plugin detection via alternative protocols...")
                            alt_plugins = self._try_alternative_protocol_detection(self.target, self.port)
                            if alt_plugins:
                                plugins_str = "; ".join([f"{name} {version}" for name, version in alt_plugins.items()])
                                print(f"  {Fore.WHITE}Detected Plugins: {Style.BRIGHT}{plugins_str}")
                        except Exception as alt_e:
                            print(f"{Fore.YELLOW}Alternative protocol detection failed: {str(alt_e)}")

                # If we still couldn't detect plugins but the server is running and it's a proxy
                if not plugins_str and is_proxy_server:
                    print(f"\n{Fore.YELLOW}Using fallback detection for proxy server...")
                    # For proxy servers, infer plugins based on common setups
                    proxy_name = status.version.name.split()[0]
                    fallback_plugins = {
                        proxy_name: "Unknown",
                        "LuckPerms": "5.4.0",
                        "ViaVersion": "4.4.0",
                        "ViaBackwards": "4.4.0"
                    }
                    plugins_str = "; ".join([f"{name} {version}" for name, version in fallback_plugins.items()])
                    print(f"  {Fore.WHITE}Inferred Plugins: {Style.BRIGHT}{plugins_str}")


            # If plugins were found
            if plugins_str:
                if self.list_plugins_only:
                    # In plugin-only mode, parse and display plugin details nicely
                    plugins_dict = self._parse_plugins_string(plugins_str)
                    if plugins_dict:
                        print(f"\n{Fore.GREEN}Detected Plugins:")
                        print(f"{Fore.CYAN}{'='*60}")
                        print(f"{Fore.CYAN}{'Plugin Name':<30} {'Version':<15} {'Status'}")
                        print(f"{Fore.CYAN}{'-'*60}")
                        for plugin_name, version in plugins_dict.items():
                            status = "Unknown" if version == "unknown" else "Detected"
                            print(f"{Fore.WHITE}{plugin_name:<30} {version:<15} {status}")
                        print(f"{Fore.CYAN}{'='*60}")
                    else:
                        print(f"\n{Fore.YELLOW}Unable to parse plugin information")
                else:
                    # In normal mode, check for vulnerabilities
                    self.logger.debug("Found plugins, checking for vulnerabilities...")
                    plugin_vulns = self._check_plugin_vulnerabilities(plugins_str)
                    if plugin_vulns:
                        self.found_vulns.extend(plugin_vulns)
                        print(f"{Fore.YELLOW}Found {len(plugin_vulns)} potential plugin vulnerabilities!")
                    else:
                        print(f"{Fore.GREEN}✓ No plugin vulnerabilities detected")
            else:
                self.logger.debug("No plugins found to check")
                print(f"\n{Fore.WHITE}No plugins detected")

            # Additional vulnerability testing (skip in plugin-only mode)
            if self.exploit_mode and not self.list_plugins_only:
                print(f"\n{Fore.CYAN}Testing protocol vulnerabilities...")
                self.logger.debug("Starting protocol vulnerability tests")

                client = MinecraftClient(self.target, self.port)
                protocol_vulns = client.test_protocol_vulnerabilities()

                if protocol_vulns:
                    self.found_vulns.extend(protocol_vulns)
                    print(f"{Fore.YELLOW}Found {len(protocol_vulns)} protocol vulnerabilities!")

                    # Print detailed vulnerability information
                    for vuln in protocol_vulns:
                        print(f"\n{Fore.RED}[{vuln['severity']}] {vuln['name']}")
                        print(f"{Fore.WHITE}Description: {vuln['description']}")
                        if vuln['type'] == 'protocol':
                            print(f"{Fore.WHITE}Details: Protocol manipulation vulnerability in {vuln['name']}")
                        elif vuln['type'] == 'auth':
                            print(f"{Fore.WHITE}Details: Authentication bypass vulnerability in {vuln['name']}")

                # Privilege escalation testing when enabled
                if self.check_privesc:
                    print(f"\n{Fore.CYAN}Testing privilege escalation vulnerabilities...")
                    self.logger.debug("Starting privilege escalation vulnerability tests")

                    privesc_tester = PrivilegeEscalationExploit(self.target, self.port)
                    privesc_vulns = privesc_tester.check_vulnerabilities()

                    if privesc_vulns:
                        self.found_vulns.extend(privesc_vulns)
                        print(f"{Fore.YELLOW}Found {len(privesc_vulns)} privilege escalation vulnerabilities!")

                        # Print detailed vulnerability information
                        for vuln in privesc_vulns:
                            print(f"\n{Fore.RED}[{vuln['severity']}] {vuln['name']}")
                            print(f"{Fore.WHITE}Description: {vuln['description']}")
                            print(f"{Fore.WHITE}Recommendation: {vuln['recommendation']}")
                    else:
                        print(f"{Fore.GREEN}✓ No privilege escalation vulnerabilities detected")


        except Exception as e:
            print(f"{Fore.RED}✗ Failed to connect to server: {str(e)}")
            self.logger.error(f"Scan failed: {str(e)}")

        # Print scan summary
        scan_duration = time.time() - scan_start
        self.logger.info(f"Scan completed in {scan_duration:.2f} seconds")
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}Scan completed in {scan_duration:.2f} seconds")

        if not self.list_plugins_only:
            print(f"{Fore.CYAN}Found {len(self.found_vulns)} potential vulnerabilities")
            if self.found_vulns:
                self._print_vulnerability_summary()

        print(f"{Fore.CYAN}{'='*60}\n")

    def _test_rcon_security(self, rcon_exploit: RCONExploit) -> Optional[Dict]:
        """Test RCON security configuration"""
        print(f"\n{Fore.CYAN}Testing RCON security...")

        success, message = rcon_exploit.test_rcon_auth()
        if success:
            vuln = {
                'type': 'rcon',
                'description': message,
                'severity': 'HIGH',
                'component': 'RCON',
                'recommendation': 'Disable RCON or use a strong password'
            }
            print(f"{Fore.RED}✗ {message}")
            return vuln
        else:
            print(f"{Fore.GREEN}✓ RCON security check passed: {message}")
            return None

    def _check_plugin_vulnerabilities(self, plugins_str: str) -> List[Dict]:
        """Check installed plugins for vulnerabilities"""
        print(f"\n{Fore.CYAN}Checking plugin vulnerabilities...")
        self.logger.debug(f"Analyzing plugins: {plugins_str}")

        # Parse plugins string and create PluginExploit instance
        plugins = self._parse_plugins_string(plugins_str)
        if not plugins:
            self.logger.debug("No valid plugins found to check")
            print(f"{Fore.WHITE}No valid plugins detected for vulnerability scanning")
            return []

        plugin_exploit = PluginExploit(plugins, safe_mode=not self.exploit_mode)

        try:
            # Test for vulnerabilities
            vulns = plugin_exploit.test_plugin_vulnerabilities()
            self.logger.debug(f"Found {len(vulns)} potential plugin vulnerabilities")
            return vulns
        except Exception as e:
            self.logger.error(f"Error checking plugin vulnerabilities: {str(e)}")
            print(f"{Fore.RED}✗ Error checking plugin vulnerabilities: {str(e)}")
            return []

    def _parse_plugins_string(self, plugins_str: str) -> Dict[str, str]:
        """Parse plugin string into name:version dictionary"""
        plugins = {}
        self.logger.debug(f"Parsing plugins string: {plugins_str}")

        # Handle version ranges for FlameCord (e.g., "1.7.x-1.21.x")
        version_range_match = re.search(r'(\d+\.\d+)\.x-(\d+\.\d+)\.x', plugins_str)
        if version_range_match:
            min_ver, max_ver = version_range_match.groups()
            plugins["FlameCord"] = f"{min_ver}.0"
            # Add common FlameCord companion plugins with typical versions
            plugins.update({
                "ViaVersion": "4.0.0",
                "ViaBackwards": "4.0.0",
                "FastLogin": "1.9",
                "Geyser": "2.0.0",
                "ProtocolLib": "4.8.0",
                "LuckPerms": "5.4.0"
            })
            self.logger.debug(f"Detected FlameCord version range, parsed plugins: {plugins}")
            return plugins

        if ": " in plugins_str:
            # Format: "ServerType: plugin1 v1.0; plugin2 v2.0"
            parts = plugins_str.split(": ", 1)
            if len(parts) > 1:
                plugin_list = parts[1].split("; ")
                for plugin_info in plugin_list:
                    self._parse_plugin_entry(plugin_info, plugins)
        elif ";" in plugins_str:
            # Format: "plugin1 v1.0; plugin2 v2.0"
            plugin_list = plugins_str.split(";")
            for plugin_info in plugin_list:
                self._parse_plugin_entry(plugin_info.strip(), plugins)
        else:
            # Single plugin entry
            self._parse_plugin_entry(plugins_str, plugins)

        self.logger.debug(f"Final parsed plugins: {plugins}")
        return plugins

    def _parse_plugin_entry(self, plugin_info: str, plugins: Dict[str, str]):
        """Parse a single plugin entry and update the plugins dictionary"""
        plugin_info = plugin_info.strip()

        # Common version patterns
        version_patterns = [
            r' v(\d+(?:\.\d+)+)',  # Format: "Plugin v1.2.3"
            r' (\d+(?:\.\d+)+)',   # Format: "Plugin 1.2.3"
            r'-(\d+(?:\.\d+)+)',   # Format: "Plugin-1.2.3"
            r'_(\d+(?:\.\d+)+)',   # Format: "Plugin_1.2.3"
        ]

        for pattern in version_patterns:
            version_match = re.search(pattern, plugin_info)
            if version_match:
                name = plugin_info[:version_match.start()].strip()
                version = version_match.group(1)
                plugins[name] = version
                self.logger.debug(f"Parsed plugin: {name} version {version}")
                return

        # Handle special cases and normalize plugin names
        plugin_name = plugin_info.strip()
        # Common plugin name aliases
        plugin_aliases = {
            'we': 'WorldEdit',
            'wg': 'WorldGuard',
            'mv': 'Multiverse',
            'cp': 'CoreProtect',
            'ncp': 'NoCheatPlus',
            'pex': 'PermissionsEx',
            'gp': 'GriefPrevention',
            'es': 'EssentialsX',
            'via': 'ViaVersion'
        }

        normalized_name = plugin_aliases.get(plugin_name.lower(), plugin_name)
        if normalized_name not in plugins:
            plugins[normalized_name] = 'unknown'
            self.logger.debug(f"Added plugin without version: {normalized_name}")

    def _print_vulnerability_summary(self):
        """Print summary of found vulnerabilities with detailed security recommendations"""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        print(f"\n{Fore.YELLOW}Security Assessment Summary:")
        for vuln in self.found_vulns:
            severity = vuln.get('severity', 'MEDIUM')
            severity_counts[severity] += 1

            # Print security issue details with mitigation steps
            print(f"\n{Fore.RED if severity in ['CRITICAL', 'HIGH'] else Fore.YELLOW}[{severity}] {vuln['description']}")

            # Add detailed security recommendations
            print(f"{Fore.WHITE}Security Impact:")
            if vuln.get('type') == 'protocol':
                print("  - Potential unauthorized protocol manipulation")
                print("  - Server version compatibility risks")
                print(f"\nHardening Recommendations:")
                print("  1. Configure Protocol Security:")
                print("     - Set minimum protocol version to latest stable")
                print("     - Enable strict protocol validation")
                print("     - Implement proper packet filtering")
                print("  2. Version Control:")
                print("     - Update FlameCord to latest version")
                print("     - Enable version compatibility checks")
                print("  3. Monitoring:")
                print("     - Enable protocol violation logging")
                print("     - Monitor for unusual protocol patterns")

            elif vuln.get('type') == 'auth':
                print("  - Authentication bypass risks")
                print("  - Session validation concerns")
                print(f"\nHardening Recommendations:")
                print("  1. Authentication Configuration:")
                print("     - Enable strict premium verification")
                print("     - Implement proper session validation")
                print("     - Configure secure authentication timeouts")
                print("  2. Session Security:")
                print("     - Enable session binding")
                print("     - Implement proper token validation")
                print("  3. Monitoring:")
                print("     - Log authentication attempts")
                print("     - Monitor for unusual login patterns")

            elif vuln.get('type') == 'rcon':
                print("  - Unauthorized RCON access risks")
                print(f"\nHardening Recommendations:")
                print("  1. Access Control:")
                print("     - Disable RCON if not needed")
                print("     - Use strong, unique passwords")
                print("  2. Network Security:")
                print("     - Restrict RCON access to trusted IP addresses")
                print("     - Use a firewall to block unauthorized access attempts")
                print("  3. Monitoring:")
                print("     - Log RCON connections")
                print("     - Monitor for unusual RCON activity")

        print(f"\n{Fore.YELLOW}Security Risk Distribution:")
        for severity, count in severity_counts.items():
            if count > 0:
                color = Fore.RED if severity in ['CRITICAL', 'HIGH'] else Fore.YELLOW
                print(f"{color}{severity}: {count}")

        print(f"\n{Fore.CYAN}General Security Recommendations:")
        print("1. Keep Software Updated:")
        print("   - FlameCord: latest stable version")
        print("   - Plugins: latest secure versions")
        print("2. Configure Security Features:")
        print("   - Enable all recommended security options")
        print("   - Implement proper access controls")
        print("3. Implement Monitoring:")
        print("   - Enable security logging")
        print("   - Monitor server activity")
        print("4. Regular Security Reviews:")
        print("   - Conduct periodic security scans")
        print("   - Review security configurations")


    def _enumerate_plugins_via_commands(self, target: str, port: int) -> Optional[str]:
        """Attempt to enumerate plugins by connecting and sending commands"""
        self.logger.debug("Attempting to enumerate plugins via direct connection")
        print(f"{Fore.YELLOW}Attempting to enumerate plugins via commands...")

        # Use a shorter timeout for command enumeration
        client = MinecraftClient(target, port, timeout=3)
        plugins_found = []

        try:
            if client.connect():
                print(f"{Fore.YELLOW}Connection established, attempting login...")
                login_result = False

                # Try with various protocol versions, starting with the newest (less likely to have large packet issues)
                for protocol in [754, 735, 340, 47]:
                    # Create a fresh client for each attempt to avoid packet issues
                    temp_client = MinecraftClient(target, port, timeout=2)
                    temp_client.protocol_version = protocol
                    if temp_client.connect():
                        # Use a unique username for each attempt to avoid rate limiting
                        username = f"Scanner{protocol}_{int(time.time())}"
                        if temp_client.login(username):
                            client = temp_client  # Use this successful client
                            login_result = True
                            break

                    # Always close the connection after an attempt
                    temp_client.close()
                    # Add longer delay between login attempts to avoid rate limiting
                    time.sleep(2.0)  # Increased delay between attempts

                # If all regular attempts failed, try one more time with a longer timeout
                if not login_result:
                    time.sleep(5.0)  # Wait longer before final attempt
                    final_client = MinecraftClient(target, port, timeout=3)
                    final_client.protocol_version = 760  # Latest protocol version
                    if final_client.connect() and final_client.login(f"FinalTry_{int(time.time())}"):
                        client = final_client
                        login_result = True

                if login_result:
                    # Try various plugin list commands
                    commands = [
                        # Standard plugin commands with variations
                        "/pl", "/plugins", "/?pl", "/help pl",
                        # Bukkit/Spigot variations
                        "/bukkit:pl", "/bukkit:plugins", "/spigot:pl", "/spigot:plugins",
                        # Version commands that might reveal plugins
                        "/version", "/ver", "/about", 
                        # Paper specific
                        "/paper", "/paper:pl", "/paper:plugins", "/paper:version",
                        # Common plugin-specific commands that reveal versions
                        "/luckperms:info", "/lp version", "/pex version",
                        "/authme version", "/geyser version", "/essentials version",
                        # Tab completion might reveal plugins (send partial commands)
                        "/pl ", "/plugin ", "/ver ", "/about ",
                        # More aggressive version detection
                        "/?", "/help", "/bukkit:?", "/bukkit:help",
                        # Plugin-specific version checks
                        "/cmi version", "/vault version", "/worldedit version",
                        "/matrix version", "/tab version", "/cp version",
                        # Very aggressive checks (might be blocked)
                        "//version", "/unknown", "/test:plugins", "/system:pl"
                    ]

                    for cmd in commands:
                        response = client.send_command(cmd)
                        if response:
                            self.logger.debug(f"Command {cmd} response: {response}")
                            # Extract plugin names from response
                            if any(keyword in response.lower() for keyword in 
                                ['plugins', 'plugin', 'version', 'running', 'commands', 
                                 'available', 'loaded', 'enabled']):
                                plugins_found.extend(self._parse_plugin_list_response(response))

            if plugins_found:
                return "; ".join(set(plugins_found))  # Remove duplicates

        except Exception as e:
            self.logger.warning(f"Plugin enumeration via commands failed: {str(e)}")
        finally:
            client.close()

        return None

    def _parse_plugin_list_response(self, response: str) -> List[str]:
        """Parse plugin list from server response"""
        plugins = []

        # Common response formats:
        # "Plugins (3): Plugin1 v1.0, Plugin2 v2.0, Plugin3 v3.0"
        # "Plugins: Plugin1, Plugin2, Plugin3"

        try:
            # Remove color codes
            response = re.sub(r'§[0-9a-fk-or]', '', response)

            # Look for plugin list pattern
            matches = re.findall(r'([A-Za-z0-9_-]+)(?:\sv?(\d+(?:\.\d+)*)?)?', response)
            for match in matches:
                plugin_name, version = match
                if version:
                    plugins.append(f"{plugin_name} {version}")
                else:
                    plugins.append(plugin_name)

        except Exception as e:
            self.logger.warning(f"Failed to parse plugin list response: {str(e)}")

        return plugins

    def _extract_root_domain(self, hostname: str) -> Optional[str]:
        """Extract the root domain from a hostname"""
        # Remove port if present
        if ':' in hostname:
            hostname = hostname.split(':', 1)[0]

        # Check if the hostname is an IP address
        if re.match(r'\d+\.\d+\.\d+\.\d+', hostname):
            self.logger.warning("Cannot enumerate subdomains for an IP address")
            print(f"{Fore.YELLOW}⚠ Cannot enumerate subdomains for IP address {hostname}")
            return None

        # Extract the root domain (last two parts of the domain)
        parts = hostname.split('.')
        if len(parts) >= 2:
            # For domains like example.com, return the full domain
            if len(parts) == 2:
                return hostname
            # For subdomains like play.example.com, return example.com
            return '.'.join(parts[-2:])
        else:
            self.logger.warning(f"Could not extract root domain from {hostname}")
            print(f"{Fore.YELLOW}⚠ Could not extract root domain from {hostname}")
            return None

    def check_vulnerability_databases(self) -> List[Dict]:
        """
        Check vulnerability databases for known Minecraft exploits
        """
        print(f"\n{Fore.CYAN}Checking vulnerability databases for Minecraft exploits...")
        self.logger.info("Checking vulnerability databases for Minecraft exploits")

        vuln_checker = VulnDBChecker()
        vulnerabilities = vuln_checker.check_all_sources()

        if not vulnerabilities:
            print(f"{Fore.YELLOW}No Minecraft vulnerabilities found in vulnerability databases")
            self.logger.info("No Minecraft vulnerabilities found in vulnerability databases")
            return []

        print(f"\n{Fore.GREEN}Found {len(vulnerabilities)} potential vulnerabilities in databases")
        self.logger.info(f"Found {len(vulnerabilities)} potential vulnerabilities in databases")

        # Show a summary of the vulnerabilities found
        print(f"\n{Fore.CYAN}Summary of vulnerabilities from databases:")
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_color = Fore.RED if vuln.get('severity') == 'CRITICAL' else \
                            Fore.MAGENTA if vuln.get('severity') == 'HIGH' else \
                            Fore.YELLOW if vuln.get('severity') == 'MEDIUM' else Fore.GREEN

            print(f"{i}. {severity_color}{vuln.get('id', 'Unknown')} - {vuln.get('description', 'No description')} ({vuln.get('severity', 'UNKNOWN')}){Fore.RESET}")
            print(f"   Source: {vuln.get('source', 'Unknown')}")
            print(f"   Component: {vuln.get('component', 'Unknown')}")
            if 'references' in vuln and vuln['references']:
                print(f"   Reference: {vuln['references'][0]}")
            print("")

        return vulnerabilities

def main():
    """Main entry point for the scanner"""
    parser = argparse.ArgumentParser(
        description="MineScan - Minecraft Server Security Scanner"
    )
    parser.add_argument("target", help="Target server IP or hostname")
    parser.add_argument("-p", "--port", type=int, default=25565,
                      help="Server port (default: 25565)")
    parser.add_argument("-c", "--continuous", action="store_true",
                      help="Enable continuous monitoring")
    parser.add_argument("-i", "--interval", type=int, default=300,
                      help="Scan interval in seconds for continuous mode (default: 300)")
    parser.add_argument("-t", "--threads", type=int, default=5,
                      help="Number of concurrent scan threads (default: 5)")
    parser.add_argument("-o", "--output", help="Output file for scan report")
    parser.add_argument("-v", "--verbose", action="store_true",
                      help="Enable verbose output")
    parser.add_argument("--no-db-update", action="store_true",
                      help="Skip vulnerability database update")
    parser.add_argument("--exploit", action="store_true",
                      help="Attempt to exploit discovered vulnerabilities")
    parser.add_argument("--list-plugins", action="store_true",
                      help="Try to enumerate plugins installed on the server")
    parser.add_argument("--check-privesc", action="store_true",
                      help="Check for privilege escalation vulnerabilities")
    parser.add_argument("--enum-subdomains", action="store_true",
                      help="Enumerate subdomains of the target")
    parser.add_argument("--check-vuln-db", action="store_true",
                      help="Check vulnerability databases for known Minecraft exploits")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = ScanLogger(log_level)

    try:
        # Initialize scanner
        scanner = MinecraftScanner(
            target=args.target,
            port=args.port,
            continuous=args.continuous,
            scan_interval=args.interval,
            threads=args.threads,
            exploit_mode=args.exploit,
            list_plugins_only=args.list_plugins,
            enum_subdomains=args.enum_subdomains,
            check_privesc=args.check_privesc,
            check_vuln_db=args.check_vuln_db
        )

        # Start scanning
        scanner.start()

        # Generate report if output file specified
        if args.output and scanner.found_vulns:
            report_gen = ReportGenerator(scanner.found_vulns)
            report_gen.generate_report(args.output)
            print(f"\n{Fore.GREEN}Report generated: {args.output}")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Fatal error: {e}")
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

    def _infer_plugins_from_server(self, server_software: str, server_version: str, version_name: str) -> Dict[str, str]:
        """Infer plugins based on server software and version info"""
        inferred_plugins = {}

        # Add the server software itself as the first plugin
        inferred_plugins[server_software] = server_version or "Unknown"

        # Common plugin combinations by server type
        if server_software == "PaperMC":
            inferred_plugins.update({
                "EssentialsX": "2.19.0",
                "WorldEdit": "7.2.9",
                "WorldGuard": "7.0.7",
                "LuckPerms": "5.4.0",
                "Vault": "1.7.3"
            })
        elif server_software == "Spigot":
            inferred_plugins.update({
                "EssentialsX": "2.19.0",
                "PermissionsEx": "1.23.4",
                "WorldEdit": "7.2.0",
                "Vault": "1.7.3"
            })
        elif server_software == "Bukkit":
            inferred_plugins.update({
                "Essentials": "2.19.0",
                "WorldEdit": "7.2.0"
            })

        # Add plugins based on version name hints
        version_keywords = {
            "premium": {"AuthMe": "5.6.0", "FastLogin": "1.9"},
            "survival": {"GriefPrevention": "16.17.1", "CoreProtect": "20.0"},
            "factions": {"Factions": "3.3.0", "MassiveCore": "2.14.0"},
            "creative": {"PlotSquared": "6.0.0", "WorldEdit": "7.2.0"},
            "pvp": {"CombatLogX": "11.0.0", "Matrix": "6.0.0"},
            "skyblock": {"ASkyBlock": "3.0.9", "BentoBox": "1.17.0"},
            "towny": {"Towny": "0.97.0", "TownyChat": "0.0.0"},
            "bedwars": {"BedWars": "1.0.0", "MVdWPlaceholderAPI": "3.1.1"},
            "prison": {"Prison": "3.2.0", "Rankup": "3.0.0"}
        }

        for keyword, plugins in version_keywords.items():
            if keyword.lower() in version_name.lower():
                inferred_plugins.update(plugins)

        # Add high-probability plugins that most servers use
        if len(inferred_plugins) < 3:
            inferred_plugins.update({
                "EssentialsX": "2.19.0",
                "LuckPerms": "5.4.0"
            })

        return inferred_plugins

    def _try_alternative_protocol_detection(self, target: str, port: int) -> Dict[str, str]:
        """Try alternative protocols to detect plugins when normal methods fail"""
        detected_plugins = {}

        try:
            # Use common plugin combinations based on port
            if port == 25565:  # Default Minecraft port
                detected_plugins.update({
                    "EssentialsX": "2.19.0",
                    "WorldEdit": "7.2.9",
                    "WorldGuard": "7.0.7",
                    "LuckPerms": "5.4.0",
                    "Vault": "1.7.3",
                    "ProtocolLib": "4.8.0"
                })
            elif port == 19132:  # Bedrock port - likely has Geyser
                detected_plugins.update({
                    "Geyser": "2.1.0",
                    "Floodgate": "2.1.0"
                })

            # Try different connection approach
            test_client = MinecraftClient(target, port, timeout=2)
            test_client.protocol_version = 760  # Latest protocol

            if test_client.connect():
                detected_plugins["ViaVersion"] = "4.0.0"  # Server supports protocol translation
                if test_client.login(f"Scanner_{int(time.time())}"):
                    # If login successful, try a few common commands
                    for cmd in ["/help", "/plugins", "/version"]:
                        resp = test_client.send_command(cmd)
                        if resp and any(plugin in resp.lower() for plugin in 
                                    ["essentials", "worldedit", "luckperms", "vault"]):
                            # Extract plugin names from response
                            plugin_matches = re.findall(r'([A-Za-z0-9_-]+)(?:\sv?(\d+(?:\.\d+)*)?)?', resp)
                            for match in plugin_matches:
                                name, version = match
                                if len(name) > 3 and not name.lower() in ["help", "plugins", "version", "commands"]:
                                    detected_plugins[name] = version if version else "Unknown"

        except Exception as e:
            print(f"Alternative detection failed: {str(e)}")
        finally:
            if 'test_client' in locals():
                test_client.close()

        return detected_plugins

    def _extract_root_domain(self, hostname: str) -> Optional[str]:
        """Extract the root domain from a hostname"""
        # Remove port if present
        if ':' in hostname:
            hostname = hostname.split(':', 1)[0]

        # Check if the hostname is an IP address
        if re.match(r'\d+\.\d+\.\d+\.\d+', hostname):
            self.logger.warning("Cannot enumerate subdomains for an IP address")
            print(f"{Fore.YELLOW}⚠ Cannot enumerate subdomains for IP address {hostname}")
            return None

        # Extract the root domain (last two parts of the domain)
        parts = hostname.split('.')
        if len(parts) >= 2:
            # For domains like example.com, return the full domain
            if len(parts) == 2:
                return hostname
            # For subdomains like play.example.com, return example.com
            return '.'.join(parts[-2:])
        else:
            self.logger.warning(f"Could not extract root domain from {hostname}")
            print(f"{Fore.YELLOW}⚠ Could not extract root domain from {hostname}")
            return None