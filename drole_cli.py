#!/usr/bin/env python3
"""
Interactive CLI Wrapper for MineScan - Minecraft Server Security Scanner
Enhances the command-line tool with an interactive prompt
"""

import os
import sys
import subprocess
import re
import time
import cmd
import random
import shutil
import math

# Import Rich library for better color handling
from rich import print as rprint
from rich.console import Console
from rich.style import Style
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

# Import the original scanner functionality
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from minecraft_scanner import MinecraftScanner
except ImportError:
    pass  # We'll handle this gracefully

# Create console for rich output
console = Console()

# Define our color scheme with Rich styles
class Colors:
    # Blood Red and Night Purple Theme
    BLOOD_RED = "#8B0000"
    DARK_RED = "#A50000"
    LIGHT_RED = "#C00000"
    CRIMSON = "#DC143C"
    
    NIGHT_PURPLE = "#2B1B6C"
    DARK_PURPLE = "#3A236C"
    MEDIUM_PURPLE = "#483D8B"
    LIGHT_PURPLE = "#7B68EE"
    
    # Additional colors
    PROMPT = "#800080"          # Purple
    SUCCESS = "#00C853"         # Green
    ERROR = "#D50000"           # Red
    WARNING = "#FF6D00"         # Orange
    INFO = "#E0E0E0"            # Off-white
    
    # RGB colors for smooth gradient
    START_COLOR_RGB = (139, 0, 0)     # Crimson (#8B0000)
    END_COLOR_RGB = (43, 27, 108)     # Dark Purple (#2B1B6C)
    
    # Intermediate colors for smoother transition (RGB)
    INTERMEDIATE_COLORS = [
        (139, 0, 0),    # Dark Red (#8B0000)
        (111, 0, 0),    # Burgundy (#6F0000)
        (84, 0, 78),    # Deep Purple (#54004E)
        (59, 0, 109),   # Dark Violet (#3B006D)
        (43, 27, 108)   # Indigo (#2B1B6C)
    ]

# Define styles for different elements
STYLES = {
    "title": Style(color=Colors.BLOOD_RED, bold=True),
    "subtitle": Style(color=Colors.MEDIUM_PURPLE, bold=True),
    "prompt": Style(color=Colors.PROMPT, bold=True),
    "success": Style(color=Colors.SUCCESS, bold=True),
    "error": Style(color=Colors.ERROR, bold=True),
    "warning": Style(color=Colors.WARNING, bold=True),
    "info": Style(color=Colors.INFO),
    "command": Style(color=Colors.LIGHT_PURPLE, bold=True),
    "panel_border": Style(color=Colors.NIGHT_PURPLE),
    "highlight": Style(color=Colors.CRIMSON),
}

# ASCII art for DROLE title
DROLE_ASCII = """
 _____                                             _____ 
( ___ )                                           ( ___ )
 |   |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|   | 
 |   | SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS |   | 
 |   | S▓█████▄SS██▀███SSS▒█████SSS██▓SSSS▓█████SS |   | 
 |   | S▒██▀S██▌▓██S▒S██▒▒██▒SS██▒▓██▒SSSS▓█SSS▀SS |   | 
 |   | S░██SSS█▌▓██S░▄█S▒▒██░SS██▒▒██░SSSS▒███SSSS |   | 
 |   | S░▓█▄SSS▌▒██▀▀█▄SS▒██SSS██░▒██░SSSS▒▓█SS▄SS |   | 
 |   | S░▒████▓S░██▓S▒██▒░S████▓▒░░██████▒░▒████▒S |   | 
 |   | SS▒▒▓SS▒S░S▒▓S░▒▓░░S▒░▒░▒░S░S▒░▓SS░░░S▒░S░S |   | 
 |   | SS░S▒SS▒SSS░▒S░S▒░SS░S▒S▒░S░S░S▒SS░S░S░SS░S |   | 
 |   | SS░S░SS░SSS░░SSS░S░S░S░S▒SSSS░S░SSSSSS░SSSS |   | 
 |   | SSSS░SSSSSSS░SSSSSSSSS░S░SSSSSS░SS░SSS░SS░S |   | 
 |   | SS░SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS |   | 
 |   | SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS |   | 
 |___|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|___| 
(_____)                                           (_____)
"""

# Gradient utility functions
def rgb_to_hex(rgb):
    """Convert RGB tuple to hex string format"""
    return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"

def interpolate_color(color1, color2, factor):
    """Linear interpolation between two colors"""
    result = tuple(int(color1[i] + factor * (color2[i] - color1[i])) for i in range(3))
    return result

def create_color_gradient(num_colors, use_intermediate=True):
    """Create a gradient of colors from start to end"""
    if use_intermediate and len(Colors.INTERMEDIATE_COLORS) > 2:
        # Use predefined intermediate colors for more control
        colors = []
        segments = len(Colors.INTERMEDIATE_COLORS) - 1
        colors_per_segment = num_colors // segments
        
        for i in range(segments):
            start = Colors.INTERMEDIATE_COLORS[i]
            end = Colors.INTERMEDIATE_COLORS[i + 1]
            segment_size = colors_per_segment
            
            # Adjust the last segment to ensure we get exactly num_colors
            if i == segments - 1:
                segment_size = num_colors - len(colors)
            
            for j in range(segment_size):
                factor = j / segment_size if segment_size > 0 else 0
                colors.append(interpolate_color(start, end, factor))
        
        # Ensure we have exactly num_colors
        while len(colors) < num_colors:
            colors.append(Colors.INTERMEDIATE_COLORS[-1])
        
        return colors
    else:
        # Simple linear interpolation from start to end
        return [interpolate_color(Colors.START_COLOR_RGB, Colors.END_COLOR_RGB, i / (num_colors - 1)) for i in range(num_colors)]

def apply_diagonal_gradient(ascii_art):
    """Apply a diagonal gradient to ASCII art"""
    # Split the ASCII art into lines
    lines = ascii_art.split('\n')
    height = len(lines)
    width = max(len(line) for line in lines)
    
    # Create a Rich Text object
    styled_text = Text()
    
    # Apply gradient based on diagonal direction
    for y, line in enumerate(lines):
        for x, char in enumerate(line):
            if char.strip():  # Skip styling whitespace
                # Normalize position along diagonal
                factor = (x / max(1, width - 1) + y / max(1, height - 1)) / 2
                
                # Get color at this position
                color_idx = min(len(Colors.INTERMEDIATE_COLORS) - 1, int(factor * (len(Colors.INTERMEDIATE_COLORS) - 1)))
                start_color = Colors.INTERMEDIATE_COLORS[color_idx]
                end_color = Colors.INTERMEDIATE_COLORS[min(color_idx + 1, len(Colors.INTERMEDIATE_COLORS) - 1)]
                
                # Fine-grained interpolation within segment
                segment_factor = (factor * (len(Colors.INTERMEDIATE_COLORS) - 1)) % 1
                color = interpolate_color(start_color, end_color, segment_factor)
                hex_color = rgb_to_hex(color)
                
                # Add the character with the calculated color
                styled_text.append(char, style=f"bold {hex_color}")
            else:
                styled_text.append(char)  # Add whitespace without styling
                
        # Add a newline character at the end of each line except the last
        if y < height - 1:
            styled_text.append("\n")
    
    return styled_text

def apply_character_based_gradient(ascii_art):
    """
    Apply a gradient based on character position in the entire ASCII art
    This creates a smoother transition across all characters
    """
    # Remove whitespace for color calculation but preserve for display
    non_space_chars = [c for c in ascii_art if c.strip()]
    total_chars = len(non_space_chars)
    
    if total_chars == 0:
        return Text(ascii_art)
    
    # Generate colors for all non-space characters
    colors = create_color_gradient(total_chars)
    
    # Apply colors to the original ASCII art
    styled_text = Text()
    color_index = 0
    
    for char in ascii_art:
        if char.strip():
            color = colors[color_index]
            hex_color = rgb_to_hex(color)
            styled_text.append(char, style=f"bold {hex_color}")
            color_index += 1
        else:
            styled_text.append(char)  # Add whitespace without styling
    
    return styled_text

class DroleCLI(cmd.Cmd):
    """Interactive command-line interface for DROLE - Minecraft Server Security Scanner"""
    
    prompt = "@Drole > "
    
    def __init__(self):
        super().__init__()
        self.current_scanner = None
        self.history = []
        self.target = None
        self.port = 25565
        self.count_commands = 0
        self.gradient_type = "diagonal"  # Default gradient type
        
        # Get terminal size
        self.term_width, self.term_height = shutil.get_terminal_size()
        
        # Custom prompt with Rich styling
        self.prompt = ""
        
        # Display the splash screen at startup
        self._show_splash()
        
        # Set intro to empty since we've already shown the splash
        self.intro = ""

    def postcmd(self, stop, line):
        """Print custom prompt after each command"""
        console.print(f"[{Colors.BLOOD_RED}]@Drole[/{Colors.BLOOD_RED}] > ", end="")
        return stop
    
    def _show_splash(self):
        """Internal method to show the splash screen once"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # Apply gradient to ASCII art
        if self.gradient_type == "character":
            styled_text = apply_character_based_gradient(DROLE_ASCII)
        else:  # Default to diagonal
            styled_text = apply_diagonal_gradient(DROLE_ASCII)
        
        # Display the styled ASCII art
        console.print(styled_text)
        
        # Create a styled panel for the subtitle
        subtitle = Panel(
            Text("DROLE - Private Minecraft Security Scanner", style=Style(color=Colors.BLOOD_RED, bold=True)),
            border_style=Style(color=Colors.NIGHT_PURPLE),
            width=70
        )
        console.print(subtitle)
        
        # Print the version and help info
        console.print(f"[{Colors.BLOOD_RED}]Version: 1.0.0[/{Colors.BLOOD_RED}]")
        console.print(f"[{Colors.INFO}]Type [{Colors.LIGHT_PURPLE}]help[/{Colors.LIGHT_PURPLE}] or [{Colors.LIGHT_PURPLE}]?[/{Colors.LIGHT_PURPLE}] to list commands.[/{Colors.INFO}]\n")
    
    def do_server(self, arg):
        """Check Minecraft server informations
        
        Usage : server [file_path]
        If file path is provided, reads server adresses frome it
        If no file path is provided, prompts for server adresses
        
        Example : server servers.txt
        """
        try:
            from exploits.server import ServerInfoChecker
            
            checker = ServerInfoChecker()
            
            if arg:
                # Provided
                checker.check_servers_from_file(arg)
            else:
                # Not Provided
                checker.check_servers_from_input()
        except ImportError as e:
            console.print(f"[{Colors.ERROR}]Error importing server module: {str(e)}[/{Colors.ERROR}]")
        except Exception as e:
            console.print(f"[{Colors.ERROR}]Error running server command: {str(e)}[/{Colors.ERROR}]")
    
    def do_clear(self, arg):
        """Clear the screen
        
        Usage: clear 
        """
        # Add code to clear the screen
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def do_scan(self, arg):
        """Scan a Minecraft server: scan [target] [options]
        
        Options:
          -p PORT, --port PORT       Specify server port (default: 25565)
          -v, --verbose              Enable verbose output
          --exploit                  Attempt to exploit discovered vulnerabilities
          --list-plugins             Try to enumerate plugins installed on the server
          --check-privesc            Check for privilege escalation vulnerabilities
          --enum-subdomains          Enumerate subdomains of the target
          --check-vuln-db            Check vulnerability databases for Minecraft exploits
        """
        args = arg.split()
        if not args:
            console.print(f"[{Colors.ERROR}]Error: Target server is required[/{Colors.ERROR}]")
            console.print(f"[{Colors.INFO}]Usage: scan [target] [options][/{Colors.INFO}]")
            return
        
        target = args[0]
        port = 25565
        options = []
        
        # Parse the options
        i = 1
        while i < len(args):
            if args[i] in ['-p', '--port'] and i + 1 < len(args):
                try:
                    port = int(args[i+1])
                    i += 2
                except ValueError:
                    console.print(f"[{Colors.ERROR}]Error: Invalid port number[/{Colors.ERROR}]")
                    return
            elif args[i] in ['-v', '--verbose']:
                options.append('--verbose')
                i += 1
            elif args[i] == '--exploit':
                options.append('--exploit')
                i += 1
            elif args[i] == '--list-plugins':
                options.append('--list-plugins')
                i += 1
            elif args[i] == '--check-privesc':
                options.append('--check-privesc')
                i += 1
            elif args[i] == '--enum-subdomains':
                options.append('--enum-subdomains')
                i += 1
            elif args[i] == '--check-vuln-db':
                options.append('--check-vuln-db')
                i += 1
            else:
                console.print(f"[{Colors.ERROR}]Error: Unknown option '{args[i]}'[/{Colors.ERROR}]")
                return
        
        # Build the command
        cmd = [sys.executable, 'minecraft_scanner.py', target, '-p', str(port)] + options
        
        # Execute the scanner
        console.print(f"[{Colors.INFO}]Starting scan against [{Colors.LIGHT_PURPLE}]{target}:{port}[/{Colors.LIGHT_PURPLE}][/{Colors.INFO}]")
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
            
            # Process and colorize the output
            for line in process.stdout:
                # Apply rich styling to the output
                styled_line = self._style_output(line)
                console.print(styled_line, end='')
                
            process.wait()
            
            if process.returncode == 0:
                console.print(f"\n[{Colors.SUCCESS}]Scan completed successfully[/{Colors.SUCCESS}]")
            else:
                console.print(f"\n[{Colors.ERROR}]Scan failed with return code {process.returncode}[/{Colors.ERROR}]")
                
        except Exception as e:
            console.print(f"[{Colors.ERROR}]Error executing scan: {str(e)}[/{Colors.ERROR}]")
    
    def do_connect(self, arg):
        """Connect to a Minecraft server: connect [target] [port]"""
        args = arg.split()
        if not args:
            console.print(f"[{Colors.ERROR}]Error: Target server is required[/{Colors.ERROR}]")
            console.print(f"[{Colors.INFO}]Usage: connect [target] [port][/{Colors.INFO}]")
            return
        
        target = args[0]
        port = 25565
        
        if len(args) > 1:
            try:
                port = int(args[1])
            except ValueError:
                console.print(f"[{Colors.ERROR}]Error: Invalid port number[/{Colors.ERROR}]")
                return
        
        console.print(f"[{Colors.INFO}]Connecting to [{Colors.LIGHT_PURPLE}]{target}:{port}[/{Colors.LIGHT_PURPLE}][/{Colors.INFO}]")
        
        # Call minecraft_scanner's connection functionality
        try:
            cmd = [sys.executable, 'minecraft_scanner.py', target, '-p', str(port)]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            # Process and colorize the output
            connected = False
            for line in process.stdout:
                styled_line = self._style_output(line)
                console.print(styled_line, end='')
                if "✓ Successfully connected to server" in line:
                    connected = True
            
            process.wait()
            
            if connected:
                self.target = target
                self.port = port
                console.print(f"\n[{Colors.SUCCESS}]Connected to {target}:{port}[/{Colors.SUCCESS}]")
            else:
                console.print(f"\n[{Colors.ERROR}]Failed to connect to {target}:{port}[/{Colors.ERROR}]")
                
        except Exception as e:
            console.print(f"[{Colors.ERROR}]Error connecting to server: {str(e)}[/{Colors.ERROR}]")
    
    def do_plugins(self, arg):
        """List plugins on a connected server: plugins [target] [port]"""
        args = arg.split()
        target = self.target
        port = self.port
        
        if args:
            target = args[0]
            if len(args) > 1:
                try:
                    port = int(args[1])
                except ValueError:
                    console.print(f"[{Colors.ERROR}]Error: Invalid port number[/{Colors.ERROR}]")
                    return
        
        if not target:
            console.print(f"[{Colors.ERROR}]Error: No target specified. Connect to a server first or provide a target.[/{Colors.ERROR}]")
            return
        
        console.print(f"[{Colors.INFO}]Listing plugins on [{Colors.LIGHT_PURPLE}]{target}:{port}[/{Colors.LIGHT_PURPLE}][/{Colors.INFO}]")
        
        # Call minecraft_scanner with the list-plugins option
        try:
            cmd = [sys.executable, 'minecraft_scanner.py', target, '-p', str(port), '--list-plugins']
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            # Process and colorize the output
            for line in process.stdout:
                styled_line = self._style_output(line)
                console.print(styled_line, end='')
                
            process.wait()
                
        except Exception as e:
            console.print(f"[{Colors.ERROR}]Error listing plugins: {str(e)}[/{Colors.ERROR}]")
    
    def do_exploit(self, arg):
        """Attempt to exploit vulnerabilities on a server: exploit [target] [port]"""
        args = arg.split()
        target = self.target
        port = self.port
        
        if args:
            target = args[0]
            if len(args) > 1:
                try:
                    port = int(args[1])
                except ValueError:
                    console.print(f"[{Colors.ERROR}]Error: Invalid port number[/{Colors.ERROR}]")
                    return
        
        if not target:
            console.print(f"[{Colors.ERROR}]Error: No target specified. Connect to a server first or provide a target.[/{Colors.ERROR}]")
            return
        
        console.print(f"[{Colors.WARNING}]Attempting to exploit vulnerabilities on [{Colors.LIGHT_PURPLE}]{target}:{port}[/{Colors.LIGHT_PURPLE}][/{Colors.WARNING}]")
        console.print(f"[{Colors.WARNING}]⚠ This operation may trigger security systems. Use with caution.[/{Colors.WARNING}]")
        
        # Confirmation
        confirm = input("Are you sure you want to continue? (y/n): ")
        if confirm.lower() != 'y':
            console.print(f"[{Colors.INFO}]Operation cancelled[/{Colors.INFO}]")
            return
        
        # Call minecraft_scanner with the exploit option
        try:
            cmd = [sys.executable, 'minecraft_scanner.py', target, '-p', str(port), '--exploit', '--check-privesc']
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            # Process and colorize the output
            for line in process.stdout:
                styled_line = self._style_output(line)
                console.print(styled_line, end='')
                
            process.wait()
                
        except Exception as e:
            console.print(f"[{Colors.ERROR}]Error during exploitation: {str(e)}[/{Colors.ERROR}]")
    
    def do_enum(self, arg):
        """Enumerate subdomains for a target: enum [domain]"""
        args = arg.split()
        if not args:
            if self.target and not self.target.replace('.', '').isdigit():  # Not an IP address
                domain = self.target
            else:
                console.print(f"[{Colors.ERROR}]Error: Domain is required[/{Colors.ERROR}]")
                console.print(f"[{Colors.INFO}]Usage: enum [domain][/{Colors.INFO}]")
                return
        else:
            domain = args[0]
        
        console.print(f"[{Colors.INFO}]Enumerating subdomains for [{Colors.LIGHT_PURPLE}]{domain}[/{Colors.LIGHT_PURPLE}][/{Colors.INFO}]")
        
        # Call minecraft_scanner with the enum-subdomains option
        try:
            cmd = [sys.executable, 'minecraft_scanner.py', domain, '--enum-subdomains']
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            # Process and colorize the output
            for line in process.stdout:
                styled_line = self._style_output(line)
                console.print(styled_line, end='')
                
            process.wait()
                
        except Exception as e:
            console.print(f"[{Colors.ERROR}]Error enumerating subdomains: {str(e)}[/{Colors.ERROR}]")
    
    def do_vulndb(self, arg):
        """Check vulnerability databases for Minecraft exploits"""
        console.print(f"[{Colors.INFO}]Checking vulnerability databases for Minecraft exploits...[/{Colors.INFO}]")
        
        # Call minecraft_scanner with the check-vuln-db option
        try:
            cmd = [sys.executable, 'minecraft_scanner.py', 'dummy.com', '--check-vuln-db']
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            # Process and colorize the output
            for line in process.stdout:
                styled_line = self._style_output(line)
                console.print(styled_line, end='')
                
            process.wait()
                
        except Exception as e:
            console.print(f"[{Colors.ERROR}]Error checking vulnerability databases: {str(e)}[/{Colors.ERROR}]")
    
    def do_exit(self, arg):
        """Exit the program"""
        console.print(f"[{Colors.INFO}]Exiting DROLE - Minecraft Server Security Scanner[/{Colors.INFO}]")
        return True
    
    def do_quit(self, arg):
        """Exit the program"""
        return self.do_exit(arg)
    
    def do_version(self, arg):
        """Show version information"""
        version_panel = Panel(
            Text.from_markup(
                f"[{Colors.BLOOD_RED}]DROLE - Minecraft Server Security Scanner[/{Colors.BLOOD_RED}]\n"
                f"[{Colors.INFO}]Version: [{Colors.BLOOD_RED}]1.0.0[/{Colors.BLOOD_RED}][/{Colors.INFO}]\n"
                f"[{Colors.INFO}]Python: [{Colors.LIGHT_PURPLE}]{sys.version.split()[0]}[/{Colors.LIGHT_PURPLE}][/{Colors.INFO}]\n"
                f"[{Colors.INFO}]Platform: [{Colors.LIGHT_PURPLE}]{sys.platform}[/{Colors.LIGHT_PURPLE}][/{Colors.INFO}]"
            ),
            border_style=Style(color=Colors.NIGHT_PURPLE),
            title="Version Info",
            title_align="left"
        )
        console.print(version_panel)
    
    def do_help(self, arg):
        """List available commands with "help" or detailed help with "help cmd"."""
        if arg:
            # Display help for a specific command
            super().do_help(arg)
        else:
            # Create a table for commands
            table = Table(title="DROLE - Minecraft Server Security Scanner - Commands", 
                         border_style=Style(color=Colors.NIGHT_PURPLE),
                         title_style=Style(color=Colors.BLOOD_RED, bold=True))
            
            table.add_column("Command", style=Style(color=Colors.LIGHT_PURPLE, bold=True))
            table.add_column("Description", style=Style(color=Colors.INFO))
            
            # General Commands
            table.add_row("help", "Display this help message")
            table.add_row("version", "Show version information")
            table.add_row("clear", "Clear the screen")
            table.add_row("exit, quit", "Exit the program")
            
            # Scanning Commands
            table.add_row("scan", "Scan a Minecraft server (main function)")
            table.add_row("connect", "Connect to a Minecraft server")
            table.add_row("plugins", "List plugins on a connected server")
            table.add_row("exploit", "Attempt to exploit vulnerabilities")
            table.add_row("enum", "Enumerate subdomains for a target")
            table.add_row("vulndb", "Check vulnerability databases")
            
            console.print(table)
            console.print(f"[{Colors.INFO}]For detailed help on a command, type: [{Colors.LIGHT_PURPLE}]help command[/{Colors.LIGHT_PURPLE}][/{Colors.INFO}]")
    
    def _style_output(self, line):
        """Add rich styling to command output"""
        # Add Rich markup to console output for consistent styling
        line = line.rstrip()
        
        # Apply custom styling based on content
        if "✓" in line or "Success" in line:
            return f"[{Colors.SUCCESS}]{line}[/{Colors.SUCCESS}]"
        elif "✗" in line or "Error" in line or "Failed" in line:
            return f"[{Colors.ERROR}]{line}[/{Colors.ERROR}]"
        elif "⚠" in line or "Warning" in line:
            return f"[{Colors.WARNING}]{line}[/{Colors.WARNING}]"
        elif "=" * 10 in line:  # Section dividers
            return f"[{Colors.NIGHT_PURPLE}]{line}[/{Colors.NIGHT_PURPLE}]"
        elif any(keyword in line for keyword in ["Starting", "Checking", "Finding", "Scanning", "Testing"]):
            return f"[{Colors.MEDIUM_PURPLE}]{line}[/{Colors.MEDIUM_PURPLE}]"
        elif any(keyword in line for keyword in ["Found", "Detected", "Discovered"]):
            return f"[{Colors.CRIMSON}]{line}[/{Colors.CRIMSON}]"
        else:
            return f"[{Colors.INFO}]{line}[/{Colors.INFO}]"
    
    def emptyline(self):
        """Do nothing on empty line"""
        pass
    
    def default(self, line):
        """Handle unknown commands"""
        console.print(f"[{Colors.ERROR}]Unknown command: {line}[/{Colors.ERROR}]")
        console.print(f"[{Colors.INFO}]Type [{Colors.LIGHT_PURPLE}]help[/{Colors.LIGHT_PURPLE}] to see available commands.[/{Colors.INFO}]")

def main():
    """Main function to run the CLI"""
    # Initialize the CLI
    cli = DroleCLI()
    
    try:
        cli.cmdloop()
    except KeyboardInterrupt:
        console.print(f"\n[{Colors.INFO}]Exiting DROLE - Minecraft Server Security Scanner[/{Colors.INFO}]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[{Colors.ERROR}]An error occurred: {str(e)}[/{Colors.ERROR}]")
        sys.exit(1)

if __name__ == "__main__":
    main()