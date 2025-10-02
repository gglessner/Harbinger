#!/usr/bin/env python3
"""
Port Connectivity Check Script
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

Quick nmap-based port connectivity check that doesn't require root privileges.
Returns exit code 0 for open port, 1 for closed port.

Usage: python port_check.py <host> <port>
"""

import sys
import subprocess
import socket
import time

def quick_port_check(host, port):
    """
    Perform a quick port connectivity check using nmap with optimized settings.
    Returns tuple: (status, message) where status is 'open', 'closed', or 'timeout'
    """
    try:
        # Use nmap with optimized settings for speed
        # -sT: TCP connect scan (no root required)
        # -T4: Aggressive timing template
        # --max-retries 0: No retries for speed
        # --host-timeout 5s: 5 second timeout per host
        # --max-parallelism 1: Single host scan
        command = [
            'nmap', '-sT', '-T4', '--max-retries', '0', 
            '--host-timeout', '5s', '--max-parallelism', '1',
            '-p', str(port), str(host)
        ]
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10  # Overall timeout of 10 seconds
        )
        
        # Check if port is open in nmap output
        if result.returncode == 0 and result.stdout:
            # Look for "open" status in the output
            if "open" in result.stdout.lower():
                return ('open', 'port is open')
            else:
                return ('closed', 'port is closed')
        
        return ('closed', 'port is closed')
        
    except subprocess.TimeoutExpired:
        return ('timeout', 'port timed out')
    except (subprocess.CalledProcessError, FileNotFoundError):
        # If nmap fails, fall back to basic socket connection
        return basic_socket_check(host, port)

def basic_socket_check(host, port):
    """
    Fallback method using basic socket connection if nmap fails.
    Returns tuple: (status, message) where status is 'open', 'closed', or 'timeout'
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)  # 5 second timeout
            result = sock.connect_ex((host, port))
            if result == 0:
                return ('open', 'port is open')
            else:
                return ('closed', 'port is closed')
    except socket.timeout:
        return ('timeout', 'port timed out')
    except Exception:
        return ('closed', 'port is closed')

def main():
    if len(sys.argv) != 3:
        print("Usage: python port_check.py <host> <port>", file=sys.stderr)
        sys.exit(1)
    
    host = sys.argv[1]
    port = sys.argv[2]
    
    # Validate port number
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            print(f"Error: Port must be between 1 and 65535", file=sys.stderr)
            sys.exit(1)
    except ValueError:
        print(f"Error: Invalid port number: {port}", file=sys.stderr)
        sys.exit(1)
    
    # Perform the check
    status, message = quick_port_check(host, port)
    
    # Print the result message
    print(message)
    
    # Return appropriate exit code
    if status == 'open':
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
