#!/usr/bin/env python3
"""
FS NSG Series Firewalls Web UI Security Scanner (HTTPS)
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests FS NSG Series Firewalls Web UI connectivity on HTTPS port and reports security configuration:
- No authentication required (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import urllib.request
import urllib.error

def test_fsnsg_connection(host, port, use_ssl=False):
    """Test basic FS NSG Series Firewalls connection"""
    try:
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            wrapped_socket = context.wrap_socket(sock, server_hostname=host)
            wrapped_socket.connect((host, port))
            wrapped_socket.close()
            return True
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.close()
            return True
    except Exception:
        return False

def test_fsnsg_auth(host, port, use_ssl=False):
    """Test FS NSG Series Firewalls Web UI authentication"""
    try:
        protocol = "https" if use_ssl else "http"
        url = f"{protocol}://{host}:{port}/"
        
        req = urllib.request.Request(url)
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        else:
            opener = urllib.request.build_opener()
        
        opener.addheaders = [('User-Agent', 'FS-NSG-Security-Scanner')]
        
        try:
            response = opener.open(req, timeout=5)
            response_data = response.read().decode('utf-8', errors='ignore')
            response.close()
            
            # Check if it's FS NSG Series Firewalls
            if 'fs' in response_data.lower() or 'nsg' in response_data.lower() or 'firewall' in response_data.lower():
                # Check for authentication indicators
                if '401' not in response_data and 'unauthorized' not in response_data.lower():
                    if 'login' not in response_data.lower() or 'password' not in response_data.lower():
                        print(f"FS NSG Series Firewalls Web UI accessible at {host}:{port}")
                        print("VULNERABLE")
                        return True
            
            return False
            
        except urllib.error.HTTPError as e:
            if e.code == 401:
                print(f"FS NSG Series Firewalls Web UI at {host}:{port} requires authentication")
                return False
            elif e.code == 403:
                print(f"FS NSG Series Firewalls Web UI at {host}:{port} - Access forbidden")
                return False
            else:
                print(f"FS NSG Series Firewalls Web UI at {host}:{port} - HTTP {e.code}")
                return False
                
    except urllib.error.URLError as e:
        error_msg = str(e).lower()
        if 'connection refused' in error_msg:
            print(f"Connection refused - service not running on {host}:{port}")
        elif 'timeout' in error_msg:
            print(f"Connection timeout - service not responding")
        else:
            print(f"Connection error - {str(e)}")
        return False
    except Exception as e:
        print(f"Error testing FS NSG Series Firewalls: {str(e)}")
        return False

def scan_fsnsg_security(host, port=44433, tls_only=True):
    """Scan FS NSG Series Firewalls security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_fsnsg_connection(host, port, use_ssl=True):
            test_fsnsg_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_fsnsg_connection(host, port, use_ssl=False):
            test_fsnsg_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='FS NSG Series Firewalls Web UI Security Scanner (HTTPS)')
    parser.add_argument('host', help='FS NSG Series Firewalls host to test')
    parser.add_argument('port', nargs='?', type=int, default=44433, help='FS NSG Series Firewalls HTTPS port (default: 44433)')
    parser.add_argument('--tls', '-t', action='store_true', help='Test TLS/SSL connection only')
    
    args = parser.parse_args()
    
    host = args.host
    port = args.port
    tls_only = args.tls
    
    if ':' in host:
        host, port_str = host.split(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            print(f"Error: Invalid port '{port_str}'", file=sys.stderr)
            sys.exit(1)
    
    scan_fsnsg_security(host, port, tls_only=True)

if __name__ == '__main__':
    main()

