#!/usr/bin/env python3
"""
IBM Web Administration Tool Admin Console Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests IBM Web Administration Tool Admin Console connectivity and reports security configuration:
- No authentication required (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import urllib.request
import urllib.error

def test_ibmwat_connection(host, port, use_ssl=False):
    """Test basic IBM Web Administration Tool connection"""
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

def test_ibmwat_auth(host, port, use_ssl=False):
    """Test IBM Web Administration Tool Admin Console authentication"""
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
        
        opener.addheaders = [('User-Agent', 'IBM-WAT-Security-Scanner')]
        
        try:
            response = opener.open(req, timeout=5)
            response_data = response.read().decode('utf-8', errors='ignore')
            response.close()
            
            # Check if it's IBM Web Administration Tool
            if 'ibm' in response_data.lower() or 'websphere' in response_data.lower() or 'administration' in response_data.lower():
                # Check for authentication indicators
                if '401' not in response_data and 'unauthorized' not in response_data.lower():
                    if 'login' not in response_data.lower() or 'password' not in response_data.lower():
                        print(f"IBM Web Administration Tool Admin Console accessible at {host}:{port}")
                        print("VULNERABLE")
                        return True
            
            return False
            
        except urllib.error.HTTPError as e:
            if e.code == 401:
                print(f"IBM Web Administration Tool Admin Console at {host}:{port} requires authentication")
                return False
            elif e.code == 403:
                print(f"IBM Web Administration Tool Admin Console at {host}:{port} - Access forbidden")
                return False
            else:
                print(f"IBM Web Administration Tool Admin Console at {host}:{port} - HTTP {e.code}")
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
        print(f"Error testing IBM Web Administration Tool: {str(e)}")
        return False

def scan_ibmwat_security(host, port=12104, tls_only=False):
    """Scan IBM Web Administration Tool security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_ibmwat_connection(host, port, use_ssl=True):
            test_ibmwat_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_ibmwat_connection(host, port, use_ssl=False):
            test_ibmwat_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='IBM Web Administration Tool Admin Console Security Scanner')
    parser.add_argument('host', help='IBM Web Administration Tool host to test')
    parser.add_argument('port', nargs='?', type=int, default=12104, help='IBM Web Administration Tool port (default: 12104)')
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
    
    scan_ibmwat_security(host, port, tls_only)

if __name__ == '__main__':
    main()

