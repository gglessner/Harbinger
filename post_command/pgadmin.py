#!/usr/bin/env python3
"""
pgAdmin Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests pgAdmin connectivity and reports security configuration:
- No authentication required (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import urllib.request
import urllib.error

def test_pgadmin_connection(host, port, use_ssl=False):
    """Test basic pgAdmin connection"""
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

def test_pgadmin_auth(host, port, use_ssl=False):
    """Test pgAdmin authentication"""
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
        
        opener.addheaders = [('User-Agent', 'pgAdmin-Security-Scanner')]
        
        try:
            response = opener.open(req, timeout=5)
            response_data = response.read().decode('utf-8', errors='ignore')
            response.close()
            
            # Check if it's pgAdmin
            if 'pgadmin' in response_data.lower():
                # Check for authentication indicators
                if '401' not in response_data and 'unauthorized' not in response_data.lower():
                    if 'login' not in response_data.lower() or 'password' not in response_data.lower():
                        print(f"pgAdmin accessible at {host}:{port}")
                        print("VULNERABLE")
                        return True
            
            return False
            
        except urllib.error.HTTPError as e:
            if e.code == 401:
                print(f"pgAdmin at {host}:{port} requires authentication")
                return False
            elif e.code == 403:
                print(f"pgAdmin at {host}:{port} - Access forbidden")
                return False
            else:
                print(f"pgAdmin at {host}:{port} - HTTP {e.code}")
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
        print(f"Error testing pgAdmin: {str(e)}")
        return False

def scan_pgadmin_security(host, port=5050, tls_only=False):
    """Scan pgAdmin security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_pgadmin_connection(host, port, use_ssl=True):
            test_pgadmin_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_pgadmin_connection(host, port, use_ssl=False):
            test_pgadmin_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='pgAdmin Security Scanner')
    parser.add_argument('host', help='pgAdmin host to test')
    parser.add_argument('port', nargs='?', type=int, default=5050, help='pgAdmin port (default: 5050)')
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
    
    scan_pgadmin_security(host, port, tls_only)

if __name__ == '__main__':
    main()

