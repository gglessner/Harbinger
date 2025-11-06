#!/usr/bin/env python3
"""
Rundeck Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Rundeck connectivity and reports security configuration:
- No authentication required (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import urllib.request
import urllib.error
import json

def test_rundeck_connection(host, port, use_ssl=False):
    """Test basic Rundeck connection"""
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

def test_rundeck_auth(host, port, use_ssl=False):
    """Test Rundeck authentication"""
    try:
        protocol = "https" if use_ssl else "http"
        url = f"{protocol}://{host}:{port}/api/version"
        
        req = urllib.request.Request(url)
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        else:
            opener = urllib.request.build_opener()
        
        opener.addheaders = [('User-Agent', 'Rundeck-Security-Scanner')]
        
        try:
            response = opener.open(req, timeout=5)
            response_data = response.read().decode('utf-8', errors='ignore')
            response.close()
            
            # Check if it's Rundeck
            if 'rundeck' in response_data.lower() or 'version' in response_data.lower():
                try:
                    # Try to parse as JSON (Rundeck API returns JSON)
                    api_data = json.loads(response_data)
                    print(f"Rundeck accessible at {host}:{port}")
                    print(f"API version: {api_data}")
                except:
                    print(f"Rundeck accessible at {host}:{port}")
                    print(f"Response: {response_data}")
                
                # Check for authentication indicators
                if '401' not in response_data and 'unauthorized' not in response_data.lower():
                    if 'login' not in response_data.lower() or 'password' not in response_data.lower():
                        print("VULNERABLE: No authentication required")
                        print("VULNERABLE")
                        return True
            
            return False
            
        except urllib.error.HTTPError as e:
            if e.code == 401:
                print(f"Rundeck at {host}:{port} requires authentication")
                return False
            elif e.code == 403:
                print(f"Rundeck at {host}:{port} - Access forbidden")
                return False
            else:
                print(f"Rundeck at {host}:{port} - HTTP {e.code}")
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
        print(f"Error testing Rundeck: {str(e)}")
        return False

def scan_rundeck_security(host, port=4440, tls_only=False):
    """Scan Rundeck security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_rundeck_connection(host, port, use_ssl=True):
            test_rundeck_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_rundeck_connection(host, port, use_ssl=False):
            test_rundeck_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='Rundeck Security Scanner')
    parser.add_argument('host', help='Rundeck host to test')
    parser.add_argument('port', nargs='?', type=int, default=4440, help='Rundeck port (default: 4440)')
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
    
    scan_rundeck_security(host, port, tls_only)

if __name__ == '__main__':
    main()

