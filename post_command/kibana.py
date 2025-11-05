#!/usr/bin/env python3
"""
Kibana Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Kibana connectivity and reports security configuration:
- No authentication required (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import urllib.request
import urllib.error

def test_kibana_connection(host, port, use_ssl=False):
    """Test basic Kibana connection"""
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

def test_kibana_auth(host, port, use_ssl=False):
    """Test Kibana authentication"""
    try:
        protocol = "https" if use_ssl else "http"
        url = f"{protocol}://{host}:{port}/api/status"
        
        req = urllib.request.Request(url)
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        else:
            opener = urllib.request.build_opener()
        
        opener.addheaders = [('User-Agent', 'Kibana-Security-Scanner')]
        
        try:
            response = opener.open(req, timeout=5)
            response_data = response.read().decode('utf-8', errors='ignore')
            response.close()
            
            # Check if it's Kibana
            if 'kibana' in response_data.lower() or 'version' in response_data.lower():
                # Check for authentication indicators
                if '401' not in response_data and 'unauthorized' not in response_data.lower():
                    if 'login' not in response_data.lower() or 'password' not in response_data.lower():
                        print(f"Kibana accessible at {host}:{port}")
                        print("VULNERABLE")
                        return True
            
            return False
            
        except urllib.error.HTTPError as e:
            if e.code == 401:
                print(f"Kibana at {host}:{port} requires authentication")
                return False
            elif e.code == 403:
                print(f"Kibana at {host}:{port} - Access forbidden")
                return False
            else:
                print(f"Kibana at {host}:{port} - HTTP {e.code}")
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
        print(f"Error testing Kibana: {str(e)}")
        return False

def scan_kibana_security(host, port=5601, tls_only=False):
    """Scan Kibana security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_kibana_connection(host, port, use_ssl=True):
            test_kibana_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_kibana_connection(host, port, use_ssl=False):
            test_kibana_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='Kibana Security Scanner')
    parser.add_argument('host', help='Kibana host to test')
    parser.add_argument('port', nargs='?', type=int, default=5601, help='Kibana port (default: 5601)')
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
    
    scan_kibana_security(host, port, tls_only)

if __name__ == '__main__':
    main()

