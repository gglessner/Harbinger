#!/usr/bin/env python3
"""
Docker API Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Docker API connectivity and reports security configuration:
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

def test_docker_api_connection(host, port, use_ssl=False):
    """Test basic Docker API connection"""
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

def test_docker_api_auth(host, port, use_ssl=False):
    """Test Docker API authentication"""
    try:
        protocol = 'https' if use_ssl else 'http'
        url = f"{protocol}://{host}:{port}/version"
        
        # Create request
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Harbinger-Docker-API-Scanner/1.0')
        
        # Handle SSL context
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        else:
            opener = urllib.request.build_opener()
        
        # Make request
        response = opener.open(req, timeout=5)
        status_code = response.getcode()
        response_data = response.read().decode('utf-8', errors='ignore')
        response.close()
        
        if status_code == 200:
            try:
                version_info = json.loads(response_data)
                version = version_info.get('Version', 'Unknown')
                print(f"Docker API accessible at {host}:{port}")
                print(f"Docker version: {version}")
                print("VULNERABLE: No authentication required")
                print("VULNERABLE")
                return True
            except json.JSONDecodeError:
                if 'Docker' in response_data or 'docker' in response_data.lower():
                    print(f"Docker API accessible at {host}:{port}")
                    print("VULNERABLE: No authentication required")
                    print("VULNERABLE")
                    return True
        
        return False
        
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print(f"Docker API requires authentication (properly secured)")
            return False
        elif e.code == 200:
            print(f"Docker API accessible at {host}:{port}")
            print("VULNERABLE: No authentication required")
            print("VULNERABLE")
            return True
        else:
            print(f"HTTP error {e.code}: {e.reason}")
            return False
    except urllib.error.URLError as e:
        error_msg = str(e).lower()
        if 'connection refused' in error_msg or 'connection reset' in error_msg:
            print(f"Connection refused - service not running on {host}:{port}")
        elif 'timeout' in error_msg:
            print(f"Connection timeout - service not responding")
        else:
            print(f"Error testing Docker API: {str(e)}")
        return False
    except Exception as e:
        error_msg = str(e).lower()
        if 'connection refused' in error_msg or 'connection reset' in error_msg:
            print(f"Connection refused - service not running on {host}:{port}")
        elif 'timeout' in error_msg:
            print(f"Connection timeout - service not responding")
        else:
            print(f"Error testing Docker API: {str(e)}")
        return False

def scan_docker_api_security(host, port=2375, tls_only=False):
    """Scan Docker API security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_docker_api_connection(host, port, use_ssl=True):
            test_docker_api_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_docker_api_connection(host, port, use_ssl=False):
            test_docker_api_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='Docker API Security Scanner')
    parser.add_argument('host', help='Docker API host to test')
    parser.add_argument('port', nargs='?', type=int, default=2375, help='Docker API port (default: 2375)')
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
    
    scan_docker_api_security(host, port, tls_only)

if __name__ == '__main__':
    main()

