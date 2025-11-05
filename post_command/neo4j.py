#!/usr/bin/env python3
"""
Neo4j Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Neo4j HTTP API connectivity and reports security configuration:
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

def test_neo4j_connection(host, port, use_ssl=False):
    """Test basic Neo4j connection"""
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

def test_neo4j_auth(host, port, use_ssl=False):
    """Test Neo4j authentication"""
    try:
        protocol = 'https' if use_ssl else 'http'
        url = f"{protocol}://{host}:{port}/db/data/"
        
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Harbinger-Neo4j-Scanner/1.0')
        req.add_header('Accept', 'application/json')
        
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        else:
            opener = urllib.request.build_opener()
        
        response = opener.open(req, timeout=5)
        status_code = response.getcode()
        response_data = response.read().decode('utf-8', errors='ignore')
        response.close()
        
        if status_code == 200:
            try:
                data = json.loads(response_data)
                print(f"Neo4j accessible at {host}:{port}")
                print("VULNERABLE: No authentication required")
                print("VULNERABLE")
                return True
            except json.JSONDecodeError:
                if 'neo4j' in response_data.lower() or 'cypher' in response_data.lower():
                    print(f"Neo4j accessible at {host}:{port}")
                    print("VULNERABLE: No authentication required")
                    print("VULNERABLE")
                    return True
        
        return False
        
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print(f"Neo4j requires authentication (properly secured)")
            return False
        elif e.code == 200:
            print(f"Neo4j accessible at {host}:{port}")
            print("VULNERABLE: No authentication required")
            print("VULNERABLE")
            return True
        else:
            print(f"HTTP error {e.code}: {e.reason}")
            return False
    except urllib.error.URLError as e:
        error_msg = str(e).lower()
        if 'connection refused' in error_msg:
            print(f"Connection refused - service not running on {host}:{port}")
        elif 'timeout' in error_msg:
            print(f"Connection timeout - service not responding")
        else:
            print(f"Error testing Neo4j: {str(e)}")
        return False
    except Exception as e:
        error_msg = str(e).lower()
        if 'connection refused' in error_msg:
            print(f"Connection refused - service not running on {host}:{port}")
        elif 'timeout' in error_msg:
            print(f"Connection timeout - service not responding")
        else:
            print(f"Error testing Neo4j: {str(e)}")
        return False

def scan_neo4j_security(host, port=7474, tls_only=False):
    """Scan Neo4j security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_neo4j_connection(host, port, use_ssl=True):
            test_neo4j_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_neo4j_connection(host, port, use_ssl=False):
            test_neo4j_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='Neo4j Security Scanner')
    parser.add_argument('host', help='Neo4j host to test')
    parser.add_argument('port', nargs='?', type=int, default=7474, help='Neo4j port (default: 7474)')
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
    
    scan_neo4j_security(host, port, tls_only)

if __name__ == '__main__':
    main()

