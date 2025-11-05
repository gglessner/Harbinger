#!/usr/bin/env python3
"""
Apache CouchDB Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Apache CouchDB connectivity and reports security configuration:
- No authentication required (vulnerable - admin party mode)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import urllib.request
import urllib.error
import json

def test_couchdb_connection(host, port, use_ssl=False):
    """Test basic CouchDB connection"""
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

def test_couchdb_auth(host, port, use_ssl=False):
    """Test CouchDB authentication"""
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
        
        opener.addheaders = [('User-Agent', 'CouchDB-Security-Scanner')]
        
        try:
            response = opener.open(req, timeout=5)
            response_data = response.read().decode('utf-8', errors='ignore')
            response.close()
            
            # Check if it's CouchDB
            try:
                data = json.loads(response_data)
                if 'couchdb' in data.get('couchdb', '').lower() or 'version' in data:
                    # Check if we can access without authentication
                    # Try to access _all_dbs endpoint
                    dbs_url = f"{protocol}://{host}:{port}/_all_dbs"
                    dbs_req = urllib.request.Request(dbs_url)
                    if use_ssl:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
                    else:
                        opener = urllib.request.build_opener()
                    opener.addheaders = [('User-Agent', 'CouchDB-Security-Scanner')]
                    
                    try:
                        dbs_response = opener.open(dbs_req, timeout=5)
                        dbs_data = dbs_response.read().decode('utf-8', errors='ignore')
                        dbs_response.close()
                        
                        # If we got databases list, no authentication required
                        print(f"Apache CouchDB accessible at {host}:{port}")
                        print("VULNERABLE")
                        return True
                    except urllib.error.HTTPError as e:
                        if e.code == 401 or e.code == 403:
                            print(f"Apache CouchDB at {host}:{port} requires authentication")
                            return False
            except json.JSONDecodeError:
                pass
            
            return False
            
        except urllib.error.HTTPError as e:
            if e.code == 401:
                print(f"Apache CouchDB at {host}:{port} requires authentication")
                return False
            elif e.code == 403:
                print(f"Apache CouchDB at {host}:{port} - Access forbidden")
                return False
            else:
                print(f"Apache CouchDB at {host}:{port} - HTTP {e.code}")
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
        print(f"Error testing CouchDB: {str(e)}")
        return False

def scan_couchdb_security(host, port=5984, tls_only=False):
    """Scan CouchDB security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_couchdb_connection(host, port, use_ssl=True):
            test_couchdb_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_couchdb_connection(host, port, use_ssl=False):
            test_couchdb_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='Apache CouchDB Security Scanner')
    parser.add_argument('host', help='CouchDB host to test')
    parser.add_argument('port', nargs='?', type=int, default=5984, help='CouchDB port (default: 5984)')
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
    
    scan_couchdb_security(host, port, tls_only)

if __name__ == '__main__':
    main()

