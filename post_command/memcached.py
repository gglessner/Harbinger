#!/usr/bin/env python3
"""
Memcached Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Memcached connectivity and reports security configuration:
- No authentication required (vulnerable - Memcached has no built-in auth)
- Accessible from network (vulnerable if exposed)
"""

import sys
import socket
import ssl
import argparse
import struct

def test_memcached_connection(host, port, use_ssl=False):
    """Test basic Memcached connection"""
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

def test_memcached_auth(host, port, use_ssl=False):
    """Test Memcached authentication (Memcached has no built-in auth)"""
    try:
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            conn = context.wrap_socket(sock, server_hostname=host)
            conn.connect((host, port))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            conn = sock
            conn.connect((host, port))
        
        # Memcached protocol: try to send a simple stats command
        # Format: "stats\r\n"
        stats_command = b"stats\r\n"
        conn.send(stats_command)
        
        # Read response
        response = conn.recv(4096)
        conn.close()
        
        # Check if we got a response (connection successful)
        if len(response) > 0:
            # If we got stats response, Memcached is accessible without authentication
            response_str = response.decode('utf-8', errors='ignore')
            if 'STAT' in response_str or 'END' in response_str:
                print(f"Memcached accessible at {host}:{port}")
                print("VULNERABLE: No authentication required (Memcached has no built-in authentication)")
                print("VULNERABLE")
                return True
        
        return False
        
    except socket.timeout:
        print(f"Connection timeout - service not responding")
        return False
    except ConnectionRefusedError:
        print(f"Connection refused - service not running on {host}:{port}")
        return False
    except Exception as e:
        error_msg = str(e).lower()
        if 'connection refused' in error_msg or 'connection reset' in error_msg:
            print(f"Connection refused - service not running on {host}:{port}")
        elif 'timeout' in error_msg:
            print(f"Connection timeout - service not responding")
        else:
            print(f"Error testing Memcached: {str(e)}")
        return False

def scan_memcached_security(host, port=11211, tls_only=False):
    """Scan Memcached security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_memcached_connection(host, port, use_ssl=True):
            test_memcached_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_memcached_connection(host, port, use_ssl=False):
            test_memcached_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='Memcached Security Scanner')
    parser.add_argument('host', help='Memcached host to test')
    parser.add_argument('port', nargs='?', type=int, default=11211, help='Memcached port (default: 11211)')
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
    
    scan_memcached_security(host, port, tls_only)

if __name__ == '__main__':
    main()

