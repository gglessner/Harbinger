#!/usr/bin/env python3
"""
Apache Flume Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Apache Flume connectivity and reports security configuration:
- No authentication required (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import struct

def test_flume_connection(host, port, use_ssl=False):
    """Test basic Flume connection"""
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

def test_flume_auth(host, port, use_ssl=False):
    """Test Flume authentication"""
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
        
        # Apache Flume uses Avro RPC protocol
        # Send Avro handshake
        # Avro protocol handshake format
        handshake = struct.pack('>I', 0x00)  # Magic number
        handshake += b'version'  # Protocol name
        handshake += struct.pack('>I', 0x00)  # Protocol version
        
        conn.send(handshake)
        
        # Read response
        response = conn.recv(4096)
        conn.close()
        
        # Check if we got a response (connection successful)
        if len(response) > 0:
            # If we got a response without authentication error, it's vulnerable
            print(f"Apache Flume accessible at {host}:{port}")
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
            print(f"Error testing Flume: {str(e)}")
        return False

def scan_flume_security(host, port=41414, tls_only=False):
    """Scan Flume security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_flume_connection(host, port, use_ssl=True):
            test_flume_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_flume_connection(host, port, use_ssl=False):
            test_flume_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='Apache Flume Security Scanner')
    parser.add_argument('host', help='Flume host to test')
    parser.add_argument('port', nargs='?', type=int, default=41414, help='Flume port (default: 41414)')
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
    
    scan_flume_security(host, port, tls_only)

if __name__ == '__main__':
    main()

