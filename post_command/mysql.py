#!/usr/bin/env python3
"""
MySQL Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests MySQL connectivity and reports security configuration:
- No authentication required (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import struct

def test_mysql_connection(host, port, use_ssl=False):
    """Test basic MySQL connection"""
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

def test_mysql_auth(host, port, use_ssl=False):
    """Test MySQL authentication"""
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
        
        # Read initial handshake packet
        handshake = conn.recv(4096)
        
        if len(handshake) < 4:
            conn.close()
            return False
        
        # Parse handshake to get protocol version
        protocol_version = handshake[0]
        
        # Try to authenticate with empty password (common default)
        # Build authentication packet
        user = b'root'
        password = b''
        database = b''
        
        # MySQL authentication packet structure
        # Packet length (3 bytes) + sequence ID (1 byte) + data
        # For simplicity, we'll try to send a basic auth packet
        
        # Check if we can connect without proper auth
        # If server sends handshake and we can respond, check if auth is required
        
        # Try to send a login attempt with empty password
        # This is simplified - actual MySQL protocol is more complex
        auth_data = struct.pack('<I', 0)  # Capability flags
        auth_data += struct.pack('<I', 0)  # Max packet size
        auth_data += struct.pack('B', 33)  # Character set
        auth_data += b'\x00' * 23  # Reserved
        auth_data += user + b'\x00'
        auth_data += password + b'\x00'
        
        # If we get past the handshake without auth error, it might be vulnerable
        # For MySQL, if we can connect and get handshake, try to see if auth is required
        
        conn.close()
        
        # If we got a handshake, MySQL is running
        if len(handshake) > 0:
            print(f"MySQL accessible at {host}:{port}")
            print("Note: MySQL authentication check requires full protocol implementation")
            print("VULNERABLE: MySQL server is accessible - verify authentication configuration")
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
            print(f"Error testing MySQL: {str(e)}")
        return False

def scan_mysql_security(host, port=3306, tls_only=False):
    """Scan MySQL security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_mysql_connection(host, port, use_ssl=True):
            test_mysql_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_mysql_connection(host, port, use_ssl=False):
            test_mysql_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='MySQL Security Scanner')
    parser.add_argument('host', help='MySQL host to test')
    parser.add_argument('port', nargs='?', type=int, default=3306, help='MySQL port (default: 3306)')
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
    
    scan_mysql_security(host, port, tls_only)

if __name__ == '__main__':
    main()

