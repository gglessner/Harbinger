#!/usr/bin/env python3
"""
Apache ZooKeeper Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Apache ZooKeeper connectivity and reports security configuration:
- No authentication required (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import struct

def test_zookeeper_connection(host, port, use_ssl=False):
    """Test basic ZooKeeper connection"""
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

def test_zookeeper_auth(host, port, use_ssl=False):
    """Test ZooKeeper authentication"""
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
        
        # ZooKeeper protocol: send connect request
        # Format: length (4 bytes) + protocol version (4 bytes) + last zxid (8 bytes) + timeout (4 bytes) + session id (8 bytes) + password length (4 bytes) + password
        # Simple connect without authentication
        timeout = 30000  # 30 seconds in milliseconds
        session_id = 0
        password = b''
        
        # Build connect request
        protocol_version = 0  # ZOOKEEPER_PROTOCOL_VERSION_CONSTANT
        last_zxid = 0
        
        # Pack the connect request
        connect_data = struct.pack('>i', protocol_version)
        connect_data += struct.pack('>q', last_zxid)
        connect_data += struct.pack('>i', timeout)
        connect_data += struct.pack('>q', session_id)
        connect_data += struct.pack('>i', len(password))
        connect_data += password
        
        # Prepend length
        request = struct.pack('>i', len(connect_data)) + connect_data
        
        conn.send(request)
        
        # Read response
        response = conn.recv(4096)
        conn.close()
        
        if len(response) > 4:
            # Parse response
            response_length = struct.unpack('>i', response[0:4])[0]
            if response_length > 0 and len(response) >= 4 + response_length:
                # Check if connection was successful (protocol version in response)
                protocol_response = struct.unpack('>i', response[4:8])[0]
                if protocol_response == 0:  # Successful connection
                    print(f"Apache ZooKeeper accessible at {host}:{port}")
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
            print(f"Error testing ZooKeeper: {str(e)}")
        return False

def scan_zookeeper_security(host, port=2181, tls_only=False):
    """Scan ZooKeeper security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_zookeeper_connection(host, port, use_ssl=True):
            test_zookeeper_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_zookeeper_connection(host, port, use_ssl=False):
            test_zookeeper_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='Apache ZooKeeper Security Scanner')
    parser.add_argument('host', help='ZooKeeper host to test')
    parser.add_argument('port', nargs='?', type=int, default=2181, help='ZooKeeper port (default: 2181)')
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
    
    scan_zookeeper_security(host, port, tls_only)

if __name__ == '__main__':
    main()

