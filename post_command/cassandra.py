#!/usr/bin/env python3
"""
Apache Cassandra Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Apache Cassandra connectivity and reports security configuration:
- No authentication required (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import struct

def test_cassandra_connection(host, port, use_ssl=False):
    """Test basic Cassandra connection"""
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

def test_cassandra_auth(host, port, use_ssl=False):
    """Test Cassandra authentication"""
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
        
        # Cassandra CQL protocol: STARTUP message
        # Version: 0x04 (CQL protocol version 4)
        # Flags: 0x00
        # Stream: 0x00
        # Opcode: 0x01 (STARTUP)
        # Length: variable
        
        # STARTUP message body: map with "CQL_VERSION" -> "3.0.0"
        startup_body = b'\x00\x01'  # Map with 1 entry
        startup_body += b'\x00\x0bCQL_VERSION'  # Key: "CQL_VERSION"
        startup_body += b'\x00\x05'  # Value length
        startup_body += b'3.0.0'  # Value
        
        # Build CQL frame
        version = 0x04
        flags = 0x00
        stream = 0x00
        opcode = 0x01  # STARTUP
        
        frame = struct.pack('>B', version)
        frame += struct.pack('>B', flags)
        frame += struct.pack('>H', stream)
        frame += struct.pack('>B', opcode)
        frame += struct.pack('>i', len(startup_body))
        frame += startup_body
        
        conn.send(frame)
        
        # Read response
        response = conn.recv(4096)
        conn.close()
        
        if len(response) >= 9:
            # Parse response header
            resp_version = response[0]
            resp_flags = response[1]
            resp_stream = struct.unpack('>H', response[2:4])[0]
            resp_opcode = response[4]
            resp_length = struct.unpack('>i', response[5:9])[0]
            
            # Opcode 0x02 = READY, 0x03 = AUTHENTICATE, 0x00 = ERROR
            if resp_opcode == 0x02:  # READY - no authentication required
                print(f"Apache Cassandra accessible at {host}:{port}")
                print("VULNERABLE")
                return True
            elif resp_opcode == 0x03:  # AUTHENTICATE - authentication required
                print(f"Apache Cassandra at {host}:{port} requires authentication")
                return False
            elif resp_opcode == 0x00:  # ERROR
                # Check error message
                if resp_length > 0 and len(response) >= 9 + resp_length:
                    error_msg = response[9:9+resp_length].decode('utf-8', errors='ignore')
                    if 'authentication' in error_msg.lower():
                        print(f"Apache Cassandra at {host}:{port} requires authentication")
                        return False
        
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
            print(f"Error testing Cassandra: {str(e)}")
        return False

def scan_cassandra_security(host, port=9042, tls_only=False):
    """Scan Cassandra security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_cassandra_connection(host, port, use_ssl=True):
            test_cassandra_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_cassandra_connection(host, port, use_ssl=False):
            test_cassandra_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='Apache Cassandra Security Scanner')
    parser.add_argument('host', help='Cassandra host to test')
    parser.add_argument('port', nargs='?', type=int, default=9042, help='Cassandra port (default: 9042)')
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
    
    scan_cassandra_security(host, port, tls_only)

if __name__ == '__main__':
    main()

