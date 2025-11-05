#!/usr/bin/env python3
"""
PostgreSQL Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests PostgreSQL connectivity and reports security configuration:
- No authentication required (vulnerable - trust authentication)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import struct

def test_postgresql_connection(host, port, use_ssl=False):
    """Test basic PostgreSQL connection"""
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

def test_postgresql_auth(host, port, use_ssl=False):
    """Test PostgreSQL authentication"""
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
        
        # PostgreSQL protocol: StartupMessage
        # Format: length (4 bytes) + protocol version (4 bytes) + parameter pairs
        
        # Protocol version 3.0
        protocol_version = 0x00030000
        
        # Parameter: user (default is postgres)
        params = b'user\0postgres\0\0'
        
        # Calculate message length
        msg_length = 4 + 4 + len(params)  # length + protocol + params
        
        startup_msg = struct.pack('>I', msg_length)
        startup_msg += struct.pack('>I', protocol_version)
        startup_msg += params
        
        conn.send(startup_msg)
        
        # Read response
        response = conn.recv(4096)
        conn.close()
        
        # Check if we got a response
        if len(response) >= 5:
            # Parse response type (first byte)
            response_type = response[0]
            
            # 'R' = Authentication request
            # 'E' = Error response
            # 'S' = Parameter status
            
            if response_type == ord('R'):
                # Authentication request - check auth type
                if len(response) >= 9:
                    auth_type = struct.unpack('>I', response[5:9])[0]
                    # 0 = AuthenticationOk
                    # 5 = MD5 password required
                    # 10 = AuthenticationCleartextPassword
                    if auth_type == 0:
                        print(f"PostgreSQL accessible at {host}:{port}")
                        print("VULNERABLE: No authentication required (trust authentication)")
                        print("VULNERABLE")
                        return True
                    else:
                        print(f"PostgreSQL at {host}:{port} requires authentication")
                        return False
            
            # If we got other response types, check for error
            if response_type == ord('E'):
                # Error response - might indicate authentication needed
                error_msg = response.decode('utf-8', errors='ignore')
                if 'authentication' in error_msg.lower():
                    print(f"PostgreSQL at {host}:{port} requires authentication")
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
            # Try with psycopg2 if available
            try:
                import psycopg2
                try:
                    if use_ssl:
                        conn = psycopg2.connect(
                            host=host,
                            port=port,
                            user='postgres',
                            password='',
                            sslmode='require',
                            connect_timeout=5
                        )
                    else:
                        conn = psycopg2.connect(
                            host=host,
                            port=port,
                            user='postgres',
                            password='',
                            connect_timeout=5
                        )
                    conn.close()
                    print(f"PostgreSQL accessible at {host}:{port}")
                    print("VULNERABLE: No authentication required (trust authentication)")
                    print("VULNERABLE")
                    return True
                except psycopg2.OperationalError as db_err:
                    if 'authentication' in str(db_err).lower():
                        print(f"PostgreSQL at {host}:{port} requires authentication")
                        return False
                    else:
                        print(f"Error testing PostgreSQL: {str(db_err)}")
                        return False
            except ImportError:
                print(f"Error testing PostgreSQL: {str(e)}")
                return False
        return False

def scan_postgresql_security(host, port=5432, tls_only=False):
    """Scan PostgreSQL security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_postgresql_connection(host, port, use_ssl=True):
            test_postgresql_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_postgresql_connection(host, port, use_ssl=False):
            test_postgresql_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='PostgreSQL Security Scanner')
    parser.add_argument('host', help='PostgreSQL host to test')
    parser.add_argument('port', nargs='?', type=int, default=5432, help='PostgreSQL port (default: 5432)')
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
    
    scan_postgresql_security(host, port, tls_only)

if __name__ == '__main__':
    main()

