#!/usr/bin/env python3
"""
Microsoft SQL Server Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Microsoft SQL Server connectivity and reports security configuration:
- No authentication required (vulnerable - Windows Authentication or weak SQL auth)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import struct

def test_mssql_connection(host, port, use_ssl=False):
    """Test basic SQL Server connection"""
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

def test_mssql_auth(host, port, use_ssl=False):
    """Test SQL Server authentication"""
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
        
        # SQL Server TDS protocol: PreLogin packet
        # Format: TDS header + PreLogin message
        
        # TDS PreLogin packet
        # Type: 0x12 (PreLogin)
        # Status: 0x01
        # Length: variable
        
        # Build PreLogin message
        prelogin = struct.pack('>B', 0x12)  # Type
        prelogin += struct.pack('>B', 0x01)  # Status
        prelogin += struct.pack('>H', 0x0000)  # Length (placeholder)
        prelogin += b'\x00\x00'  # Spid
        prelogin += b'\x00'  # PacketID
        prelogin += b'\x00'  # Window
        
        # Option token list
        # Token: VERSION
        prelogin += b'\x00'  # Token type (0 = VERSION)
        prelogin += struct.pack('>H', 6)  # Length
        prelogin += struct.pack('>BBBBBB', 14, 0, 0, 0, 0, 0)  # Version 14.0.0.0
        
        # Token: ENCRYPT
        prelogin += b'\x01'  # Token type (1 = ENCRYPT)
        prelogin += struct.pack('>H', 1)  # Length
        prelogin += b'\x00'  # Not encrypted
        
        # Token: INSTOPT
        prelogin += b'\x02'  # Token type (2 = INSTOPT)
        prelogin += struct.pack('>H', 0)  # Length
        
        # Token: THREADID
        prelogin += b'\x03'  # Token type (3 = THREADID)
        prelogin += struct.pack('>H', 4)  # Length
        prelogin += struct.pack('>I', 0)  # Thread ID
        
        # Token: MARS
        prelogin += b'\x04'  # Token type (4 = MARS)
        prelogin += struct.pack('>H', 1)  # Length
        prelogin += b'\x00'  # MARS disabled
        
        # Token: TERMINATOR
        prelogin += b'\xFF'  # Token type (255 = TERMINATOR)
        
        # Calculate length
        length = len(prelogin)
        prelogin = struct.pack('>B', 0x12) + struct.pack('>B', 0x01) + struct.pack('>H', length) + prelogin[4:]
        
        conn.send(prelogin)
        
        # Read response
        response = conn.recv(4096)
        conn.close()
        
        # Check if we got a response (connection successful)
        if len(response) > 0:
            # If we got a PreLogin response, SQL Server is accessible
            # Try to connect without authentication (using pymssql if available)
            try:
                import pymssql
                try:
                    conn = pymssql.connect(
                        server=host,
                        port=port,
                        user='sa',
                        password='',
                        timeout=5
                    )
                    conn.close()
                    print(f"Microsoft SQL Server accessible at {host}:{port}")
                    print("VULNERABLE: No authentication required or weak authentication")
                    print("VULNERABLE")
                    return True
                except pymssql.OperationalError as db_err:
                    if 'authentication' in str(db_err).lower() or 'login' in str(db_err).lower():
                        print(f"Microsoft SQL Server at {host}:{port} requires authentication")
                        return False
                    else:
                        print(f"Error testing SQL Server: {str(db_err)}")
                        return False
            except ImportError:
                # If pymssql not available, assume connection successful means vulnerable
                print(f"Microsoft SQL Server accessible at {host}:{port}")
                print("VULNERABLE: Connection successful (authentication status unknown - install pymssql for full test)")
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
            print(f"Error testing SQL Server: {str(e)}")
        return False

def scan_mssql_security(host, port=1433, tls_only=False):
    """Scan SQL Server security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_mssql_connection(host, port, use_ssl=True):
            test_mssql_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_mssql_connection(host, port, use_ssl=False):
            test_mssql_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='Microsoft SQL Server Security Scanner')
    parser.add_argument('host', help='SQL Server host to test')
    parser.add_argument('port', nargs='?', type=int, default=1433, help='SQL Server port (default: 1433)')
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
    
    scan_mssql_security(host, port, tls_only)

if __name__ == '__main__':
    main()

